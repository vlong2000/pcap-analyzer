# -*- coding: utf-8 -*-
"""GTP-U 拆解逻辑单元测试。"""

import contextlib
import io
import ipaddress
import os
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pcap_analyzer  # noqa: E402
from pcap_analyzer import (  # noqa: E402
    _gtp_tunnel_json,
    _identify_l7,
    _parse_gtp,
    _parse_gtp_c,
    _parse_udp,
    PacketInfo,
    ReassemblyCache,
    Statistics,
    print_report,
)


def _gtp(mtype, teid, b0=0x30, length=0, seq=None, npdu=0, next_ext=None):
    """构造 GTP 头；seq/npdu/next_ext 非空时自动置 E/S/PN 标志。"""
    if seq is not None:
        b0 |= 0x02
    if npdu:
        b0 |= 0x01
    if next_ext is not None:
        b0 |= 0x04
    hdr = struct.pack("!BBHI", b0, mtype, length, teid)
    if seq is not None or npdu or next_ext is not None:
        hdr += struct.pack("!HBB", seq or 0, npdu, next_ext or 0)
    return hdr


def _inner_ipv4(proto, payload=b""):
    total = 20 + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0,
        bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)),
    ) + payload


def _inner_ipv6(nxt, payload=b""):
    src = ipaddress.IPv6Address("2a02:9b0::7c8c").packed
    dst = ipaddress.IPv6Address("2a02:ce0:7:c000::c185").packed
    return struct.pack("!IHBB", 0x60000000, len(payload), nxt, 64) + src + dst + payload


def _new_info():
    return PacketInfo(index=0, ts=0.0, wire_len=0, cap_len=0)


def _parse(frame, cache=None):
    info = _new_info()
    ok = _parse_gtp(frame, 0, len(frame), info, cache)
    return ok, info


class TestGtpHeader(unittest.TestCase):
    def test_echo_request(self):
        ok, info = _parse(_gtp(0x01, 0, length=0))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_type"], "Echo Request")
        self.assertEqual(info.detail["gtp_teid"], "0x00000000")
        self.assertEqual(info.detail["gtp_version"], 1)
        self.assertEqual(info.note, "GTP Echo Request teid=0x00000000")

    def test_unknown_message_type(self):
        ok, info = _parse(_gtp(0x55, 0x0102))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_type"], "0x55")

    def test_truncated_header(self):
        ok, info = _parse(b"\x30\xff\x00")
        self.assertFalse(ok)
        self.assertEqual(info.note, "GTP 头部截断")

    def test_sequence_number_flag(self):
        ok, info = _parse(_gtp(0x01, 0, seq=0x1234))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_sequence"], 0x1234)

    def test_npdu_flag(self):
        ok, info = _parse(_gtp(0x01, 0, npdu=7))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_npdu"], 7)

    def test_optional_fields_truncated(self):
        frame = struct.pack("!BBHI", 0x32, 0x01, 0, 0) + b"\x00"
        ok, info = _parse(frame)
        self.assertFalse(ok)
        self.assertEqual(info.note, "GTP 可选字段截断")

    def test_extension_header_skipped(self):
        """E=1：跳过 4 字节扩展头后仍能定位内层 IPv4"""
        ext = bytes((1, 0x11, 0x22, 0x00))       # 长度 1（4 字节），末字节 0 结束
        frame = _gtp(0xFF, 0xABCD, next_ext=0x85) + ext + _inner_ipv4(6)
        ok, info = _parse(frame)
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_inner_proto"], "TCP")


class TestGtpInner(unittest.TestCase):
    def test_gpdu_ipv4_inner(self):
        ok, info = _parse(_gtp(0xFF, 0xDEADBEEF) + _inner_ipv4(6))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_inner_version"], 4)
        self.assertEqual(info.detail["gtp_inner_proto"], "TCP")
        self.assertEqual(info.detail["gtp_inner_src"], "10.0.0.1")
        self.assertEqual(info.detail["gtp_inner_dst"], "10.0.0.2")
        self.assertIn("IPv4 TCP", info.note)

    def test_gpdu_ipv6_inner_esp(self):
        ok, info = _parse(_gtp(0xFF, 0x5BD40F19) + _inner_ipv6(50, b"\x00" * 28))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_inner_version"], 6)
        self.assertEqual(info.detail["gtp_inner_proto"], "ESP")
        self.assertEqual(info.detail["gtp_inner_src"], "2a02:9b0::7c8c")
        self.assertEqual(info.detail["gtp_inner_len"], 28)
        self.assertIn("inner IPv6 ESP len=28", info.note)

    def test_gpdu_without_inner(self):
        ok, info = _parse(_gtp(0xFF, 0x01))
        self.assertTrue(ok)
        self.assertNotIn("inner", info.note)
        self.assertNotIn("gtp_inner_proto", info.detail)

    def test_inner_version_unknown_ignored(self):
        ok, info = _parse(_gtp(0xFF, 0x01) + b"\x00" * 40)
        self.assertTrue(ok)
        self.assertNotIn("gtp_inner_version", info.detail)

    def test_inner_truncated_ipv4(self):
        ok, info = _parse(_gtp(0xFF, 0x01) + b"\x45\x00\x00")
        self.assertTrue(ok)
        self.assertNotIn("gtp_inner_proto", info.detail)


class TestGtpOverUdp(unittest.TestCase):
    def _udp(self, dport, payload, sport=2152):
        return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

    def test_udp_port_2152_parsed(self):
        info = _new_info()
        frame = self._udp(2152, _gtp(0x01, 0))
        _parse_udp(frame, 0, len(frame), info)
        self.assertEqual(info.l4, "GTP-U")
        self.assertEqual(info.detail["gtp_type"], "Echo Request")

    def test_udp_truncated_gtp_stays_udp(self):
        info = _new_info()
        frame = self._udp(2152, b"\x30\xff\x00")
        _parse_udp(frame, 0, len(frame), info)
        self.assertEqual(info.l4, "UDP")
        self.assertEqual(info.note, "GTP 头部截断")

    def test_gtp_c_identified_by_port(self):
        self.assertEqual(_identify_l7(b"\x00" * 12, 2123, 40000, is_udp=True), "GTP-C")


def _inner_ipv4_frag(proto, payload, ip_id=0x1234, frag_off=0, more=False, total=None):
    """构造内层 IPv4 分片；frag_off 以字节计，内部换算成 8 字节单位。"""
    frag = (0x2000 if more else 0) | (frag_off // 8)
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total if total is not None else 20 + len(payload),
        ip_id, frag, 64, proto, 0, bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)),
    ) + payload


def _inner_ipv6_frag(nxt, body, frag_off=0, more=False, frag_id=1):
    """构造内层 IPv6 分片；frag_off 以字节计，内部换算成 8 字节单位。"""
    frag_bits = ((frag_off // 8) << 3) | (1 if more else 0)
    frag = bytes((nxt, 0)) + struct.pack("!H", frag_bits) + struct.pack("!I", frag_id)
    return _inner_ipv6(44, frag + body)


def _tcp_header(sport, dport, flags=0x18):
    return struct.pack("!HHIIHHHH", sport, dport, 1, 0, (5 << 12) | flags, 65535, 0, 0)


def _udp_header(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


class TestGtpInnerTransport(unittest.TestCase):
    def test_inner_tcp_ports(self):
        ok, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv4(6, _tcp_header(1234, 80)))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_inner_sport"], 1234)
        self.assertEqual(info.detail["gtp_inner_dport"], 80)
        self.assertEqual(info.detail["gtp_inner_tcp_flags"], "PSH,ACK")
        self.assertIn("IPv4 TCP 1234->80", info.note)

    def test_inner_udp_ports(self):
        ok, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv4(17, _udp_header(5060, 5060)))
        self.assertEqual(info.detail["gtp_inner_sport"], 5060)
        self.assertIn("UDP 5060->5060", info.note)

    def test_inner_icmp(self):
        ok, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv4(1, bytes((8, 0, 0, 0))))
        self.assertEqual(info.detail["gtp_inner_icmp_type"], 8)
        self.assertIn("ICMP type=8 code=0", info.note)

    def test_inner_ipv6_tcp_ports(self):
        ok, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv6(6, _tcp_header(443, 51000)))
        self.assertEqual(info.detail["gtp_inner_sport"], 443)
        self.assertEqual(info.detail["gtp_inner_dport"], 51000)
        self.assertIn("IPv6 TCP 443->51000", info.note)

    def test_inner_ipv6_hopbyhop_then_tcp(self):
        """Hop-by-Hop 扩展头后下钻到 TCP 端口"""
        ext = bytes((6, 0)) + b"\x00" * 6
        ok, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv6(0, ext + _tcp_header(1234, 80)))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtp_inner_ext"], 1)
        self.assertEqual(info.detail["gtp_inner_proto"], "TCP")
        self.assertEqual(info.detail["gtp_inner_dport"], 80)
        self.assertIn("IPv6 TCP 1234->80", info.note)

    def test_inner_ipv6_two_extension_headers(self):
        """Routing + Destination Options 两层扩展头后到达 UDP"""
        ext1 = bytes((60, 0)) + b"\x00" * 6
        ext2 = bytes((17, 0)) + b"\x00" * 6
        ok, info = _parse(_gtp(0xFF, 0x01)
                          + _inner_ipv6(43, ext1 + ext2 + _udp_header(1000, 2000)))
        self.assertEqual(info.detail["gtp_inner_ext"], 2)
        self.assertEqual(info.detail["gtp_inner_proto"], "UDP")
        self.assertEqual(info.detail["gtp_inner_dport"], 2000)

    def test_inner_ipv6_ah_then_tcp(self):
        """AH 长度公式为 (len+2)*4"""
        ext = bytes((6, 2)) + b"\x00" * 14
        ok, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv6(51, ext + _tcp_header(443, 9000)))
        self.assertEqual(info.detail["gtp_inner_ext"], 1)
        self.assertEqual(info.detail["gtp_inner_sport"], 443)
        self.assertEqual(info.detail["gtp_inner_dport"], 9000)

    def test_inner_ipv6_fragment_header_noted(self):
        """分片扩展头（offset=0, M=1）标注分片，不解析传输层"""
        frag = bytes((6, 0)) + struct.pack("!H", 0x0001) + b"\x00\x00\x00\x01"
        ok, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv6(44, frag + b"\x00" * 8))
        self.assertEqual(info.detail["gtp_inner_frag_offset"], 0)
        self.assertEqual(info.detail["gtp_inner_proto"], "TCP")
        self.assertIn("分片(offset=0, more=1)", info.note)
        self.assertNotIn("gtp_inner_sport", info.detail)

    def test_inner_ipv6_extension_truncated(self):
        """扩展头声明 8 字节但载荷不足，不崩溃并标记截断"""
        ok, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv6(0, bytes((6, 0))))
        self.assertTrue(ok)
        self.assertTrue(info.detail["gtp_inner_ext_truncated"])

    def test_inner_ipv6_fragment_reassembled(self):
        """IPv6 分片头两片拼齐后标记重组完成"""
        cache = ReassemblyCache()
        frag1 = _inner_ipv6_frag(6, b"\x00" * 8, frag_off=0, more=True, frag_id=0xABC)
        frag2 = _inner_ipv6_frag(6, b"\x11" * 4, frag_off=8, more=False, frag_id=0xABC)
        _, info1 = _parse(_gtp(0xFF, 0x01) + frag1, cache)
        self.assertIn("分片(offset=0, more=1)", info1.note)
        self.assertNotIn("重组完成", info1.note)
        _, info2 = _parse(_gtp(0xFF, 0x01) + frag2, cache)
        self.assertEqual(info2.detail["gtp_inner_frag_len"], 12)
        self.assertIn("重组完成=12B", info2.note)
        self.assertEqual(info2.detail["gtp_inner_src"], "2a02:9b0::7c8c")

    def test_inner_ipv6_fragments_different_id_not_mixed(self):
        """分片标识不同时不互相拼接"""
        cache = ReassemblyCache()
        frag1 = _inner_ipv6_frag(6, b"\x00" * 8, frag_off=0, more=True, frag_id=1)
        frag2 = _inner_ipv6_frag(6, b"\x00" * 4, frag_off=8, more=False, frag_id=2)
        _parse(_gtp(0xFF, 0x01) + frag1, cache)
        _, info = _parse(_gtp(0xFF, 0x01) + frag2, cache)
        self.assertNotIn("gtp_inner_frag_len", info.detail)
        self.assertNotIn("重组完成", info.note)

    def test_inner_ipv6_fragment_without_cache_noted(self):
        frag = _inner_ipv6_frag(6, b"\x00" * 8, frag_off=0, more=True)
        ok, info = _parse(_gtp(0xFF, 0x01) + frag)
        self.assertTrue(ok)
        self.assertNotIn("gtp_inner_frag_len", info.detail)

    def test_first_fragment_with_dest_opts_shows_ports(self):
        """首片在分片头之后带 DestOpts，仍能剥离并给出端口"""
        dest = bytes((6, 0)) + b"\x00" * 6
        body = dest + _tcp_header(1234, 80) + b"\x00" * 4
        _, info = _parse(_gtp(0xFF, 0x01) + _inner_ipv6_frag(60, body, frag_off=0, more=True))
        self.assertNotIn("gtp_inner_ext_truncated", info.detail)
        self.assertEqual(info.detail["gtp_inner_sport"], 1234)
        self.assertIn("IPv6 TCP 1234->80 [PSH,ACK] 分片(offset=0, more=1)", info.note)

    def test_fragment_with_ext_header_reassembled_and_stripped(self):
        """可分片部分的扩展头计入偏移；重组后再剥离，端口仍正确"""
        cache = ReassemblyCache()
        dest = bytes((6, 0)) + b"\x00" * 6
        body1 = dest + _tcp_header(5555, 443) + b"\x00" * 4     # 8 + 20 + 4 = 32
        body2 = b"\xaa" * 4
        f1 = _inner_ipv6_frag(60, body1, frag_off=0, more=True, frag_id=0x55)
        f2 = _inner_ipv6_frag(60, body2, frag_off=len(body1), more=False, frag_id=0x55)
        _parse(_gtp(0xFF, 0x01) + f1, cache)
        _, info = _parse(_gtp(0xFF, 0x01) + f2, cache)
        self.assertEqual(info.detail["gtp_inner_frag_len"], 36)
        self.assertEqual(info.detail["gtp_inner_ext_in_frag"], 8)
        self.assertEqual(info.detail["gtp_inner_sport"], 5555)
        self.assertEqual(info.detail["gtp_inner_dport"], 443)
        self.assertIn("重组完成=36B", info.note)

    def test_nonfirst_fragment_not_treated_as_ext_header(self):
        """非首片的数据不是扩展头，不应误标截断"""
        cache = ReassemblyCache()
        frag = _inner_ipv6_frag(60, b"\xff" * 8, frag_off=8, more=False, frag_id=0x77)
        ok, info = _parse(_gtp(0xFF, 0x01) + frag, cache)
        self.assertTrue(ok)
        self.assertNotIn("gtp_inner_ext_truncated", info.detail)
        self.assertNotIn("gtp_inner_frag_len", info.detail)

    def test_ipv6_fragment_last_first_completes_on_gap_fill(self):
        """末片先到、首片后补：补到首片时应立即完成重组"""
        cache = ReassemblyCache()
        dest = bytes((6, 0)) + b"\x00" * 6
        body1 = dest + _tcp_header(7000, 80) + b"\x00" * 4
        body2 = b"\xbb" * 4
        last = _inner_ipv6_frag(60, body2, frag_off=len(body1), more=False, frag_id=0x99)
        first = _inner_ipv6_frag(60, body1, frag_off=0, more=True, frag_id=0x99)
        _, info_last = _parse(_gtp(0xFF, 0x01) + last, cache)
        self.assertNotIn("gtp_inner_frag_len", info_last.detail)
        _, info_first = _parse(_gtp(0xFF, 0x01) + first, cache)
        self.assertEqual(info_first.detail["gtp_inner_frag_len"], 36)
        self.assertEqual(info_first.detail["gtp_inner_dport"], 80)
        self.assertIn("重组完成=36B", info_first.note)

    def test_ipv4_fragment_last_first_completes_on_gap_fill(self):
        """IPv4 分片同样支持末片先到、补首片即完成"""
        cache = ReassemblyCache()
        tcp = _tcp_header(4321, 22)
        first = _inner_ipv4_frag(6, tcp[:8], ip_id=0x88, frag_off=0, more=True, total=32)
        last = _inner_ipv4_frag(6, b"\x00" * 4, ip_id=0x88, frag_off=8, more=False,
                                total=32)
        _, info_last = _parse(_gtp(0xFF, 0x01) + last, cache)
        self.assertNotIn("gtp_inner_frag_len", info_last.detail)
        _, info_first = _parse(_gtp(0xFF, 0x01) + first, cache)
        self.assertEqual(info_first.detail["gtp_inner_frag_len"], 12)
        self.assertIn("重组完成=12B", info_first.note)

    def test_ipv6_frag_id_reuse_rebuilds_flow(self):
        """同 frag_id 被新报文复用：首片内容不同则重建，不与旧数据拼接"""
        cache = ReassemblyCache()
        old_head = b"\x00" * 8
        new_head = _udp_header(3000, 4000)
        _parse(_gtp(0xFF, 0x01)
               + _inner_ipv6_frag(17, old_head, frag_off=0, more=True, frag_id=0x77), cache)
        _parse(_gtp(0xFF, 0x01)
               + _inner_ipv6_frag(17, new_head, frag_off=0, more=True, frag_id=0x77), cache)
        self.assertEqual(cache.reuse_resets, 1)
        _, info = _parse(_gtp(0xFF, 0x01)
                         + _inner_ipv6_frag(17, b"\x00" * 8, frag_off=8, more=False,
                                            frag_id=0x77), cache)
        self.assertEqual(info.detail["gtp_inner_frag_len"], 16)
        self.assertEqual(info.detail["gtp_inner_sport"], 3000)
        self.assertEqual(info.detail["gtp_inner_dport"], 4000)

    def test_ipv6_duplicate_first_fragment_keeps_flow(self):
        """首片重传内容相同，不应清空已缓存分片"""
        cache = ReassemblyCache()
        head = _udp_header(1000, 2000)
        frag1 = _inner_ipv6_frag(17, head, frag_off=0, more=True, frag_id=0x88)
        _parse(_gtp(0xFF, 0x01) + frag1, cache)
        _parse(_gtp(0xFF, 0x01) + frag1, cache)
        self.assertEqual(cache.reuse_resets, 0)
        _, info = _parse(_gtp(0xFF, 0x01)
                         + _inner_ipv6_frag(17, b"\x00" * 8, frag_off=8, more=False,
                                            frag_id=0x88), cache)
        self.assertEqual(info.detail["gtp_inner_frag_len"], 16)
        self.assertEqual(info.detail["gtp_inner_dport"], 2000)

    def test_ipv6_headless_fragment_flagged_then_completes(self):
        """首片缺失时标记缺首片，补到首片后完成重组"""
        cache = ReassemblyCache()
        tail = _inner_ipv6_frag(17, b"\x00" * 8, frag_off=8, more=False, frag_id=0x66)
        head = _inner_ipv6_frag(17, _udp_header(1234, 5678), frag_off=0, more=True,
                               frag_id=0x66)
        _, info_tail = _parse(_gtp(0xFF, 0x01) + tail, cache)
        self.assertTrue(info_tail.detail["gtp_inner_frag_headless"])
        self.assertIn("缺首片", info_tail.note)
        _, info_head = _parse(_gtp(0xFF, 0x01) + head, cache)
        self.assertEqual(info_head.detail["gtp_inner_frag_len"], 16)
        self.assertNotIn("gtp_inner_frag_headless", info_head.detail)
        self.assertEqual(info_head.detail["gtp_inner_dport"], 5678)

    def test_ipv6_overlap_conflict_invalidates_datagram(self):
        """首片均缺失且内容冲突：按 RFC 8200 作废整包，不重组"""
        cache = ReassemblyCache()
        old_tail = _inner_ipv6_frag(17, b"\x11" * 8, frag_off=8, more=True, frag_id=0x55)
        new_tail = _inner_ipv6_frag(17, b"\x22" * 8, frag_off=8, more=False, frag_id=0x55)
        _parse(_gtp(0xFF, 0x01) + old_tail, cache)
        _, info = _parse(_gtp(0xFF, 0x01) + new_tail, cache)
        self.assertTrue(info.detail["gtp_inner_frag_invalid"])
        self.assertNotIn("gtp_inner_frag_len", info.detail)
        self.assertIn("分片作废(重叠)", info.note)

    def test_ipv6_fragment_beyond_65535_invalid(self):
        """偏移加长度超过 65535 的分片必须丢弃"""
        cache = ReassemblyCache()
        frag = _inner_ipv6_frag(17, b"\x00" * 16, frag_off=65520, more=False, frag_id=0x44)
        _, info = _parse(_gtp(0xFF, 0x01) + frag, cache)
        self.assertTrue(info.detail["gtp_inner_frag_invalid"])
        self.assertIn("超出 65535", info.note)
        self.assertEqual(cache.flow_count(), 0)

    def test_ipv6_nonlast_fragment_length_not_multiple_of_8(self):
        """非末片长度必须是 8 的倍数，否则丢弃"""
        cache = ReassemblyCache()
        frag = _inner_ipv6_frag(17, b"\x00" * 12, frag_off=0, more=True, frag_id=0x45)
        _, info = _parse(_gtp(0xFF, 0x01) + frag, cache)
        self.assertTrue(info.detail["gtp_inner_frag_invalid"])
        self.assertIn("非末片长度非 8 倍数", info.note)

    def test_ipv6_duplicate_nonfirst_fragment_tolerated(self):
        """非首片重复（内容一致）按重传处理，不判废"""
        cache = ReassemblyCache()
        head = _inner_ipv6_frag(17, _udp_header(1000, 2000), frag_off=0, more=True,
                               frag_id=0x34)
        tail = _inner_ipv6_frag(17, b"\x00" * 8, frag_off=8, more=True, frag_id=0x34)
        _parse(_gtp(0xFF, 0x01) + head, cache)
        _parse(_gtp(0xFF, 0x01) + tail, cache)
        _, info = _parse(_gtp(0xFF, 0x01) + tail, cache)     # 重复末片
        self.assertNotIn("gtp_inner_frag_invalid", info.detail)
        key = ("gtp-frag6", 0x01, "2a02:9b0::7c8c", "2a02:ce0:7:c000::c185", 0x34)
        self.assertFalse(cache.is_invalid(key))

    def test_inner_fragment_reassembled(self):
        cache = ReassemblyCache()
        frag1 = _inner_ipv4_frag(6, b"\x00" * 8, frag_off=0, more=True, total=32)
        frag2 = _inner_ipv4_frag(6, b"\x00" * 4, frag_off=8, more=False, total=32)
        _, info1 = _parse(_gtp(0xFF, 0x01) + frag1, cache)
        self.assertIn("分片", info1.note)
        self.assertNotIn("重组完成", info1.note)
        _, info2 = _parse(_gtp(0xFF, 0x01) + frag2, cache)
        self.assertEqual(info2.detail["gtp_inner_frag_len"], 12)
        self.assertIn("重组完成=12B", info2.note)

    def test_inner_fragment_without_cache_noted(self):
        frag = _inner_ipv4_frag(6, b"\x00" * 8, frag_off=0, more=True, total=32)
        ok, info = _parse(_gtp(0xFF, 0x01) + frag)
        self.assertTrue(ok)
        self.assertIn("分片", info.note)
        self.assertNotIn("gtp_inner_frag_len", info.detail)


class TestGtpv2(unittest.TestCase):
    @staticmethod
    def _v2(mtype, seq=1, teid=None, ies=b"", b0=None):
        flags = 0x40 if b0 is None else b0
        if teid is not None:
            flags |= 0x08
        hdr = struct.pack("!BBH", flags, mtype, 4 + (4 if teid is not None else 0) + len(ies))
        if teid is not None:
            hdr += struct.pack("!I", teid)
        hdr += int(seq).to_bytes(3, "big") + b"\x00"
        return hdr + ies

    @staticmethod
    def _ie(ie_type, value, instance=0):
        return struct.pack("!BH", ie_type, (instance << 12) | len(value)) + value

    def _parse_c(self, frame):
        info = _new_info()
        ok = _parse_gtp_c(frame, 0, len(frame), info)
        return ok, info

    def test_create_session_request_with_ies(self):
        ies = self._ie(1, b"\x01\x02\x03\x04\x05\x06\x07\x08") + self._ie(71, b"internet")
        ok, info = self._parse_c(self._v2(32, seq=0x010203, teid=0x11223344, ies=ies))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtpv2_type"], "Create Session Request")
        self.assertEqual(info.detail["gtpv2_teid"], "0x11223344")
        self.assertEqual(info.detail["gtpv2_sequence"], 0x010203)
        self.assertEqual(info.detail["gtpv2_ies"], ["IMSI", "APN"])
        self.assertIn("IE 2个: IMSI, APN", info.note)

    def test_imsi_decoded_from_tbcd(self):
        ies = self._ie(1, bytes([0x21, 0x43, 0x65, 0x87, 0x09]))
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["IMSI"], "1234567890")

    def test_imsi_trailing_filler_skipped(self):
        ies = self._ie(1, bytes([0x21, 0x43, 0xF5]))
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["IMSI"], "12345")

    def test_apn_multi_label_decoded(self):
        ies = self._ie(71, b"\x08internet\x03ims")
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["APN"], "internet.ims")

    def test_apn_empty_not_recorded(self):
        ies = self._ie(71, b"\x00")
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ies"], ["APN"])
        self.assertNotIn("gtpv2_ie_values", info.detail)

    def test_cause_name_decoded(self):
        ies = self._ie(2, b"\x40")
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["Cause"], "Context Not Found")

    def test_unknown_cause_code_kept_raw(self):
        ies = self._ie(2, b"\xfe")
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["Cause"], "cause-254")

    def test_scalar_ies_decoded(self):
        ies = (self._ie(3, b"\x07") + self._ie(73, b"\x05")
               + self._ie(77, b"\x06"))
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        values = info.detail["gtpv2_ie_values"]
        self.assertEqual(values["Recovery"], "7")
        self.assertEqual(values["EPS Bearer ID"], "5")
        self.assertEqual(values["RAT Type"], "6")

    def test_f_teid_with_ipv4_decoded(self):
        ies = self._ie(87, b"\x80" + struct.pack("!I", 0x01020304) + bytes((10, 0, 0, 1)))
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["F-TEID"],
                         "teid=0x01020304 ipv4=10.0.0.1")

    def test_f_teid_without_v4_flag(self):
        ies = self._ie(87, b"\x00" + struct.pack("!I", 0x11223344))
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["F-TEID"], "teid=0x11223344")

    def test_ambr_decoded(self):
        ies = self._ie(72, struct.pack("!I", 100000) + struct.pack("!I", 200000))
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["AMBR"],
                         "ul=100000 kbps dl=200000 kbps")

    def test_ambr_unit_mbps(self):
        ies = self._ie(72, bytes([0x20, 0x00, 0x00, 100]) + struct.pack("!I", 50))
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["AMBR"],
                         "ul=100 Mbps dl=50 kbps")

    def test_ambr_reserved_unit_kept_raw(self):
        ies = self._ie(72, bytes([0x60, 0x00, 0x00, 7]) + struct.pack("!I", 8))
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["AMBR"],
                         "ul=7 unit=3 dl=8 kbps")

    def test_cause_common_codes(self):
        cases = {66: "Invalid length", 68: "System failure",
                 70: "Missing or unknown APN", 72: "Try again later"}
        for code, name in cases.items():
            _, info = self._parse_c(self._v2(32, seq=1, teid=1,
                                             ies=self._ie(2, bytes([code]))))
            self.assertEqual(info.detail["gtpv2_ie_values"]["Cause"], name,
                             msg=f"cause {code}")

    def test_unknown_ie_type_has_no_value(self):
        ies = self._ie(200, b"\xde\xad")
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ies"], ["IE-200"])
        self.assertNotIn("gtpv2_ie_values", info.detail)

    def test_uli_tai_and_ecgi_decoded(self):
        tai = b"\x64\x00\xf1" + b"\x12\x34"          # PLMN 460/01 + TAC
        ecgi = b"\x64\x00\xf1" + b"\x01\x02\x03\x04"
        ies = self._ie(75, b"\x05" + tai + b"\x07" + ecgi)
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["ULI"],
                         "tai=mcc=460 mnc=01 tac=0x1234 "
                         "ecgi=mcc=460 mnc=01 eci=0x01020304")

    def test_uli_three_digit_mnc(self):
        tai = b"\x64\x00\x10" + b"\x00\x01"          # MNC 第三位非 0xF → 三位
        ies = self._ie(75, b"\x05" + tai)
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertIn("mnc=001", info.detail["gtpv2_ie_values"]["ULI"])

    def test_bearer_qos_arp_and_qci(self):
        ies = self._ie(83, bytes([0x08 | 0x01, 0x05]) + b"\x00" * 20)
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["Bearer QoS"], "arp=9 qci=5")

    def test_indication_flags_hex(self):
        ies = self._ie(78, b"\x00\x01")
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        self.assertEqual(info.detail["gtpv2_ie_values"]["Indication"], "0001")

    def test_nonzero_ie_instance_gets_suffix(self):
        ies = self._ie(87, b"\x00" + struct.pack("!I", 0xAA)) + \
              self._ie(87, b"\x00" + struct.pack("!I", 0xBB), instance=2)
        _, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=ies))
        values = info.detail["gtpv2_ie_values"]
        self.assertEqual(values["F-TEID"], "teid=0x000000aa")
        self.assertEqual(values["F-TEID#2"], "teid=0x000000bb")

    def test_echo_request_without_teid(self):
        ok, info = self._parse_c(self._v2(1, seq=7))
        self.assertTrue(ok)
        self.assertEqual(info.detail["gtpv2_type"], "Echo Request")
        self.assertNotIn("gtpv2_teid", info.detail)
        self.assertEqual(info.note, "GTPv2-C Echo Request seq=7")

    def test_wrong_version_rejected(self):
        frame = self._v2(1, seq=1, b0=0x30)          # 版本 1
        ok, info = self._parse_c(frame)
        self.assertFalse(ok)
        self.assertEqual(info.note, "GTP 版本非 2 (v1)")

    def test_truncated_ie_flagged(self):
        bad = struct.pack("!BH", 1, 16) + b"\x00\x00"
        ok, info = self._parse_c(self._v2(32, seq=1, teid=1, ies=bad))
        self.assertTrue(ok)
        self.assertTrue(info.detail["gtpv2_ie_truncated"])
        self.assertNotIn("gtpv2_ies", info.detail)

    def test_udp_port_2123_parsed(self):
        info = _new_info()
        payload = self._v2(1, seq=3)
        frame = struct.pack("!HHHH", 2123, 2123, 8 + len(payload), 0) + payload
        _parse_udp(frame, 0, len(frame), info)
        self.assertEqual(info.l4, "GTP-C")
        self.assertEqual(info.detail["gtpv2_type"], "Echo Request")


class TestGtpStatistics(unittest.TestCase):
    def test_teid_aggregation(self):
        stats = Statistics()
        for wire in (158, 1354, 150):
            info = _new_info()
            info.wire_len = wire
            info.l4 = "GTP-U"
            info.detail["gtp_teid"] = "0x5bd40f19"
            info.detail["gtp_inner_proto"] = "ESP"
            stats.feed(info)
        self.assertEqual(stats.gtp_teids["0x5bd40f19"], [3, 158 + 1354 + 150])
        self.assertEqual(stats.gtp_inner_protos["ESP"], 3)


class TestGtpTeidMerge(unittest.TestCase):
    """GTP-U 内层数据按 TEID 合并输出。"""

    @staticmethod
    def _feed(stats, frame):
        info = _new_info()
        info.wire_len = len(frame)
        info.l4 = "GTP-U"
        _parse_gtp(frame, 0, len(frame), info)
        stats.feed(info)
        return info

    def test_merge_concatenates_inner_data(self):
        stats = Statistics()
        inner1 = _inner_ipv4(17, _udp_header(1000, 2000, b"one"))
        inner2 = _inner_ipv4(17, _udp_header(1000, 2000, b"two"))
        self._feed(stats, _gtp(0xFF, 0x0102) + inner1)
        self._feed(stats, _gtp(0xFF, 0x0102) + inner2)
        rec = stats.gtp_merge["0x00000102"]
        self.assertEqual(rec.packets, 2)
        self.assertEqual(rec.bytes, len(inner1) + len(inner2))
        self.assertEqual(bytes(rec.merged), inner1 + inner2)
        self.assertFalse(rec.truncated)

    def test_merge_separates_teids(self):
        stats = Statistics()
        self._feed(stats, _gtp(0xFF, 0x01) + _inner_ipv4(17, _udp_header(1, 2)))
        self._feed(stats, _gtp(0xFF, 0x02) + _inner_ipv4(17, _udp_header(3, 4)))
        self.assertEqual(len(stats.gtp_merge), 2)
        self.assertEqual(stats.gtp_merge["0x00000001"].packets, 1)
        self.assertEqual(stats.gtp_merge["0x00000002"].packets, 1)

    def test_non_gpdu_not_merged(self):
        stats = Statistics()
        self._feed(stats, _gtp(0x01, 0))
        self.assertEqual(stats.gtp_merge, {})

    def test_merge_tracks_sequence(self):
        stats = Statistics()
        for seq in (1, 2, 5):
            self._feed(stats, _gtp(0xFF, 0xAA, seq=seq)
                       + _inner_ipv4(17, _udp_header(1, 2)))
        rec = stats.gtp_merge["0x000000aa"]
        self.assertEqual(rec.seq_first, 1)
        self.assertEqual(rec.seq_last, 5)
        self.assertEqual(rec.seq_jumps, 1)          # 2 -> 5 跳号

    def test_merge_sequence_wrap_not_counted_as_jump(self):
        stats = Statistics()
        for seq in (0xFFFF, 0):
            self._feed(stats, _gtp(0xFF, 0xBB, seq=seq)
                       + _inner_ipv4(17, _udp_header(1, 2)))
        rec = stats.gtp_merge["0x000000bb"]
        self.assertEqual(rec.seq_jumps, 0)
        self.assertEqual(rec.seq_last, 0)

    def test_merge_truncates_at_limit(self):
        stats = Statistics()
        inner = _inner_ipv4(17, _udp_header(1, 2, b"0123456789"))
        with mock.patch.object(pcap_analyzer, "GTP_MERGE_MAX_BYTES", 10):
            self._feed(stats, _gtp(0xFF, 0xCC) + inner)
            self._feed(stats, _gtp(0xFF, 0xCC) + inner)
        rec = stats.gtp_merge["0x000000cc"]
        self.assertEqual(len(rec.merged), 10)
        self.assertEqual(rec.bytes, len(inner) * 2)
        self.assertTrue(rec.truncated)

    def test_merge_aggregates_inner_flows(self):
        stats = Statistics()
        for _ in range(2):
            self._feed(stats, _gtp(0xFF, 0xDD)
                       + _inner_ipv4(17, _udp_header(5060, 5060)))
        self._feed(stats, _gtp(0xFF, 0xDD) + _inner_ipv4(6, _tcp_header(1234, 80)))
        rec = stats.gtp_merge["0x000000dd"]
        self.assertEqual(rec.inner_protos["UDP"], 2)
        self.assertEqual(rec.inner_protos["TCP"], 1)
        self.assertEqual(rec.flows["UDP 10.0.0.1:5060->10.0.0.2:5060"], 2)
        self.assertEqual(rec.flows["TCP 10.0.0.1:1234->10.0.0.2:80"], 1)

    def test_merge_records_segment_offset(self):
        info = _new_info()
        frame = _gtp(0xFF, 0xEE) + _inner_ipv4(17, _udp_header(1, 2))
        _parse_gtp(frame, 0, len(frame), info)
        self.assertEqual(info.gtp_seg_off, 8)
        self.assertTrue(info.gtp_seg.startswith(b"\x45"))

    def test_merge_payload_bytes_and_lines(self):
        stats = Statistics()
        inner = _inner_ipv4(17, _udp_header(1, 2, b"xyz"))
        self._feed(stats, _gtp(0xFF, 0xFA) + inner)
        rec = stats.gtp_merge["0x000000fa"]
        self.assertIsInstance(rec.payload, bytes)
        self.assertEqual(rec.payload, inner)
        self.assertTrue(rec.payload_lines("hex"))

    def test_merge_marks_truncated_when_buffer_exactly_full(self):
        """首包正好填满上限(不算截断), 后续包到达时仍需置截断标记。"""
        stats = Statistics()
        inner = _inner_ipv4(17, _udp_header(1, 2, b"0123456789"))
        with mock.patch.object(pcap_analyzer, "GTP_MERGE_MAX_BYTES", len(inner)):
            self._feed(stats, _gtp(0xFF, 0xF3) + inner)
            rec = stats.gtp_merge["0x000000f3"]
            self.assertFalse(rec.truncated)
            self._feed(stats, _gtp(0xFF, 0xF3) + inner)
        self.assertTrue(rec.truncated)
        self.assertEqual(len(rec.merged), len(inner))
        self.assertEqual(rec.packets, 2)
        self.assertEqual(rec.bytes, len(inner) * 2)

    def test_merge_ipv6_flow_uses_brackets(self):
        """内层 IPv6 地址加方括号, 避免与端口分隔符混淆。"""
        stats = Statistics()
        self._feed(stats, _gtp(0xFF, 0xF4) + _inner_ipv6(17, _udp_header(5060, 5060)))
        rec = stats.gtp_merge["0x000000f4"]
        label, count = next(iter(rec.flows.items()))
        self.assertEqual(
            label, "UDP [2a02:9b0::7c8c]:5060->[2a02:ce0:7:c000::c185]:5060")
        self.assertEqual(count, 1)


class _StubReader:
    path = os.path.join("test", "pcaps", "stub.pcap")
    format_name = "pcap"
    linktypes = [1]


class TestGtpMergeReport(unittest.TestCase):
    def _stats(self):
        stats = Statistics()
        for seq in (1, 2):
            info = _new_info()
            info.wire_len = 100
            info.l4 = "GTP-U"
            frame = _gtp(0xFF, 0x0102, seq=seq) + _inner_ipv4(
                17, _udp_header(1000, 2000, b"hi"))
            _parse_gtp(frame, 0, len(frame), info)
            stats.feed(info)
        return stats

    def _report(self, stats, dump=None, dump_bytes=256):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_report(_StubReader(), stats, dump, dump_bytes)
        return buf.getvalue()

    def test_report_contains_merge_section(self):
        out = self._report(self._stats())
        self.assertIn("GTP-U TEID 合并输出 (1 条隧道)", out)
        self.assertIn("TEID=0x00000102 packets=2", out)
        self.assertIn("内层协议: UDP(2)", out)
        self.assertIn("seq=1..2", out)

    def test_report_dump_shows_merged_hex(self):
        out = self._report(self._stats(), "hex", 256)
        self.assertIn("45 00", out)          # 内层 IPv4 首字节
        self.assertNotIn("剩余", out)

    def test_report_dump_truncation_hint(self):
        out = self._report(self._stats(), "hex", 4)
        self.assertIn("剩余", out)

    def test_tunnel_json_payload_block(self):
        stats = self._stats()
        rec = stats.gtp_merge["0x00000102"]
        item = _gtp_tunnel_json(rec, "hex", 4)
        self.assertEqual(item["teid"], "0x00000102")
        self.assertEqual(item["packets"], 2)
        self.assertEqual(item["payload"]["shown"], 4)
        self.assertEqual(item["payload"]["total"], len(rec.merged))
        self.assertEqual(item["payload"]["hex"], bytes(rec.merged[:4]).hex())

    def test_tunnel_json_without_dump_has_no_payload(self):
        item = _gtp_tunnel_json(self._stats().gtp_merge["0x00000102"])
        self.assertNotIn("payload", item)
        self.assertEqual(item["seq_first"], 1)
        self.assertEqual(item["seq_jumps"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
