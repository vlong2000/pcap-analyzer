# -*- coding: utf-8 -*-
"""ESP 头解析（RFC 4303）单元测试。

未解密时只有 SPI 与序列号可读，加密域内容（Padding/Pad Length/
Next Header/ICV）不解析，密文部分由 payload_raw 保留供 dump 展示。
"""

import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from pcap_analyzer import (   # noqa: E402
    PacketInfo,
    RawPacket,
    Statistics,
    _match_filter,
    main,
    parse_packet,
)


def _raw(frame, ts=0.0, index=0):
    return RawPacket(index, ts, frame, len(frame), 1)


def _eth(ethertype, payload=b""):
    return b"\x00" * 12 + struct.pack("!H", ethertype) + payload


def _ipv4(proto, payload=b""):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0,
                       64, proto, 0,
                       bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))) + payload


def _ipv6(nxt, payload=b""):
    return (struct.pack("!IHBB", 0x60000000, len(payload), nxt, 64)
            + bytes(16) + bytes(16) + payload)


def _esp(spi, seq, cipher=b""):
    return struct.pack("!II", spi, seq) + cipher


def _ipv4_custom(proto, payload, total=None, ihl=5, frag=0):
    """可指定总长/头部长度/分片字段的 IPv4 帧体。"""
    if total is None:
        total = ihl * 4 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, 0x1234, frag,
                       64, proto, 0,
                       bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))
                       ) + bytes(ihl * 4 - 20) + payload


def _ipv6_custom(nxt, payload, plen=None):
    """可指定 payload length 字段的 IPv6 帧体。"""
    if plen is None:
        plen = len(payload)
    return (struct.pack("!IHBB", 0x60000000, plen, nxt, 64)
            + bytes(16) + bytes(16) + payload)


def _udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _vlan_eth(payload, tags=2, ethertype=0x0800):
    """带 tags 层 802.1Q 标签的以太网帧。"""
    hdr = b"\x00" * 12 + struct.pack("!H", 0x8100)
    for i in range(tags - 1):
        hdr += struct.pack("!HH", i + 1, 0x8100)
    return hdr + struct.pack("!HH", tags, ethertype) + payload


class TestEspHeader(unittest.TestCase):
    def test_ipv4_esp(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(
            0xDEADBEEF, 0x01020304, b"\xaa" * 24)))))
        self.assertEqual(info.l3, "IPv4")
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.detail["esp_spi"], "0xdeadbeef")
        self.assertEqual(info.detail["esp_seq"], 0x01020304)
        self.assertEqual(info.detail["esp_cipher_len"], 24)
        self.assertEqual(info.payload_len, 32)
        self.assertEqual(info.note, "ESP spi=0xdeadbeef seq=16909060 密文=24B")

    def test_ipv6_esp(self):
        info = parse_packet(_raw(_eth(0x86DD, _ipv6(50, _esp(
            0x00000001, 1, b"\x00" * 32)))))
        self.assertEqual(info.l3, "IPv6")
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.detail["esp_spi"], "0x00000001")
        self.assertEqual(info.detail["esp_cipher_len"], 32)

    def test_cipher_raw_and_offset(self):
        cipher = bytes(range(16, 48))
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(
            0x1001, 7, cipher)))))
        # 14(以太网) + 20(IPv4) + 8(ESP 头) = 42
        self.assertEqual(info.payload_off, 42)
        self.assertEqual(info.payload_raw, cipher)

    def test_header_only_without_cipher(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(0x10, 3)))))
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.detail["esp_cipher_len"], 0)
        self.assertEqual(info.note, "ESP spi=0x00000010 seq=3 密文=0B")
        self.assertEqual(info.payload_raw, b"")

    def test_truncated_header(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, b"\x00\x00\x01"))))
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.note, "ESP 头部截断")
        self.assertNotIn("esp_spi", info.detail)
        self.assertEqual(info.payload_off, 34)
        self.assertEqual(info.payload_raw, b"\x00\x00\x01")

    def test_sequence_wraps_to_zero(self):
        """序列号 32 位无符号, 到达 0xFFFFFFFF 后回绕"""
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(
            0x01000001, 0xFFFFFFFF, b"\x00" * 8)))))
        self.assertEqual(info.detail["esp_seq"], 0xFFFFFFFF)

    def test_non_multiple_of_four_length(self):
        """ICV 长度由算法决定, ESP 段总长不要求 4 字节对齐"""
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(
            0x02, 5, b"\x11" * 13)))))
        self.assertEqual(info.detail["esp_cipher_len"], 13)

    def test_ah_keeps_whole_segment(self):
        """AH(51) 仍走未解码分支, 保留整段（含 12 字节 AH 头）"""
        ah = struct.pack("!BBH", 51, 1, 0) + b"\x00\x00\x00\x01" + b"\x00" * 4
        info = parse_packet(_raw(_eth(0x0800, _ipv4(51, ah))))
        self.assertEqual(info.l4, "AH")
        self.assertEqual(info.payload_off, 34)
        self.assertEqual(info.payload_raw, ah)


class TestEspLengthBoundary(unittest.TestCase):
    """ESP 段长度边界: 截断 / 恰好 8 字节 / 1 字节密文"""

    def test_zero_length_truncated(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, b""))))
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.note, "ESP 头部截断")
        self.assertEqual(info.payload_len, 0)
        self.assertEqual(info.payload_raw, b"")
        self.assertEqual(info.payload_off, 34)
        self.assertNotIn("esp_cipher_len", info.detail)

    def test_seven_bytes_truncated(self):
        """比 8 字节头少 1 字节"""
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, b"\x00" * 7))))
        self.assertEqual(info.note, "ESP 头部截断")
        self.assertEqual(info.payload_raw, b"\x00" * 7)
        self.assertNotIn("esp_spi", info.detail)

    def test_one_byte_cipher(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(
            0x03, 1, b"\x99")))))
        self.assertEqual(info.detail["esp_cipher_len"], 1)
        self.assertEqual(info.payload_raw, b"\x99")
        self.assertEqual(info.payload_off, 42)

    def test_ipv4_total_shorter_than_capture(self):
        """IPv4 total length 只覆盖部分密文时按 total 截断, 不多读帧尾字节"""
        esp = _esp(0x04, 2, b"\xaa" * 32)
        info = parse_packet(_raw(_eth(0x0800, _ipv4_custom(
            50, esp, total=20 + 8 + 4))))
        self.assertEqual(info.payload_len, 12)
        self.assertEqual(info.detail["esp_cipher_len"], 4)
        self.assertEqual(info.payload_raw, b"\xaa" * 4)

    def test_ipv4_capture_truncated(self):
        """抓包被截断(total 大于实际帧)时按可用字节计算密文长度"""
        esp = _esp(0x05, 3, b"\xbb" * 10)
        info = parse_packet(_raw(_eth(0x0800, _ipv4_custom(
            50, esp, total=20 + 40))))
        self.assertEqual(info.payload_len, 18)
        self.assertEqual(info.detail["esp_cipher_len"], 10)

    def test_ipv6_zero_payload_length_uses_capture(self):
        """IPv6 payload length 为 0 时沿用捕获长度(处理 Jumbo/异常包)"""
        esp = _esp(0x06, 4, b"\xcc" * 16)
        info = parse_packet(_raw(_eth(0x86DD, _ipv6_custom(50, esp, plen=0))))
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.detail["esp_cipher_len"], 16)


class TestEspFieldValues(unittest.TestCase):
    """SPI / 序列号取值边界"""

    def test_spi_zero(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(0, 1)))))
        self.assertEqual(info.detail["esp_spi"], "0x00000000")

    def test_spi_max(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(
            0xFFFFFFFF, 1)))))
        self.assertEqual(info.detail["esp_spi"], "0xffffffff")

    def test_sequence_zero(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(1, 0)))))
        self.assertEqual(info.detail["esp_seq"], 0)

    def test_payload_len_equals_cipher_plus_header(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(
            0x07, 9, b"\x00" * 21)))))
        self.assertEqual(info.payload_len,
                         info.detail["esp_cipher_len"] + 8)


class TestEspEncapsulation(unittest.TestCase):
    """ESP 在不同封装位置下的偏移计算"""

    def test_double_vlan_offset(self):
        esp = _esp(0x10, 1, b"\x00" * 8)
        info = parse_packet(_raw(_vlan_eth(_ipv4(50, esp), tags=2)))
        self.assertEqual(info.detail["vlan_tags"], 2)
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.payload_off, 50)          # 22 + 20 + 8

    def test_ipv4_options_offset(self):
        """IHL=24（含 4 字节选项）时 ESP 头偏移随之前移"""
        esp = _esp(0x11, 2, b"\x00" * 8)
        info = parse_packet(_raw(_eth(0x0800, _ipv4_custom(
            50, esp, ihl=6))))
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.payload_off, 46)          # 14 + 24 + 8

    def test_ipv6_hopbyhop_offset(self):
        ext = bytes((50, 0)) + b"\x00" * 6
        esp = _esp(0x12, 3, b"\x00" * 8)
        info = parse_packet(_raw(_eth(0x86DD, _ipv6(0, ext + esp))))
        self.assertEqual(info.detail["ext_headers"], 1)
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.payload_off, 70)          # 14 + 40 + 8 + 8

    def test_ipv6_first_fragment_parses_header(self):
        """分片首片带完整 ESP 头, 仍可读出 SPI"""
        frag = bytes((50, 0)) + struct.pack("!H", 0x0001) + struct.pack("!I", 1)
        esp = _esp(0x13, 4, b"\x00" * 24)
        info = parse_packet(_raw(_eth(0x86DD, _ipv6(44, frag + esp))))
        self.assertEqual(info.detail["next_header"], 50)
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.detail["esp_spi"], "0x00000013")

    def test_ipv6_non_first_fragment_not_parsed(self):
        frag = bytes((50, 0)) + struct.pack("!H", 0x0008) + struct.pack("!I", 1)
        info = parse_packet(_raw(_eth(0x86DD, _ipv6(44, frag + b"\x00" * 16))))
        self.assertEqual(info.l4, "IPv6-frag")
        self.assertNotIn("esp_spi", info.detail)

    def test_ipv4_non_first_fragment_not_parsed(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4_custom(
            50, b"\x00" * 16, frag=0x0001))))
        self.assertEqual(info.l4, "IPv4-frag")
        self.assertNotIn("esp_spi", info.detail)

    def test_gtp_inner_esp_has_no_esp_fields(self):
        """GTP 内层 ESP 不经过 _parse_esp, 不产生 ESP 头字段"""
        gtp = struct.pack("!BBHI", 0x30, 0xFF, 0, 0xABC)
        inner = _ipv6(50, _esp(0x14, 5, b"\x00" * 24))
        udp = struct.pack("!HHHH", 2152, 2152, 8 + len(gtp) + len(inner), 0) \
            + gtp + inner
        info = parse_packet(_raw(_eth(0x0800, _ipv4(17, udp))))
        self.assertEqual(info.l4, "GTP-U")
        self.assertIn("inner IPv6 ESP", info.note)
        self.assertNotIn("esp_spi", info.detail)


class TestEspFilter(unittest.TestCase):
    def test_filter_matches_esp(self):
        info = parse_packet(_raw(_eth(0x0800, _ipv4(50, _esp(1, 1)))))
        self.assertTrue(_match_filter(info, "esp"))
        self.assertTrue(_match_filter(info, "ESP"))
        self.assertFalse(_match_filter(info, "tcp"))
        self.assertFalse(_match_filter(info, "udp"))


class TestNatt(unittest.TestCase):
    """UDP 4500 NAT-T 解封装 (RFC 3948)"""

    def _natt(self, payload):
        return parse_packet(_raw(_eth(0x0800, _ipv4(
            17, _udp(4500, 4500, payload)))))

    def test_esp_over_udp_4500(self):
        info = self._natt(_esp(0x20, 1, b"\x00" * 16))
        self.assertEqual(info.l4, "ESP")
        self.assertTrue(info.detail["natt"])
        self.assertEqual(info.detail["esp_spi"], "0x00000020")
        self.assertEqual(info.detail["esp_cipher_len"], 16)
        self.assertEqual(info.payload_off, 50)          # 14 + 20 + 8 + 8
        self.assertTrue(info.note.startswith("NAT-T ESP spi="))

    def test_keepalive_single_byte(self):
        info = self._natt(b"\xff")
        self.assertEqual(info.l4, "NAT-T")
        self.assertEqual(info.note, "NAT-T Keepalive")
        self.assertNotIn("esp_spi", info.detail)

    def test_single_byte_non_ff_is_esp(self):
        """4500 上的单字节并非都是 Keepalive: 非 0xFF 按 ESP 截断处理。"""
        info = self._natt(b"\x00")
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.note, "NAT-T ESP 头部截断")
        self.assertEqual(info.payload_raw, b"\x00")

    def test_ike_non_esp_marker(self):
        ike = bytes(range(24))
        info = self._natt(b"\x00\x00\x00\x00" + ike)
        self.assertEqual(info.l4, "IKE")
        self.assertIn("non-ESP marker", info.note)
        self.assertIn("IKE 载荷 24B", info.note)
        self.assertEqual(info.payload_off, 46)          # 14 + 20 + 8 + 4
        self.assertEqual(info.payload_raw, ike)

    def test_short_zero_prefix_is_esp_not_ike(self):
        """4 字节 0x00 前缀但总长不足 28B 时不判为 IKE(SPI=0 的短 ESP)"""
        info = self._natt(b"\x00\x00\x00\x00" + struct.pack("!I", 8))
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.detail["esp_spi"], "0x00000000")
        self.assertEqual(info.detail["esp_seq"], 8)

    def test_truncated_esp_in_natt(self):
        info = self._natt(b"\x01\x02\x03\x04\x05\x06")
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.note, "NAT-T ESP 头部截断")
        self.assertEqual(info.payload_raw, b"\x01\x02\x03\x04\x05\x06")

    def test_empty_payload(self):
        info = self._natt(b"")
        self.assertEqual(info.l4, "NAT-T")
        self.assertEqual(info.note, "NAT-T 空载荷")

    def test_natt_esp_matches_esp_filter(self):
        info = self._natt(_esp(0x21, 2, b"\x00" * 8))
        self.assertTrue(_match_filter(info, "esp"))


def _esp_info(spi, seq, wire=100):
    info = PacketInfo(index=0, ts=0.0, wire_len=wire, cap_len=wire)
    info.l4 = "ESP"
    info.detail = {"esp_spi": f"0x{spi:08x}", "esp_seq": seq}
    return info


class TestEspStatistics(unittest.TestCase):
    def test_spi_aggregation(self):
        stats = Statistics()
        for seq in (1, 2, 3):
            stats.feed(_esp_info(0x10, seq, wire=100))
        self.assertEqual(stats.esp_spis["0x00000010"], [3, 300])
        self.assertEqual(stats.esp_seq_regress, 0)

    def test_multiple_spis(self):
        stats = Statistics()
        stats.feed(_esp_info(0x10, 1))
        stats.feed(_esp_info(0x20, 1))
        self.assertEqual(set(stats.esp_spis), {"0x00000010", "0x00000020"})

    def test_sequence_regress_detected(self):
        stats = Statistics()
        stats.feed(_esp_info(0x10, 5))
        stats.feed(_esp_info(0x10, 3))
        self.assertEqual(stats.esp_seq_regress, 1)
        self.assertIn("0x00000010", stats.esp_regress_spis)

    def test_duplicate_sequence_counts_as_regress(self):
        stats = Statistics()
        stats.feed(_esp_info(0x10, 7))
        stats.feed(_esp_info(0x10, 7))
        self.assertEqual(stats.esp_seq_regress, 1)

    def test_regress_then_recover_counts_twice(self):
        """回退后再出现原序号仍算回退: 最大序号必须保留而不是被回退值覆盖。"""
        stats = Statistics()
        for seq in (5, 3, 5):
            stats.feed(_esp_info(0x10, seq))
        self.assertEqual(stats.esp_seq_regress, 2)
        self.assertEqual(stats.esp_spis["0x00000010"], [3, 300])

    def test_other_spi_unaffected_by_regress(self):
        stats = Statistics()
        stats.feed(_esp_info(0x10, 5))
        stats.feed(_esp_info(0x10, 4))
        stats.feed(_esp_info(0x20, 1))
        self.assertEqual(stats.esp_regress_spis, {"0x00000010"})
        self.assertEqual(stats.esp_spis["0x00000020"], [1, 100])


def _write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            f.write(struct.pack("<IIII", int(ts), 0, len(frame), len(frame)))
            f.write(frame)


class TestEspReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "esp.pcap")
        _write_pcap(self.path, [
            (0, _eth(0x0800, _ipv4(50, _esp(0x10, 5, b"\x00" * 8)))),
            (1, _eth(0x0800, _ipv4(50, _esp(0x10, 3, b"\x00" * 8)))),
            (2, _eth(0x0800, _ipv4(50, _esp(0x20, 1, b"\x00" * 8)))),
        ])
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        os.remove(self.path)
        os.rmdir(self.tmp)

    def test_report_contains_spi_section(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main([self.path])
        out = buf.getvalue()
        self.assertIn("ESP SPI 分布 (2 条)", out)
        self.assertIn("SPI=0x00000010 packets=2", out)
        self.assertIn("SPI=0x00000020 packets=1", out)
        self.assertIn("疑似重放/乱序", out)
        self.assertIn("序列号未递增 1 次", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
