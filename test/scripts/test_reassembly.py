# -*- coding: utf-8 -*-
"""ReassemblyCache 的 L1 单元测试（U1-U12）与 TCP DNS 重组的 L2 集成测试"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from pcap_analyzer import (
    _identify_l7,
    _parse_tcp,
    _seq_delta,
    PacketInfo,
    ReassemblyCache,
)

KEY = ("10.0.0.1", "10.0.0.2", 40000, 53)
ISN = 1000


class TestSeqDelta(unittest.TestCase):
    """序号差值工具函数"""

    def test_normal_delta(self):
        self.assertEqual(_seq_delta(1100, ISN), 100)

    def test_wraparound_delta(self):
        """跨 2^32 的差值应为小的正数"""
        self.assertEqual(_seq_delta(5, 0xFFFFFFF0), 21)

    def test_negative_delta(self):
        """回退的序号应得到负值"""
        self.assertEqual(_seq_delta(ISN - 50, ISN), -50)


class TestReassemblyCache(unittest.TestCase):
    """ReassemblyCache 基础行为"""

    def setUp(self):
        self.cache = ReassemblyCache()

    # U1
    def test_single_segment_roundtrip(self):
        """单段写入后可完整取回"""
        self.cache.put(KEY, ISN, b"hello", ts=1.0)
        self.assertEqual(self.cache.take(KEY), b"hello")

    # U2
    def test_out_of_order_segments_assembled(self):
        """乱序写入两段，按序号拼接"""
        self.cache.put(KEY, ISN + 5, b"world", ts=1.0)
        self.cache.put(KEY, ISN, b"hello", ts=1.1)
        self.assertEqual(self.cache.take(KEY, expect_len=10), b"helloworld")

    # U3
    def test_duplicate_segment_deduped(self):
        """同序号同内容重复写入不新增条目"""
        self.cache.put(KEY, ISN, b"hello", ts=1.0)
        self.cache.put(KEY, ISN, b"hello", ts=1.1)
        self.assertEqual(self.cache.segment_count(KEY), 1)
        self.assertEqual(self.cache.take(KEY), b"hello")

    # U4
    def test_overlapping_segments_not_inflated(self):
        """部分重叠的两段拼接后长度不膨胀"""
        self.cache.put(KEY, ISN, b"0123456789", ts=1.0)
        self.cache.put(KEY, ISN + 5, b"56789abcde", ts=1.1)
        data = self.cache.take(KEY)
        self.assertEqual(len(data), 15)
        self.assertEqual(data, b"0123456789abcde")

    # U5
    def test_gap_stops_assembly(self):
        """存在空洞时只返回前缀，指定 expect_len 则返回 None"""
        self.cache.put(KEY, ISN + 10, b"tail", ts=1.0)
        self.cache.put(KEY, ISN, b"head", ts=1.1)
        self.assertEqual(self.cache.take(KEY), b"head")
        self.assertEqual(self.cache.contiguous_len(KEY), 4)
        self.assertIsNone(self.cache.take(KEY, expect_len=8))

    # U6
    def test_flow_capacity_evicts_oldest(self):
        """流表超上限时淘汰最久未活动的流"""
        cache = ReassemblyCache(max_flows=2)
        k1 = ("a", "b", 1, 2)
        k2 = ("c", "d", 3, 4)
        k3 = ("e", "f", 5, 6)
        cache.put(k1, ISN, b"1", ts=1.0)
        cache.put(k2, ISN, b"2", ts=2.0)
        cache.put(k3, ISN, b"3", ts=3.0)
        self.assertEqual(cache.flow_count(), 2)
        self.assertIsNone(cache.take(k1))
        self.assertIsNotNone(cache.take(k3))
        self.assertEqual(cache.evicted_flows, 1)

    # U7
    def test_directions_are_independent(self):
        """同一连接的反方向使用不同 key，互不干扰"""
        rev = (KEY[1], KEY[0], KEY[3], KEY[2])
        self.cache.put(KEY, ISN, b"req", ts=1.0)
        self.cache.put(rev, 5000, b"resp", ts=1.1)
        self.assertEqual(self.cache.take(KEY), b"req")
        self.assertEqual(self.cache.take(rev), b"resp")
        self.assertEqual(self.cache.flow_count(), 2)

    # U8
    def test_close_removes_flow(self):
        """FIN/RST 关闭后条目被清理"""
        self.cache.put(KEY, ISN, b"data", ts=1.0)
        self.cache.close(KEY)
        self.assertEqual(self.cache.flow_count(), 0)
        self.assertIsNone(self.cache.take(KEY))

    # U9
    def test_idle_timeout_boundary(self):
        """恰好等于超时阈值时保留，超过才清理"""
        self.cache.put(KEY, ISN, b"data", ts=0.0)
        self.assertEqual(self.cache.evict_expired(120.0), 0)
        self.assertEqual(self.cache.flow_count(), 1)
        self.assertEqual(self.cache.evict_expired(120.001), 1)
        self.assertEqual(self.cache.flow_count(), 0)

    # U10
    def test_sequence_wraparound(self):
        """序号回绕时按模运算拼接"""
        base = 0xFFFFFFF8
        self.cache.put(KEY, base, b"abcdefgh", ts=1.0)
        self.cache.put(KEY, 0, b"ijkl", ts=1.1)  # 回绕后的后续数据
        self.assertEqual(self.cache.take(KEY, expect_len=12), b"abcdefghijkl")

    # U11
    def test_per_flow_byte_limit(self):
        """单流缓冲超上限时整条流被丢弃"""
        cache = ReassemblyCache(max_bytes_per_flow=10)
        cache.put(KEY, ISN, b"12345", ts=1.0)
        cache.put(KEY, ISN + 5, b"67890", ts=1.1)
        cache.put(KEY, ISN + 10, b"abcde", ts=1.2)  # 超过 10 字节
        self.assertIsNone(cache.take(KEY))
        self.assertEqual(cache.segment_count(KEY), 0)
        self.assertEqual(cache.dropped_flows, 1)

    def test_flow_exactly_at_byte_limit_not_dropped(self):
        """总量恰好等于上限时不丢弃(上限是闭区间)。"""
        cache = ReassemblyCache(max_bytes_per_flow=8)
        self.assertTrue(cache.put(KEY, ISN, b"ABCDEFGH", ts=1.0))
        self.assertEqual(cache.take(KEY), b"ABCDEFGH")
        self.assertEqual(cache.dropped_flows, 0)

    # U12
    def test_ipv6_key_isolated_from_ipv4(self):
        """相同端口但不同地址族的流互不冲突"""
        v6 = ("2001:db8::1", "2001:db8::2", 40000, 53)
        self.cache.put(KEY, ISN, b"v4", ts=1.0)
        self.cache.put(v6, ISN, b"v6", ts=1.0)
        self.assertEqual(self.cache.take(KEY), b"v4")
        self.assertEqual(self.cache.take(v6), b"v6")

    # U13
    def test_retransmission_after_consume_ignored(self):
        """已交付数据的重传不再进入缓存"""
        self.cache.put(KEY, ISN, b"hello", ts=1.0)
        self.cache.consume(KEY, 5)
        self.assertFalse(self.cache.put(KEY, ISN, b"hello", ts=1.1))
        self.assertIsNone(self.cache.take(KEY))

    # U14
    def test_overlap_after_consume_keeps_new_tail(self):
        """重传段与已交付区重叠但带新尾部时，只追加超出部分"""
        self.cache.put(KEY, ISN, b"0123456789", ts=1.0)
        self.cache.consume(KEY, 6)                       # 已交付 "012345"
        self.assertTrue(self.cache.put(KEY, ISN + 4, b"456789XY", ts=1.1))
        self.assertEqual(self.cache.take(KEY), b"6789XY")


def _tcp_frame(sport, dport, seq, payload, flags=0x18):
    """构造仅含固定 20 字节头部的 TCP 报文"""
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, 0,
                      (5 << 12) | flags, 65535, 0, 0)
    return hdr + payload


def _dns_message(txn_id=0x1234, qr=1, qname=b"\x03www\x07example\x03com\x00"):
    flags = 0x8180 if qr else 0x0100
    return struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


class TestTCPDNSReassembly(unittest.TestCase):
    """L2：_parse_tcp + ReassemblyCache 的联合行为"""

    def setUp(self):
        self.cache = ReassemblyCache()
        self.msg = _dns_message()
        self.prefixed = struct.pack("!H", len(self.msg)) + self.msg

    def _feed(self, seq, payload, ts=1.0, sport=40000, dport=53,
              src="10.0.0.1", dst="10.0.0.2", flags=0x18):
        frame = _tcp_frame(sport, dport, seq, payload, flags=flags)
        info = PacketInfo(index=0, ts=ts, wire_len=54 + len(frame), cap_len=54 + len(frame))
        info.src, info.dst = src, dst
        _parse_tcp(frame, 0, len(frame), info, self.cache)
        return info

    # R1
    def test_single_segment_with_cache(self):
        """接入缓存后单段报文结果不变，且不出现「重组」字样"""
        info = self._feed(ISN, self.prefixed)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x1234)
        self.assertNotIn("重组", info.note)

    # R2
    def test_two_segments_in_order(self):
        """消息切两段顺序到达：首段只提示等待，末段完成解析"""
        first, second = self.prefixed[:22], self.prefixed[22:]
        info1 = self._feed(ISN, first)
        self.assertEqual(info1.l4, "TCP")
        self.assertIn("等待后续段", info1.note)
        self.assertNotIn("dns_id", info1.detail)

        info2 = self._feed(ISN + 22, second)
        self.assertEqual(info2.l4, "DNS")
        self.assertEqual(info2.detail["dns_id"], 0x1234)

    # R4
    def test_two_segments_out_of_order(self):
        """后段先到：首包等待缺段，补齐前段后解析成功"""
        first, second = self.prefixed[:22], self.prefixed[22:]
        info1 = self._feed(ISN + 22, second)
        self.assertEqual(info1.l4, "TCP")
        self.assertIn("等待后续段", info1.note)

        info2 = self._feed(ISN, first)
        self.assertEqual(info2.l4, "DNS")
        self.assertEqual(info2.detail["dns_id"], 0x1234)

    # 一次写入两条消息（同段粘包）
    def test_two_messages_in_one_segment(self):
        """同一段内粘两条 DNS 消息时应解析两条"""
        info = self._feed(ISN, self.prefixed + self.prefixed)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_messages"], 2)

    # 消息跨段 + 同段粘包
    def test_message_split_then_bundled(self):
        """第一段含消息尾与第二条消息的头，补齐后两条均可解析"""
        second = _dns_message(txn_id=0x5678)
        combined = self.prefixed + struct.pack("!H", len(second)) + second
        info1 = self._feed(ISN, combined[:30])
        self.assertEqual(info1.l4, "TCP")
        info2 = self._feed(ISN + 30, combined[30:])
        self.assertEqual(info2.l4, "DNS")
        self.assertEqual(info2.detail["dns_messages"], 2)

    # SYN 重置旧缓存
    def test_syn_resets_buffer(self):
        """同四元组新 SYN 应清空旧缓存，避免旧数据参与拼接"""
        first = self.prefixed[:22]
        self._feed(ISN, first)
        frame = _tcp_frame(40000, 53, 5000, b"", flags=0x02)  # SYN
        info = PacketInfo(index=1, ts=2.0, wire_len=54, cap_len=54)
        info.src, info.dst = "10.0.0.1", "10.0.0.2"
        _parse_tcp(frame, 0, len(frame), info, self.cache)
        self.assertEqual(self.cache.flow_count(), 0)

    # R3
    def test_three_segments_in_order(self):
        """消息切三段顺序到达仍能完整解析"""
        s = self.prefixed
        self._feed(ISN, s[:10])
        self._feed(ISN + 10, s[10:20])
        info = self._feed(ISN + 20, s[20:])
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x1234)

    # R5
    def test_three_segments_reversed(self):
        """三段完全逆序到达，补齐后解析成功"""
        s = self.prefixed
        self._feed(ISN + 20, s[20:])
        self._feed(ISN + 10, s[10:20])
        info = self._feed(ISN, s[:10])
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x1234)

    # R11
    def test_missing_middle_segment_blocks_then_completes(self):
        """缺中间段时不解析，补齐后完成"""
        s = self.prefixed
        self._feed(ISN, s[:10])
        info = self._feed(ISN + 20, s[20:])          # 跳过 10..19
        self.assertEqual(info.l4, "TCP")
        self.assertIn("等待", info.note)
        info2 = self._feed(ISN + 10, s[10:20])
        self.assertEqual(info2.l4, "DNS")
        self.assertEqual(info2.detail["dns_id"], 0x1234)

    def test_prefix_shorter_than_header_rejected(self):
        """前缀声明 5 字节（不足 DNS 头部 12）时不推进，等待更多数据"""
        payload = struct.pack("!H", 5) + b"\x12\x34\x81\x80\x00"
        info = self._feed(ISN, payload)
        self.assertEqual(info.l4, "TCP")
        self.assertIn("等待后续段", info.note)
        self.assertNotIn("dns_id", info.detail)

    # R16
    def test_oversized_prefix_does_not_hang(self):
        """前缀 0xFFFF 而实际数据远不足时只等待，不挂起"""
        payload = b"\xff\xff" + _dns_message()[:12]
        info = self._feed(ISN, payload)
        self.assertEqual(info.l4, "TCP")
        self.assertIn("等待后续段", info.note)

    def test_segment_split_across_seq_wraparound(self):
        """分段跨越 2^32 序号回绕时仍正确拼接"""
        base = 0xFFFFFFF0
        s = self.prefixed
        self._feed(base, s[:20])
        info = self._feed((base + 20) & 0xFFFFFFFF, s[20:])
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x1234)

    def test_rst_clears_buffer(self):
        """RST 应清空该流缓存"""
        self._feed(ISN, self.prefixed[:10])
        frame = _tcp_frame(40000, 53, 5000, b"", flags=0x04)  # RST
        info = PacketInfo(index=1, ts=2.0, wire_len=54, cap_len=54)
        info.src, info.dst = "10.0.0.1", "10.0.0.2"
        _parse_tcp(frame, 0, len(frame), info, self.cache)
        self.assertEqual(self.cache.flow_count(), 0)

    def test_incomplete_second_message_completed_later(self):
        """同段第二条消息不完整时只解析第一条，补齐后解析第二条"""
        msg2 = _dns_message(txn_id=0x5678)
        combined = self.prefixed + struct.pack("!H", len(msg2)) + msg2
        first_len = len(combined) - 5
        info1 = self._feed(ISN, combined[:first_len])
        self.assertEqual(info1.l4, "DNS")
        self.assertEqual(info1.detail["dns_id"], 0x1234)
        self.assertNotIn("dns_messages", info1.detail)

        info2 = self._feed(ISN + first_len, combined[first_len:])
        self.assertEqual(info2.l4, "DNS")
        self.assertEqual(info2.detail["dns_id"], 0x5678)

    def test_bidirectional_flows_not_interleaved(self):
        """同一条连接两个方向各自重组，互不串扰"""
        query = _dns_message(txn_id=0x9999, qr=False)
        qstream = struct.pack("!H", len(query)) + query
        self._feed(ISN, qstream[:10])                                  # 请求前半段
        info_r = self._feed(5000, self.prefixed, sport=53, dport=40000,
                            src="10.0.0.2", dst="10.0.0.1")            # 反方向完整响应
        self.assertEqual(info_r.l4, "DNS")
        self.assertEqual(info_r.detail["dns_id"], 0x1234)
        info_q = self._feed(ISN + 10, qstream[10:])                    # 请求后半段
        self.assertEqual(info_q.l4, "DNS")
        self.assertEqual(info_q.detail["dns_id"], 0x9999)

    def test_concurrent_flows_isolated(self):
        """两条并发流的交错分段不会互相干扰"""
        m2 = _dns_message(txn_id=0xAAAA)
        s2 = struct.pack("!H", len(m2)) + m2
        self._feed(ISN, self.prefixed[:15])
        self._feed(8000, s2[:15], sport=40001)
        info_a = self._feed(ISN + 15, self.prefixed[15:])
        info_b = self._feed(8015, s2[15:], sport=40001)
        self.assertEqual(info_a.detail["dns_id"], 0x1234)
        self.assertEqual(info_b.detail["dns_id"], 0xAAAA)

    def test_prefix_split_across_three_segments(self):
        """长度前缀本身被切成 1+1+剩余三段"""
        s = self.prefixed
        self._feed(ISN, s[:1])
        self._feed(ISN + 1, s[1:2])
        info = self._feed(ISN + 2, s[2:])
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x1234)

    def test_flow_capacity_eviction_in_tcp_path(self):
        """流表满时最旧流被淘汰，其后续数据无法再解析"""
        cache = ReassemblyCache(max_flows=1)
        self.cache = cache
        self._feed(ISN, self.prefixed[:15])
        self._feed(8000, self.prefixed[:15], sport=40001)   # 挤掉上一条流
        self.assertEqual(cache.flow_count(), 1)
        info = self._feed(ISN + 15, self.prefixed[15:])     # 旧流已淘汰，重建后拼不出整条
        self.assertEqual(info.l4, "TCP")
        self.assertNotIn("dns_id", info.detail)

    def test_overflow_drops_flow_silently(self):
        """单流超容量时静默丢弃，不产生等待提示"""
        self.cache = ReassemblyCache(max_bytes_per_flow=10)
        info = self._feed(ISN, self.prefixed)               # 31 字节 > 10
        self.assertEqual(info.l4, "TCP")
        self.assertEqual(info.note, "")
        self.assertEqual(self.cache.dropped_flows, 1)

    def test_compression_pointer_relative_to_message(self):
        """跨段重组后，压缩指针按消息起点解释（而非包内绝对偏移）"""
        qname = b"\x03www\x07example\x03com\x00"
        question = qname + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        msg = struct.pack("!HHHHHH", 0x7777, 0x8180, 1, 1, 0, 0) + question + answer
        stream = struct.pack("!H", len(msg)) + msg
        self._feed(ISN, stream[:20])
        info = self._feed(ISN + 20, stream[20:])
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["queries"], ["www.example.com"])
        self.assertEqual(len(info.detail["answers"]), 1)
        self.assertTrue(info.detail["answers"][0].startswith("www.example.com"))

    # FIN 语义
    def test_fin_carrying_final_segment_parsed_then_closed(self):
        """FIN 段携带最后一段数据：先完成解析，再释放缓存"""
        s = self.prefixed
        self._feed(ISN, s[:20])
        info = self._feed(ISN + 20, s[20:], flags=0x19)   # FIN+PSH+ACK
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x1234)
        self.assertEqual(self.cache.flow_count(), 0)

    def test_fin_without_payload_closes_buffer(self):
        """空 FIN 直接释放该方向的未完成缓存"""
        self._feed(ISN, self.prefixed[:10])
        info = self._feed(ISN + 10, b"", flags=0x11)      # FIN+ACK
        self.assertEqual(info.l4, "TCP")
        self.assertEqual(self.cache.flow_count(), 0)

    # 非标准端口跨段
    def test_nonstandard_port_split_message_recognized(self):
        """非 53 端口：首段靠 DNS 头部结构识别，后续段靠已有流延续"""
        s = self.prefixed
        info1 = self._feed(ISN, s[:16], dport=5353)
        self.assertEqual(info1.l4, "TCP")
        self.assertIn("等待后续段", info1.note)
        info2 = self._feed(ISN + 16, s[16:], dport=5353)
        self.assertEqual(info2.l4, "DNS")
        self.assertEqual(info2.detail["dns_id"], 0x1234)

    def test_nonstandard_port_random_binary_not_dns(self):
        """前缀自洽但 DNS 头部不合理（qdcount=0）时不误判为 DNS"""
        payload = struct.pack("!H", 20) + struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0)
        self.assertIsNone(_identify_l7(payload, 5353, 40000, is_udp=False))


class TestReadyAfterTotal(unittest.TestCase):
    """set_total/ready：末片先到时，补齐即完成"""

    def test_ready_after_total_set_out_of_order(self):
        c = ReassemblyCache()
        key = ("k",)
        c.put(key, 8, b"ijkl", 0.0)
        self.assertIsNone(c.ready(key))          # 尚未记录总长
        c.set_total(key, 12)
        self.assertIsNone(c.ready(key))          # 首段缺失，尚未连续
        c.put(key, 0, b"abcdefgh", 0.0)
        self.assertEqual(c.ready(key), b"abcdefghijkl")

    def test_ready_requires_start_at_zero(self):
        c = ReassemblyCache()
        key = ("k",)
        c.put(key, 8, b"ijkl", 0.0)
        c.set_total(key, 4)                      # 数据不从 0 开始，不应判定完成
        self.assertIsNone(c.ready(key))

    def test_ready_returns_none_when_short(self):
        c = ReassemblyCache()
        key = ("k",)
        c.put(key, 0, b"abcd", 0.0)
        c.set_total(key, 8)
        self.assertIsNone(c.ready(key))
        c.put(key, 4, b"efgh", 0.0)
        self.assertEqual(c.ready(key), b"abcdefgh")


class TestFirstFragmentReuse(unittest.TestCase):
    """put_first：同键首片内容不同时视为 frag_id 复用，清空重建"""

    def test_different_first_fragment_resets(self):
        c = ReassemblyCache()
        key = ("frag",)
        c.put_first(key, 0, b"AAAA", 0.0)
        c.put(key, 4, b"BBBB", 0.0)
        c.put_first(key, 0, b"CCCC", 0.0)
        self.assertEqual(c.reuse_resets, 1)
        self.assertEqual(c.contiguous_len(key), 4)
        self.assertEqual(c.take(key), b"CCCC")

    def test_identical_first_fragment_keeps_buffer(self):
        c = ReassemblyCache()
        key = ("frag",)
        c.put_first(key, 0, b"AAAA", 0.0)
        c.put(key, 4, b"BBBB", 0.0)
        c.put_first(key, 0, b"AAAA", 0.0)      # 重传，不应清空
        self.assertEqual(c.reuse_resets, 0)
        self.assertEqual(c.take(key), b"AAAABBBB")

    def test_reset_drops_recorded_total(self):
        c = ReassemblyCache()
        key = ("frag",)
        c.put_first(key, 0, b"AAAA", 0.0)
        c.set_total(key, 8)
        c.put_first(key, 0, b"ZZZZ", 0.0)
        self.assertIsNone(c.ready(key))        # 旧的期望总长已随重建清空
        c.put(key, 4, b"YYYY", 0.0)
        c.set_total(key, 8)
        self.assertEqual(c.ready(key), b"ZZZZYYYY")


class TestConflictingOverlap(unittest.TestCase):
    """put：非首片重叠且内容冲突时按 RFC 8200 整体作废，不得重组"""

    def test_conflicting_overlap_invalidates_datagram(self):
        c = ReassemblyCache()
        key = ("gtp-frag",)
        c.put(key, 0, b"AAAABBBB", 0.0)
        c.put(key, 4, b"XXXX", 0.0)             # 非首片，与已缓存内容冲突
        self.assertTrue(c.is_invalid(key))
        self.assertEqual(c.dropped_flows, 1)
        self.assertIsNone(c.take(key))
        self.assertFalse(c.put(key, 8, b"YYYY", 0.0))   # 作废后不再接收

    def test_identical_overlap_on_fragment_kept(self):
        """非首片的重复分片内容一致时按重传处理，不判废"""
        c = ReassemblyCache()
        key = ("gtp-frag",)
        c.put(key, 4, b"BBBB", 0.0)             # 非首片
        c.put(key, 4, b"BBBB", 0.0)             # 内容一致的重复
        self.assertFalse(c.is_invalid(key))
        self.assertEqual(c.take(key), b"BBBB")

    def test_identical_overlap_on_stream_kept(self):
        """TCP 重组路径不受 RFC 分片规则影响，重复段按重传处理"""
        c = ReassemblyCache()
        key = ("tcp", "a", "b", 1, 2)
        c.put(key, 0, b"AAAABBBB", 0.0)
        c.put(key, 4, b"BBBB", 0.0)
        self.assertFalse(c.is_invalid(key))
        self.assertEqual(c.take(key), b"AAAABBBB")

    def test_first_fragment_duplicate_tolerated(self):
        """首片重传内容一致时仍按重传处理，不判废"""
        c = ReassemblyCache()
        key = ("gtp-frag6",)
        c.put_first(key, 0, b"AAAABBBB", 0.0)
        c.put_first(key, 0, b"AAAABBBB", 0.0)
        self.assertFalse(c.is_invalid(key))
        self.assertEqual(c.take(key), b"AAAABBBB")

    def test_starts_at_zero_flag(self):
        c = ReassemblyCache()
        key = ("frag",)
        c.put(key, 8, b"ijkl", 0.0)
        self.assertFalse(c.starts_at_zero(key))
        c.put(key, 0, b"abcdefgh", 0.0)
        self.assertTrue(c.starts_at_zero(key))

    def test_fragment_timeout_is_60_seconds(self):
        c = ReassemblyCache(idle_timeout=120.0)
        c.put(("gtp-frag6", 1, "a", "b", 7), 0, b"abcd", 0.0)
        c.put(("tcp", "a", "b", 1, 2), 0, b"abcd", 0.0)
        self.assertEqual(c.evict_expired(61.0), 1)       # 分片 60 秒即过期
        self.assertIn(("tcp", "a", "b", 1, 2), c._flows)
        self.assertEqual(c.evict_expired(121.0), 1)      # TCP 流 120 秒后过期


if __name__ == "__main__":
    unittest.main()