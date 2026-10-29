"""资源与健壮性用例（S1-S5）：流表上限、缓冲区上限、耗时、畸形输入。

这些用例只验证资源约束与不崩溃，不验证协议语义。
"""

import os
import random
import struct
import sys
import time
import tracemalloc
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from pcap_analyzer import RawPacket, ReassemblyCache, parse_packet   # noqa: E402


def _raw(frame, ts=0.0, index=0):
    """把链路层帧包成 RawPacket，供 parse_packet 使用。"""
    return RawPacket(index, ts, frame, len(frame), 1)


def _eth_ipv4_tcp(sport, dport, payload=b"", seq=1):
    """构造 Ethernet + IPv4 + TCP 帧。"""
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0, (5 << 12) | 0x18,
                      65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


def _sum_buffered(cache):
    """缓存中所有流的字节总数（直接读内部状态，用于内存断言）。"""
    return sum(f.total_bytes for f in cache._flows.values())


class TestFlowTableBound(unittest.TestCase):
    """S1：流表条数与内存不随输入流数线性增长"""

    def test_flow_count_capped(self):
        cache = ReassemblyCache(max_flows=500)
        for i in range(5000):
            cache.put(("tcp", "10.0.0.1", "10.0.0.2", 10000 + i, 53), 0, b"x", float(i))
        self.assertEqual(cache.flow_count(), 500)

    def test_memory_stays_bounded(self):
        tracemalloc.start()
        cache = ReassemblyCache(max_flows=500)
        for i in range(5000):
            cache.put(("tcp", "10.0.0.1", "10.0.0.2", 10000 + i, 53), 0,
                      b"\x00\x0e" + b"z" * 12, float(i))
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLessEqual(cache.flow_count(), 500)
        self.assertLess(peak, 4 * 1024 * 1024, f"峰值内存 {peak} 字节")

    def test_eviction_keeps_most_recent(self):
        cache = ReassemblyCache(max_flows=2)
        cache.put(("a",), 0, b"1", 1.0)
        cache.put(("b",), 0, b"2", 2.0)
        cache.put(("c",), 0, b"3", 3.0)
        self.assertEqual(cache.flow_count(), 2)
        self.assertEqual(cache.evicted_flows, 1)


class TestBufferedBytesBound(unittest.TestCase):
    """S2：单流持续输入不会让缓冲区无限增长"""

    def test_single_flow_byte_limit_drops(self):
        cache = ReassemblyCache(max_bytes_per_flow=1024)
        key = ("tcp", "10.0.0.1", "10.0.0.2", 1234, 53)
        for i in range(10000):
            cache.put(key, i * 8, b"y" * 8, float(i))
        self.assertEqual(cache.dropped_flows, 1)
        self.assertIsNone(cache.take(key))
        self.assertLessEqual(_sum_buffered(cache), 1024)

    def test_garbage_segments_per_flow_bounded(self):
        cache = ReassemblyCache(max_bytes_per_flow=256)
        for flow in range(20):
            key = ("tcp", "10.0.0.1", "10.0.0.2", 20000 + flow, 53)
            for i in range(200):
                cache.put(key, i, b"q", float(i))
        self.assertLessEqual(_sum_buffered(cache), 20 * 256)


class TestParseCost(unittest.TestCase):
    """S3：单包解析耗时不随缓存规模退化"""

    def test_throughput_floor(self):
        cache = ReassemblyCache()
        frame = _eth_ipv4_tcp(40000, 53, b"\x00\x0e" + b"a" * 12)
        start = time.perf_counter()
        for _ in range(2000):
            parse_packet(_raw(frame), cache)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 5.0, f"2000 包耗时 {elapsed:.2f}s")

    def test_cost_unaffected_by_cached_flows(self):
        frame = _eth_ipv4_tcp(40000, 53, b"\x00\x0e" + b"a" * 12)
        cold = ReassemblyCache()
        start = time.perf_counter()
        for _ in range(500):
            parse_packet(_raw(frame), cache=cold)
        cold_cost = time.perf_counter() - start

        warm = ReassemblyCache(max_flows=5000)
        for i in range(3000):
            warm.put(("tcp", "10.0.0.1", "10.0.0.2", 30000 + i, 53), 0, b"w", 0.0)
        start = time.perf_counter()
        for _ in range(500):
            parse_packet(_raw(frame), cache=warm)
        warm_cost = time.perf_counter() - start
        self.assertGreater(cold_cost, 0)
        self.assertLess(warm_cost, cold_cost * 10 + 0.5,
                        f"冷缓存 {cold_cost:.4f}s，5000 流缓存 {warm_cost:.4f}s")


class TestAttackInput(unittest.TestCase):
    """S4：声明超长前缀的攻击包不预分配内存"""

    def test_oversize_prefix_packets_do_not_allocate(self):
        tracemalloc.start()
        cache = ReassemblyCache()
        for i in range(10000):
            # 每个包用不同源端口，制造 1 万条独立流
            frame = _eth_ipv4_tcp(41000 + i, 53, b"\xff\xff" + b"\x00" * 12)
            parse_packet(_raw(frame, float(i), i), cache)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, 4 * 1024 * 1024, f"峰值内存 {peak} 字节")
        self.assertLessEqual(_sum_buffered(cache), cache.max_flows * 64)
        self.assertLessEqual(cache.flow_count(), cache.max_flows)


class TestMalformedRobustness(unittest.TestCase):
    """S5：畸形与随机输入不得抛出异常"""

    def test_random_buffers_do_not_raise(self):
        rng = random.Random(20261028)
        cache = ReassemblyCache()
        for i in range(300):
            parse_packet(_raw(rng.randbytes(rng.randint(0, 120)), index=i), cache)

    def test_truncated_frames_do_not_raise(self):
        cache = ReassemblyCache()
        full = _eth_ipv4_tcp(42000, 53, b"\x00\x0e" + b"a" * 12)
        for cut in range(1, len(full) - 1):
            parse_packet(_raw(full[:cut]), cache)

    def test_garbage_in_dns_payload_does_not_raise(self):
        cache = ReassemblyCache()
        rng = random.Random(7)
        for _ in range(200):
            payload = b"\x00" + bytes([rng.randint(0, 255)]) + rng.randbytes(20)
            parse_packet(_raw(_eth_ipv4_tcp(43000, 53, payload)), cache)


if __name__ == "__main__":
    unittest.main()
