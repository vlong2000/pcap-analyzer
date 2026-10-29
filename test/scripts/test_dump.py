# -*- coding: utf-8 -*-
"""载荷 dump（--dump hex/str/both）单元测试。

覆盖三层：
  * 格式化层 : _ascii_col / format_hex / format_text / format_payload / payload_block
  * 数据层   : PacketInfo.payload_raw / payload_off 的采集与 to_json 输出
  * 展示层   : print_packets 与命令行 run() 的端到端输出
"""

import contextlib
import io
import json
import os
import random
import struct
import sys
import tempfile
import unittest
from functools import lru_cache

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from pcap_analyzer import (  # noqa: E402
    PacketInfo,
    RawPacket,
    _ascii_col,
    format_hex,
    format_payload,
    format_text,
    main,
    parse_packet,
    payload_block,
    print_packets,
)


def _raw(frame, ts=0.0, index=0):
    """把链路层帧包成 RawPacket。"""
    return RawPacket(index, ts, frame, len(frame), 1)


def _eth(ethertype, payload=b""):
    return b"\x00" * 12 + struct.pack("!H", ethertype) + payload


def _ipv4(proto, payload=b"", frag=0, total=None):
    """构造 IPv4 头；frag 直接传原始标志+偏移字段（如 0x2000、0x0001）。"""
    if total is None:
        total = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, frag, 64, proto, 0,
                       bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))) + payload


def _ipv6(nxt, payload=b""):
    return (struct.pack("!IHBB", 0x60000000, len(payload), nxt, 64)
            + bytes(16) + bytes(16) + payload)


def _tcp(sport, dport, payload=b""):
    return (struct.pack("!HHIIHHHH", sport, dport, 1, 0, (5 << 12) | 0x18,
                        65535, 0, 0) + payload)


def _udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _info():
    return PacketInfo(index=0, ts=0.0, wire_len=0, cap_len=0)


# ---------------------------------------------------------------- 参数化扫描基础设施

HEX_WIDTH = 16        # format_hex 每行字节数
TEXT_WIDTH = 64       # format_text 每行字符数
HEX_FIELD = HEX_WIDTH * 3 - 1   # 十六进制字段固定宽度(含单空格分隔)
_HEX_MODES = ("hex", "both")
_TEXT_MODES = ("str", "both")


@lru_cache(maxsize=None)
def _pattern(n):
    """确定性字节序列: 同时覆盖控制符、空格、可打印与高位字节。"""
    return bytes((i * 37 + 11) % 256 for i in range(n))


def _effective_limits(n):
    """归并等价 limit: <=0 与 >=n 都是全量, 只需各测一次。

    返回按升序排列的去重取值; 负值/超长语义由 test_unlimited_equivalence 单独覆盖。
    """
    if n == 0:
        return (0,)
    values = {0}
    values.update(k for k in (1, 2, 5, 15, 16, 17, 33, 63, 64, 65, 128) if k < n)
    if n >= 2:
        values.add(n - 1)
    return tuple(sorted(values))


def _truncated_limit(n):
    """一个真正产生截断的最小 limit(不截断时返回 0)。"""
    return min(17, n - 1) if n >= 2 else 0


def _ascii_expected(chunk):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def _hint(n):
    return f"... 剩余 {n} 字节未显示 (--dump-bytes 0 显示全部)"


def _split_offset(line):
    """拆出 '偏移 + 两空格 + 正文'。正文允许以空格开头。"""
    off_text, rest = line.split("  ", 1)
    return off_text, rest


def _check_lines(tc, lines, data, mode, base, limit):
    """校验 dump 行结构与内容不变式(不依赖具体实现拼接细节)。"""
    shown = data if limit <= 0 else data[:limit]
    n_hex = -(-len(shown) // HEX_WIDTH) if mode in _HEX_MODES else 0
    n_text = -(-len(shown) // TEXT_WIDTH) if mode in _TEXT_MODES else 0
    truncated = len(shown) < len(data)

    tc.assertIsInstance(lines, list)                            # 返回 list[str], 非生成器/元组
    tc.assertEqual(len(lines), n_hex + n_text + (1 if truncated else 0),
                   f"行数不符 mode={mode} base={base} limit={limit} n={len(data)}")
    for line in lines:
        tc.assertIsInstance(line, str)
        tc.assertNotIn("\n", line)

    for i in range(n_hex):
        chunk = shown[i * HEX_WIDTH:(i + 1) * HEX_WIDTH]
        off_text, rest = _split_offset(lines[i])
        # 偏移文本: 小写十六进制, 至少 4 位, 超出则自然加宽, 不截断不回绕
        tc.assertEqual(off_text, f"{base + i * HEX_WIDTH:04x}")
        tc.assertEqual(rest[HEX_FIELD:HEX_FIELD + 3], "  |")   # 固定宽度 + 分隔符
        tc.assertEqual(rest[-1], "|")
        tokens = rest[:HEX_FIELD].split()
        tc.assertEqual(tokens, [f"{b:02x}" for b in chunk])     # 十六进制回环
        tc.assertEqual(rest[HEX_FIELD + 3:-1], _ascii_expected(chunk))

    for j in range(n_text):
        chunk = shown[j * TEXT_WIDTH:(j + 1) * TEXT_WIDTH]
        off_text, rest = _split_offset(lines[n_hex + j])
        tc.assertEqual(off_text, f"{base + j * TEXT_WIDTH:04x}")
        tc.assertEqual(rest, _ascii_expected(chunk))            # 文本列逐字节映射

    if truncated:
        tc.assertEqual(lines[-1], _hint(len(data) - len(shown)))
        tc.assertEqual(sum(line == _hint(len(data) - len(shown)) for line in lines), 1)


def _check_layout(tc, data, mode, base, limit):
    _check_lines(tc, format_payload(data, mode, base, limit), data, mode, base, limit)


_LENGTHS = (0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 127, 128, 129, 255, 256, 257)
_BASES = (0, 1, 0xF, 0x10, 0xFF, 0xFFF8, 0xFFFF, 0x10000, 0x12345)
_MODES = ("hex", "str", "both", "")


class TestAsciiCol(unittest.TestCase):
    def test_printable_kept(self):
        self.assertEqual(_ascii_col(b"GET /"), "GET /")

    def test_control_and_high_bytes_replaced(self):
        self.assertEqual(_ascii_col(b"\x00\x1f\x7f\x80\xff"), ".....")

    def test_empty(self):
        self.assertEqual(_ascii_col(b""), "")


class TestFormatHex(unittest.TestCase):
    def test_single_line_layout(self):
        line = format_hex(b"ABC")[0]
        self.assertEqual(line, "0000  " + "41 42 43".ljust(47) + "  |ABC|")

    def test_base_offset_applied(self):
        line = format_hex(b"ABC", base=0x36)[0]
        self.assertTrue(line.startswith("0036  41 42 43"))

    def test_width_split(self):
        lines = format_hex(bytes(range(20)))
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[1].startswith("0010  "))
        self.assertTrue(lines[1].endswith("|....|"))

    def test_short_line_padded(self):
        lines = format_hex(b"\x01")
        self.assertTrue(lines[0].endswith("|.|"))
        self.assertEqual(len(lines[0]), len("0000  ") + 47 + 2 + 3)

    def test_empty_returns_no_lines(self):
        self.assertEqual(format_hex(b""), [])


class TestFormatText(unittest.TestCase):
    def test_wraps_at_64_columns(self):
        lines = format_text(b"A" * 70)
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[1].startswith("0040  "))
        self.assertEqual(lines[1], "0040  " + "A" * 6)

    def test_nonprintable_dots(self):
        self.assertEqual(format_text(b"\x00hi\x00"), ["0000  .hi."])


class TestFormatPayload(unittest.TestCase):
    def test_hex_mode_only(self):
        lines = format_payload(b"hello", "hex", 0, 256)
        self.assertEqual(len(lines), 1)
        self.assertIn("|hello|", lines[0])

    def test_str_mode_has_no_hex_column(self):
        lines = format_payload(b"hello", "str", 0, 256)
        self.assertEqual(lines, ["0000  hello"])
        self.assertNotIn("|", lines[0])

    def test_both_mode_concatenates(self):
        lines = format_payload(b"hello", "both", 0, 256)
        self.assertEqual(len(lines), 2)
        self.assertIn("|hello|", lines[0])
        self.assertEqual(lines[1], "0000  hello")

    def test_limit_truncates_and_notes(self):
        lines = format_payload(b"hello world", "hex", 0, 4)
        self.assertIn("|hell|", lines[0])
        self.assertIn("剩余 7 字节未显示", lines[-1])
        self.assertIn("--dump-bytes 0", lines[-1])

    def test_limit_zero_shows_all(self):
        lines = format_payload(b"hello world", "hex", 0, 0)
        self.assertIn("|hello world|", lines[0])
        self.assertFalse(any("剩余" in line for line in lines))

    def test_empty_payload(self):
        self.assertEqual(format_payload(b"", "both", 0, 256), [])

    def test_empty_payload_with_any_limit(self):
        self.assertEqual(format_payload(b"", "hex", 0, 1), [])
        self.assertEqual(format_payload(b"", "str", 0, -1), [])

    def test_limit_negative_means_unlimited(self):
        lines = format_payload(b"hello world", "hex", 0, -5)
        self.assertIn("|hello world|", lines[0])
        self.assertFalse(any("剩余" in line for line in lines))

    def test_limit_equal_length_has_no_hint(self):
        lines = format_payload(b"abc", "hex", 0, 3)
        self.assertIn("|abc|", lines[0])
        self.assertFalse(any("剩余" in line for line in lines))

    def test_limit_larger_than_data_has_no_hint(self):
        lines = format_payload(b"abc", "hex", 0, 999)
        self.assertIn("|abc|", lines[0])
        self.assertFalse(any("剩余" in line for line in lines))

    def test_limit_one_byte(self):
        lines = format_payload(b"abc", "hex", 0, 1)
        self.assertIn("|a|", lines[0])
        self.assertEqual(lines[-1], "... 剩余 2 字节未显示 (--dump-bytes 0 显示全部)")

    def test_unknown_mode_yields_no_dump_lines(self):
        self.assertEqual(format_payload(b"hello", "raw", 0, 256), [])
        self.assertEqual(format_payload(b"hello", "", 0, 256), [])

    def test_unknown_mode_with_truncation_only_hint(self):
        lines = format_payload(b"hello", "", 0, 2)
        self.assertEqual(len(lines), 1)
        self.assertIn("剩余 3 字节未显示", lines[0])

    def test_both_mode_order_hex_text_then_hint(self):
        lines = format_payload(b"hello world", "both", 0, 4)
        self.assertEqual(len(lines), 3)
        self.assertIn("|hell|", lines[0])
        self.assertEqual(lines[1], "0000  hell")
        self.assertIn("剩余 7 字节未显示", lines[2])

    def test_hex_multiline_wrap(self):
        lines = format_payload(bytes(range(33)), "hex", 0, 0)
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[1].startswith("0010  "))
        self.assertTrue(lines[2].startswith("0020  "))

    def test_text_multiline_wrap(self):
        lines = format_payload(b"A" * 65, "str", 0, 0)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "0040  A")

    def test_base_propagates_to_both_modes(self):
        lines = format_payload(b"AB", "both", 0x1000, 0)
        self.assertEqual(lines[0], "1000  " + "41 42".ljust(47) + "  |AB|")
        self.assertEqual(lines[1], "1000  AB")

    def test_base_beyond_16_bits_keeps_full_offset(self):
        line = format_payload(b"Z", "hex", 0x10000, 0)[0]
        self.assertTrue(line.startswith("10000  5a"))

    def test_limit_at_hex_line_boundary(self):
        lines = format_payload(bytes(range(32)), "hex", 0, 16)
        self.assertEqual(len(lines), 2)                        # 1 行数据 + 提示
        self.assertTrue(lines[0].endswith("|................|"))
        self.assertEqual(lines[1], "... 剩余 16 字节未显示 (--dump-bytes 0 显示全部)")

    def test_limit_one_over_hex_line(self):
        lines = format_payload(bytes(range(20)), "hex", 0, 17)
        self.assertEqual(len(lines), 3)                        # 2 行数据 + 提示
        self.assertTrue(lines[1].startswith("0010  10"))
        self.assertTrue(lines[1].endswith("|.|"))
        self.assertIn("剩余 3 字节未显示", lines[2])

    def test_base_near_wrap_carries_into_next_line(self):
        lines = format_payload(bytes(range(32)), "hex", 0xFFF8, 0)
        self.assertTrue(lines[0].startswith("fff8  "))
        self.assertTrue(lines[1].startswith("10008  10"))

    def test_both_mode_exact_64_bytes_line_counts(self):
        lines = format_payload(b"A" * 64, "both", 0, 0)
        self.assertEqual(len(lines), 5)                        # 4 行 hex + 1 行文本
        self.assertEqual(lines[4], "0000  " + "A" * 64)

    def test_both_mode_empty_with_limit(self):
        self.assertEqual(format_payload(b"", "both", 0, 10), [])

    def test_huge_limit_no_hint(self):
        lines = format_payload(b"abc", "hex", 0, 10 ** 9)
        self.assertIn("|abc|", lines[0])
        self.assertFalse(any("剩余" in line for line in lines))

    def test_str_printable_range_boundaries(self):
        # 0x1f 控制符/0x20 空格/0x7e 上界可打印/0x7f DEL
        lines = format_payload(b"\x1f\x20\x7e\x7f", "str", 0, 0)
        self.assertEqual(lines, ["0000  . ~."])

    def test_str_exact_64_bytes_single_line(self):
        lines = format_payload(b"A" * 64, "str", 0, 0)
        self.assertEqual(lines, ["0000  " + "A" * 64])

    def test_str_exact_128_bytes_two_lines(self):
        lines = format_payload(b"A" * 128, "str", 0, 0)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "0040  " + "A" * 64)

    def test_str_129_bytes_three_lines(self):
        lines = format_payload(b"A" * 129, "str", 0, 0)
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[2], "0080  A")

    def test_hint_single_remaining_byte(self):
        lines = format_payload(b"hello", "hex", 0, 4)
        self.assertEqual(lines[-1], "... 剩余 1 字节未显示 (--dump-bytes 0 显示全部)")

    def test_both_limit_at_text_width(self):
        lines = format_payload(b"A" * 128, "both", 0, 64)
        # 4 行 hex(16B/行) + 1 行文本(64B) + 提示
        self.assertEqual(len(lines), 6)
        self.assertTrue(lines[3].startswith("0030  "))
        self.assertEqual(lines[4], "0000  " + "A" * 64)
        self.assertIn("剩余 64 字节未显示", lines[5])

    def test_large_input_line_count(self):
        lines = format_payload(b"\x00" * 1024, "hex", 0, 0)
        self.assertEqual(len(lines), 64)
        self.assertTrue(lines[-1].startswith("03f0  "))

    def test_all_byte_values_text_wrap(self):
        lines = format_payload(b"\x00" * 256, "str", 0, 0)
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[3], "00c0  " + "." * 64)

    def test_empty_with_nonzero_base(self):
        self.assertEqual(format_payload(b"", "hex", 0x40, 0), [])

    def test_utf8_multibyte_text_mode_by_byte(self):
        # 按字节渲染, UTF-8 中文每个字节均不可打印
        lines = format_payload("中文".encode("utf-8"), "str", 0, 0)
        self.assertEqual(lines, ["0000  ......"])

    def test_hex_mode_high_bytes_ascii_column(self):
        lines = format_payload(b"\x80\xff", "hex", 0, 0)
        self.assertIn("80 ff", lines[0])
        self.assertTrue(lines[0].endswith("|..|"))

    def test_both_exact_16_bytes_no_hint(self):
        lines = format_payload(b"A" * 16, "both", 0, 16)
        self.assertEqual(len(lines), 2)                        # 1 行 hex + 1 行文本
        self.assertEqual(lines[1], "0000  " + "A" * 16)
        self.assertFalse(any("剩余" in line for line in lines))

    def test_limit_15_partial_hex_line(self):
        lines = format_payload(b"A" * 20, "hex", 0, 15)
        self.assertTrue(lines[0].endswith("|" + "A" * 15 + "|"))
        self.assertIn("剩余 5 字节未显示", lines[1])

    def test_both_limit_counts_bytes_once(self):
        lines = format_payload(b"A" * 20, "both", 0, 16)
        # 截断按原始字节计一次, 不按 hex/文本两份重复计算
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[1], "0000  " + "A" * 16)
        self.assertIn("剩余 4 字节未显示", lines[2])

    def test_returned_list_independent(self):
        first = format_payload(b"hi", "hex", 0, 0)
        first.clear()
        second = format_payload(b"hi", "hex", 0, 0)
        self.assertEqual(len(second), 1)
        self.assertIn("|hi|", second[0])

    def test_hex_exact_16_byte_line_layout(self):
        lines = format_payload(bytes(range(16)), "hex", 0, 0)
        self.assertEqual(
            lines[0],
            "0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  |................|")

    def test_ascii_column_all_byte_ranges(self):
        lines = format_payload(bytes(range(256)), "hex", 0, 0)
        self.assertEqual(len(lines), 16)
        self.assertTrue(lines[2].startswith("0020  "))
        self.assertTrue(lines[2].endswith('| !"#$%&\'()*+,-./|'))
        self.assertTrue(lines[15].endswith("|" + "." * 16 + "|"))

    def test_bytes_like_input_bytearray(self):
        lines = format_payload(bytearray(b"hi"), "hex", 0, 0)
        self.assertIn("68 69", lines[0])
        self.assertTrue(lines[0].endswith("|hi|"))

    def test_text_large_payload_4096(self):
        lines = format_payload(b"A" * 4096, "str", 0, 0)
        self.assertEqual(len(lines), 64)
        self.assertEqual(lines[-1], "0fc0  " + "A" * 64)

    def test_text_mode_keeps_verbatim_delimiters(self):
        # 载荷里的 '|' 与连续空格不转义, 文本列原样保留
        lines = format_payload(b"a  |b|", "str", 0, 0)
        self.assertEqual(lines, ["0000  a  |b|"])

    def test_newline_byte_does_not_split_line(self):
        lines = format_payload(b"a\nb", "both", 0, 0)
        self.assertEqual(len(lines), 2)                         # 1 行 hex + 1 行文本
        self.assertTrue(lines[0].endswith("|a.b|"))
        self.assertEqual(lines[1], "0000  a.b")
        self.assertFalse(any("\n" in line for line in lines))


class TestPayloadBlock(unittest.TestCase):
    def test_hex_block(self):
        block = payload_block(b"hello", "hex", 0, 54)
        self.assertEqual(block, {"offset": 54, "total": 5, "shown": 5,
                                 "hex": b"hello".hex()})

    def test_str_block(self):
        block = payload_block(b"hi\x00", "str", 0, 8)
        self.assertEqual(block["text"], "hi.")
        self.assertNotIn("hex", block)
        self.assertEqual(block["offset"], 8)

    def test_limit_truncation(self):
        block = payload_block(b"hello", "both", 2, 0)
        self.assertEqual(block["shown"], 2)
        self.assertEqual(block["total"], 5)
        self.assertEqual(block["hex"], b"he".hex())


class TestPacketInfoJson(unittest.TestCase):
    def _sample(self, raw=b"hello raw", off=54):
        info = _info()
        info.l4 = "ESP"
        info.payload_raw = raw
        info.payload_off = off
        return info

    def test_no_dump_omits_payload(self):
        self.assertNotIn("payload", self._sample().to_json())

    def test_dump_with_empty_raw_omits_payload(self):
        info = _info()
        self.assertNotIn("payload", info.to_json("hex", 256))

    def test_hex_mode(self):
        block = self._sample().to_json("hex", 256)["payload"]
        self.assertEqual(block["hex"], b"hello raw".hex())
        self.assertEqual(block["offset"], 54)
        self.assertEqual(block["total"], 9)
        self.assertNotIn("text", block)

    def test_str_mode(self):
        block = self._sample().to_json("str", 256)["payload"]
        self.assertEqual(block["text"], "hello raw")
        self.assertNotIn("hex", block)

    def test_both_mode_and_truncation(self):
        block = self._sample().to_json("both", 4)["payload"]
        self.assertEqual(block["shown"], 4)
        self.assertEqual(block["total"], 9)
        self.assertEqual(block["hex"], b"hell".hex())
        self.assertEqual(block["text"], "hell")


class TestPacketPayloadAccess(unittest.TestCase):
    """统一的 bytes 负荷访问器与展示入口。"""

    def test_payload_property_returns_bytes(self):
        info = _info()
        info.payload_raw = b"\x01\x02"
        self.assertIsInstance(info.payload, bytes)
        self.assertEqual(info.payload, b"\x01\x02")

    def test_payload_property_empty(self):
        self.assertEqual(_info().payload, b"")

    def test_payload_lines_uses_packet_offset(self):
        info = _info()
        info.payload_raw = b"AB"
        info.payload_off = 0x10
        self.assertEqual(info.payload_lines("hex"),
                         ["0010  " + "41 42".ljust(47) + "  |AB|"])

    def test_payload_lines_limit_truncates(self):
        info = _info()
        info.payload_raw = b"hello"
        lines = info.payload_lines("both", 2)
        self.assertIn("剩余 3 字节未显示", lines[-1])

    def test_payload_lines_empty_returns_nothing(self):
        info = _info()
        for mode in ("hex", "str", "both"):
            self.assertEqual(info.payload_lines(mode), [])
            self.assertEqual(info.payload_lines(mode, 16), [])

    def test_payload_lines_default_limit_shows_all(self):
        info = _info()
        info.payload_raw = b"hello world"
        info.payload_off = 0x20
        lines = info.payload_lines("hex")
        self.assertIn("|hello world|", lines[0])
        self.assertTrue(lines[0].startswith("0020  "))
        self.assertFalse(any("剩余" in line for line in lines))

    def test_payload_lines_negative_limit_shows_all(self):
        info = _info()
        info.payload_raw = b"hello"
        lines = info.payload_lines("str", -1)
        self.assertEqual(lines, ["0000  hello"])

    def test_payload_lines_limit_equal_length_has_no_hint(self):
        info = _info()
        info.payload_raw = b"hello"
        lines = info.payload_lines("hex", 5)
        self.assertIn("|hello|", lines[0])
        self.assertFalse(any("剩余" in line for line in lines))

    def test_payload_lines_both_mode_order(self):
        info = _info()
        info.payload_raw = b"AB"
        info.payload_off = 8
        lines = info.payload_lines("both")
        self.assertEqual(lines[0], "0008  " + "41 42".ljust(47) + "  |AB|")
        self.assertEqual(lines[1], "0008  AB")

    def test_payload_lines_str_mode_replaces_high_bytes(self):
        info = _info()
        info.payload_raw = b"\x00\xff\x80A"
        self.assertEqual(info.payload_lines("str"), ["0000  ...A"])

    def test_payload_lines_large_offset(self):
        info = _info()
        info.payload_raw = b"Z"
        info.payload_off = 0x12345
        self.assertTrue(info.payload_lines("hex")[0].startswith("12345  5a"))

    def test_payload_lines_unknown_mode_empty(self):
        info = _info()
        info.payload_raw = b"hello"
        self.assertEqual(info.payload_lines("raw"), [])

    def test_payload_lines_offset_carries_into_second_line(self):
        info = _info()
        info.payload_raw = b"A" * 17
        info.payload_off = 0x30
        lines = info.payload_lines("hex")
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[1].startswith("0040  "))          # 0x30 + 0x10
        self.assertTrue(lines[1].endswith("|A|"))

    def test_payload_lines_reflects_later_payload_change(self):
        info = _info()
        info.payload_raw = b"AB"
        self.assertIn("|AB|", info.payload_lines("hex")[0])
        info.payload_raw = b"XYZ"
        lines = info.payload_lines("hex")
        self.assertEqual(lines[0], "0000  58 59 5a".ljust(len("0000  ") + 47) + "  |XYZ|")

    def test_payload_lines_both_exact_text_width(self):
        info = _info()
        info.payload_raw = b"A" * 64
        lines = info.payload_lines("both")
        self.assertEqual(len(lines), 5)                         # 4 行 hex + 1 行文本
        self.assertEqual(lines[4], "0000  " + "A" * 64)

    def test_payload_lines_limit_at_hex_boundary(self):
        info = _info()
        info.payload_raw = b"A" * 20
        lines = info.payload_lines("hex", 16)
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("0000  "))
        self.assertEqual(lines[1], "... 剩余 4 字节未显示 (--dump-bytes 0 显示全部)")

    def test_payload_lines_offset_applied_when_truncated(self):
        info = _info()
        info.payload_raw = b"A" * 20
        info.payload_off = 0x10
        lines = info.payload_lines("hex", 4)
        self.assertTrue(lines[0].startswith("0010  "))          # 偏移不随截断推进
        self.assertIn("|AAAA|", lines[0])
        self.assertIn("剩余 16 字节", lines[1])

    def test_payload_lines_str_exact_64_bytes(self):
        info = _info()
        info.payload_raw = b"A" * 64
        self.assertEqual(info.payload_lines("str"), ["0000  " + "A" * 64])

    def test_payload_lines_single_byte_limit(self):
        info = _info()
        info.payload_raw = b"AB"
        lines = info.payload_lines("hex", 1)
        self.assertIn("|A|", lines[0])
        self.assertEqual(lines[-1], "... 剩余 1 字节未显示 (--dump-bytes 0 显示全部)")

    def test_payload_lines_explicit_zero_limit(self):
        info = _info()
        info.payload_raw = b"hello"
        lines = info.payload_lines("hex", 0)
        self.assertIn("|hello|", lines[0])
        self.assertFalse(any("剩余" in line for line in lines))

    def test_payload_lines_large_payload_line_count(self):
        info = _info()
        info.payload_raw = b"\x00" * 1024
        lines = info.payload_lines("hex")
        self.assertEqual(len(lines), 64)
        self.assertTrue(lines[-1].startswith("03f0  "))

    def test_payload_lines_text_mode_uses_offset(self):
        info = _info()
        info.payload_raw = b"hello"
        info.payload_off = 0x100
        self.assertEqual(info.payload_lines("str"), ["0100  hello"])

    def test_payload_lines_both_limit_counts_bytes_once(self):
        info = _info()
        info.payload_raw = b"A" * 20
        lines = info.payload_lines("both", 16)
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[1], "0000  " + "A" * 16)
        self.assertIn("剩余 4 字节未显示", lines[2])

    def test_payload_lines_high_bytes_hex_ascii_column(self):
        info = _info()
        info.payload_raw = b"\x80\xff"
        lines = info.payload_lines("hex")
        self.assertIn("80 ff", lines[0])
        self.assertTrue(lines[0].endswith("|..|"))

    def test_payload_lines_utf8_payload_dots(self):
        info = _info()
        info.payload_raw = "中文".encode("utf-8")
        self.assertEqual(info.payload_lines("str"), ["0000  ......"])

    def test_payload_lines_returns_independent_list(self):
        info = _info()
        info.payload_raw = b"hi"
        first = info.payload_lines("hex")
        first.clear()
        second = info.payload_lines("hex")
        self.assertEqual(len(second), 1)
        self.assertIn("|hi|", second[0])

    def test_payload_lines_both_truncated_keeps_offset(self):
        info = _info()
        info.payload_raw = b"A" * 20
        info.payload_off = 0x20
        lines = info.payload_lines("both", 4)
        self.assertTrue(lines[0].startswith("0020  "))
        self.assertEqual(lines[1], "0020  AAAA")
        self.assertIn("剩余 16 字节未显示", lines[2])


class TestPayloadCapture(unittest.TestCase):
    """解析器在何处采集 payload_raw / payload_off"""

    def _parse(self, frame):
        return parse_packet(_raw(frame))

    def test_esp_over_ipv4(self):
        esp = struct.pack("!II", 0x1001, 7) + bytes(range(16, 48))
        info = self._parse(_eth(0x0800, _ipv4(50, esp)))
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.payload_off, 42)          # 跳过 8 字节 ESP 头
        self.assertEqual(info.payload_raw, esp[8:])

    def test_esp_over_ipv6(self):
        esp = bytes(40)
        info = self._parse(_eth(0x86DD, _ipv6(50, esp)))
        self.assertEqual(info.l4, "ESP")
        self.assertEqual(info.payload_off, 62)          # 跳过 8 字节 ESP 头
        self.assertEqual(info.payload_raw, esp[8:])

    def test_unknown_ip_protocol(self):
        info = self._parse(_eth(0x0800, _ipv4(253, b"\xaa\xbb")))
        self.assertEqual(info.l4, "IP-proto-253")
        self.assertEqual(info.payload_raw, b"\xaa\xbb")
        self.assertEqual(info.payload_off, 34)

    def test_unknown_ethertype(self):
        body = b"\x04\x00\x00\x00"
        info = self._parse(_eth(0x88CC, body))
        self.assertEqual(info.l3, "LLDP")
        self.assertEqual(info.payload_raw, body)
        self.assertEqual(info.payload_off, 14)

    def test_ipv4_non_first_fragment(self):
        info = self._parse(_eth(0x0800, _ipv4(17, b"fragdata", frag=0x0001)))
        self.assertEqual(info.l4, "IPv4-frag")
        self.assertEqual(info.payload_raw, b"fragdata")
        self.assertEqual(info.payload_off, 34)

    def test_ipv6_non_first_fragment(self):
        frag_hdr = bytes((17, 0)) + struct.pack("!H", 0x0008) + struct.pack("!I", 9)
        info = self._parse(_eth(0x86DD, _ipv6(44, frag_hdr + b"fragdata")))
        self.assertEqual(info.l4, "IPv6-frag")
        self.assertEqual(info.payload_raw, b"fragdata")
        self.assertEqual(info.payload_off, 62)

    def test_udp_unknown_application(self):
        payload = b"payload-data"
        info = self._parse(_eth(0x0800, _ipv4(17, _udp(40000, 9999, payload))))
        self.assertEqual(info.l4, "UDP")
        self.assertEqual(info.payload_raw, payload)
        self.assertEqual(info.payload_off, 42)

    def test_udp_dns_parse_failure_keeps_raw(self):
        payload = b"\x00\x01\x02\x03"
        info = self._parse(_eth(0x0800, _ipv4(17, _udp(55000, 53, payload))))
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertEqual(info.payload_raw, payload)

    def test_tcp_unknown_application(self):
        payload = b"hello raw text"
        info = self._parse(_eth(0x0800, _ipv4(6, _tcp(1234, 9999, payload))))
        self.assertEqual(info.l4, "TCP")
        self.assertEqual(info.payload_raw, payload)
        self.assertEqual(info.payload_off, 54)

    def test_tcp_http_not_captured(self):
        info = self._parse(_eth(0x0800, _ipv4(
            6, _tcp(1234, 80, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"))))
        self.assertEqual(info.l4, "HTTP")
        self.assertEqual(info.payload_raw, b"")

    def test_gtp_inner_esp_captured(self):
        gtp = struct.pack("!BBHI", 0x30, 0xFF, 0, 0xABC)
        inner = (_ipv6(50, bytes(range(4, 32))))
        info = self._parse(_eth(0x0800, _ipv4(
            17, _udp(2152, 2152, gtp + inner))))
        self.assertEqual(info.l4, "GTP-U")
        self.assertIn("inner IPv6 ESP", info.note)
        self.assertEqual(info.payload_raw, bytes(range(4, 32)))
        self.assertEqual(info.payload_off, 90)

    def test_gtp_inner_tcp_not_captured(self):
        gtp = struct.pack("!BBHI", 0x30, 0xFF, 0, 0xABC)
        inner = _ipv4(6, _tcp(1234, 80))
        info = self._parse(_eth(0x0800, _ipv4(17, _udp(2152, 2152, gtp + inner))))
        self.assertEqual(info.l4, "GTP-U")
        self.assertEqual(info.payload_raw, b"")


def _write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            f.write(struct.pack("<IIII", int(ts), 0, len(frame), len(frame)))
            f.write(frame)


def _frames():
    esp = struct.pack("!II", 0x1001, 7) + bytes(range(16, 48))
    return [
        (1700000000, _eth(0x0800, _ipv4(6, _tcp(1234, 9999, b"hello raw text")))),
        (1700000001, _eth(0x0800, _ipv4(50, esp))),
        (1700000002, _eth(0x0800, _ipv4(
            6, _tcp(1234, 80, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")))),
    ]


class TestCliDump(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "dump.pcap")
        _write_pcap(self.path, _frames())
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for name in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main([self.path] + argv)
        return code, buf.getvalue()

    def test_dump_implies_packet_list(self):
        code, out = self._run(["--dump", "hex"])
        self.assertEqual(code, 0)
        self.assertIn("逐包列表", out)

    def test_hex_output(self):
        _, out = self._run(["--dump", "hex"])
        self.assertIn("68 65 6c 6c 6f 20 72 61 77", out)
        self.assertIn("|hello raw text|", out)

    def test_str_output_has_no_hex(self):
        _, out = self._run(["--dump", "str"])
        self.assertIn("hello raw text", out)
        self.assertNotIn("68 65 6c 6c", out)

    def test_dump_bytes_truncation_note(self):
        _, out = self._run(["--dump", "hex", "--dump-bytes", "4"])
        self.assertIn("|hell|", out)
        self.assertIn("剩余 10 字节未显示", out)

    def test_json_payload_block(self):
        _, out = self._run(["--json", "--dump", "both", "--dump-bytes", "4"])
        data = json.loads(out)
        packets = data["packets"]
        self.assertEqual(packets[0]["l4"], "TCP")
        self.assertEqual(packets[0]["payload"]["offset"], 54)
        self.assertEqual(packets[0]["payload"]["total"], 14)
        self.assertEqual(packets[0]["payload"]["shown"], 4)
        self.assertEqual(packets[0]["payload"]["hex"], b"hell".hex())
        self.assertEqual(packets[0]["payload"]["text"], "hell")
        # ESP 包同样带 payload，HTTP 包已解码故不带
        self.assertEqual(packets[1]["l4"], "ESP")
        self.assertEqual(packets[1]["payload"]["offset"], 42)
        self.assertNotIn("payload", packets[2])

    def test_json_without_dump_has_no_payload(self):
        _, out = self._run(["--json"])
        for packet in json.loads(out)["packets"]:
            self.assertNotIn("payload", packet)


class TestPrintPackets(unittest.TestCase):
    def test_only_packets_with_raw_are_dumped(self):
        infos = []
        for idx, raw in enumerate((b"raw-bytes", b"")):
            info = _info()
            info.index = idx
            info.l4 = "ESP"
            info.payload_raw = raw
            info.payload_off = 34
            infos.append(info)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_packets(infos, "hex", 256)
        out = buf.getvalue()
        self.assertEqual(out.count("0022  "), 1)
        self.assertIn("|raw-bytes|", out)


class TestFormatPayloadSweep(unittest.TestCase):
    """format_payload 的参数化组合扫描: 只断言不变式, 不逐例硬编码期望串。"""

    def test_layout_sweep(self):
        """长度 × 模式 × 有效 limit: 行数/偏移/十六进制回环/ASCII 列/提示。"""
        for n in _LENGTHS:
            data = _pattern(n)
            for mode in _MODES:
                for limit in _effective_limits(n):
                    with self.subTest(n=n, mode=mode, limit=limit):
                        _check_layout(self, data, mode, 0, limit)

    def test_base_sweep(self):
        """base 跨 4 位/5 位十六进制与进位边界; limit 只取全量与最小截断各一次。"""
        for n in (0, 1, 16, 17, 64, 65, 257):
            data = _pattern(n)
            limits = tuple(filter(None, (0, _truncated_limit(n)))) or (0,)
            for base in _BASES:
                for mode in _MODES:
                    for limit in limits:
                        with self.subTest(n=n, base=base, mode=mode, limit=limit):
                            _check_layout(self, data, mode, base, limit)

    def test_unlimited_equivalence(self):
        """limit <= 0 与 limit >= len 输出必须完全一致(全量展示)。"""
        for n in _LENGTHS:
            data = _pattern(n)
            for mode in _MODES:
                with self.subTest(n=n, mode=mode):
                    full = format_payload(data, mode, 0, 0)
                    for limit in (-3, -1, n, n + 1, n + 500):
                        self.assertEqual(format_payload(data, mode, 0, limit), full)

    def test_truncation_is_prefix(self):
        """截断保留完整的整行: 不为末行补零, 也不改写已输出的完整行。"""
        for n in _LENGTHS:
            data = _pattern(n)
            for mode, width in (("hex", HEX_WIDTH), ("str", TEXT_WIDTH)):
                with self.subTest(n=n, mode=mode):
                    full = format_payload(data, mode, 0, 0)
                    for limit in _effective_limits(n)[1:]:
                        part = format_payload(data, mode, 0, limit)
                        complete = limit // width
                        self.assertEqual(part[:complete], full[:complete],
                                         f"limit={limit} 完整行被改写")
                        self.assertEqual(part[-1], _hint(n - limit))
                        _check_lines(self, part, data, mode, 0, limit)

    def test_deterministic_repeat(self):
        for n in (0, 1, 17, 64, 200):
            data = _pattern(n)
            for mode in _MODES:
                for limit in (0, 7):
                    with self.subTest(n=n, mode=mode, limit=limit):
                        self.assertEqual(format_payload(data, mode, 0x10, limit),
                                         format_payload(data, mode, 0x10, limit))

    def test_64k_boundary(self):
        """GTP 合并上限 64KB 附近: 行数与末行偏移精确, 不丢字节。"""
        for n in (65535, 65536):
            data = b"A" * n
            with self.subTest(n=n, mode="hex"):
                lines = format_payload(data, "hex", 0, 0)
                self.assertEqual(len(lines), -(-n // HEX_WIDTH))
                self.assertTrue(lines[-1].startswith(f"{((n - 1) // HEX_WIDTH) * HEX_WIDTH:04x}  "))
            with self.subTest(n=n, mode="str"):
                lines = format_payload(data, "str", 0, 0)
                self.assertEqual(len(lines), -(-n // TEXT_WIDTH))
                self.assertTrue(lines[-1].startswith(f"{((n - 1) // TEXT_WIDTH) * TEXT_WIDTH:04x}  "))
            with self.subTest(n=n, limit=n - 1):
                part = format_payload(data, "hex", 0, n - 1)
                self.assertEqual(part[-1], _hint(1))
                self.assertEqual(len(part) - 1, -(-(n - 1) // HEX_WIDTH))

    def test_huge_base_no_wrap(self):
        """偏移文本超出 32 位仍自然加宽, 不回绕、不截断。"""
        data = _pattern(17)
        for base in (0x7FFFFFFF, 0xFFFFFFFF, 0x100000000, 0x123456789AB):
            with self.subTest(base=base):
                _check_layout(self, data, "hex", base, 0)
                _check_layout(self, data, "str", base, 0)

    def test_adversarial_lengths_near_64k(self):
        """行宽非整倍数与 64KB 上下 1 字节: 行数/末行偏移/截断余量用公式校验。"""
        for n in (4095, 4096, 4097, 65519, 65520, 65521):
            data = b"A" * n
            for mode, width in (("hex", HEX_WIDTH), ("str", TEXT_WIDTH)):
                with self.subTest(n=n, mode=mode):
                    lines = format_payload(data, mode, 0, 0)
                    self.assertEqual(len(lines), -(-n // width))
                    self.assertTrue(lines[-1].startswith(f"{((n - 1) // width) * width:04x}  "))
                    part = format_payload(data, mode, 0, n - 1)
                    self.assertEqual(part[-1], _hint(1))
                    self.assertEqual(len(part) - 1, -(-(n - 1) // width))

    def test_fuzz_layout(self):
        """固定种子随机扫描: 随机长度/内容/模式/limit/base 交叉验证不变式。"""
        rnd = random.Random(20261028)
        for case in range(300):
            n = rnd.randrange(0, 321)
            data = bytes(rnd.randrange(256) for _ in range(n))
            mode = rnd.choice(_MODES)
            limit = rnd.choice(_effective_limits(n) + (-2, n, n + 99, 4096))
            base = rnd.choice((0, rnd.randrange(0, 0x10000), rnd.randrange(0x10000, 0x100000)))
            with self.subTest(case=case, n=n, mode=mode, limit=limit, base=base):
                lines = format_payload(data, mode, base, limit)
                _check_lines(self, lines, data, mode, base, limit)
                self.assertEqual(lines, format_payload(data, mode, base, limit))


class TestPayloadLinesSweep(unittest.TestCase):
    """payload_lines 扫描: 偏移/长度/模式/limit 组合下与 format_payload 同构。"""

    def test_accessor_sweep(self):
        for n in (0, 1, 16, 17, 63, 64, 65, 200):
            limits = tuple(dict.fromkeys((0, -1, _truncated_limit(n))))
            for off in (0, 1, 0x10, 0xFFF0, 0xFFFF, 0x10000, 0x123456):
                for mode in ("hex", "str", "both"):
                    for limit in limits:
                        with self.subTest(n=n, off=off, mode=mode, limit=limit):
                            info = _info()
                            info.payload_raw = _pattern(n)
                            info.payload_off = off
                            _check_lines(self, info.payload_lines(mode, limit),
                                         info.payload, mode, off, limit)

    def test_matches_format_payload(self):
        """访问器与统一展示函数的契约: 偏移取 payload_off, 内容取 payload。"""
        for n in (0, 5, 16, 17, 70):
            for off in (0, 0x20):
                for mode in _MODES:
                    for limit in (0, 3):
                        with self.subTest(n=n, off=off, mode=mode, limit=limit):
                            info = _info()
                            info.payload_raw = _pattern(n)
                            info.payload_off = off
                            self.assertEqual(info.payload_lines(mode, limit),
                                             format_payload(info.payload, mode, off, limit))

    def test_offset_change_updates_base(self):
        """偏移是实时读取: 修改 payload_off 后同一对象输出随之平移。"""
        info = _info()
        info.payload_raw = b"AB"
        info.payload_off = 0x20
        self.assertTrue(info.payload_lines("hex")[0].startswith("0020  "))
        info.payload_off = 0x40
        self.assertTrue(info.payload_lines("hex")[0].startswith("0040  "))

    def test_accessor_has_no_side_effects(self):
        """展示是只读操作: 不改动 payload_raw/payload_off, 重复调用结果一致。"""
        info = _info()
        info.payload_raw = b"abcdef"
        info.payload_off = 0x30
        first = info.payload_lines("both", 4)
        self.assertEqual(info.payload_raw, b"abcdef")
        self.assertEqual(info.payload_off, 0x30)
        self.assertEqual(info.payload_lines("both", 4), first)

    def test_64k_hex_tail_offset(self):
        """64KB 内层负荷 + 近 0xFFFF 偏移: 末行偏移不丢位、不回绕。"""
        info = _info()
        info.payload_raw = b"A" * 65536
        info.payload_off = 0xFFF0
        lines = info.payload_lines("hex")
        self.assertEqual(len(lines), 4096)
        self.assertTrue(lines[-1].startswith(f"{0xFFF0 + 4095 * HEX_WIDTH:04x}  "))


if __name__ == "__main__":
    unittest.main(verbosity=2)
