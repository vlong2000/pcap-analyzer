#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""变异测试工具(可复跑, 支持切换目标源码与用例模块)。

内置两组变异:
    dump  载荷展示(format_hex/format_text/format_payload/payload_lines), 用例 test_dump
    core  GTP-U 合并 / ESP+NAT-T / L7 识别 / 重组缓存, 用例 test_gtp 等六个模块

逐条注入单点变异, 每条变异都重跑目标用例模块, 用「是否被用例捕获」评估测试强度。

用法:
    python test/scripts/mutation_dump.py                 # 跑 dump 组
    python test/scripts/mutation_dump.py --group core    # 跑 GTP/ESP/L7/重组
    python test/scripts/mutation_dump.py --list          # 只打印变异清单
    python test/scripts/mutation_dump.py --only M05,M17  # 只跑指定编号
    python test/scripts/mutation_dump.py --verbose       # 打印首个捕获用例
    python test/scripts/mutation_dump.py --target pcap_analyzer.py \
        --tests test_gtp,test_esp --spec my_mutants.json # 外部清单

外部清单 JSON 为数组, 每项含 id/desc/old/new, 可选 equivalent:
    [{"id": "X01", "desc": "...", "old": "...", "new": "..."}]

判定与退出码:
    * 非等价变异被用例捕获 -> 杀死(KILLED)
    * 等价变异(行为与原文完全一致, 标记 equivalent=True) -> 存活(SURVIVED, 预期)
    * 非等价变异未被捕获, 或等价变异被捕获 -> 记为问题
    退出码 0 表示不存在问题; 1 表示存在问题; 2 表示基线用例本身不通过。

注意: 变异体在进程内替换目标模块后重载用例模块, 因此单个变异体若造成输出规模
      爆炸会拖慢整轮执行(例如让 ASCII 列取整段数据, 叠加 64KB 用例)。遇到此类
      变异请拆成小规模等价形式。
"""

import argparse
import importlib
import io
import json
import os
import sys
import time
import types
import unittest
from collections import namedtuple

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_PATH = os.path.join(ROOT, "pcap_analyzer.py")
TEST_DIR = os.path.join(ROOT, "test", "scripts")

Mutant = namedtuple("Mutant", "mid desc old new equivalent")


def _m(mid, desc, old, new, equivalent=False):
    return Mutant(mid, desc, old, new, equivalent)


MUTANTS = [
    _m("M01", "hex 行补位少 1 列", "ljust(width * 3 - 1)", "ljust(width * 3 - 2)"),
    _m("M02", "hex 行补位多 1 列", "ljust(width * 3 - 1)", "ljust(width * 3)"),
    _m("M03", "hex 字节改大写", 'hex_part = " ".join(f"{b:02x}" for b in chunk)',
       'hex_part = " ".join(f"{b:02X}" for b in chunk)'),
    _m("M04", "hex 偏移改大写", 'f"{base + i:04x}  {hex_part}', 'f"{base + i:04X}  {hex_part}'),
    _m("M05", "hex 偏移改空格补位", 'f"{base + i:04x}  {hex_part}', 'f"{base + i:4x}  {hex_part}'),
    _m("M06", "hex 偏移 +1", 'f"{base + i:04x}  {hex_part}', 'f"{base + i + 1:04x}  {hex_part}'),
    _m("M07", "hex 每行少取 1 字节", "chunk = data[i:i + width]", "chunk = data[i:i + width - 1]"),
    _m("M08", "hex ASCII 列只取前 4 字节", "|{_ascii_col(chunk)}|", "|{_ascii_col(chunk[:4])}|"),
    _m("M09", "ASCII 上界含 0x7f", "32 <= b < 127", "32 <= b <= 127"),
    _m("M10", "ASCII 下界排除空格", "32 <= b < 127", "33 <= b < 127"),
    _m("M11", "ASCII 上界扩到 0x7f", "32 <= b < 127", "32 <= b < 128"),
    _m("M12", "不可打印字符换成 ?", 'else "." for b in chunk', 'else "?" for b in chunk'),
    _m("M13", "文本行多取 1 字节", "{_ascii_col(data[i:i + width])}",
       "{_ascii_col(data[i:i + width + 1])}"),
    _m("M14", "文本行偏移 +1", 'f"{base + i:04x}  {_ascii_col(', 'f"{base + i + 1:04x}  {_ascii_col('),
    _m("M15", "limit=0 不再视为全量",
       "shown = data if limit <= 0 else data[:limit]\n    lines: list[str] = []",
       "shown = data if limit < 0 else data[:limit]\n    lines: list[str] = []"),
    _m("M16", "截断多取 1 字节",
       "else data[:limit]\n    lines: list[str] = []",
       "else data[:limit + 1]\n    lines: list[str] = []"),
    _m("M17", "both 模式丢弃 hex 块",
       'if mode in ("hex", "both"):\n        lines.extend(format_hex(shown, base))',
       'if mode in ("hex",):\n        lines.extend(format_hex(shown, base))'),
    _m("M18", "both 模式丢弃文本块",
       'if mode in ("str", "both"):\n        lines.extend(format_text(shown, base))',
       'if mode in ("str",):\n        lines.extend(format_text(shown, base))'),
    _m("M19", "both 模式先文本后 hex",
       '    if mode in ("hex", "both"):\n        lines.extend(format_hex(shown, base))\n'
       '    if mode in ("str", "both"):\n        lines.extend(format_text(shown, base))',
       '    if mode in ("str", "both"):\n        lines.extend(format_text(shown, base))\n'
       '    if mode in ("hex", "both"):\n        lines.extend(format_hex(shown, base))'),
    _m("M20", "未截断也输出提示", "if len(shown) < len(data):", "if len(shown) <= len(data):"),
    _m("M21", "提示剩余字节数错误", 'f"... 剩余 {len(data) - len(shown)} 字节未显示 "',
       'f"... 剩余 {len(data)} 字节未显示 "'),
    _m("M22", "提示文案删去说明", "(--dump-bytes 0 显示全部)", "(--dump-bytes 0)"),
    _m("M23", "payload_lines 忽略偏移",
       "format_payload(self.payload, mode, self.payload_off, limit)",
       "format_payload(self.payload, mode, 0, limit)"),
    _m("M24", "payload_lines 偏移 +1",
       "format_payload(self.payload, mode, self.payload_off, limit)",
       "format_payload(self.payload, mode, self.payload_off + 1, limit)"),
    _m("M25", "payload_lines 实参顺序颠倒",
       "format_payload(self.payload, mode, self.payload_off, limit)",
       "format_payload(self.payload, mode, limit, self.payload_off)"),
    _m("M26", "hex 默认行宽 16→8",
       "def format_hex(data: bytes, base: int = 0, width: int = 16) -> list[str]:",
       "def format_hex(data: bytes, base: int = 0, width: int = 8) -> list[str]:"),
    _m("M27", "text 默认行宽 64→63",
       "def format_text(data: bytes, base: int = 0, width: int = 64) -> list[str]:",
       "def format_text(data: bytes, base: int = 0, width: int = 63) -> list[str]:"),
    _m("M28", "hex 块绕过截断", "lines.extend(format_hex(shown, base))",
       "lines.extend(format_hex(data, base))"),
    _m("M29", "text 块绕过截断", "lines.extend(format_text(shown, base))",
       "lines.extend(format_text(data, base))"),
    _m("M30", "等价: 提示条件 < 改 !=", "if len(shown) < len(data):",
       "if len(shown) != len(data):", equivalent=True),
]

CORE_MUTANTS = [
    # GTP-U 拆解与按 TEID 合并
    _m("G01", "G-PDU 不保存内层数据", "        info.gtp_seg = data[pos:end]",
       '        info.gtp_seg = b""'),
    _m("G02", "内层数据偏移记成 GTP 头起点", "        info.gtp_seg_off = pos",
       "        info.gtp_seg_off = off"),
    _m("G03", "合并上限不生效", "        room = GTP_MERGE_MAX_BYTES - len(self.merged)",
       "        room = GTP_MERGE_MAX_BYTES"),
    _m("G04", "缓存已满时不置截断标记",
       "        else:\n            self.truncated = True", "        else:\n            pass"),
    _m("G05", "合并记录不累加包数", "        self.packets += 1", "        self.packets += 0"),
    _m("G06", "字节数误用合并后长度", "        self.bytes += len(seg)",
       "        self.bytes += len(self.merged)"),
    _m("G07", "首个序列号不记录",
       "            if self.seq_first is None:\n                self.seq_first = seq",
       "            if self.seq_first is None:\n                self.seq_first = None"),
    _m("G08", "跳变阈值改为 0",
       "            if self.prev_seq is not None and ((seq - self.prev_seq) & 0xFFFF) != 1:",
       "            if self.prev_seq is not None and ((seq - self.prev_seq) & 0xFFFF) != 0:"),
    _m("G09", "跳变判定未做 16 位回绕",
       "            if self.prev_seq is not None and ((seq - self.prev_seq) & 0xFFFF) != 1:",
       "            if self.prev_seq is not None and (seq - self.prev_seq) != 1:"),
    _m("G10", "内层 IPv6 地址不加方括号",
       '                a = f"[{src}]:{sport}" if ":" in src else f"{src}:{sport}"',
       '                a = f"{src}:{sport}"'),
    _m("G11", "TEID 分布合并成单一键",
       '            rec = self.gtp_teids.setdefault(info.detail["gtp_teid"], [0, 0])',
       '            rec = self.gtp_teids.setdefault("ALL", [0, 0])'),
    _m("G12", "所有隧道合并进同一 TEID",
       '            teid = info.detail.get("gtp_teid", "0x00000000")',
       '            teid = "0x00000000"'),
    _m("G13", "内层协议不统计", '        if "gtp_inner_proto" in info.detail:',
       "        if False:"),

    # ESP 与 NAT-T 解封装
    _m("E01", "NAT-T 空载荷未识别", "    if seg_len == 0:", "    if seg_len < 0:"),
    _m("E02", "Keepalive 只判长度不判 0xFF",
       "    if seg_len == 1 and data[off] == 0xFF:", "    if seg_len == 1:"),
    _m("E03", "IKE 长度门槛降到 4 字节",
       '    if seg_len >= 28 and data[off:off + 4] == b"\\x00\\x00\\x00\\x00":',
       '    if seg_len >= 4 and data[off:off + 4] == b"\\x00\\x00\\x00\\x00":'),
    _m("E04", "IKE 载荷偏移未跳过标记",
       "        info.payload_raw, info.payload_off = data[off + 4:end], off + 4",
       "        info.payload_raw, info.payload_off = data[off:end], off"),
    _m("E05", "ESP 截断门槛降到 6 字节",
       "    if end - off < 8:\n        info.note = \"ESP 头部截断\"",
       "    if end - off < 6:\n        info.note = \"ESP 头部截断\""),
    _m("E06", "密文长度未扣除 ESP 头",
       "    cipher_len = max(0, end - off - 8)", "    cipher_len = max(0, end - off)"),
    _m("E07", "密文偏移未跳过 ESP 头",
       "        info.payload_raw, info.payload_off = data[off + 8:end], off + 8",
       "        info.payload_raw, info.payload_off = data[off:end], off"),
    _m("E08", "重放判定放宽(相等不告警)",
       "            if last is not None and seq <= last:", "            if last is not None and seq < last:"),
    _m("E09", "回退不出现在 SPI 集合", "                self.esp_regress_spis.add(spi)",
       "                pass"),
    _m("E10", "回退时也覆盖最大序号", "            if last is None or seq > last:", "            if True:"),
    _m("E11", "SPI 统计键误用序列号", '            spi = info.detail["esp_spi"]',
       '            spi = str(info.detail.get("esp_seq", 0))'),

    # L7 识别
    _m("L01", "目的端口映射失效",
       "    if dport is not None and dport in port_map:\n        return port_map[dport]",
       "    if False:\n        return port_map[dport]"),
    _m("L02", "源端口映射失效",
       "    if sport is not None and sport in port_map:\n        return port_map[sport]",
       "    if False:\n        return port_map[sport]"),
    _m("L04", "TCP DNS 长度前缀偏移改 2",
       "            dns_offsets.insert(0, 4)", "            dns_offsets.insert(0, 2)"),
    _m("L05", "长度前缀自洽判定放宽",
       "        if prefix_len == len(payload) - 2:", "        if prefix_len > 0:"),
    _m("L06", "DNS 响应标志位掩码改 0x0001", "[0] & 0x8000", "[0] & 0x0001"),
    _m("L07", "HTTP 方法表丢掉 POST",
       '("GET ", "POST", "PUT ", "DELE", "HEAD")',
       '("GET ", "PUT ", "DELE", "HEAD")'),
    _m("L08", "识别阶段 SIP token 阈值降到 2",
       '    if len(tokens) >= 3 and tokens[0] in SIP_METHODS:\n        return "SIP"\n',
       '    if len(tokens) >= 2 and tokens[0] in SIP_METHODS:\n        return "SIP"\n'),

    # 重组缓存
    _m("R01", "重叠头部不裁剪", "                trim = -d", "                trim = 0"),
    _m("R02", "等长重复分片再写入",
       "                if len(payload) <= len(existing):\n                    return False",
       "                if len(payload) < len(existing):\n                    return False"),
    _m("R04", "流字节上限判定改为 >=",
       "        if flow.total_bytes > self.max_bytes_per_flow:",
       "        if flow.total_bytes >= self.max_bytes_per_flow:"),
    _m("R05", "等价: 首片内容变也不重建", "                    if chunk != payload:",
       "                    if False:", equivalent=True),
    _m("R06", "总长记录不生效", "            flow.expected = total",
       "            flow.expected = None"),
    _m("R07", "等价: 已交付序号未做 32 位截断",
       "        flow.delivered = (flow.base + target) & 0xFFFFFFFF",
       "        flow.delivered = flow.base + target", equivalent=True),
    _m("R08", "不足总长也返回数据",
       "        if expect_len is not None and len(buf) < expect_len:\n            return None",
       "        if False:\n            return None"),
    _m("R09", "ready 不要求从偏移 0 开始",
       "        if not flow.segments or flow.base + min(flow.segments) != 0:\n            return None",
       "        if not flow.segments:\n            return None"),
]


class Group:
    """一组变异配置: 目标源码、被替换的模块名、需要重跑的用例模块。"""

    def __init__(self, name, src_path, module_name, test_modules, mutants_name):
        self.name = name
        self.src_path = src_path
        self.module_name = module_name
        self.test_modules = tuple(test_modules)
        self.mutants_name = mutants_name


GROUPS = {
    "dump": Group("dump", SRC_PATH, "pcap_analyzer", ("test_dump",), "MUTANTS"),
    "core": Group("core", SRC_PATH, "pcap_analyzer",
                  ("test_gtp", "test_esp", "test_reassembly",
                   "test_l7_identify", "test_resources", "test_dump"),
                  "CORE_MUTANTS"),
}


def _load_module(source, group=None):
    """把(可能被变异的)源码加载为新模块并挂到 sys.modules。

    加载失败时回滚到调用前的 sys.modules 状态, 避免留下半成品模块。
    """
    group = group or GROUPS["dump"]
    name = group.module_name
    module = types.ModuleType(name)
    module.__file__ = group.src_path
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(source, group.src_path, "exec"), module.__dict__)
    except BaseException:
        if previous is not None:
            sys.modules[name] = previous
        else:
            sys.modules.pop(name, None)
        raise
    return module


def _run_suite(group=None):
    """重载该组的用例模块并执行, 返回 (是否全绿, 用例数, 失败用例名列表)。"""
    group = group or GROUPS["dump"]
    caught = []
    total = 0
    for name in group.test_modules:
        module = importlib.import_module(name)
        importlib.reload(module)
        suite = unittest.TestLoader().loadTestsFromModule(module)
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        total += result.testsRun
        caught.extend(test.id().split(".")[-1]
                      for test, _ in result.failures + result.errors)
    return not caught, total, caught


def _prepare_paths():
    """保证 TEST_DIR 在最前、ROOT 次之, 与调用前的 sys.path 状态无关。"""
    for path in reversed((TEST_DIR, ROOT)):
        while path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)


def _select(mutants, only):
    """按 --only 过滤; 空白串或全为逗号时视为不筛选。"""
    wanted = {item.strip().upper() for item in (only or "").split(",") if item.strip()}
    if not wanted:
        return mutants
    selected = [m for m in mutants if m.mid.upper() in wanted]
    missing = wanted - {m.mid.upper() for m in selected}
    if missing:
        raise SystemExit(f"未知变异编号: {', '.join(sorted(missing))}")
    return selected


def _mutation_score(killed, missed):
    """变异得分 = 杀死 / (杀死 + 遗漏); 无可用变异体时视为满分。"""
    denominator = killed + missed
    return (killed / denominator * 100) if denominator else 100.0


def _spec_group(args):
    """按 --target/--tests/--spec 构建外部变异组。"""
    if not args.target or not args.tests:
        raise SystemExit("--spec 需要同时指定 --target 与 --tests")
    source_path = os.path.abspath(args.target)
    if not os.path.isfile(source_path):
        raise SystemExit(f"目标源码不存在: {source_path}")
    modules = tuple(item.strip() for item in args.tests.split(",") if item.strip())
    if not modules:
        raise SystemExit("--tests 未给出有效用例模块")
    if not os.path.isfile(args.spec):
        raise SystemExit(f"变异清单不存在: {args.spec}")
    try:
        with open(args.spec, encoding="utf-8") as stream:
            data = json.load(stream)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"变异清单不是合法 JSON: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise SystemExit("外部清单必须是含至少一条变异的数组")
    mutants = []
    for index, item in enumerate(data, 1):
        missing = [key for key in ("id", "desc", "old", "new") if key not in item]
        if missing:
            raise SystemExit(f"第 {index} 条变异缺少字段: {', '.join(missing)}")
        mutants.append(_m(item["id"], item["desc"], item["old"], item["new"],
                          bool(item.get("equivalent", False))))
    ids = [m.mid for m in mutants]
    if len(set(ids)) != len(ids):
        raise SystemExit("外部清单存在重复编号: --only 将无法区分")
    for m in mutants:
        if m.old == m.new:
            raise SystemExit(f"{m.mid} 的 old 与 new 相同, 不会产生任何变异")
    return Group("spec", source_path, os.path.splitext(os.path.basename(source_path))[0],
                 modules, ""), mutants


def main(argv=None):
    parser = argparse.ArgumentParser(description="变异测试工具(可切换目标与用例)")
    parser.add_argument("--group", default="dump", choices=sorted(GROUPS),
                        help="内置变异组, 默认 dump")
    parser.add_argument("--target", default="", help="外部模式: 目标源码路径")
    parser.add_argument("--tests", default="", help="外部模式: 用例模块, 逗号分隔")
    parser.add_argument("--spec", default="", help="外部模式: 变异清单 JSON")
    parser.add_argument("--list", action="store_true", help="只打印变异清单")
    parser.add_argument("--only", default="", help="只跑指定编号, 逗号分隔, 如 M05,M17")
    parser.add_argument("--verbose", action="store_true", help="打印每条变异的首个捕获用例")
    args = parser.parse_args(argv)

    if args.target or args.tests:
        if not args.spec:
            raise SystemExit("--target/--tests 需要配合 --spec 使用")

    if args.spec:
        group, mutants = _spec_group(args)
    else:
        group = GROUPS[args.group]
        mutants = list(globals()[group.mutants_name])

    if args.list:
        print(f"组 {group.name}: 目标 {os.path.basename(group.src_path)}, "
              f"用例 {', '.join(group.test_modules)}")
        for m in mutants:
            flag = " [等价]" if m.equivalent else ""
            print(f"{m.mid}  {m.desc}{flag}")
        return 0

    _prepare_paths()
    mutants = _select(mutants, args.only)
    with open(group.src_path, encoding="utf-8") as stream:
        source = stream.read()

    for m in mutants:
        occurrences = source.count(m.old)
        if occurrences != 1:
            raise SystemExit(f"{m.mid} 变异点出现 {occurrences} 次(预期 1 次), 请修正清单: {m.desc}")

    original = sys.modules.get(group.module_name)     # 保留原模块对象, 收尾按引用还原
    _load_module(source, group)
    ok, count, caught = _run_suite(group)
    print(f"目标 {os.path.basename(group.src_path)}  用例 {', '.join(group.test_modules)}")
    print(f"基线: {count} 用例 {'通过' if ok else '失败 ' + str(caught)}")
    if not ok:
        return 2

    killed, survived, problems, skipped = [], [], [], []
    try:
        for m in mutants:
            started = time.time()
            try:
                _load_module(source.replace(m.old, m.new, 1), group)
                ok, _, caught = _run_suite(group)
            except Exception as exc:                     # 变异体自身加载/执行异常
                skipped.append((m, f"{type(exc).__name__}"))
                print(f"{m.mid} 跳过  {m.desc}  ({type(exc).__name__})")
                continue

            cost = time.time() - started
            first = caught[0] if caught else "-"
            if m.equivalent:
                if ok:
                    survived.append(m)
                    print(f"{m.mid} 存活(预期)  {m.desc}  ({cost:.1f}s)")
                else:
                    problems.append((m, f"等价变异被用例捕获: {first}"))
                    print(f"{m.mid} 预期不符  {m.desc}  <- {first}")
            elif ok:
                problems.append((m, "未被任何用例捕获"))
                print(f"{m.mid} 存活(遗漏)  {m.desc}  ({cost:.1f}s)")
            else:
                killed.append((m, first))
                message = f"{m.mid} 杀死  {m.desc}  ({cost:.1f}s)"
                if args.verbose and caught:
                    message += f"  <- {first}"
                print(message)
    finally:
        if original is not None:                     # 回填原对象, 避免留下重复的模块定义
            sys.modules[group.module_name] = original
        else:
            _load_module(source, group)
        for name in group.test_modules:
            importlib.reload(importlib.import_module(name))

    total = len(killed) + len(survived) + len(problems) + len(skipped)
    missed = [m for m, _ in problems if not m.equivalent]     # 真正的遗漏(非等价却存活)
    score = _mutation_score(len(killed), len(missed))
    print(f"\n汇总: 变异体 {total}, 杀死 {len(killed)}, 遗漏 {len(missed)}, "
          f"等价存活 {len(survived)}, 预期不符 {len(problems) - len(missed)}, "
          f"跳过 {len(skipped)}, 变异得分 {score:.1f}%")
    if survived:
        print("等价存活:")
        for m in survived:
            print(f"  {m.mid} {m.desc}")
    if problems:
        print("问题清单:")
        for m, why in problems:
            print(f"  {m.mid} {m.desc}: {why}")
    if skipped:
        print("跳过清单:")
        for m, why in skipped:
            print(f"  {m.mid} {m.desc}: {why}")

    return 0 if not problems and not skipped else 1


if __name__ == "__main__":
    sys.exit(main())
