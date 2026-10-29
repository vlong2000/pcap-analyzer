#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""一键回归: 顺序执行全部用例模块, 可选叠加变异扫描。

用法:
    python test/scripts/run_all.py                 # 只跑单元测试
    python test/scripts/run_all.py --mutation dump # 额外跑载荷展示组变异
    python test/scripts/run_all.py --mutation core # 额外跑 GTP/ESP/L7/重组组
    python test/scripts/run_all.py --mutation all  # 两组都跑(约 3 分钟)

退出码: 0 表示全部通过; 1 表示存在失败(含变异扫描未通过)。
"""

import argparse
import io
import os
import sys
import time
import unittest
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST_DIR = os.path.join(ROOT, "test", "scripts")

MODULES = (
    "test_dump",
    "test_esp",
    "test_gtp",
    "test_l7_identify",
    "test_reassembly",
    "test_resources",
    "test_mutation_tool",
)


def _prepare_paths():
    for path in reversed((TEST_DIR, ROOT)):
        while path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)
    os.chdir(ROOT)


def run_module(name):
    """导入并执行单个用例模块, 返回 (用例数, 耗时, 失败描述列表)。"""
    started = time.time()
    try:
        module = __import__(name)
        if name not in sys.modules:
            raise ImportError(name)
        suite = unittest.TestLoader().loadTestsFromModule(module)
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    except Exception:
        return 0, time.time() - started, [traceback.format_exc(limit=3).strip().splitlines()[-1]]
    failures = [test.id().split(".")[-1] for test, _ in result.failures]
    errors = [test.id().split(".")[-1] for test, _ in result.errors]
    return result.testsRun, time.time() - started, failures + errors


def run_units():
    _prepare_paths()
    total = 0
    failed = []
    started = time.time()
    for index, name in enumerate(MODULES, 1):
        count, cost, problems = run_module(name)
        total += count
        status = "通过" if not problems else "失败 " + ", ".join(problems)
        print(f"[{index}/{len(MODULES)}] {name:<18} {count:>4} 用例  "
              f"{cost:6.2f}s  {status}", flush=True)
        if problems:
            failed.extend(f"{name}.{item}" for item in problems)
    cost = time.time() - started
    print(f"\n单元测试: {len(MODULES)} 个模块, {total} 用例, {cost:.2f}s, "
          f"{'全部通过' if not failed else '失败 ' + str(len(failed)) + ' 项'}")
    return failed


def run_mutation(choice):
    import mutation_dump

    groups = ("dump", "core") if choice == "all" else (choice,)
    codes = []
    for group in groups:
        print(f"\n== 变异扫描: {group} ==")
        codes.append(mutation_dump.main(["--group", group]))
    return codes


def main(argv=None):
    parser = argparse.ArgumentParser(description="一键回归")
    parser.add_argument("--mutation", choices=("none", "dump", "core", "all"),
                        default="none", help="额外执行变异扫描, 默认不跑")
    args = parser.parse_args(argv)

    failed = run_units()
    codes = []
    if args.mutation != "none":
        codes = run_mutation(args.mutation)

    ok = not failed and all(code == 0 for code in codes)
    print(f"\n结论: {'全部通过' if ok else '存在失败'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
