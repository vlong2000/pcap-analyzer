# -*- coding: utf-8 -*-
"""mutation_dump.py(变异测试工具自身)的单元测试。

覆盖: 变异清单完整性与唯一性、--only 解析、变异得分边界、模块加载与还原、
主流程四种结局(基线失败/全部杀死/存在遗漏/等价变异)、异常变异体跳过、CLI 参数。
"""

import argparse
import contextlib
import importlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST_DIR = os.path.join(ROOT, "test", "scripts")
for _path in (ROOT, TEST_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import mutation_dump as md

with open(md.SRC_PATH, encoding="utf-8") as _stream:
    SOURCE = _stream.read()


def _run_main(argv):
    """执行工具主流程并捕获 stdout, 返回 (退出码, 输出文本)。"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = md.main(argv)
    return code, buf.getvalue()


_FIXTURE_BODY = (
    "import unittest\n"
    "class T(unittest.TestCase):\n"
    "    def test_fail(self):\n"
    "        self.fail('boom')\n"
    "    def test_error(self):\n"
    "        raise RuntimeError('bang')\n"
    "    def test_ok(self):\n"
    "        pass\n"
)


def _synthetic_suite(body):
    """写入临时用例模块并执行 _run_suite, 返回 (ok, count, caught)。"""
    import shutil
    import tempfile
    tmpdir = tempfile.mkdtemp()
    name = "_mut_target_fixture"
    with open(os.path.join(tmpdir, name + ".py"), "w", encoding="utf-8") as stream:
        stream.write(body)
    previous = md.GROUPS["dump"].test_modules
    sys.path.insert(0, tmpdir)
    md.GROUPS["dump"].test_modules = (name,)
    try:
        return md._run_suite()
    finally:
        md.GROUPS["dump"].test_modules = previous
        sys.modules.pop(name, None)
        sys.path.remove(tmpdir)
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestMutantSpec(unittest.TestCase):
    """清单本身的不变式: 变异点唯一、编号合法、描述非空。"""

    def test_old_fragment_unique(self):
        for m in md.MUTANTS:
            with self.subTest(mid=m.mid):
                self.assertEqual(SOURCE.count(m.old), 1, f"{m.mid} 变异点不唯一")

    def test_old_differs_from_new(self):
        for m in md.MUTANTS:
            with self.subTest(mid=m.mid):
                self.assertNotEqual(m.old, m.new)

    def test_ids_unique_and_well_formed(self):
        ids = [m.mid for m in md.MUTANTS]
        self.assertEqual(len(ids), len(set(ids)), "变异编号重复")
        for mid in ids:
            with self.subTest(mid=mid):
                self.assertRegex(mid, r"^M\d{2}$")

    def test_descriptions_non_empty(self):
        for m in md.MUTANTS:
            with self.subTest(mid=m.mid):
                self.assertTrue(m.desc.strip())

    def test_default_not_equivalent(self):
        m = md._m("X9", "描述", "old", "new")
        self.assertFalse(m.equivalent)

    def test_exactly_one_equivalent_mutant(self):
        """等价变异必须显式标注, 且当前清单只有提示条件那一处。"""
        marked = [m.mid for m in md.MUTANTS if m.equivalent]
        self.assertEqual(marked, ["M30"])

    def test_covers_target_functions(self):
        """清单需覆盖四个展示函数与 payload_lines 访问器。"""
        joined = "\n".join(m.old for m in md.MUTANTS)
        for token in ("hex_part", "base + i", "_ascii_col", "shown = data",
                      "format_text(shown", "self.payload_off"):
            with self.subTest(token=token):
                self.assertIn(token, joined)

    def test_mutant_is_immutable_namedtuple(self):
        m = md._m("X1", "描述", "old", "new")
        self.assertEqual(m._fields, ("mid", "desc", "old", "new", "equivalent"))
        with self.assertRaises(AttributeError):
            m.mid = "X2"


class TestSelect(unittest.TestCase):
    """--only 解析: 空/空白/重复/大小写/未知编号。"""

    def test_empty_returns_all(self):
        self.assertEqual(md._select(md.MUTANTS, ""), md.MUTANTS)

    def test_none_returns_all(self):
        self.assertEqual(md._select(md.MUTANTS, None), md.MUTANTS)

    def test_blank_and_commas_return_all(self):
        for only in (" ", ",", " , , "):
            with self.subTest(only=only):
                self.assertEqual(md._select(md.MUTANTS, only), md.MUTANTS)

    def test_single_selection(self):
        picked = md._select(md.MUTANTS, "M05")
        self.assertEqual([m.mid for m in picked], ["M05"])

    def test_case_insensitive_and_whitespace(self):
        picked = md._select(md.MUTANTS, " m05 , M17 ")
        self.assertEqual([m.mid for m in picked], ["M05", "M17"])

    def test_duplicates_collapse(self):
        picked = md._select(md.MUTANTS, "M05,m05,M05")
        self.assertEqual([m.mid for m in picked], ["M05"])

    def test_missing_id_raises_system_exit(self):
        with self.assertRaises(SystemExit) as ctx:
            md._select(md.MUTANTS, "M05,ZZ")
        self.assertIn("ZZ", str(ctx.exception))

    def test_selection_keeps_list_order(self):
        picked = md._select(md.MUTANTS, "M17,M05")
        self.assertEqual([m.mid for m in picked], ["M05", "M17"])

    def test_all_selection_is_same_object(self):
        """不筛选时直接返回原列表, 不做无谓拷贝。"""
        self.assertIs(md._select(md.MUTANTS, "  "), md.MUTANTS)

    def test_extra_commas_tolerated(self):
        picked = md._select(md.MUTANTS, "M05,,M17,")
        self.assertEqual([m.mid for m in picked], ["M05", "M17"])

    def test_short_id_rejected(self):
        """不做前缀匹配: M1 不等于 M01。"""
        with self.assertRaises(SystemExit) as ctx:
            md._select(md.MUTANTS, "M1")
        self.assertIn("M1", str(ctx.exception))


class TestMutationScore(unittest.TestCase):
    """变异得分: 分母为零、全杀、部分遗漏。"""

    def test_no_usable_mutant_is_full_score(self):
        self.assertEqual(md._mutation_score(0, 0), 100.0)

    def test_all_killed(self):
        self.assertEqual(md._mutation_score(29, 0), 100.0)

    def test_partial(self):
        self.assertAlmostEqual(md._mutation_score(1, 3), 25.0, places=6)

    def test_only_missed(self):
        self.assertEqual(md._mutation_score(0, 5), 0.0)

    def test_monotonic_in_killed(self):
        self.assertGreater(md._mutation_score(2, 2), md._mutation_score(1, 2))

    def test_returns_float(self):
        self.assertIsInstance(md._mutation_score(0, 0), float)
        self.assertIsInstance(md._mutation_score(3, 1), float)


class TestLoadModule(unittest.TestCase):
    """模块加载: 注册到 sys.modules、变异立即生效、可被再次覆盖。"""

    def test_registers_module(self):
        mod = md._load_module(SOURCE)
        self.assertIs(sys.modules["pcap_analyzer"], mod)
        self.assertEqual(mod.__file__, md.SRC_PATH)
        self.assertTrue(hasattr(mod, "format_payload"))
        self.assertTrue(hasattr(mod, "PacketInfo"))

    def test_mutation_takes_effect(self):
        pristine_line = md._load_module(SOURCE).format_payload(b"AB", "hex")[0]
        mutated = md._load_module(SOURCE.replace("ljust(width * 3 - 1)",
                                                 "ljust(width * 3)", 1))
        self.assertNotEqual(mutated.format_payload(b"AB", "hex")[0], pristine_line)

    def test_reload_overwrites_previous(self):
        md._load_module(SOURCE.replace("ljust(width * 3 - 1)", "ljust(width * 3)", 1))
        mod = md._load_module(SOURCE)
        self.assertTrue(mod.format_payload(b"AB", "hex")[0].endswith("|AB|"))

    def test_failed_load_registers_nothing_without_previous(self):
        sys.modules.pop("pcap_analyzer", None)
        with self.assertRaises(SyntaxError):
            md._load_module("def broken(:")
        self.assertNotIn("pcap_analyzer", sys.modules)

    def test_failed_load_rolls_back_to_previous(self):
        previous = md._load_module(SOURCE)
        with self.assertRaises(SyntaxError):
            md._load_module("def broken(:")
        self.assertIs(sys.modules["pcap_analyzer"], previous)
        self.assertTrue(previous.format_payload(b"AB", "hex")[0].endswith("|AB|"))

    def test_runtime_error_also_rolls_back(self):
        """运行期异常(非语法)同样回滚, 不留下半初始化模块。"""
        previous = md._load_module(SOURCE)
        with self.assertRaises(ZeroDivisionError):
            md._load_module("boom = 1 / 0\n")
        self.assertIs(sys.modules["pcap_analyzer"], previous)

    def test_prepare_paths_idempotent(self):
        md._prepare_paths()
        md._prepare_paths()
        self.assertEqual(sum(1 for p in sys.path if p == md.ROOT), 1)
        self.assertEqual(sum(1 for p in sys.path if p == md.TEST_DIR), 1)

    def test_prepare_paths_partial_presence_is_deterministic(self):
        """无论 ROOT/TEST_DIR 哪个已存在, 结果顺序都固定。"""
        for preexisting in ((md.ROOT,), (md.TEST_DIR,), ()):
            with self.subTest(preexisting=preexisting):
                for path in (md.ROOT, md.TEST_DIR):
                    while path in sys.path:
                        sys.path.remove(path)
                for path in preexisting:
                    sys.path.insert(0, path)
                md._prepare_paths()
                self.assertEqual(sys.path[:2], [md.TEST_DIR, md.ROOT])

    def test_system_exit_in_module_rolls_back(self):
        """模块在加载期主动退出, 也不能留下半初始化条目。"""
        previous = md._load_module(SOURCE)
        with self.assertRaises(SystemExit):
            md._load_module("import sys\nsys.exit(2)\n")
        self.assertIs(sys.modules["pcap_analyzer"], previous)


class TestMainFlow(unittest.TestCase):
    """主流程结局: 基线失败=2, 全杀=0, 遗漏=1, 等价存活=0, 等价误杀=1, 跳过=1。"""

    @staticmethod
    def _suite(results):
        return mock.patch.object(md, "_run_suite", side_effect=list(results))

    def test_baseline_failure_returns_2(self):
        with self._suite([(False, 123, ["t_baseline"])]):
            code, out = _run_main(["--only", "M05"])
        self.assertEqual(code, 2)
        self.assertIn("基线", out)
        self.assertIn("t_baseline", out)

    def test_all_killed_returns_0(self):
        with self._suite([(True, 123, []), (False, 123, ["t_kill"])]):
            code, out = _run_main(["--only", "M05"])
        self.assertEqual(code, 0)
        self.assertIn("杀死", out)
        self.assertIn("遗漏 0", out)
        self.assertIn("变异得分 100.0%", out)

    def test_missed_mutant_returns_1(self):
        with self._suite([(True, 123, []), (True, 123, [])]):
            code, out = _run_main(["--only", "M05"])
        self.assertEqual(code, 1)
        self.assertIn("遗漏 1", out)
        self.assertIn("未被任何用例捕获", out)

    def test_equivalent_survivor_returns_0(self):
        with self._suite([(True, 123, []), (True, 123, [])]):
            code, out = _run_main(["--only", "M30"])
        self.assertEqual(code, 0)
        self.assertIn("变异体 1", out)
        self.assertIn("等价存活 1", out)
        self.assertIn("变异得分 100.0%", out)

    def test_empty_mutant_list_is_noop_success(self):
        with mock.patch.object(md, "MUTANTS", []):
            with self._suite([(True, 123, [])]):
                code, out = _run_main(["--only", ""])
        self.assertEqual(code, 0)
        self.assertIn("变异体 0", out)
        self.assertIn("变异得分 100.0%", out)

    def test_verbose_without_caught_name(self):
        """用例数不足被判定失败但没有失败名时, 不应输出空的 <- 。"""
        with self._suite([(True, 123, []), (False, 123, [])]):
            code, out = _run_main(["--only", "M05", "--verbose"])
        self.assertEqual(code, 0)
        self.assertNotIn("<-", out)

    def test_problems_and_skips_together(self):
        bad = md._m("X2", "破坏语法", "ljust(width * 3 - 1)", "ljust(width * 3 - 1")
        with mock.patch.object(md, "MUTANTS", md.MUTANTS + [bad]):
            with self._suite([(True, 123, []), (True, 123, [])]):
                code, out = _run_main(["--only", "M05,X2"])
        self.assertEqual(code, 1)
        self.assertIn("变异体 2", out)
        self.assertIn("遗漏 1", out)
        self.assertIn("跳过 1", out)
        self.assertIn("问题清单", out)
        self.assertIn("跳过清单", out)

    def test_unexpected_exception_counts_as_skip(self):
        import pcap_analyzer
        with self._suite([(True, 123, []), RuntimeError("boom")]):
            code, out = _run_main(["--only", "M05"])
        self.assertEqual(code, 1)
        self.assertIn("跳过 1", out)
        self.assertIn("RuntimeError", out)
        self.assertIs(sys.modules["pcap_analyzer"], pcap_analyzer)

    def test_equivalent_killed_is_reported(self):
        with self._suite([(True, 123, []), (False, 123, ["t_x"])]):
            code, out = _run_main(["--only", "M30"])
        self.assertEqual(code, 1)
        self.assertIn("预期不符 1", out)
        self.assertIn("等价变异被用例捕获", out)

    def test_occurrence_mismatch_aborts_before_run(self):
        fragment = next(f for f in ("return lines", "lines.append(", "range(")
                        if SOURCE.count(f) != 1)
        bad = md._m("X1", "重复变异点", fragment, "pass")
        with mock.patch.object(md, "MUTANTS", md.MUTANTS + [bad]):
            with self._suite([(True, 123, [])]) as suite:
                with self.assertRaises(SystemExit) as ctx:
                    _run_main(["--only", "X1"])
                md._run_suite.assert_not_called()
        self.assertIn("出现", str(ctx.exception))

    def test_score_rounding_one_third(self):
        with self._suite([(True, 123, []), (False, 123, ["t"]),
                          (True, 123, []), (True, 123, [])]):
            code, out = _run_main(["--only", "M01,M02,M03"])
        self.assertEqual(code, 1)
        self.assertIn("杀死 1", out)
        self.assertIn("遗漏 2", out)
        self.assertIn("变异得分 33.3%", out)

    def test_equivalent_kill_not_counted_as_missed(self):
        """等价变异被误杀只计入「预期不符」, 不拉低得分。"""
        with self._suite([(True, 123, []), (True, 123, []), (False, 123, ["t"])]):
            code, out = _run_main(["--only", "M05,M30"])
        self.assertEqual(code, 1)
        self.assertIn("遗漏 1", out)
        self.assertIn("预期不符 1", out)
        self.assertIn("变异得分 0.0%", out)

    def test_lowercase_id_accepted(self):
        with self._suite([(True, 123, []), (False, 123, ["t"])]):
            code, out = _run_main(["--only", "m30"])
        self.assertEqual(code, 1)                       # 等价变异被误杀
        self.assertIn("预期不符 1", out)

    def test_output_follows_mutant_order(self):
        with self._suite([(True, 123, []), (False, 123, []), (True, 123, [])]):
            _, out = _run_main(["--only", "M17,M01"])
        self.assertLess(out.index("M01"), out.index("M17"))

    def test_syntax_error_mutant_is_skipped(self):
        bad = md._m("X2", "破坏语法的变异", "ljust(width * 3 - 1)", "ljust(width * 3 - 1")
        with mock.patch.object(md, "MUTANTS", md.MUTANTS + [bad]):
            with self._suite([(True, 123, [])]):
                code, out = _run_main(["--only", "X2"])
        self.assertEqual(code, 1)
        self.assertIn("跳过 1", out)
        self.assertIn("SyntaxError", out)

    def test_verbose_shows_first_caught_test(self):
        with self._suite([(True, 123, []), (False, 123, ["t_abc"])]):
            code, out = _run_main(["--only", "M05", "--verbose"])
        self.assertEqual(code, 0)
        self.assertIn("<- t_abc", out)

    def test_mixed_kill_miss_equivalent_score_half(self):
        with self._suite([(True, 123, []), (False, 123, ["t"]),
                          (True, 123, []), (True, 123, [])]):
            code, out = _run_main(["--only", "M01,M05,M30"])
        self.assertEqual(code, 1)                       # 因为存在遗漏
        self.assertIn("杀死 1", out)
        self.assertIn("遗漏 1", out)
        self.assertIn("等价存活 1", out)
        self.assertIn("变异得分 50.0%", out)

    def test_run_without_existing_module_restores_functional_copy(self):
        """首次运行(此前无 pcap_analyzer)时, 收尾需重新加载可用实现。"""
        sys.modules.pop("pcap_analyzer", None)
        with self._suite([(True, 123, []), (False, 123, ["t"])]):
            code, out = _run_main(["--only", "M05"])
        self.assertEqual(code, 0)
        restored = sys.modules.get("pcap_analyzer")
        self.assertIsNotNone(restored)
        self.assertTrue(restored.format_payload(b"AB", "hex")[0].endswith("|AB|"))

    def test_killed_and_skip_together(self):
        """杀死 + 跳过并存: 总数含两类, 得分不受跳过影响。"""
        bad = md._m("X2", "破坏语法", "ljust(width * 3 - 1)", "ljust(width * 3 - 1")
        with mock.patch.object(md, "MUTANTS", md.MUTANTS + [bad]):
            with self._suite([(True, 123, []), (False, 123, ["t"])]):
                code, out = _run_main(["--only", "M05,X2"])
        self.assertEqual(code, 1)
        self.assertIn("变异体 2", out)
        self.assertIn("杀死 1", out)
        self.assertIn("遗漏 0", out)
        self.assertIn("跳过 1", out)
        self.assertIn("变异得分 100.0%", out)

    def test_baseline_load_failure_propagates(self):
        """基线加载失败不做兜底, 直接抛出, 且不留下残留模块。"""
        previous = md._load_module(SOURCE)
        with mock.patch.object(md, "_load_module", side_effect=SyntaxError("bad")):
            with self.assertRaises(SyntaxError):
                _run_main(["--only", "M05"])
        self.assertIs(sys.modules["pcap_analyzer"], previous)


class TestRunSuite(unittest.TestCase):
    """真实执行目标用例模块, 校验返回契约。"""

    def test_returns_ok_count_and_no_failures(self):
        md._load_module(SOURCE)
        ok, count, caught = md._run_suite()
        self.assertTrue(ok)
        self.assertGreater(count, 100)
        self.assertEqual(caught, [])

    def test_detects_failing_and_erroring_tests(self):
        """失败(failures)与异常(errors)都要计入 captured 名称。"""
        ok, count, caught = _synthetic_suite(_FIXTURE_BODY)
        self.assertFalse(ok)
        self.assertEqual(count, 3)
        self.assertEqual(sorted(caught), ["test_error", "test_fail"])

    def test_failures_reported_before_errors(self):
        """captured 顺序为 failures 在前、errors 在后, 供 --verbose 取首个。"""
        ok, count, caught = _synthetic_suite(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_a_error(self):\n"
            "        raise RuntimeError('bang')\n"
            "    def test_b_fail(self):\n"
            "        self.fail('boom')\n"
        )
        self.assertFalse(ok)
        self.assertEqual(count, 2)
        self.assertEqual(caught, ["test_b_fail", "test_a_error"])

    def test_missing_target_module_raises(self):
        with mock.patch.object(md.GROUPS["dump"], "test_modules",
                               ("no_such_test_module",)):
            with self.assertRaises(ModuleNotFoundError):
                md._run_suite()


class TestCli(unittest.TestCase):
    """命令行参数行为。"""

    def test_argv_none_uses_sys_argv(self):
        with mock.patch.object(sys, "argv", ["mutation_dump.py", "--list"]):
            code, out = _run_main(None)
        self.assertEqual(code, 0)
        self.assertIn("M01", out)

    def test_list_returns_0_and_prints_every_mutant(self):
        code, out = _run_main(["--list"])
        self.assertEqual(code, 0)
        for m in md.MUTANTS:
            self.assertIn(m.mid, out)
        self.assertIn("[等价]", out)
        self.assertIn(md.MUTANTS[0].desc, out)

    def test_unknown_only_raises(self):
        with self.assertRaises(SystemExit):
            _run_main(["--only", "ZZ"])

    def test_list_ignores_only(self):
        code, out = _run_main(["--list", "--only", "M05"])
        self.assertEqual(code, 0)
        self.assertIn("M30", out)

    def test_list_has_no_side_effects(self):
        """--list 只读打印: 不加载模块、不执行用例。"""
        before = sys.modules.get("pcap_analyzer")
        with mock.patch.object(md, "_run_suite") as suite:
            code, _ = _run_main(["--list"])
        self.assertEqual(code, 0)
        suite.assert_not_called()
        self.assertIs(sys.modules.get("pcap_analyzer"), before)

    def test_unknown_flag_raises_with_code_2(self):
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--bogus"])
        self.assertEqual(ctx.exception.code, 2)


class TestRealRun(unittest.TestCase):
    """真实执行一次变异, 确认收尾后原始实现被完整还原。"""

    def test_run_restores_pristine_module(self):
        import pcap_analyzer
        baseline = pcap_analyzer.format_payload(b"AB", "hex")
        code, out = _run_main(["--only", "M05"])
        self.assertEqual(code, 0)
        self.assertIn("杀死 1", out)
        self.assertIs(sys.modules["pcap_analyzer"], pcap_analyzer)
        self.assertEqual(pcap_analyzer.format_payload(b"AB", "hex"), baseline)
        self.assertTrue(baseline[0].startswith("0000  41 42"))
        self.assertTrue(baseline[0].endswith("|AB|"))


class TestGroups(unittest.TestCase):
    """内置变异组(dump / core)与通用执行路径。"""

    def test_builtin_groups_defined(self):
        self.assertEqual(sorted(md.GROUPS), ["core", "dump"])
        for name, group in md.GROUPS.items():
            with self.subTest(group=name):
                self.assertTrue(os.path.isfile(group.src_path))
                self.assertNotEqual(group.module_name, "")
                self.assertTrue(group.test_modules)
                for module in group.test_modules:
                    self.assertTrue(
                        os.path.isfile(os.path.join(md.TEST_DIR, module + ".py")))

    def test_core_mutant_ids_unique_and_prefixes_covered(self):
        mutants = md.CORE_MUTANTS
        ids = [m.mid for m in mutants]
        self.assertEqual(len(set(ids)), len(ids))
        prefixes = {mid[0] for mid in ids}
        self.assertEqual(prefixes, {"G", "E", "L", "R"})

    def test_group_switches_target_mutants(self):
        code, out = _run_main(["--list", "--group", "core"])
        self.assertEqual(code, 0)
        self.assertIn("G01", out)
        self.assertIn("R09", out)
        self.assertNotIn("M01", out)
        self.assertIn("test_gtp", out)

    def test_core_group_run_passes_core_group_to_suite(self):
        with mock.patch.object(md, "_run_suite",
                               side_effect=[(True, 300, []), (False, 300, ["t"])]) as suite:
            code, out = _run_main(["--group", "core", "--only", "G01"])
        self.assertEqual(code, 0)
        self.assertIn("杀死 1", out)
        self.assertEqual(suite.call_args[0][0].name, "core")

    def test_unknown_group_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--group", "nope"])
        self.assertEqual(ctx.exception.code, 2)


class TestExternalSpec(unittest.TestCase):
    """--target/--tests/--spec 外部清单模式。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _spec(self, items):
        path = os.path.join(self.tmp, "spec.json")
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(items, stream, ensure_ascii=False)
        return path

    def test_requires_target_and_tests(self):
        spec = self._spec([{"id": "X01", "desc": "d", "old": "a", "new": "b"}])
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--spec", spec])
        self.assertIn("--target", str(ctx.exception))

    def test_missing_target_file_rejected(self):
        spec = self._spec([{"id": "X01", "desc": "d", "old": "a", "new": "b"}])
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--spec", spec, "--target", os.path.join(self.tmp, "nope.py"),
                       "--tests", "test_dump"])
        self.assertIn("不存在", str(ctx.exception))

    def test_entry_missing_field_rejected(self):
        spec = self._spec([{"id": "X01", "desc": "d", "old": "a"}])
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--spec", spec, "--target", md.SRC_PATH, "--tests", "test_dump"])
        self.assertIn("new", str(ctx.exception))

    def test_spec_must_be_non_empty_list(self):
        spec = self._spec({"id": "X01"})
        with self.assertRaises(SystemExit):
            _run_main(["--spec", spec, "--target", md.SRC_PATH, "--tests", "test_dump"])

    def test_blank_tests_rejected(self):
        spec = self._spec([{"id": "X01", "desc": "d", "old": "a", "new": "b"}])
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--spec", spec, "--target", md.SRC_PATH, "--tests", " , "])
        self.assertIn("用例模块", str(ctx.exception))

    def test_occurrence_mismatch_aborts_before_run(self):
        """外部清单里出现多次替换点, 应在跑基线前中止。"""
        spec = self._spec([{"id": "X01", "desc": "d", "old": "return None",
                            "new": "return 1"}])
        with mock.patch.object(md, "_run_suite") as suite:
            with self.assertRaises(SystemExit):
                _run_main(["--spec", spec, "--target", md.SRC_PATH,
                           "--tests", "test_dump"])
        suite.assert_not_called()

    def test_external_run_end_to_end(self):
        """真实执行最小外部清单: 一个被杀死 + 一个等价存活, 得分 100%。"""
        spec = self._spec([
            {"id": "X01", "desc": "ASCII 替换符", "old": 'else "." for b in chunk',
             "new": 'else "?" for b in chunk'},
            {"id": "X02", "desc": "等价: 提示条件", "old": "if len(shown) < len(data):",
             "new": "if len(shown) != len(data):", "equivalent": True},
        ])
        code, out = _run_main(["--spec", spec, "--target", md.SRC_PATH,
                               "--tests", "test_dump"])
        self.assertEqual(code, 0)
        self.assertIn("杀死 1", out)
        self.assertIn("等价存活 1", out)
        self.assertIn("pcap_analyzer.py", out)
        self.assertIn("变异得分 100.0%", out)

    def test_target_without_spec_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--target", md.SRC_PATH])
        self.assertIn("--spec", str(ctx.exception))

    def test_tests_without_spec_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--tests", "test_dump"])
        self.assertIn("--spec", str(ctx.exception))

    def test_duplicate_ids_rejected(self):
        spec = self._spec([
            {"id": "X01", "desc": "a", "old": "else \".\" for b in chunk",
             "new": "else \"?\" for b in chunk"},
            {"id": "X01", "desc": "b", "old": "if len(shown) < len(data):",
             "new": "if len(shown) != len(data):"},
        ])
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--spec", spec, "--target", md.SRC_PATH, "--tests", "test_dump"])
        self.assertIn("重复编号", str(ctx.exception))

    def test_identical_old_and_new_rejected(self):
        spec = self._spec([{"id": "X01", "desc": "无变化", "old": "return None",
                            "new": "return None"}])
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--spec", spec, "--target", md.SRC_PATH, "--tests", "test_dump"])
        self.assertIn("不会产生任何变异", str(ctx.exception))

    def test_list_with_spec_does_not_touch_modules(self):
        spec = self._spec([{"id": "X01", "desc": "d", "old": "return 1", "new": "return 2"}])
        before = sys.modules.get("pcap_analyzer")
        with mock.patch.object(md, "_run_suite") as suite:
            code, out = _run_main(["--list", "--spec", spec, "--target", md.SRC_PATH,
                                   "--tests", "test_dump"])
        self.assertEqual(code, 0)
        self.assertIn("X01", out)
        self.assertIn("test_dump", out)
        suite.assert_not_called()
        self.assertIs(sys.modules.get("pcap_analyzer"), before)

    def test_equivalent_flag_accepts_truthy_values(self):
        """equivalent 字段按真值解释: 字符串/1 与 true 等价。"""
        spec = self._spec([
            {"id": "X01", "desc": "等价(字符串真值)", "old": "if len(shown) < len(data):",
             "new": "if len(shown) != len(data):", "equivalent": "yes"},
            {"id": "X02", "desc": "非等价(0)", "old": "else \".\" for b in chunk",
             "new": "else \"?\" for b in chunk", "equivalent": 0},
        ])
        with mock.patch.object(md, "_run_suite",
                               side_effect=[(True, 10, []), (True, 10, []),
                                            (False, 10, ["t"])]):
            code, out = _run_main(["--spec", spec, "--target", md.SRC_PATH,
                                   "--tests", "test_dump"])
        self.assertEqual(code, 0)
        self.assertIn("杀死 1", out)
        self.assertIn("等价存活 1", out)

    def test_external_target_module_restored_to_pristine(self):
        """外部目标的模块名取文件名主干, 收尾后只留下原始实现。"""
        target = os.path.join(self.tmp, "foo.py")
        with open(target, "w", encoding="utf-8") as stream:
            stream.write("def f():\n    return 1\n")
        spec = self._spec([{"id": "X01", "desc": "改返回值", "old": "return 1",
                            "new": "return 2"}])
        with mock.patch.object(md, "_run_suite",
                               side_effect=[(True, 10, []), (False, 10, ["t"])]):
            code, out = _run_main(["--spec", spec, "--target", target,
                                   "--tests", "test_dump"])
        self.assertEqual(code, 0)
        self.assertIn("foo.py", out)
        self.assertEqual(sys.modules["foo"].f(), 1)
        self.assertIn("pcap_analyzer", sys.modules)

    def test_core_group_accepts_lowercase_only(self):
        with mock.patch.object(md, "_run_suite",
                               side_effect=[(True, 300, []), (False, 300, ["t"])]):
            code, out = _run_main(["--group", "core", "--only", "g01"])
        self.assertEqual(code, 0)
        self.assertIn("杀死 1", out)

    def test_missing_spec_file_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--spec", os.path.join(self.tmp, "nope.json"),
                       "--target", md.SRC_PATH, "--tests", "test_dump"])
        self.assertIn("清单不存在", str(ctx.exception))

    def test_malformed_spec_json_rejected(self):
        path = os.path.join(self.tmp, "bad.json")
        with open(path, "w", encoding="utf-8") as stream:
            stream.write("{not json]")
        with self.assertRaises(SystemExit) as ctx:
            _run_main(["--spec", path, "--target", md.SRC_PATH, "--tests", "test_dump"])
        self.assertIn("不是合法 JSON", str(ctx.exception))

    def test_relative_target_resolved_to_absolute(self):
        spec = self._spec([{"id": "X01", "desc": "d", "old": "return 1", "new": "return 2"}])
        args = argparse.Namespace(spec=spec, target="pcap_analyzer.py",
                                 tests="test_dump", group="dump")
        cwd = os.getcwd()
        try:
            os.chdir(md.ROOT)
            group, mutants = md._spec_group(args)
        finally:
            os.chdir(cwd)
        self.assertEqual(group.src_path, md.SRC_PATH)
        self.assertEqual(group.module_name, "pcap_analyzer")
        self.assertEqual(len(mutants), 1)

    def test_unknown_extra_keys_ignored(self):
        spec = self._spec([{"id": "X01", "desc": "d", "old": "return 1", "new": "return 2",
                            "note": "多余字段"}])
        with mock.patch.object(md, "_run_suite",
                               side_effect=[(True, 10, []), (False, 10, ["t"])]):
            code, out = _run_main(["--spec", spec, "--target", md.SRC_PATH,
                                   "--tests", "test_dump"])
        self.assertEqual(code, 0)
        self.assertIn("X01 杀死", out)

    def test_duplicate_wanted_ids_collapse(self):
        selected = md._select(md.MUTANTS, "M05, M05 ,m05")
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].mid, "M05")

    def test_list_with_empty_mutants_prints_header_only(self):
        with mock.patch.object(md, "MUTANTS", []):
            code, out = _run_main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("组 dump", out)
        self.assertNotIn("变异体", out)


class TestMultiModuleSuite(unittest.TestCase):
    """_run_suite 支持一次性跑多个用例模块。"""

    def _write(self, tmpdir, name, body):
        path = os.path.join(tmpdir, name + ".py")
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(body)
        return path

    def test_failure_from_second_module_is_captured(self):
        tmpdir = tempfile.mkdtemp()
        self._write(tmpdir, "_a_green",
                    "import unittest\nclass T(unittest.TestCase):\n"
                    "    def test_ok(self):\n        pass\n")
        self._write(tmpdir, "_b_red",
                    "import unittest\nclass T(unittest.TestCase):\n"
                    "    def test_bad(self):\n        self.fail('boom')\n")
        previous = md.GROUPS["dump"].test_modules
        sys.path.insert(0, tmpdir)
        md.GROUPS["dump"].test_modules = ("_a_green", "_b_red")
        try:
            ok, total, caught = md._run_suite()
        finally:
            md.GROUPS["dump"].test_modules = previous
            sys.path.remove(tmpdir)
            for name in ("_a_green", "_b_red"):
                sys.modules.pop(name, None)
            shutil.rmtree(tmpdir, ignore_errors=True)
        self.assertFalse(ok)
        self.assertEqual(total, 2)
        self.assertEqual(caught, ["test_bad"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
