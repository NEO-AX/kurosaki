"""すり抜け試験を回帰テストとして固定する。

`bypass_drill.py` の結果表を期待値として持つ。ゲートが緩んだら（止まっていた経路が
止まらなくなったら）ここで落ちる。逆に、残存リスクを勝手に「解消した」と書き換える
こともできない（期待値との不一致で落ちる）。
"""

import os
import sys
import unittest

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOL_ROOT)
sys.path.insert(0, os.path.join(TOOL_ROOT, "tests"))

import bypass_drill                       # noqa: E402

# 番号 → (止まるべきか, 止まる場所に含まれる語)
EXPECTED = {
    1: (True, "pre-commit"),
    2: (True, "pre-push"),
    3: (False, "CI"),                     # ローカルは外せる。CIが最終防衛線
    4: (False, "D7-01"),                  # フック改変。commit は通るが監査が検知
    5: (True, "pre-push"),
    6: (True, "pre-commit"),
    7: (True, "pre-commit"),
    8: (True, "pre-commit"),
    9: (True, "pre-push"),
    "9b": (False, "D3-01"),               # 基盤ごと消せば commit/push は通る。監査が不在を検知
    10: (True, "D7-03"),
}


class TestBypassDrill(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {r["no"]: r for r in bypass_drill.drill()}

    def test_all_scenarios_ran(self):
        self.assertEqual(set(self.results), set(EXPECTED),
                         "試験の項目が期待表と食い違う（項目を増やしたら期待表も更新すること）")

    def test_each_scenario_stops_where_expected(self):
        for no, (should_stop, where) in EXPECTED.items():
            with self.subTest(scenario=no):
                r = self.results[no]
                if should_stop:
                    self.assertNotEqual(r["exit"], 0,
                                        f"#{no} が止まらなくなった: {r['scenario']}")
                else:
                    self.assertEqual(r["exit"], 0,
                                     f"#{no} の前提が変わった（止まるようになった）: {r['scenario']}")
                self.assertIn(where, r["stopped_at"],
                              f"#{no} の停止点が変わった: {r['stopped_at']}")

    def test_residual_risks_are_exactly_three_and_documented(self):
        leaks = sorted(str(no) for no, (stop, _w) in EXPECTED.items() if not stop)
        self.assertEqual(leaks, ["3", "4", "9b"])
        doc = os.path.join(TOOL_ROOT, "docs", "BYPASS_DRILL.md")
        self.assertTrue(os.path.isfile(doc), "残存リスクの文書が無い")
        with open(doc, encoding="utf-8") as fh:
            body = fh.read()
        for no in leaks:
            self.assertIn(f"#{no}", body, f"残存リスク #{no} が文書に書かれていない")


if __name__ == "__main__":
    unittest.main(verbosity=2)
