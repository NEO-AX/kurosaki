"""体制監査の検証。

方針: 欠陥全部入りの合成リポジトリと、正しく導入した合成リポジトリの2個に対し、
**全手続を当てて**「壊れた側で所見が出る」「健全な側で出ない」を固定する。
手続を足したら、この表に1行足さないとテストが落ちる（＝黙って追加できない）。
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOL_ROOT)
sys.path.insert(0, os.path.join(TOOL_ROOT, "tests"))

import fabricate                                            # noqa: E402
from kurosaki import opinion                                # noqa: E402
from kurosaki.checks import base as checks_base             # noqa: E402
from kurosaki.checks import data as _d, gates as _g, independence as _i, structure as _s  # noqa: E402,F401
from kurosaki.rules import CRITICAL, HIGH, LOW, MEDIUM      # noqa: E402

# 手続ID → 壊れた側で出るべき最低の重大度（None = 所見が出なくてよい手続）
EXPECT_ON_BROKEN = {
    "D1-01": HIGH, "D1-02": None, "D2-01": HIGH, "D2-02": CRITICAL,
    "D3-01": HIGH, "D3-02": HIGH, "D3-03": HIGH, "D3-04": CRITICAL,
    "D3-05": None, "D3-06": None,
    "D5-01": HIGH, "D5-02": HIGH, "D5-03": HIGH,
    "D6-01": CRITICAL, "D6-02": CRITICAL,
    "D7-01": HIGH, "D7-02": HIGH, "D7-03": CRITICAL,
}
_RANK = {CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0}


class TestAuditProcedures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        cls.broken = fabricate.broken(cls.root)
        cls.healthy = fabricate.healthy(cls.root)
        cls.res_broken = {r.id: r for r in checks_base.run(checks_base.Context(cls.broken, TOOL_ROOT))}
        cls.res_healthy = {r.id: r for r in checks_base.run(checks_base.Context(cls.healthy, TOOL_ROOT))}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_every_procedure_is_covered_by_this_table(self):
        """手続を足したら、この表にも足させる（黙って未検証の手続を増やせない）。"""
        registered = {p["id"] for p in checks_base.registry()}
        self.assertEqual(registered, set(EXPECT_ON_BROKEN),
                         f"表と登録手続が食い違う: 表に無い={registered - set(EXPECT_ON_BROKEN)} / "
                         f"登録に無い={set(EXPECT_ON_BROKEN) - registered}")

    def test_broken_repo_triggers_expected_findings(self):
        for pid, min_sev in EXPECT_ON_BROKEN.items():
            if min_sev is None:
                continue
            with self.subTest(procedure=pid):
                r = self.res_broken[pid]
                self.assertTrue(r.observations, f"{pid}: 壊れたリポジトリで所見が出ていない（{r.examined or r.reason}）")
                worst = max(_RANK[o.severity] for o in r.observations)
                self.assertGreaterEqual(worst, _RANK[min_sev],
                                        f"{pid}: 期待した重大度に達していない（期待 {min_sev} 以上）")

    def test_healthy_repo_has_no_blocking_findings(self):
        bad = [(r.id, o.severity, o.fact) for r in self.res_healthy.values()
               for o in r.observations if o.severity in (CRITICAL, HIGH)]
        self.assertEqual(bad, [], f"健全なリポジトリで Critical/High が出た: {bad}")

    def test_opinions(self):
        self.assertEqual(opinion.form(list(self.res_broken.values()))["verdict"], "不適正")
        self.assertEqual(opinion.form(list(self.res_healthy.values()))["verdict"], "適正")

    def test_every_done_procedure_states_what_it_examined(self):
        for label, results in (("broken", self.res_broken), ("healthy", self.res_healthy)):
            for r in results.values():
                with self.subTest(repo=label, procedure=r.id):
                    if r.status == "done":
                        self.assertTrue(r.examined.strip(), f"{r.id}: 何を見たかの記録が無い")
                    else:
                        self.assertTrue((r.reason or "").strip(), f"{r.id}: 実施不能の理由が無い")

    def test_no_raw_pii_or_secret_in_audit_output(self):
        """監査出力に架空PII・架空シークレットの生値が混ざらないこと。"""
        raw = ["架空 花子", "hanako@kasou-oubo.co.jp", "090-1234-5678", "東京都渋谷区神宮前1-2-3",
               "AKIA" + "Z" * 16, "sk-ant-" + "0" * 24]
        proc = subprocess.run([os.path.join(TOOL_ROOT, "bin", "kurosaki"), "audit",
                               "--repo", self.broken, "--no-save"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)
        blob = proc.stdout + proc.stderr
        for v in raw:
            self.assertNotIn(v, blob, f"監査出力に生値が混ざった: {v[:4]}…")

    def test_exit_codes(self):
        k = os.path.join(TOOL_ROOT, "bin", "kurosaki")
        self.assertEqual(subprocess.run([k, "audit", "--repo", self.broken, "--no-save", "--quiet"]).returncode, 1)
        self.assertEqual(subprocess.run([k, "audit", "--repo", self.healthy, "--no-save", "--quiet"]).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
