"""Layer 1 の検証。

ここで守っているのは3つ。
1. 架空PIIを**必ず**検出する（見逃しゼロの実証）
2. 日本語の文章を氏名と誤認しない（運用が成立することの実証）
3. **出力に生のPIIが混ざらない**（スキャナ自身が漏洩経路にならないことの実証）
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(TOOL_ROOT, "tests", "fixtures")
sys.path.insert(0, TOOL_ROOT)

from kurosaki import allowlist as allowlist_mod            # noqa: E402
from kurosaki.report import exit_code, render_json, render_text  # noqa: E402
from kurosaki.rules import looks_like_card, luhn_ok         # noqa: E402
from kurosaki.scan import Scanner, scan_text                # noqa: E402

# フィクスチャに入れた架空値。**この文字列が出力に現れたら不合格。**
RAW_PII = [
    "架空 花子", "虚構 太郎", "仮名 次郎", "仮想 三郎", "想像 四郎",
    "カクウ ハナコ", "キョコウ タロウ",
    "hanako@kasou-oubo.co.jp", "taro@kasou-oubo.co.jp", "jiro@kasou-unei.co.jp",
    "saburo@kasou-oubo.co.jp", "shiro@kasou-oubo.co.jp",
    "090-1234-5678", "03-1234-5678", "08098765432", "080-9876-5432", "090-1111-2222",
    "A2019123", "B2020456",
    "東京都渋谷区神宮前1-2-3", "神奈川県横浜市西区1-2",
    "4111 1111 1111 1111", "4111111111111111",
    "1998-04-01", "1999年12月31日",
]

PII_FIXTURES = ["pii_seed.sql", "pii_dump.sql", "pii_applicants.csv", "pii_seed.ts", "pii_card.txt"]
CLEAN_FIXTURES = ["clean_seed.sql", "clean_docs.md", "clean_reserved.txt"]


def scan_file(path, allow=None):
    sc = Scanner(os.path.dirname(path), allow=allow)
    return sc.scan_paths([path])


def scan_string(name, text):
    """相対パスの分類（重点パスか否か）を正しく試すため、repo基準の相対パスで走査する。"""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        sc = Scanner(d)
        return sc.scan_paths([name])


class TestDetection(unittest.TestCase):
    def test_pii_fixtures_all_fail(self):
        for name in PII_FIXTURES:
            with self.subTest(fixture=name):
                res = scan_file(os.path.join(FIX, name))
                self.assertGreater(res.count("Critical"), 0, f"{name} で Critical が出ていない")
                self.assertEqual(exit_code(res), 1, f"{name} で終了コードが1でない")

    def test_expected_rules_per_fixture(self):
        expect = {
            "pii_seed.sql": {"JP_PERSON_NAME", "EMAIL", "JP_PHONE", "BIRTHDATE", "JP_ADDRESS", "STUDENT_ID"},
            "pii_dump.sql": {"JP_PERSON_NAME", "EMAIL", "JP_PHONE"},
            "pii_applicants.csv": {"JP_PERSON_NAME", "EMAIL", "JP_PHONE", "BIRTHDATE", "JP_ADDRESS", "STUDENT_ID"},
            "pii_seed.ts": {"JP_PERSON_NAME", "EMAIL", "JP_PHONE"},
            "pii_card.txt": {"CREDIT_CARD"},
        }
        for name, rules in expect.items():
            with self.subTest(fixture=name):
                got = {f.rule for f in scan_file(os.path.join(FIX, name)).active}
                self.assertTrue(rules <= got, f"{name}: 期待したルールが出ていない 不足={rules - got}")

    def test_clean_fixtures_do_not_block(self):
        for name in CLEAN_FIXTURES:
            with self.subTest(fixture=name):
                res = scan_file(os.path.join(FIX, name))
                self.assertEqual(res.blocking, 0,
                                 f"{name} で誤検知が出た: {[(f.rule, f.line, f.why) for f in res.active]}")

    def test_japanese_prose_is_not_a_name(self):
        text = "-- 山田 太郎 について書いた設計コメント。氏名は入れない。\n" \
               "INSERT INTO selection_steps (id, name) VALUES (1, '書類選考');\n"
        res = scan_string("clean.sql", text)
        self.assertEqual(res.blocking, 0, f"文章を氏名と誤認した: {[(f.rule, f.why) for f in res.active]}")

    def test_uuid_is_not_a_credit_card(self):
        text = "assert.equal(await getPerson(db, '00000000-0000-0000-0000-000000000001'), null)\n"
        res = scan_string("t.ts", text)
        self.assertNotIn("CREDIT_CARD", {f.rule for f in res.active})

    def test_card_requires_iin_and_length(self):
        self.assertTrue(looks_like_card("4111111111111111"))
        self.assertTrue(luhn_ok("00000000000000018"))          # Luhnは通るが
        self.assertFalse(looks_like_card("00000000000000018"))  # カードではない

    def test_nul_byte_cannot_hide_pii(self):
        """NULを混ぜて走査を飛ばす回避路が塞がれていること。"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "seed_evasion.sql")
            with open(p, "wb") as fh:
                fh.write("INSERT INTO applicants (氏名, email) VALUES ".encode())
                fh.write(b"\x00")
                fh.write("('架空 花子', 'hanako@kasou-oubo.co.jp');\n".encode())
            res = scan_file(p)
            self.assertGreater(res.count("Critical"), 0, "NUL混入で検査を飛ばせてしまう")

    def test_reserved_domains_are_not_reported(self):
        res = scan_string("t.txt", "email: a@example.com\nemail: b@sub.example.org\nemail: c@x.test\n")
        self.assertEqual(len(res.active), 0)

    def test_critical_path_elevates_severity(self):
        body = 'const x = { name: "架空 花子" }\n'
        a = scan_string("app/page.ts", body)
        b = scan_string("seed_data.ts", body)
        self.assertEqual({f.severity for f in a.active}, {"High"})
        self.assertEqual({f.severity for f in b.active}, {"Critical"})


class TestOutputSafety(unittest.TestCase):
    """スキャナ自身が漏洩経路にならないこと。CI ログもローカル出力も同じ。"""

    def _outputs(self, path):
        res = scan_file(path)
        meta = {"mode": "test", "repo": os.path.dirname(path)}
        return [render_text(res, meta), render_json(res, meta)]

    def test_no_raw_pii_in_any_output(self):
        for name in PII_FIXTURES:
            for out in self._outputs(os.path.join(FIX, name)):
                for raw in RAW_PII:
                    self.assertNotIn(raw, out, f"{name}: 出力に生値が混ざった → {raw[:2]}…")

    def test_evidence_is_one_char_plus_stars(self):
        for name in PII_FIXTURES:
            for f in scan_file(os.path.join(FIX, name)).findings:
                self.assertRegex(f.evidence, r"^(?:.\*\*\*|\*\*\*)$",
                                 f"{name}: マスク形式が崩れている ({f.evidence!r})")

    def test_cli_stdout_has_no_raw_pii(self):
        cmd = [os.path.join(TOOL_ROOT, "bin", "kurosaki"), "scan", "--paths"] + \
              [os.path.join(FIX, n) for n in PII_FIXTURES]
        for fmt in ("text", "json"):
            proc = subprocess.run(cmd + ["--format", fmt], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, "CLI が FAIL を返していない")
            blob = proc.stdout + proc.stderr
            for raw in RAW_PII:
                self.assertNotIn(raw, blob, f"CLI({fmt}) の出力に生値が混ざった")


class TestAllowlist(unittest.TestCase):
    def _write(self, body):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "allowlist.yml")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body)
        return allowlist_mod.load(p)

    def test_missing_approver_is_ignored(self):
        al = self._write("allow:\n  - path: '*'\n    reason: 理由だけある\n")
        self.assertEqual(al.entries, [])
        self.assertTrue(al.problems)

    def test_expired_entry_is_ignored(self):
        al = self._write("allow:\n  - path: '*'\n    reason: r\n    approved_by: h\n    expires: 2020-01-01\n")
        self.assertIsNone(al.matches("x.sql", "EMAIL", "abc"))

    def test_unparsable_disables_everything(self):
        al = self._write("allow:\n\t- path: x\n")
        self.assertEqual(al.entries, [])
        self.assertTrue(al.problems)

    def test_unknown_key_disables_everything(self):
        al = self._write("allow:\n  - path: '*'\n    reason: r\n    approved_by: h\nsomething_else: 1\n")
        self.assertEqual(al.entries, [])

    def test_valid_entry_suppresses_and_passes(self):
        al = self._write("allow:\n  - path: '*pii_seed.sql'\n    rules: ['*']\n    fingerprints: ['*']\n"
                         "    reason: 検出試験用の架空データ\n    approved_by: 'human: test'\n")
        res = scan_file(os.path.join(FIX, "pii_seed.sql"), allow=al)
        self.assertEqual(res.blocking, 0)
        self.assertGreater(sum(1 for f in res.findings if f.allowlisted), 0)
        self.assertEqual(exit_code(res), 0)

    def test_faker_claim_without_faker_does_not_relax(self):
        al = self._write("faker_ja_jp_paths:\n  - '*pii_seed.sql'\n")
        res = scan_file(os.path.join(FIX, "pii_seed.sql"), allow=al)
        if allowlist_mod.faker_ja_jp_corpus() is None:
            self.assertGreater(res.blocking, 0, "Faker未導入なのに緩和が効いてしまった")
            self.assertTrue(any("Faker" in n for n in res.notes))


if __name__ == "__main__":
    unittest.main(verbosity=2)
