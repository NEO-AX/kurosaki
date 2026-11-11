"""調書のハッシュ連鎖（D7-03）の並び順。

誤検知: ファイル名順に並べると、衝突時の `-01` が無印より前に来る・head（コミットハッシュ）が
時系列に並ばない、の2つで、改ざんが無くても連鎖が切れて見えた（実在の被監査リポジトリで Critical 28 件）。
ここでは「名前の並びが時系列と食い違っても切れ目は0件」と「本物の改ざん・欠落・分岐は
今までどおり切れ目として出る」の両方を固定する。
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOL_ROOT)

from kurosaki import workpaper  # noqa: E402

REPORTS = workpaper.REPORT_DIR


def _clock(*stamps):
    """save() の保存時刻を順に返す偽の時計。"""
    it = iter(stamps)

    class _DT(workpaper.datetime):
        @classmethod
        def now(cls, tz=None):
            return workpaper.datetime.fromisoformat(next(it))
    return mock.patch.object(workpaper, "datetime", _DT)


class ChainOrderTest(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def _save(self, head, n=1):
        return [workpaper.save(self.repo, {"head": head, "observations": [], "i": i}) for i in range(n)]

    def _names(self):
        return [os.path.basename(i["path"]) for i in workpaper.history(self.repo)]

    def _load(self, path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def _dump(self, path, data):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)

    # --- 誤検知が消える例 -------------------------------------------------------
    def test_numbered_copies_of_same_head_are_not_a_break(self):
        """同じ head で3回保存（無印・-01・-02）。名前順では -01 が無印より先に来る。"""
        self._save("1a2b3c4", 3)
        self.assertEqual(workpaper.verify_chain(self.repo), [])
        self.assertEqual(self._names(), ["%s-1a2b3c4.json" % self._day(),
                                         "%s-1a2b3c4-01.json" % self._day(),
                                         "%s-1a2b3c4-02.json" % self._day()])

    def test_later_head_sorting_earlier_by_name_is_not_a_break(self):
        """後から保存した調書の head が辞書順で前（7d8e9f0 の後に 5c6d7e8）。"""
        self._save("7d8e9f0")
        self._save("5c6d7e8")
        self._save("1a2b3c4")
        self.assertEqual(workpaper.verify_chain(self.repo), [])
        self.assertEqual([n.split("-", 3)[3] for n in self._names()],
                         ["7d8e9f0.json", "5c6d7e8.json", "1a2b3c4.json"])

    def test_same_second_saves_follow_prev_digest(self):
        """保存時刻が秒まで同じでも、prev_digest の指す順に並ぶ。"""
        with _clock(*["2026-08-19T02:32:01+00:00"] * 3):
            self._save("fff0000")
            self._save("aaa0000")
            self._save("0000000")
        self.assertEqual(workpaper.verify_chain(self.repo), [])
        self.assertEqual([n[11:18] for n in self._names()], ["fff0000", "aaa0000", "0000000"])

    def test_renaming_files_does_not_change_the_verdict(self):
        """名前を入れ替えても中身が無傷なら切れ目は出ない（並びは名前に頼らない）。"""
        a, b = self._save("1111111")[0], self._save("2222222")[0]
        tmp = a + ".tmp"
        os.rename(a, tmp); os.rename(b, a); os.rename(tmp, b)
        self.assertEqual(workpaper.verify_chain(self.repo), [])

    def test_save_links_to_the_chain_tip_not_the_last_name(self):
        """save() の prev は名前順の最後ではなく、連鎖の先端（最後に保存した調書）。"""
        first = self._save("1a2b3c4", 2)
        third = self._save("1a2b3c4")[0]
        tip = self._load(first[1])["self_digest"]
        self.assertEqual(self._load(third)["prev_digest"], tip)

    # --- 本物を逃さない例 -------------------------------------------------------
    def test_content_rewrite_without_rehash_is_detected(self):
        paths = self._save("1a2b3c4", 3)
        d = self._load(paths[1]); d["opinion"] = "適正"; self._dump(paths[1], d)
        problems = workpaper.verify_chain(self.repo)
        self.assertTrue(any("1a2b3c4-01.json" in p and "自己ハッシュ不一致" in p for p in problems), problems)

    def test_content_rewrite_with_recomputed_digest_breaks_the_chain(self):
        """中身を書き換えて自己ハッシュも計算し直した偽物は、次の調書との連鎖で切れる。"""
        paths = self._save("1a2b3c4", 3)
        d = self._load(paths[1]); d["opinion"] = "適正"
        body = {k: v for k, v in d.items() if k != "self_digest"}
        d["self_digest"] = workpaper._digest(body)
        self._dump(paths[1], d)
        problems = workpaper.verify_chain(self.repo)
        self.assertTrue(any("連鎖が切れている" in p for p in problems), problems)

    def test_deleted_middle_workpaper_is_detected(self):
        """途中の調書を消すと、次の調書の prev が宙に浮いて切れ目になる（git revert で調書が消えたときと同じ形）。"""
        with _clock("2026-08-22T01:32:14+00:00", "2026-08-23T06:04:28+00:00", "2026-08-23T07:42:02+00:00"):
            self._save("2468ace")
            mid = self._save("3579bdf")[0]
            self._save("4680bdf")
        os.remove(mid)
        problems = workpaper.verify_chain(self.repo)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("4680bdf.json: 直前の調書とのハッシュ連鎖が切れている", problems[0])

    def test_fork_is_detected(self):
        """同じ親を指す調書が2本（分岐）なら、どちらかが切れ目として出る。"""
        a = self._save("aaaaaaa")[0]
        b = self._save("bbbbbbb")[0]
        d = self._load(b)
        d.update({"head": "ccccccc", "observations": ["別の枝"]})
        d["saved_at"] = "2099-01-01T00:00:00+00:00"
        d["prev_digest"] = self._load(a)["self_digest"]
        body = {k: v for k, v in d.items() if k != "self_digest"}
        d["self_digest"] = workpaper._digest(body)
        self._dump(os.path.join(os.path.dirname(b), "2099-01-01-ccccccc.json"), d)
        self.assertEqual(len(workpaper.verify_chain(self.repo)), 1)

    def test_unreadable_workpaper_is_reported(self):
        self._save("1a2b3c4", 2)
        with open(os.path.join(self.repo, REPORTS, "2026-01-01-broken.json"), "w") as fh:
            fh.write("{not json")
        problems = workpaper.verify_chain(self.repo)
        self.assertTrue(any("読めない" in p for p in problems), problems)

    def _day(self):
        return workpaper.history(self.repo)[0]["data"]["saved_at"][:10]


if __name__ == "__main__":
    unittest.main(verbosity=2)
