"""`.audit/allowlist.yml` の読み込み。

設計の要点:
- **fail closed**。書式が読めない、理由が無い、承認者が無い、期限切れ —— どれも
  「除外しない」側へ倒す。allowlist は監査を通すための抜け道になり得るので、
  不備は緩和ではなく無効化として扱う。
- `pyyaml` が入っていない環境で動く。標準ライブラリだけの最小パーサを持ち、
  対応しない書式は**エラーにする**（黙って読み飛ばさない）。
- 値そのものは書かせない。指紋（sha256先頭16桁）で指す。
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import re
from dataclasses import dataclass, field

_ALLOWED_TOP = {"version", "allow", "faker_ja_jp_paths"}
_ALLOWED_ENTRY = {"path", "rules", "fingerprints", "reason", "approved_by", "expires", "note"}


class AllowlistError(Exception):
    pass


# ---------------------------------------------------------------- 最小YAML

def _parse_scalar(s: str):
    s = s.strip()
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(x) for x in inner.split(",")]
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    if s in ("true", "True", "yes"):
        return True
    if s in ("false", "False", "no"):
        return False
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


def _mini_yaml(text: str):
    """`key: value` / `key:` ＋ `- item` / `- key: value` だけを解釈する。

    ブロックスカラー(`|`, `>`)、アンカー、複数文書、フロー辞書は**未対応で例外**。
    allowlist にそれらを使う必要はなく、黙って解釈を誤るより止める方が安全。
    """
    root: dict = {}
    stack = [(-1, root)]
    lines = text.split("\n")
    for no, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = raw.split(" #", 1)[0].rstrip() if " #" in raw else raw.rstrip()
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if "\t" in raw:
            raise AllowlistError(f"{no}行目: タブは使えない（インデントは半角空白）")
        if body.endswith("|") or body.endswith(">") or body.startswith("&") or body.startswith("*") or body.startswith("---"):
            raise AllowlistError(f"{no}行目: 未対応の YAML 記法（`{body}`）。allowlist では使わない")

        while stack and indent <= stack[-1][0] and len(stack) > 1:
            stack.pop()
        parent = stack[-1][1]

        if body.startswith("- "):
            item = body[2:].strip()
            if not isinstance(parent, list):
                raise AllowlistError(f"{no}行目: リスト項目の親がリストではない")
            if ":" in item and not item.startswith(("'", '"')):
                k, _, v = item.partition(":")
                d = {k.strip(): _parse_scalar(v)} if v.strip() else {k.strip(): None}
                parent.append(d)
                stack.append((indent, d))
            else:
                parent.append(_parse_scalar(item))
            continue

        if ":" not in body:
            raise AllowlistError(f"{no}行目: `key: value` の形になっていない（`{body}`）")
        k, _, v = body.partition(":")
        k = k.strip()
        if v.strip():
            if not isinstance(parent, dict):
                raise AllowlistError(f"{no}行目: `{k}` の親が辞書ではない")
            parent[k] = _parse_scalar(v)
        else:
            # 次の行のインデントで、辞書かリストかを決める
            nxt = None
            for future in lines[no:]:
                if future.strip() and not future.lstrip().startswith("#"):
                    nxt = future
                    break
            child = [] if (nxt and nxt.strip().startswith("- ")) else {}
            if not isinstance(parent, dict):
                raise AllowlistError(f"{no}行目: `{k}` の親が辞書ではない")
            parent[k] = child
            stack.append((indent, child))
    return root


def _load_mapping(text: str) -> dict:
    try:
        import yaml  # あれば使う
    except Exception:
        return _mini_yaml(text)
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise AllowlistError("allowlist の最上位は辞書でなければならない")
    return data


# ---------------------------------------------------------------- Faker 照合

def faker_ja_jp_corpus():
    """Faker(ja_JP) が生成しうる姓・名の集合。入っていなければ None。

    None のときは Faker 由来という主張を**検証できない**ので、緩和は適用しない。
    「Fakerで作ったつもり」という自己申告を根拠にしないため（P3）。
    """
    try:
        from faker.providers.person.ja_JP import Provider  # type: ignore
    except Exception:
        return None
    corpus = set()
    for attr in ("last_names", "first_names", "first_names_male", "first_names_female",
                 "last_kana_names", "first_kana_names", "first_kana_names_male",
                 "first_kana_names_female", "last_romanized_names", "first_romanized_names"):
        vals = getattr(Provider, attr, None)
        if not vals:
            continue
        try:
            corpus |= {str(v) for v in vals}
        except TypeError:
            pass
    return corpus or None


def is_faker_name(value: str, corpus) -> bool:
    if not corpus:
        return False
    parts = [p for p in re.split(r"[ 　]+", str(value).strip()) if p]
    return bool(parts) and all(p in corpus for p in parts)


# ---------------------------------------------------------------- 本体

@dataclass
class Entry:
    path: str
    rules: tuple
    fingerprints: tuple
    reason: str
    approved_by: str
    expires: str | None = None
    disabled_reason: str | None = None

    def active(self, today: _dt.date) -> bool:
        if self.disabled_reason:
            return False
        if self.expires:
            try:
                if _dt.date.fromisoformat(str(self.expires)) < today:
                    return False
            except ValueError:
                return False
        return True


@dataclass
class Allowlist:
    entries: list = field(default_factory=list)
    faker_paths: tuple = ()
    problems: list = field(default_factory=list)
    source: str | None = None

    def matches(self, relpath: str, rule: str, fp: str, today=None) -> Entry | None:
        today = today or _dt.date.today()
        for e in self.entries:
            if not e.active(today):
                continue
            if not fnmatch.fnmatch(relpath, e.path):
                continue
            if "*" not in e.rules and rule not in e.rules:
                continue
            if "*" not in e.fingerprints and fp not in e.fingerprints:
                continue
            return e
        return None

    def faker_allowed(self, relpath: str) -> bool:
        return any(fnmatch.fnmatch(relpath, p) for p in self.faker_paths)


def load(path) -> Allowlist:
    """読めない allowlist は空扱い＋problem 記録。除外は一切効かせない。"""
    al = Allowlist(source=str(path))
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return al
    except OSError as exc:
        al.problems.append(f"allowlist を読めない: {exc}")
        return al

    try:
        data = _load_mapping(text)
    except (AllowlistError, Exception) as exc:  # noqa: BLE001 —— 解釈できない設定は無効化する
        al.problems.append(f"allowlist を解釈できないため、除外を一切適用しない: {exc}")
        return al

    unknown = set(data) - _ALLOWED_TOP
    if unknown:
        al.problems.append(f"未知のキー {sorted(unknown)} があるため、除外を一切適用しない")
        return al

    fp = data.get("faker_ja_jp_paths") or []
    if isinstance(fp, str):
        fp = [fp]
    al.faker_paths = tuple(str(x) for x in fp)

    for i, raw in enumerate(data.get("allow") or [], 1):
        if not isinstance(raw, dict):
            al.problems.append(f"allow[{i}] が辞書ではないため無効")
            continue
        bad = set(raw) - _ALLOWED_ENTRY
        if bad:
            al.problems.append(f"allow[{i}] に未知のキー {sorted(bad)} があるため無効")
            continue
        path_v = raw.get("path")
        reason = raw.get("reason")
        approver = raw.get("approved_by")
        if not path_v:
            al.problems.append(f"allow[{i}] に path が無いため無効")
            continue
        missing = [k for k, v in (("reason", reason), ("approved_by", approver)) if not v]
        if missing:
            al.problems.append(f"allow[{i}] ({path_v}) に {missing} が無いため無効（理由と承認者の記載を必須にしている）")
            continue
        # リポジトリ全体を対象にする項目は無効。報告だけにしていたところ、
        # `path: '*'` ひとつで個人情報の所見が全部消えることを実測した。
        # 抜け道になりうる指定は、指摘する前に**効かせない**。
        if str(path_v).strip() in ("*", "**", "**/*", "*/*", "."):
            al.problems.append(
                f"allow[{i}] の path が広すぎる（`{path_v}`）ため無効。"
                f"除外はファイル単位まで絞ること")
            continue
        rules = raw.get("rules") or ["*"]
        fps = raw.get("fingerprints") or ["*"]
        if isinstance(rules, str):
            rules = [rules]
        if isinstance(fps, str):
            fps = [fps]
        al.entries.append(Entry(str(path_v), tuple(str(r) for r in rules), tuple(str(f) for f in fps),
                                str(reason), str(approver), raw.get("expires")))
    return al
