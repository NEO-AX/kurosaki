"""走査エンジン。

入力は「パスと中身」だけ。実装セッションの会話・意図・コミットメッセージは
一切入力にしない（P1 独立性）。出力には生値を載せない（3-1 の絶対条件）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict

from . import allowlist as allowlist_mod
from . import gitio, paths as pathmod
from .comments import strip_comments
from .mask import fingerprint, mask, masked_len
from .rules import CRITICAL, HIGH, LOW, MEDIUM, scan_line_shapes
from .structure import delimited_findings, keyvalue_findings, sql_findings

MAX_BYTES = 8 * 1024 * 1024          # これを超えるテキストは走査せず「未検査」として報告する
MAX_FINDINGS_PER_FILE = 200          # ログ爆発を防ぐ。打ち切った件数は必ず notes に残す
LARGE_FILE_BYTES = 1 * 1024 * 1024   # 追加されたデータファイルの早期検知（3-2 相当）

_STRUCT_SQL = {".sql", ".psql", ".ddl"}
_STRUCT_CSV = {".csv"}
_STRUCT_TSV = {".tsv", ".tab"}
_STRUCT_KV = {".json", ".jsonl", ".ndjson", ".yml", ".yaml", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".toml", ".env", ".ini"}

_SEV_WEAK = {"BIRTHDATE", "STUDENT_ID", "JP_POSTAL"}
# 断定できない検出。重点パスでも Medium で止める。黙って捨てるより弱く出す。
_NEVER_BLOCKING = {"JP_PERSON_NAME_WEAK"}


@dataclass
class Finding:
    rule: str
    file: str
    line: int
    severity: str
    evidence: str          # マスク済み断片のみ
    fingerprint: str
    length: int
    why: str
    critical_path: bool
    allowlisted: bool = False
    allow_reason: str | None = None
    origin: str = "worktree"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    scanned: int = 0
    skipped: list = field(default_factory=list)
    unchecked: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    @property
    def active(self) -> list:
        return [f for f in self.findings if not f.allowlisted]

    def count(self, severity: str) -> int:
        return sum(1 for f in self.active if f.severity == severity)

    @property
    def blocking(self) -> int:
        return self.count(CRITICAL) + self.count(HIGH)


def severity_for(rule: str, critical_path: bool) -> str:
    if rule in _NEVER_BLOCKING:
        return MEDIUM
    if rule == "CREDIT_CARD":
        return CRITICAL          # カード番号は場所を問わない
    if rule == "OPAQUE_DATA":
        return CRITICAL if critical_path else HIGH
    if rule == "LARGE_FILE":
        return MEDIUM
    if critical_path:
        return CRITICAL          # 重点走査パスは検出時に即FAIL（仕様 3-1）
    return MEDIUM if rule in _SEV_WEAK else HIGH


def _decode(data: bytes):
    """テキストとして読めるところまで読む。読めた割合が低いときだけバイナリ扱い。

    NULバイトが1つあるだけで走査を諦める実装にしていたが、それは
    「seedファイルにNULを1バイト混ぜれば検査を飛ばせる」という回避路になる。
    実測でも、NUL が混入したソースが未検査になっていた。
    したがってNULは取り除いて走査し、判定は**復号できた割合**で行う。
    """
    raw = data.replace(b"\x00", b"")
    for enc in ("utf-8", "cp932"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    text = raw.decode("utf-8", "replace")
    if not text:
        return None
    broken = text.count("\ufffd") / max(len(text), 1)
    return None if broken > 0.05 else text


def scan_text(relpath: str, text: str) -> list:
    """1ファイル分の生ヒット（Hit）を返す。重複は (rule, line, 値) で畳む。"""
    suffix = os.path.splitext(relpath)[1].lower()
    body = strip_comments(text, suffix)
    hits = []

    body_lines = body.split("\n")
    for i, line in enumerate(text.split("\n"), 1):
        if len(line) > 4000:
            line = line[:4000]
        b = body_lines[i - 1][:4000] if i - 1 < len(body_lines) else line
        hits.extend(scan_line_shapes(i, line, b))

    if suffix in _STRUCT_SQL:
        hits.extend(sql_findings(body))
    elif suffix in _STRUCT_CSV:
        hits.extend(delimited_findings(text, ",", table_hint=relpath))
    elif suffix in _STRUCT_TSV:
        hits.extend(delimited_findings(text, "\t", table_hint=relpath))
    elif suffix in _STRUCT_KV:
        hits.extend(keyvalue_findings(body))

    deduped, seen = [], set()
    for h in hits:
        sig = (h.rule, h.line, h.value.strip())
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(h)
    return deduped


class Scanner:
    def __init__(self, repo: str, allow=None, faker_corpus=None, origin: str = "worktree"):
        self.repo = repo
        self.allow = allow or allowlist_mod.Allowlist()
        self.faker_corpus = faker_corpus
        self.origin = origin
        self.result = ScanResult()
        for p in self.allow.problems:
            self.result.notes.append(f"allowlist: {p}")
        if self.allow.faker_paths and faker_corpus is None:
            self.result.notes.append(
                "allowlist に faker_ja_jp_paths があるが Faker が入っていないため、"
                "Faker由来という主張を検証できない。したがってこの緩和は適用しない（fail closed）。")

    # ------------------------------------------------------------ 1ファイル

    def feed(self, relpath: str, data: bytes, size: int | None = None):
        skip = pathmod.should_skip(relpath)
        if skip:
            self.result.skipped.append({"file": relpath, "reason": skip})
            return
        critical = pathmod.is_critical_path(relpath)
        size = len(data) if size is None else size

        if pathmod.is_opaque_data(relpath):
            reason = pathmod.opaque_risk(relpath)
            if reason:
                self._add(Finding("OPAQUE_DATA", relpath, 0, severity_for("OPAQUE_DATA", critical),
                                  mask(os.path.basename(relpath)), fingerprint(relpath), size,
                                  f"中身を機械検査できない形式が追跡対象に入っている（{reason}）",
                                  critical, origin=self.origin))
            else:
                # 資産（ロゴ・アイコン等）まで所見にすると本物の所見が埋もれる。
                # ただし「見ていない」ことは未検査として必ず残す。
                self.result.unchecked.append({"file": relpath, "reason": "機械検査できない形式のため中身未検査"})
            self.result.scanned += 1
            return

        if size > LARGE_FILE_BYTES:
            self._add(Finding("LARGE_FILE", relpath, 0, severity_for("LARGE_FILE", critical),
                              mask(os.path.basename(relpath)), fingerprint(relpath), size,
                              f"{size // 1024}KB のファイルが追跡対象に入っている（データ混入の早期検知）",
                              critical, origin=self.origin))

        if size > MAX_BYTES:
            self.result.unchecked.append({"file": relpath, "reason": f"{size // 1024}KB > 上限のため中身未検査"})
            return

        text = _decode(data)
        if text is None:
            self.result.unchecked.append({"file": relpath, "reason": "バイナリのため中身未検査"})
            return

        self.result.scanned += 1
        hits = scan_text(relpath, text)
        if len(hits) > MAX_FINDINGS_PER_FILE:
            self.result.notes.append(
                f"{relpath}: 検出 {len(hits)} 件のうち {MAX_FINDINGS_PER_FILE} 件までを報告した"
                f"（{len(hits) - MAX_FINDINGS_PER_FILE} 件を打ち切り。件数は隠していない）")
            hits = hits[:MAX_FINDINGS_PER_FILE]

        for h in hits:
            fp = fingerprint(h.value)
            sev = severity_for(h.rule, critical)
            f = Finding(h.rule, relpath, h.line, sev, mask(h.value), fp, masked_len(h.value),
                        h.why, critical, origin=self.origin)
            entry = self.allow.matches(relpath, h.rule, fp)
            if entry:
                f.allowlisted = True
                f.allow_reason = f"allowlist: {entry.reason}（承認 {entry.approved_by}）"
            elif h.kind == "name" and self.allow.faker_allowed(relpath) and self.faker_corpus:
                from .allowlist import is_faker_name
                if is_faker_name(h.value, self.faker_corpus):
                    f.allowlisted = True
                    f.allow_reason = "Faker(ja_JP) の語彙で構成された氏名（照合済み）"
            self._add(f)

    def _add(self, f: Finding):
        self.result.findings.append(f)

    # ------------------------------------------------------------ 走査モード

    def scan_paths(self, files: list):
        for rel in files:
            abs_path = rel if os.path.isabs(rel) else os.path.join(self.repo, rel)
            try:
                with open(abs_path, "rb") as fh:
                    data = fh.read(MAX_BYTES + 1)
                size = os.path.getsize(abs_path)
            except (OSError, ValueError) as exc:
                self.result.unchecked.append({"file": rel, "reason": f"読めない: {exc}"})
                continue
            self.feed(rel, data, size)
        return self.result

    def scan_worktree(self, include_untracked: bool = False):
        files = gitio.tracked_files(self.repo)
        if include_untracked:
            files += gitio.untracked_files(self.repo)
        return self.scan_paths(files)

    def scan_staged(self):
        for rel in gitio.staged_files(self.repo):
            data = gitio.read_staged(self.repo, rel)
            self.feed(rel, data)
        return self.result

    def scan_changed_vs(self, ref: str):
        """差分行ではなく、変更されたファイルの**全内容**を見る（仕様 3-3 ジョブA）。"""
        for rel in gitio.changed_vs(self.repo, ref):
            abs_path = os.path.join(self.repo, rel)
            if os.path.exists(abs_path):
                self.scan_paths([rel])
            else:
                self.result.unchecked.append({"file": rel, "reason": "作業ツリーに存在しない（削除済み）"})
        return self.result

    def scan_history(self, limit: int | None = None):
        """履歴全体のブロブを走査する（仕様 3-3 ジョブC）。

        作業ツリーから消したファイルも、履歴に残っていれば公開されたままである。
        """
        n = 0
        for sha, path in gitio.all_blobs(self.repo):
            if not path or path.endswith("/"):
                continue
            if pathmod.should_skip(path):
                continue
            data = gitio.read_blob(self.repo, sha)
            if not data:
                continue
            self.origin = f"blob:{sha[:8]}"
            self.feed(path, data)
            n += 1
            if limit and n >= limit:
                self.result.notes.append(f"履歴走査を {limit} ブロブで打ち切った（--limit 指定）")
                break
        self.result.meta["history_blobs"] = n
        return self.result
