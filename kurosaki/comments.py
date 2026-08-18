"""コメントを空白へ潰す。行番号と桁位置は保つ。

Phase 1 の実測: 日本語コメントの入った SQL / Markdown へ
「漢字2-4文字＋空白＋漢字2-4文字」を当てると `db/DECISIONS.md` で3518件、
各マイグレーションで数十〜174件ヒットした。氏名らしさをコメント本文で
判定すると運用が成立しない。よって氏名系ルールはコメントを潰した本文へ当てる。

潰す（置換する）のは同じ長さの半角空白なので、行番号・列位置はずれない。
"""

from __future__ import annotations

import re

_SQL_LIKE = {".sql", ".psql", ".ddl"}
_C_LIKE = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".java", ".go", ".c", ".h", ".cpp", ".cs", ".swift", ".kt", ".rs", ".scss", ".css"}
_HASH_LIKE = {".py", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".toml", ".ini", ".conf", ".rb", ".pl"}


def _blank_out(text: str, spans) -> str:
    if not spans:
        return text
    buf = list(text)
    for start, end in spans:
        for i in range(start, end):
            if buf[i] != "\n":
                buf[i] = " "
    return "".join(buf)


def _string_spans(text: str, quotes=("'", '"', "`")) -> list:
    """文字列リテラルの範囲。コメント記号が文字列の中にある場合を守る。"""
    spans = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in quotes:
            q = ch
            j = i + 1
            while j < n:
                if text[j] == "\\" and q != "'":
                    j += 2
                    continue
                if text[j] == q:
                    # SQL の '' エスケープ
                    if q == "'" and j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            spans.append((i, min(j + 1, n)))
            i = j + 1
            continue
        i += 1
    return spans


def _in_spans(pos: int, spans) -> bool:
    for start, end in spans:
        if start <= pos < end:
            return True
    return False


def strip_comments(text: str, suffix: str) -> str:
    """拡張子に応じてコメントを空白化した本文を返す。未知の拡張子は素通し。"""
    suffix = (suffix or "").lower()
    spans = []
    if suffix in _SQL_LIKE:
        lit = _string_spans(text, ("'",))
        spans += [m.span() for m in re.finditer(r"--[^\n]*", text) if not _in_spans(m.start(), lit)]
        spans += [m.span() for m in re.finditer(r"/\*.*?\*/", text, re.S) if not _in_spans(m.start(), lit)]
    elif suffix in _C_LIKE:
        lit = _string_spans(text)
        spans += [m.span() for m in re.finditer(r"//[^\n]*", text) if not _in_spans(m.start(), lit)]
        spans += [m.span() for m in re.finditer(r"/\*.*?\*/", text, re.S) if not _in_spans(m.start(), lit)]
    elif suffix in _HASH_LIKE:
        lit = _string_spans(text)
        spans += [m.span() for m in re.finditer(r"#[^\n]*", text) if not _in_spans(m.start(), lit)]
    return _blank_out(text, spans)
