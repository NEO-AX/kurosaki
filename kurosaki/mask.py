"""検出値をそのまま外へ出さないための唯一の出口。

スキャナが個人情報を出力してしまえば、CIログ・端末履歴・チャット履歴という
新しい漏洩経路を作るだけになる。したがって report 層は生値を受け取らず、
**必ずこのモジュールを通した文字列だけ**を扱う。
"""

from __future__ import annotations

import hashlib
import unicodedata

_STARS = "***"


def mask(value: str) -> str:
    """先頭1文字＋`***`。仕様（3-1）の出力形式。

    先頭1文字は「どのルールがどこで当たったか」を人間が突き合わせるための
    最小の手がかり。2文字目以降は復元できない。
    """
    if value is None:
        return _STARS
    s = str(value).strip()
    if not s:
        return _STARS
    head = s[0]
    # 制御文字・書式文字は先頭に出さない（ログ汚染と誤読を防ぐ）
    if unicodedata.category(head)[0] in ("C", "Z"):
        return _STARS
    return head + _STARS


def fingerprint(value: str) -> str:
    """同一値の再検出を allowlist で指し示すための指紋。

    値そのものは記録しない。sha256 の先頭16桁。短いのは目視用であり、
    衝突耐性を売りにしていない（allowlist は path と rule も併記して効く）。
    """
    s = "" if value is None else str(value)
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def masked_len(value: str) -> int:
    """長さだけは残す。氏名2文字とメール30文字を区別できないと調査が進まない。"""
    return 0 if value is None else len(str(value))
