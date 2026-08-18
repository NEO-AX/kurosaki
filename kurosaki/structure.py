"""構造からPIIを当てる層。

氏名・生年月日・学籍番号は「形」だけでは実データと日本語の文章を区別できない。
そこで **カラム名 / ヘッダ / キー名** を根拠にして、その位置にある値だけを見る。

対応する構造:
- SQL: `INSERT INTO t (col,...) VALUES (...)` と `COPY t (col,...) FROM stdin`
       （pg_dump のテキスト形式。実データの持ち出しはこの形で起きやすい）
- CSV / TSV: 1行目をヘッダとして列を対応させる
- JSON / JSONL / YAML / TS / JS: `"key": "value"` の対
"""

from __future__ import annotations

import csv
import io
import re

from .rules import (
    RE_CARD_CAND, RE_DATE, RE_EMAIL, RE_NAME_HIRA_SEP, RE_NAME_KANA_BARE, RE_NAME_KANA_SEP,
    RE_NAME_KANJI_BARE, RE_NAME_KANJI_SEP, RE_PHONE_FLAT, RE_PHONE_LANDLINE, RE_PHONE_MOBILE,
    RE_POSTAL, RE_PREF, Hit, is_person_table, is_reserved_email, is_strong_name_label,
    is_structurally_impossible_phone, label_kind, looks_like_card,
)

_NULLISH = {"", "null", "NULL", "None", "-", "—", "n/a", "N/A", "未設定", "なし", "TBD"}


def validate_value(kind: str, value: str, column=None, table=None, corroborated: bool = False):
    """PII列に入っている値が、実際にその種類の値の形をしているか。

    戻り値は (rule, why) か None。ここで None を返すのは「形をしていない」場合だけで、
    「ダミーだろう」という推測では None にしない（P3）。
    """
    v = (value or "").strip().strip("'\"`")
    if v in _NULLISH or len(v) < 2:
        return None

    if kind == "email":
        m = RE_EMAIL.search(v)
        if m and not is_reserved_email(m.group(0)):
            return "EMAIL", "メール列の値がメール形式"
        return None
    if kind == "phone":
        for rx in (RE_PHONE_MOBILE, RE_PHONE_LANDLINE, RE_PHONE_FLAT):
            m = rx.search(v)
            if m and not is_structurally_impossible_phone(m.group(0)):
                return "JP_PHONE", "電話列の値が電話番号形式"
        return None
    if kind == "address":
        if RE_PREF.search(v) or RE_POSTAL.search(v):
            return "JP_ADDRESS", "住所列の値に都道府県名または郵便番号"
        return None
    if kind == "birth":
        if RE_DATE.search(v):
            return "BIRTHDATE", "生年月日列の値が日付形式"
        return None
    if kind == "student_id":
        if re.fullmatch(r"[A-Za-z]{0,4}[0-9]{3,12}[A-Za-z]?", v):
            return "STUDENT_ID", "学籍番号列の値が番号形式"
        return None
    if kind == "card":
        m = RE_CARD_CAND.search(v)
        if m and looks_like_card(m.group(0)):
            return "CREDIT_CARD", "カード列の値が桁数・IIN・Luhnを通過"
        return None
    if kind == "name":
        # 「氏名らしさ」は値の形だけでは決まらない。`name` 列は人物表なら氏名、
        # `selection_steps` のような表ならラベルである。誤検知でCriticalを出すと
        # allowlist が広く使われ、結果として監査が空洞化する。
        # そこで: 強い列名 or 人物表 or 同じ行に他のPII がある → 断定(Critical候補)。
        #        それ以外で区切り無しの氏名形状 → 弱い検出(Medium。黙って捨てない)。
        strong_ctx = is_strong_name_label(column) or is_person_table(table) or corroborated
        sep = None
        if RE_NAME_KANJI_SEP.search(v):
            sep = "漢字の姓名"
        elif RE_NAME_KANA_SEP.search(v):
            sep = "カナの姓名"
        elif RE_NAME_HIRA_SEP.search(v):
            sep = "かなの姓名"
        if sep:
            # 姓と名の間の空白は強い信号。日本語のラベル（`書類選考`『論理構成』）に
            # 空白が入ることは稀で、`name` 列であっても人物と見て良い。
            if strong_ctx:
                return "JP_PERSON_NAME", f"氏名列の値が{sep}"
            return "JP_PERSON_NAME", f"`name` 系の列の値が{sep}（表は人物表と断定できないが、姓名の区切りがある）"
        if RE_NAME_KANJI_BARE.fullmatch(v) or RE_NAME_KANA_BARE.fullmatch(v):
            if strong_ctx:
                return "JP_PERSON_NAME", "氏名列の値が区切り無しの氏名形状"
            return "JP_PERSON_NAME_WEAK", "`name` 列だが表が人物表と断定できず、値も区切り無し（要確認）"
        return None
    return None


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# ------------------------------------------------------------------ SQL

_RE_INSERT = re.compile(r"INSERT\s+INTO\s+([A-Za-z0-9_.\"`]+)\s*\(([^)]*)\)\s*VALUES", re.I | re.S)
_RE_INSERT_NOCOLS = re.compile(r"INSERT\s+INTO\s+([A-Za-z0-9_.\"`]+)\s*VALUES", re.I)
_RE_COPY = re.compile(r"COPY\s+([A-Za-z0-9_.\"`]+)\s*\(([^)]*)\)\s*FROM\s+stdin\s*;", re.I)


def _split_tuples(text: str, start: int):
    """`VALUES` の直後から、トップレベルの `(...)` を順に取り出す。

    SQL の `''` エスケープと入れ子括弧（関数呼び出し）を跨いで壊れないよう、
    正規表現ではなく手で走らせる。戻り値は [(値文字列, 絶対オフセット), ...] のリスト。
    """
    out, i, n = [], start, len(text)
    while i < n:
        ch = text[i]
        if ch == ";":
            break
        if ch == "(":
            depth, j, cur, vals, in_str = 1, i + 1, [], [], False
            cur_start = j
            while j < n and depth > 0:
                c = text[j]
                if in_str:
                    if c == "'":
                        if j + 1 < n and text[j + 1] == "'":
                            cur.append("''"); j += 2; continue
                        in_str = False
                    cur.append(c); j += 1; continue
                if c == "'":
                    in_str = True; cur.append(c); j += 1; continue
                if c == "(":
                    depth += 1; cur.append(c); j += 1; continue
                if c == ")":
                    depth -= 1
                    if depth == 0:
                        vals.append(("".join(cur), cur_start))
                        j += 1
                        break
                    cur.append(c); j += 1; continue
                if c == "," and depth == 1:
                    vals.append(("".join(cur), cur_start))
                    cur = []
                    j += 1
                    cur_start = j
                    continue
                cur.append(c); j += 1
            out.append(vals)
            i = j
            continue
        i += 1
    return out


def sql_findings(text: str) -> list:
    hits: list = []

    for m in _RE_INSERT.finditer(text):
        cols = [c.strip() for c in m.group(2).split(",")]
        kinds = [label_kind(c) for c in cols]
        if not any(kinds):
            continue
        table = m.group(1)
        for row in _split_tuples(text, m.end()):
            # 1周目: 氏名以外のPIIが同じ行にあるか（行単位の裏取り）
            corroborated = any(
                kinds[i] and kinds[i] != "name" and validate_value(kinds[i], raw)
                for i, (raw, _off) in enumerate(row) if i < len(kinds))
            # 2周目: 判定
            for idx, (raw, off) in enumerate(row):
                if idx >= len(kinds) or not kinds[idx]:
                    continue
                res = validate_value(kinds[idx], raw, column=cols[idx], table=table,
                                     corroborated=corroborated)
                if res:
                    rule, why = res
                    hits.append(Hit(rule, _line_of(text, off), raw.strip().strip("'"), kinds[idx],
                                    f"{why}（列 `{cols[idx].strip()}` / 表 {table}）"))

    # 列名が書かれていない INSERT。列名で当てられないので、値の形だけで拾う。
    for m in _RE_INSERT_NOCOLS.finditer(text):
        for row in _split_tuples(text, m.end()):
            for raw, off in row:
                v = raw.strip()
                if not (v.startswith("'") and v.endswith("'")):
                    continue
                inner = v[1:-1]
                if RE_NAME_KANJI_SEP.fullmatch(inner) or RE_NAME_KANA_SEP.fullmatch(inner):
                    hits.append(Hit("JP_PERSON_NAME", _line_of(text, off), inner, "name",
                                    f"列名の無いINSERT値が姓名形状（表 {m.group(1)}）"))

    # pg_dump のテキスト形式。COPY 〜 \. の間はタブ区切りの生データ。
    for m in _RE_COPY.finditer(text):
        cols = [c.strip() for c in m.group(2).split(",")]
        kinds = [label_kind(c) for c in cols]
        body_start = m.end()
        end = text.find("\n\\.", body_start)
        body = text[body_start: end if end != -1 else len(text)]
        base_line = _line_of(text, body_start)
        table = m.group(1)
        for r, line in enumerate(body.split("\n")):
            if not line.strip():
                continue
            cells = line.split("\t")
            corroborated = any(
                kinds[i] and kinds[i] != "name" and validate_value(kinds[i], c)
                for i, c in enumerate(cells) if i < len(kinds))
            for idx, cell in enumerate(cells):
                if idx >= len(kinds) or not kinds[idx]:
                    continue
                res = validate_value(kinds[idx], cell, column=cols[idx], table=table,
                                     corroborated=corroborated)
                if res:
                    rule, why = res
                    hits.append(Hit(rule, base_line + r, cell, kinds[idx],
                                    f"{why}（COPY 列 `{cols[idx]}` / 表 {m.group(1)}）"))
    return hits


# ------------------------------------------------------------------ CSV / TSV

def delimited_findings(text: str, delimiter: str, table_hint: str | None = None) -> list:
    hits: list = []
    try:
        rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    except csv.Error:
        return hits
    if not rows:
        return hits
    header = rows[0]
    kinds = [label_kind(c) for c in header]
    if not any(kinds):
        return hits
    for r, row in enumerate(rows[1:], start=2):
        corroborated = any(
            kinds[i] and kinds[i] != "name" and validate_value(kinds[i], c)
            for i, c in enumerate(row) if i < len(kinds))
        for idx, cell in enumerate(row):
            if idx >= len(kinds) or not kinds[idx]:
                continue
            res = validate_value(kinds[idx], cell, column=header[idx], table=table_hint,
                                 corroborated=corroborated)
            if res:
                rule, why = res
                hits.append(Hit(rule, r, cell, kinds[idx], f"{why}（列 `{header[idx]}`）"))
    return hits


# ------------------------------------------------------------------ key: value

_RE_KV_QUOTED = re.compile(r"""["'`]?([A-Za-z0-9_\-ぁ-んァ-ヶー一-鿿]{1,32})["'`]?\s*[:=]\s*["'`]([^"'`\n]{1,200})["'`]""")
_RE_KV_BARE = re.compile(r"""^\s*["'`]?([A-Za-z0-9_\-ぁ-んァ-ヶー一-鿿]{1,32})["'`]?\s*[:=]\s*([^\s"'`#][^\n#]{0,200}?)\s*,?\s*$""", re.M)


def keyvalue_findings(text: str) -> list:
    """JSON / JSONL / YAML / TS / JS の `key: value` を構造として読む。

    パースせず正規表現で読むのは、壊れたJSON・JSONL・TSのオブジェクトリテラル・
    YAMLを同じ経路で扱えるようにするため。行番号もそのまま取れる。
    """
    hits: list = []
    seen = set()
    for rx in (_RE_KV_QUOTED, _RE_KV_BARE):
        for m in rx.finditer(text):
            key, value = m.group(1), m.group(2)
            kind = label_kind(key)
            if not kind:
                continue
            line_text = text[text.rfind("\n", 0, m.start()) + 1: text.find("\n", m.start()) if text.find("\n", m.start()) != -1 else len(text)]
            corroborated = bool(RE_EMAIL.search(line_text) or RE_PHONE_MOBILE.search(line_text)
                                or RE_PHONE_LANDLINE.search(line_text))
            res = validate_value(kind, value, column=key, table=None, corroborated=corroborated)
            if not res:
                continue
            rule, why = res
            line = _line_of(text, m.start(2))
            sig = (rule, line, value.strip())
            if sig in seen:
                continue
            seen.add(sig)
            hits.append(Hit(rule, line, value.strip(), kind, f"{why}（キー `{key}`）"))
    return hits
