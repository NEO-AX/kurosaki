"""検出ルールの正本。

方針:
- 「形」で当てられるもの（メール・電話・カード番号）は行走査で当てる。
- 「形だけでは当てられないもの」（氏名・生年月日・学籍番号）は
  **カラム名・キー名・ラベルという構造**を根拠にする。日本語コメントを
  氏名と誤認する事故は Phase 1 で実測済み（`comments.py` 参照）。
- 除外はRFCで予約された非到達値など、**理屈で安全と言える範囲だけ**に限る。
  「たぶんダミー」は除外しない（P3 性悪説：安全側の立証責任は主張者にある）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CRITICAL, HIGH, MEDIUM, LOW = "Critical", "High", "Medium", "Low"

# ---------------------------------------------------------------- 文字クラス

KANJI = r"[一-鿿々〇豈-﫿㐀-䶿]"
KATA = r"[ァ-ヺー]"
HIRA = r"[ぁ-ゖー]"

_SEP = r"[ 　]"

# 氏名の形。姓と名が区切られている場合（区切りなしは構造判定のみで使う）
RE_NAME_KANJI_SEP = re.compile(rf"{KANJI}{{1,4}}{_SEP}{KANJI}{{1,4}}")
RE_NAME_KANA_SEP = re.compile(rf"{KATA}{{2,8}}{_SEP}{KATA}{{2,8}}")
RE_NAME_HIRA_SEP = re.compile(rf"{HIRA}{{2,8}}{_SEP}{HIRA}{{2,8}}")
RE_NAME_KANJI_BARE = re.compile(rf"^{KANJI}{{2,5}}$")
RE_NAME_KANA_BARE = re.compile(rf"^{KATA}{{2,10}}$")

# ---------------------------------------------------------------- 形で当てる

RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
RE_PHONE_MOBILE = re.compile(r"(?<![0-9A-Za-z_\-])(?:\+81[ \-]?|0)[789]0[ \-]?[0-9]{4}[ \-]?[0-9]{4}(?![0-9A-Za-z_])")
RE_PHONE_LANDLINE = re.compile(r"(?<![0-9A-Za-z_\-])0[0-9]{1,4}[ \-][0-9]{1,4}[ \-][0-9]{4}(?![0-9A-Za-z_])")
RE_PHONE_FLAT = re.compile(r"(?<![0-9A-Za-z_\-])0[0-9]{9}(?![0-9A-Za-z_])")  # ハイフン無し10桁
RE_POSTAL = re.compile(r"(?:〒\s*)?(?<![0-9\-])[0-9]{3}-[0-9]{4}(?![0-9])")
RE_CARD_CAND = re.compile(r"(?<![0-9A-Za-z_])(?:[0-9][ \-]?){12,18}[0-9](?![0-9A-Za-z_])")
# 数字だけのUUID（`00000000-0000-0000-0000-000000000001` 等）はテストで多用され、
# ときどき Luhn を通る。実測: あるリポジトリのテストで Critical 16件がこれだった。
RE_UUID_DIGITS = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])")
# 実在のカードブランドの発行者識別番号。ここに当たらない数字列はカード番号ではない。
RE_CARD_IIN = re.compile(r"^(?:4[0-9]{12}(?:[0-9]{3})?(?:[0-9]{3})?|5[1-5][0-9]{14}|2[2-7][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35[0-9]{3})[0-9]{11})$")
CARD_LENGTHS = frozenset((13, 14, 15, 16, 19))
RE_DATE = re.compile(r"(?:19|20)[0-9]{2}[-/年](?:0?[1-9]|1[0-2])[-/月](?:0?[1-9]|[12][0-9]|3[01])日?")

PREFECTURES = (
    "北海道", "青森県", "岩手県", "宮城県", "秋田県", "山形県", "福島県", "茨城県", "栃木県",
    "群馬県", "埼玉県", "千葉県", "東京都", "神奈川県", "新潟県", "富山県", "石川県", "福井県",
    "山梨県", "長野県", "岐阜県", "静岡県", "愛知県", "三重県", "滋賀県", "京都府", "大阪府",
    "兵庫県", "奈良県", "和歌山県", "鳥取県", "島根県", "岡山県", "広島県", "山口県", "徳島県",
    "香川県", "愛媛県", "高知県", "福岡県", "佐賀県", "長崎県", "熊本県", "大分県", "宮崎県",
    "鹿児島県", "沖縄県",
)
RE_PREF = re.compile("|".join(PREFECTURES))
RE_ADDR_TAIL = re.compile(r"[0-9０-９]+\s*(?:丁目|番地|番|号)|[市区町村郡]|[0-9０-９]+-[0-9０-９]+")

# ---------------------------------------------------------------- ラベル語彙

LABEL_NAME = ("氏名", "名前", "お名前", "姓名", "フルネーム", "応募者", "候補者", "受講者",
              "参加者", "担当者", "保護者", "推薦者", "面接官", "フリガナ", "ふりがな", "カナ氏名")
LABEL_NAME_ASCII = ("name", "full_name", "fullname", "first_name", "last_name", "family_name",
                    "given_name", "applicant", "candidate", "person_name", "contact_name",
                    "handler", "manager_name", "kana", "furigana", "namae")
LABEL_EMAIL = ("メール", "メールアドレス", "eメール", "email", "e_mail", "mail", "mail_address", "email_address")
LABEL_PHONE = ("電話", "電話番号", "携帯", "携帯番号", "連絡先", "tel", "telephone", "phone", "mobile", "phone_number")
LABEL_ADDR = ("住所", "現住所", "所在地", "郵便番号", "address", "addr", "postal", "postal_code", "zip", "zipcode")
LABEL_BIRTH = ("生年月日", "誕生日", "生年", "birth", "birthday", "birth_date", "birthdate", "dob", "date_of_birth")
LABEL_STUDENT = ("学籍番号", "学生番号", "生徒番号", "学籍", "student_id", "student_no", "studentnumber", "school_id")
LABEL_CARD = ("カード番号", "クレジット", "card_number", "cardno", "card_no", "credit_card", "pan")

_ALL_PII_LABELS = LABEL_NAME + LABEL_NAME_ASCII + LABEL_EMAIL + LABEL_PHONE + LABEL_ADDR + LABEL_BIRTH + LABEL_STUDENT + LABEL_CARD


# 人物を格納する表の語彙。`name` 列が氏名かラベルかは、表の名前で決まる。
PERSON_TABLE_WORDS = ("applicant", "candidate", "person", "people", "user", "staff", "member",
                      "student", "youth", "guardian", "contact", "employee", "teacher",
                      "participant", "attendee", "interview", "profile", "recruit",
                      "応募", "候補", "受講", "生徒", "職員", "会員", "参加", "保護者", "面接")

# 表の名前に関係なく氏名だと言える列名。`name` 単独は**ここに入れない**。
STRONG_NAME_LABELS = ("氏名", "名前", "お名前", "姓名", "フルネーム", "応募者", "候補者", "受講者",
                      "参加者", "担当者", "保護者", "推薦者", "面接官", "フリガナ", "ふりがな", "カナ氏名",
                      "full_name", "fullname", "first_name", "last_name", "family_name", "given_name",
                      "applicant", "candidate", "person_name", "contact_name", "manager_name",
                      "furigana", "kana_name", "author_name", "respondent_name", "staff_name",
                      "student_name", "guardian_name", "handler_name", "interviewer_name",
                      "recipient_name", "member_name", "user_name", "owner_name")


def _norm_ident(token) -> str:
    """列名・キー名の正規化。`familyName` と `family_name` と `FAMILY NAME` を同じにする。

    実測: 正規化していなかったため `familyName` を「断定できない列」に落としていた。
    """
    return re.sub(r"[^0-9a-z\u3000-\u9fff\uf900-\ufaff]", "", str(token or "").lower())


def is_person_table(table: str | None) -> bool:
    if not table:
        return False
    t = _norm_ident(table)
    return any(_norm_ident(w) in t for w in PERSON_TABLE_WORDS)


def is_strong_name_label(column: str | None) -> bool:
    if not column:
        return False
    c = _norm_ident(column)
    return any(_norm_ident(w) in c for w in STRONG_NAME_LABELS)


def label_kind(token: str) -> str | None:
    """カラム名・キー名・ヘッダ語から、どの種類のPII列かを判定する。"""
    if not token:
        return None
    t = _norm_ident(token)
    if not t:
        return None
    def hit(vocab):
        return any(v in t for v in vocab)
    # 順序に意味がある。furigana は name 系より先に拾いたいので name 判定に含めている
    if hit([v.lower() for v in LABEL_CARD]):
        return "card"
    if hit([v.lower() for v in LABEL_STUDENT]):
        return "student_id"
    if hit([v.lower() for v in LABEL_BIRTH]):
        return "birth"
    if hit([v.lower() for v in LABEL_EMAIL]):
        return "email"
    if hit([v.lower() for v in LABEL_PHONE]):
        return "phone"
    if hit([v.lower() for v in LABEL_ADDR]):
        return "address"
    if hit([v.lower() for v in LABEL_NAME]) or t in [v.lower() for v in LABEL_NAME_ASCII] or hit(("氏名", "name")):
        return "name"
    return None


def line_pii_labels(line: str) -> set:
    """同一行に現れる PII ラベルの**集合**。

    1つだけ返す実装にしていたところ、`(name, email, tel)` のように複数の
    ラベルが並ぶ行で先に当たった種類しか見ず、氏名を落としていた。
    """
    found = set()
    low = line.lower()
    for vocab, kind in ((LABEL_CARD, "card"), (LABEL_STUDENT, "student_id"), (LABEL_BIRTH, "birth"),
                        (LABEL_EMAIL, "email"), (LABEL_PHONE, "phone"), (LABEL_ADDR, "address"),
                        (LABEL_NAME, "name")):
        for v in vocab:
            if v.lower() in low:
                found.add(kind)
                break
    for v in LABEL_NAME_ASCII:
        if re.search(rf"(?<![a-z0-9_]){re.escape(v)}(?![a-z0-9_])", low):
            found.add("name")
            break
    return found


# ---------------------------------------------------------------- 安全側の除外
# ここに入れてよいのは「規格上、実在の個人に到達しないと言えるもの」だけ。

RESERVED_TLDS = (".test", ".example", ".invalid", ".localhost")
RESERVED_DOMAINS = ("example.com", "example.net", "example.org", "example.co.jp", "localhost")


def is_reserved_email(value: str) -> bool:
    """RFC 2606 / RFC 6761 で予約されたドメインは実在の受信者へ到達しない。"""
    m = re.search(r"@([A-Za-z0-9.\-]+)$", value.strip())
    if not m:
        return False
    dom = m.group(1).lower().rstrip(".")
    for d in RESERVED_DOMAINS:
        if dom == d or dom.endswith("." + d):   # sub.example.org も予約（RFC 2606）
            return True
    return any(dom == t.lstrip(".") or dom.endswith(t) for t in RESERVED_TLDS)


def is_structurally_impossible_phone(value: str) -> bool:
    """総務省が番組・教材用に指定した 0X0-0000-00XX 帯、および 000/1111 の類。"""
    d = re.sub(r"\D", "", value)
    if len(set(d)) <= 1:
        return True
    if len(d) == 11 and d[3:7] == "0000":  # 090-0000-XXXX（教材用）
        return True
    if d.startswith("0120") or d.startswith("0570"):  # フリーダイヤル等は個人番号ではない
        return False
    return False


def looks_like_card(value: str) -> bool:
    """カード番号として成立するか。Luhn だけでは足りない。

    Luhn は10桁もあれば偶然通る。桁数・発行者識別番号（IIN）まで見て、
    「実在のブランドが発行しうる番号の形」であることを要求する。
    """
    d = re.sub(r"\D", "", value)
    if len(d) not in CARD_LENGTHS:
        return False
    if not RE_CARD_IIN.match(d):
        return False
    return luhn_ok(d)


def luhn_ok(value: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", value)]
    if not (13 <= len(d) <= 19):
        return False
    total, alt = 0, False
    for c in reversed(d):
        if alt:
            c *= 2
            if c > 9:
                c -= 9
        total += c
        alt = not alt
    return total % 10 == 0


# ---------------------------------------------------------------- 走査本体

_RE_QUOTED_VALUE = re.compile(r"""['"`]([^'"`\n]{2,40})['"`]""")
_LABEL_ALT = "|".join(re.escape(v) for v in (LABEL_NAME + LABEL_NAME_ASCII))
_RE_LABELED_VALUE = re.compile(rf"({_LABEL_ALT})\s*[:：=]\s*['\"`]?([^,\n'\"`]{{2,40}})", re.I)


def _full_name_shape(v: str):
    """値の**全体**が氏名の形をしているか。部分一致では判定しない。"""
    v = v.strip()
    if not v or len(v) > 20:
        return None
    if RE_NAME_KANJI_SEP.fullmatch(v):
        return "漢字の姓名"
    if RE_NAME_KANA_SEP.fullmatch(v):
        return "カナの姓名"
    if RE_NAME_HIRA_SEP.fullmatch(v):
        return "かなの姓名"
    return None


@dataclass
class Hit:
    rule: str
    line: int
    value: str          # 生値。ここから外へ出るときは必ず mask() を通す
    kind: str           # email / phone / address / card / birth / student_id / name
    why: str            # なぜ当たったか（構造 or 形）


def scan_line_shapes(line_no: int, line: str, body_line: str) -> list:
    """形で当てられるものを1行から拾う。

    `line` は原文（ラベル文脈の判定に使う）、`body_line` はコメントを潰した本文。
    形で当たるものはコメント内にあっても危険（コメントに実データを貼る事故は多い）ため、
    メール・電話・カードは原文に対して当てる。
    """
    hits: list = []

    for m in RE_EMAIL.finditer(line):
        v = m.group(0)
        if is_reserved_email(v):
            continue
        hits.append(Hit("EMAIL", line_no, v, "email", "メールアドレス形式"))

    for rx, why in ((RE_PHONE_MOBILE, "携帯電話形式"), (RE_PHONE_LANDLINE, "固定電話形式"), (RE_PHONE_FLAT, "電話番号(ハイフン無し)形式")):
        for m in rx.finditer(line):
            v = m.group(0)
            if is_structurally_impossible_phone(v):
                continue
            if any(h.value == v and h.kind == "phone" for h in hits):
                continue
            hits.append(Hit("JP_PHONE", line_no, v, "phone", why))

    uuid_spans = [m.span() for m in RE_UUID_DIGITS.finditer(line)]
    for m in RE_CARD_CAND.finditer(line):
        v = m.group(0)
        if any(a <= m.start() < b or a < m.end() <= b for a, b in uuid_spans):
            continue                      # UUIDの一部はカード番号ではない
        if looks_like_card(v):
            hits.append(Hit("CREDIT_CARD", line_no, v, "card", "カード番号形式(桁数・IIN・Luhnすべて通過)"))

    labels = line_pii_labels(line)

    if RE_PREF.search(line) and (RE_POSTAL.search(line) or RE_ADDR_TAIL.search(line)):
        pm = RE_POSTAL.search(line)
        frag = pm.group(0) if pm else RE_PREF.search(line).group(0)
        hits.append(Hit("JP_ADDRESS", line_no, frag, "address", "都道府県名＋番地/郵便番号らしい行"))
    elif RE_POSTAL.search(line) and "address" in labels:
        hits.append(Hit("JP_POSTAL", line_no, RE_POSTAL.search(line).group(0), "address", "郵便番号形式＋住所ラベル"))

    if "birth" in labels:
        for m in RE_DATE.finditer(line):
            hits.append(Hit("BIRTHDATE", line_no, m.group(0), "birth", "生年月日ラベル＋日付形式"))
    if "student_id" in labels:
        for m in re.finditer(r"[A-Za-z]{0,4}[0-9]{4,12}[A-Za-z]?", line):
            hits.append(Hit("STUDENT_ID", line_no, m.group(0), "student_id", "学籍番号ラベル＋番号形式"))

    # 氏名は「文章の中に漢字2文字の語が並んだだけ」で当ててはならない（実測の誤検知源）。
    # ラベルが同じ行にあることに加えて、次のどちらかを要求する:
    #   (a) 引用符で囲まれた値の**全体**が氏名の形をしている（`name: '架空 花子'`）
    #   (b) `氏名: 架空 花子` のようにラベルと値が区切り記号で結ばれている
    # `console.log(\`職員 補助 ${n} 件\`)` のような散文は、どちらにも当たらない。
    if "name" in labels:
        for m in _RE_QUOTED_VALUE.finditer(body_line):
            v = m.group(1).strip()
            why = _full_name_shape(v)
            if why:
                hits.append(Hit("JP_PERSON_NAME", line_no, v, "name", f"氏名ラベルのある行で、引用符内の値の全体が{why}"))
        for m in _RE_LABELED_VALUE.finditer(body_line):
            v = m.group(2).strip().strip("'\"`")
            why = _full_name_shape(v)
            if why:
                hits.append(Hit("JP_PERSON_NAME", line_no, v, "name", f"`{m.group(1)}` に続く値が{why}"))

    return hits
