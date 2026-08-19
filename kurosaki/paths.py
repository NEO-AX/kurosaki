"""パスの分類。「重点走査パス」で当たったら即FAIL（仕様 3-1）。"""

from __future__ import annotations

import fnmatch
import posixpath
import re

# 検出したら Critical にする重点パス。テストデータ・投入データが入りうる場所。
CRITICAL_GLOBS = (
    "**/seed*", "seed*", "**/seeds/**", "**/fixture*", "fixture*", "**/fixtures/**",
    "**/migrations/**", "migrations/**", "**/migration/**",
    "*.sql", "**/*.sql", "*.csv", "**/*.csv", "*.tsv", "**/*.tsv",
    "*.json", "**/*.json", "*.jsonl", "**/*.jsonl", "*.ndjson", "**/*.ndjson",
    "**/dump*", "dump*", "**/backup*", "backup*", "**/*.dump", "**/*.bak",
)

# 走査しても意味が薄く、量が多い場所。**スキップしたことは必ず報告に出す。**
SKIP_DIR_PARTS = (
    ".git/", "node_modules/", ".next/", ".nuxt/", "dist/", "build/", "out/", "coverage/",
    ".venv/", "venv/", "__pycache__/", ".pgdata/", ".pgdata-pilot/", ".mypy_cache/",
    ".pytest_cache/", "vendor/", ".turbo/", ".vercel/", ".tmp/", ".claude-tmp/",
)
SKIP_NAME_GLOBS = (
    "*.min.js", "*.map", "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "poetry.lock",
    "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot", "*.ico", "*.svg",
)

# 中身を読めない／読んでも構造が取れないが、実データを含みうる形式。
OPAQUE_DATA_GLOBS = (
    "*.xlsx", "*.xls", "*.xlsm", "*.pptx", "*.docx", "*.numbers", "*.pages",
    "*.zip", "*.gz", "*.tar", "*.7z", "*.rar", "*.sqlite", "*.db", "*.parquet",
    "*.png", "*.jpg", "*.jpeg", "*.heic", "*.pdf",
)


_RE_DATA_WORD = re.compile(r"(?:^|[^a-z0-9])(seeds?|fixtures?|dumps?|backups?|exports?|intake)(?:[^a-z0-9]|$)")


def _match_any(path: str, globs) -> bool:
    name = posixpath.basename(path)
    for g in globs:
        if fnmatch.fnmatch(path, g) or fnmatch.fnmatch(name, g):
            return True
    return False


def is_critical_path(path: str) -> bool:
    p = path.replace("\\", "/")
    if _match_any(p, CRITICAL_GLOBS):
        return True
    # `**/seed*` は fnmatch では 1階層しか跨がないので、部分一致でも見る。
    # `src/data/dashboard-seed.ts` のように語尾に付く形も重点パス扱いにする
    # （実測: NEO-Youth の `src/data/dashboard-seed.ts` がこの形だった）。
    low = p.lower()
    if any(k in low for k in ("/seed", "seed/", "/fixture", "fixture/", "/migrations/", "/dump", "/backup")):
        return True
    # 語として現れる場合だけ。`exporter.ts` を実データ置き場と見なすのは行き過ぎ。
    return bool(_RE_DATA_WORD.search(posixpath.basename(low)))


def should_skip(path: str) -> str | None:
    p = path.replace("\\", "/")
    for part in SKIP_DIR_PARTS:
        if p.startswith(part) or f"/{part}" in p:
            return f"除外ディレクトリ({part})"
    if _match_any(p, SKIP_NAME_GLOBS):
        return "除外ファイル形式"
    return None


def is_opaque_data(path: str) -> bool:
    return _match_any(path.replace("\\", "/"), OPAQUE_DATA_GLOBS)


# 中身を読めない形式のうち、**人物が写り/含まれうる**手掛かり。
# 例: 顔写真のフォルダ、応募管理の表計算ファイル。
PERSON_HINT_WORDS = (
    "顔", "写真", "portrait", "face", "photo", "履歴書", "resume", "cv",
    "名簿", "応募", "候補", "受講", "参加", "会員", "生徒", "職員", "社員", "個人",
    "applicant", "candidate", "member", "student", "staff", "person", "people",
    "profile", "roster", "attendee", "契約", "身分", "証明",
)
_ALWAYS_OPAQUE_RISK = (".xlsx", ".xls", ".xlsm", ".docx", ".pptx", ".numbers", ".pages",
                       ".sqlite", ".db", ".parquet", ".zip", ".gz", ".tar", ".7z", ".rar")


def opaque_risk(path: str) -> str | None:
    """機械検査できないファイルを所見として立てるべきか。理由か None を返す。"""
    p = path.replace("\\", "/").lower()
    ext = posixpath.splitext(p)[1]
    if ext in _ALWAYS_OPAQUE_RISK:
        return "表計算・文書・アーカイブ・DBの形式は実データを含みうる"
    if any(w.lower() in p for w in PERSON_HINT_WORDS):
        return "パスに人物を示す語がある"
    if is_critical_path(path):
        return "重点走査パスにある"
    return None
