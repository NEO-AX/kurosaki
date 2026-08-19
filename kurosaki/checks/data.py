"""領域6 —— データ取扱い。

既に実装・検証済みの Layer 1（PII走査）を、監査手続としてここに収容する。
走査そのものの正しさは `tests/test_scan.py` が固定している。この手続の責任は
「走査を確実に走らせ、走らなかった範囲を隠さずに意見へ渡すこと」。
"""

from __future__ import annotations

import os

from .. import allowlist as allowlist_mod
from ..rules import CRITICAL, HIGH, LOW, MEDIUM
from ..scan import Scanner
from .base import Context, ProcedureResult, observe, procedure, unverifiable


@procedure("D6-01", "データ取扱い", "個人情報が追跡下・履歴に混入していないか")
def d6_01(ctx: Context, res: ProcedureResult) -> None:
    if not ctx.is_git:
        unverifiable(res, "git リポジトリではないため追跡対象を確定できない", examined="git 判定")
        return

    allow = allowlist_mod.load(os.path.join(ctx.repo, ".audit", "allowlist.yml"))
    corpus = allowlist_mod.faker_ja_jp_corpus()
    scanner = Scanner(ctx.repo, allow=allow, faker_corpus=corpus)

    history = bool(ctx.opts.get("history"))
    result = scanner.scan_history() if history else scanner.scan_worktree()

    mode = "履歴の全ブロブ" if history else "追跡ファイル（作業ツリー）"
    res.examined = (f"{mode} を走査: 検査 {result.scanned} 件 / 除外 {len(result.skipped)} 件 / "
                    f"中身未検査 {len(result.unchecked)} 件"
                    f"{' / 履歴ブロブ ' + str(result.meta.get('history_blobs')) if history else ''}"
                    f"。allowlist 除外 {sum(1 for f in result.findings if f.allowlisted)} 件")

    # 所見はファイル×ルールで畳む。行単位は走査の JSON 報告に残す（意見を読める長さに保つ）。
    grouped: dict = {}
    for f in result.active:
        grouped.setdefault((f.severity, f.file, f.rule), []).append(f.line)
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
    for (sev, path, rule), lines in sorted(grouped.items(), key=lambda kv: (order.get(kv[0][0], 9), kv[0][1])):
        head = ", ".join(f"L{n}" for n in lines[:6]) + (f" …ほか {len(lines) - 6} 箇所" if len(lines) > 6 else "")
        observe(res, sev, f"`{path}` に {rule} が {len(lines)} 件（{mode}）",
                "実データを取り除き、ダミーは Faker(ja_JP) で生成する。既に push 済みなら"
                "履歴からの除去を不可逆操作として人間の承認のもとで行う",
                [f"{path}: {head}"], key=f"pii:{path}:{rule}")

    # 走査できなかった範囲があるなら、意見の側でそれを見せる（無罪の証明にしない）
    for note in result.notes:
        observe(res, LOW, f"走査の限界: {note}", "限界を承知の上で判断するか、走査対象を広げる",
                ["scan notes"], key=f"scan-note:{note[:40]}")
    if result.unchecked:
        observe(res, MEDIUM,
                f"中身を検査できなかったファイルが {len(result.unchecked)} 件ある（安全だと言っていない）",
                "検査できる形式へ変換するか、リポジトリの外へ出す",
                [u["file"] for u in result.unchecked[:6]], key="unchecked-files")


import re  # noqa: E402  —— 以下のシークレット検査で使う

# 誤検知が理屈上ほぼ起きない確定パターンだけを持つ。
# 汎用のシークレット検出は作らない（gitleaks があるならそれに委ねる）。
SECRET_PATTERNS = (
    ("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", CRITICAL),
    ("GITHUB_TOKEN", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b", CRITICAL),
    ("GITHUB_PAT", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", CRITICAL),
    ("ANTHROPIC_KEY", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b", CRITICAL),
    ("OPENAI_KEY", r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b", CRITICAL),
    ("GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z\-_]{35}\b", CRITICAL),
    ("SLACK_TOKEN", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", CRITICAL),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", CRITICAL),
    ("SUPABASE_SERVICE_ROLE", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]*service_role[A-Za-z0-9_\-]*\.", CRITICAL),
    ("STRIPE_SECRET", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b", CRITICAL),
    ("SENDGRID_KEY", r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b", CRITICAL),
)


@procedure("D6-02", "データ取扱い", "確定パターンのシークレットが追跡下に入っていないか")
def d6_02(ctx: Context, res: ProcedureResult) -> None:
    if not ctx.is_git:
        unverifiable(res, "git リポジトリではないため追跡対象を確定できない", examined="git 判定")
        return
    from .. import paths as pathmod
    from ..mask import mask

    from .. import allowlist as allowlist_mod
    from ..mask import fingerprint
    allow = allowlist_mod.load(os.path.join(ctx.repo, ".audit", "allowlist.yml"))

    tracked = ctx.tracked()
    scanned, skipped = 0, 0
    hits: dict = {}
    excluded = 0
    for rel in tracked:
        if pathmod.should_skip(rel) or pathmod.is_opaque_data(rel):
            skipped += 1
            continue
        try:
            with open(ctx.path(rel), "rb") as fh:
                raw = fh.read(2 * 1024 * 1024)
        except OSError:
            skipped += 1
            continue
        text = raw.replace(b"\x00", b"").decode("utf-8", "replace")
        scanned += 1
        for name, pat, sev in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                line = text.count("\n", 0, m.start()) + 1
                # 秘密の検出も allowlist の対象にする。試験用のプレースホルダを
                # 通すために検出ルール自体を緩めるのは筋が悪い（人間が指紋で署名する）。
                if allow.matches(rel, f"SECRET:{name}", fingerprint(m.group(0))):
                    excluded += 1
                    continue
                hits.setdefault((name, rel, sev), []).append((line, m.group(0)))

    gitleaks = ctx.opts.get("gitleaks_available")
    res.examined = (f"追跡ファイル {len(tracked)} 件のうち {scanned} 件を {len(SECRET_PATTERNS)} 種の"
                    f"確定パターンへ突合（{skipped} 件は形式・除外対象でスキップ）。"
                    f"汎用のシークレット検出は範囲外（gitleaks={'あり' if gitleaks else '未確認/無し'}）。"
                    f"allowlist で除外 {excluded} 件")

    for (name, rel, sev), found in sorted(hits.items()):
        # 値は出さない。先頭1文字＋*** と件数だけ（スキャナが漏洩経路にならないため）
        observe(res, sev, f"`{rel}` に {name} 形式の秘密が {len(found)} 件（{mask(found[0][1])}）",
                "鍵を失効させて再発行し、追跡から外す。履歴に入っているなら履歴除去を"
                "不可逆操作として人間の承認のもとで行う",
                [f"{rel}:{found[0][0]}"], key=f"secret:{rel}:{name}")

    if not hits:
        # 「確定パターンで出なかった」は「秘密が無い」ではない。範囲の限界を明示する。
        observe(res, LOW,
                f"確定パターン {len(SECRET_PATTERNS)} 種では秘密を検出しなかった"
                f"（これは秘密が無いことの証明ではない。独自形式のトークンは対象外）",
                "必要なら gitleaks / detect-secrets を併用する", ["D6-02 の走査範囲"],
                key="secret-scope-limit")
