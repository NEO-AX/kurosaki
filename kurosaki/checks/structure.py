"""領域1・2 —— 体制文書とフォルダ構成。

見ているのは「AIに何をさせない体制になっているか」が**構造として**成立しているか。
文書に何が書かれているかではなく、書かれた制約が機械で守られているかを見る。
"""

from __future__ import annotations

import fnmatch
import json
import os
import re

from .. import paths as pathmod
from ..rules import CRITICAL, HIGH, LOW, MEDIUM
from ._shared import hook_bodies as _hook_bodies
from .base import Context, ProcedureResult, observe, procedure, unverifiable

# AI開発体制の規律文書として通用するファイル名
DISCIPLINE_DOCS = ("CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".cursor/rules",
                   "CONTRIBUTING.md", "docs/CLAUDE.md")
# 実装担当より上位に立つ（＝実装AIが変更してはならない）文書
SUPERIOR_DOCS = ("SUPERVISOR.md", "GOVERNANCE.md", "docs/SUPERVISOR.md", ".audit/AUDIT_CHARTER.md",
                 "CODEOWNERS", ".github/CODEOWNERS")

GENERATED_DIRS = ("node_modules/", ".next/", "dist/", "build/", "out/", "coverage/", ".turbo/",
                  ".venv/", "__pycache__/", ".pgdata/")


@procedure("D1-01", "体制文書", "AI開発体制の規律文書が実在するか")
def d1_01(ctx: Context, res: ProcedureResult) -> None:
    found = [d for d in DISCIPLINE_DOCS if ctx.exists(d)]
    superior = [d for d in SUPERIOR_DOCS if ctx.exists(d)]
    res.examined = (f"規律文書候補 {len(DISCIPLINE_DOCS)} 件・上位文書候補 {len(SUPERIOR_DOCS)} 件の実在を確認"
                    f"（発見: 規律 {found or 'なし'} / 上位 {superior or 'なし'}）")
    if not found:
        observe(res, HIGH, "AIへの実装規律が文書として存在しない（CLAUDE.md 等が無い）",
                "実装規律を1文書に置き、禁止事項と完了条件を明記する", ["リポジトリ直下"], key="no-discipline-doc")
    if not superior:
        observe(res, MEDIUM, "実装担当より上位に立つ文書（監督・所有者定義）が無い。"
                            "規律の変更を誰が許可するのかが構造として決まっていない",
                "SUPERVISOR.md 相当と CODEOWNERS を置き、変更権限を分離する", ["リポジトリ直下"],
                key="no-superior-doc")


@procedure("D1-02", "体制文書", "上位文書・規律文書が実装AIから書き換え可能でないか")
def d1_02(ctx: Context, res: ProcedureResult) -> None:
    targets = [d for d in DISCIPLINE_DOCS + SUPERIOR_DOCS if ctx.exists(d)]
    if not targets:
        unverifiable(res, "保護対象となる文書が存在しないため、保護の有無を判定できない（D1-01 の所見を見ること）",
                     examined="規律文書・上位文書の実在確認")
        return

    codeowners = None
    for c in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        if ctx.exists(c):
            codeowners = ctx.read(c) or ""
            break
    manifest = ctx.read(os.path.join(".audit", "MANIFEST.sha256"))
    hook_bodies = _hook_bodies(ctx)

    unprotected = []
    for t in targets:
        by_owner = bool(codeowners and (os.path.basename(t) in codeowners or "*" in codeowners))
        by_manifest = bool(manifest and t in manifest)
        by_hook = any(t in b for b in hook_bodies.values())
        if not (by_owner or by_manifest or by_hook):
            unprotected.append(t)

    res.examined = (f"{len(targets)} 件の文書について、CODEOWNERS・監査マニフェスト・フック本文の"
                    f"いずれかで保護されているかを照合（CODEOWNERS={'有' if codeowners else '無'} / "
                    f"MANIFEST={'有' if manifest else '無'} / フック {len(hook_bodies)} 本）")
    for t in unprotected:
        observe(res, HIGH, f"`{t}` は実装セッションのAIが書き換えても機械的に検知されない",
                "CODEOWNERS で人間の承認を必須にするか、監査マニフェストへ登録して照合対象にする",
                [t], key=f"unprotected-doc:{t}")


@procedure("D2-01", "フォルダ構成", "実データ候補が git の外に置かれているか（.gitignore 単独防壁でないか）")
def d2_01(ctx: Context, res: ProcedureResult) -> None:
    tracked = set(ctx.tracked())
    candidates, inspected = [], 0
    for root, dirs, files in os.walk(ctx.repo):
        dirs[:] = [d for d in dirs if not any(f"{d}/" == g or d == g.rstrip("/") for g in GENERATED_DIRS)
                   and d != ".git"]
        for name in files:
            abs_p = os.path.join(root, name)
            rel = os.path.relpath(abs_p, ctx.repo)
            inspected += 1
            if inspected > 20000:
                break
            risk = pathmod.opaque_risk(rel) if pathmod.is_opaque_data(rel) else None
            hint = any(w.lower() in rel.lower() for w in pathmod.PERSON_HINT_WORDS)
            if (risk or hint) and rel not in tracked:
                candidates.append(rel)

    res.examined = (f"作業ツリー {inspected} ファイルを走査し、人物を示す語・機械検査できない形式を持つ"
                    f"未追跡ファイルを {len(candidates)} 件検出")
    if candidates:
        shown = candidates[:12]
        observe(res, HIGH,
                f"実データ候補 {len(candidates)} 件が作業ツリーにあり、追跡外である"
                f"（＝`.gitignore` の1行が唯一の防壁。ignore を1行崩せば公開される）",
                "実データはリポジトリの外（別ディレクトリ・別ボリューム）へ移し、"
                "リポジトリ内には受け入れ口を置かない。ignore に依存した保護をやめる",
                shown + ([f"…ほか {len(candidates) - len(shown)} 件"] if len(candidates) > len(shown) else []),
                key="realdata-in-worktree")


@procedure("D2-02", "フォルダ構成", "追跡してはならないものが追跡下に入っていないか")
def d2_02(ctx: Context, res: ProcedureResult) -> None:
    if not ctx.is_git:
        unverifiable(res, "git リポジトリではないため追跡状態を検査できない", examined="git 判定")
        return
    tracked = ctx.tracked()
    rules = (
        (CRITICAL, "秘密の実体", lambda p: fnmatch.fnmatch(os.path.basename(p), ".env")
         or (os.path.basename(p).startswith(".env.") and ".example" not in p and ".sample" not in p)),
        (CRITICAL, "非公開データ置き場", lambda p: "/private/" in f"/{p}" or p.startswith("private/")),
        (CRITICAL, "人物を含みうる不透明ファイル",
         lambda p: pathmod.is_opaque_data(p) and any(w.lower() in p.lower() for w in pathmod.PERSON_HINT_WORDS)),
        # 「production」と名の付く投入データ。中身に人物データが無ければ
        # マスタ（期・選考段・評価観点など）なので、High ではなく Medium にする。
        # 名前だけで重く扱うと、本当の混入が埋もれる。
        (HIGH, "本番投入用データ", lambda p: bool(re.search(r"production.*\.(sql|csv|json)$", p, re.I))),
        (MEDIUM, "生成物", lambda p: any(g in f"{p}" for g in GENERATED_DIRS) or p.endswith(".tsbuildinfo")),
    )
    hits: dict = {}
    for p in tracked:
        for sev, label, pred in rules:
            if pred(p):
                hits.setdefault((sev, label), []).append(p)
                break
    # 本番投入用データは中身を見て重大度を決める（名前だけで断定しない）
    from ..scan import scan_text
    key = (HIGH, "本番投入用データ")
    if key in hits:
        with_pii = []
        for rel in hits[key]:
            body = ctx.read(rel) or ""
            # 断定できない弱い検出（WEAK）は「人物データあり」の根拠にしない。
            if [h for h in scan_text(rel, body) if h.rule != "JP_PERSON_NAME_WEAK"]:
                with_pii.append(rel)
        if not with_pii:
            hits[(MEDIUM, "本番投入用データ（人物データは検出されず）")] = hits.pop(key)

    res.examined = f"追跡ファイル {len(tracked)} 件を5分類の禁止パターンへ突合"
    for (sev, label), files in sorted(hits.items(), key=lambda kv: kv[0][0]):
        shown = files[:8]
        observe(res, sev, f"{label} が追跡下にある（{len(files)} 件）",
                "追跡から外し、必要なら履歴からの除去を人間の承認のもとで行う（.audit/IRREVERSIBLE_OPS.md）",
                shown + ([f"…ほか {len(files) - len(shown)} 件"] if len(files) > len(shown) else []),
                key=f"tracked-forbidden:{label}")
