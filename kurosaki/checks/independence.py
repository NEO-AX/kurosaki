"""領域7 —— 監査の独立性（P2 不可侵性）。

独立ツールにした最大の利得がここ。検出ロジックの正本は監査法人側（このツール）にあり、
被監査リポジトリへ配るのはフック・CI・基準書だけ。配ったファイルはインストール時の
ハッシュを `.audit/MANIFEST.sha256` に記録し、**ツール側の雛形と現物の両方**に照合する。

- 現物 ≠ マニフェスト → 導入後に改変された（Critical）
- マニフェスト = 現物 だが ツール雛形 ≠ 現物 → 雛形が更新された可能性（Medium。改変とは区別する）
"""

from __future__ import annotations

import hashlib
import os

from ..rules import CRITICAL, HIGH, LOW, MEDIUM
from .base import Context, ProcedureResult, observe, procedure, unverifiable

MANIFEST_REL = os.path.join(".audit", "MANIFEST.sha256")


def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def parse_manifest(text: str) -> dict:
    """`<sha256>  <相対パス>` 形式。解釈できない行は捨てずに呼び出し側へ渡す。"""
    entries, bad = {}, []
    for lineno, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            bad.append(lineno)
            continue
        entries[parts[1].strip()] = parts[0]
    return {"entries": entries, "bad_lines": bad}


def template_path(tool_root: str, rel: str) -> str | None:
    """被監査リポジトリの相対パス → ツール側の雛形パス。"""
    cand = os.path.join(tool_root, "templates", rel)
    return cand if os.path.isfile(cand) else None


@procedure("D7-01", "監査の独立性", "配置済みの監査基盤が導入後に改変されていないか")
def d7_01(ctx: Context, res: ProcedureResult) -> None:
    raw = ctx.read(MANIFEST_REL)
    if raw is None:
        installed = [p for p in (".audit", ".githooks") if ctx.exists(p)]
        res.examined = (f"`{MANIFEST_REL}` の実在を確認（無し）。"
                        f"監査基盤の痕跡: {installed or 'なし'}")
        observe(res, HIGH,
                "監査基盤の正本ハッシュ（MANIFEST）が無い。配置したフック・CI・基準書が"
                "書き換えられても機械的に検知できない",
                "kurosaki install を実行してマニフェストを作り、D7-01 の照合対象にする",
                [MANIFEST_REL], key="no-manifest")
        return

    man = parse_manifest(raw)
    entries = man["entries"]
    changed, missing, drifted, ok = [], [], [], []
    for rel, expect in sorted(entries.items()):
        actual = sha256_file(ctx.path(rel))
        if actual is None:
            missing.append(rel)
            continue
        if actual != expect:
            changed.append(rel)
            continue
        tpl = template_path(ctx.tool_root, rel)
        if tpl and sha256_file(tpl) != actual:
            drifted.append(rel)
        else:
            ok.append(rel)

    res.examined = (f"`{MANIFEST_REL}` の {len(entries)} 件について、現物のsha256を再計算し、"
                    f"さらにツール側 templates/ の雛形と突合"
                    f"（一致 {len(ok)} / 改変 {len(changed)} / 欠落 {len(missing)} / 雛形差 {len(drifted)}）")

    for rel in changed:
        observe(res, CRITICAL, f"`{rel}` が導入時のハッシュと一致しない（導入後に書き換えられている）",
                "改変を戻す（kurosaki install --force で正本から再配置）。改変が意図的なら"
                "人間のコミットとして記録し、マニフェストを更新する",
                [rel], key=f"audit-file-modified:{rel}")
    for rel in missing:
        observe(res, CRITICAL, f"`{rel}` がマニフェストに載っているが現物が無い（削除されている）",
                "再配置する（kurosaki install）", [rel], key=f"audit-file-removed:{rel}")
    for rel in drifted:
        observe(res, MEDIUM, f"`{rel}` は改変されていないが、ツール側の雛形と内容が違う（雛形が更新された）",
                "kurosaki install で最新の雛形へ更新する", [rel], key=f"audit-file-stale:{rel}")
    for lineno in man["bad_lines"]:
        observe(res, HIGH, f"`{MANIFEST_REL}` の {lineno} 行目を解釈できない（照合が抜ける）",
                "マニフェストを再生成する", [f"{MANIFEST_REL}:{lineno}"], key=f"manifest-bad-line:{lineno}")


@procedure("D7-02", "監査の独立性", "allowlist が抜け道になっていないか")
def d7_02(ctx: Context, res: ProcedureResult) -> None:
    from .. import allowlist as allowlist_mod

    rel = os.path.join(".audit", "allowlist.yml")
    if not ctx.exists(rel):
        res.examined = f"`{rel}` の実在を確認（無し）。除外は一切効いていない状態"
        return

    al = allowlist_mod.load(ctx.path(rel))
    raw = ctx.read(rel) or ""
    broad = [e for e in al.entries if e.path in ("*", "**", "**/*") or e.path.startswith("*")]
    all_rules = [e for e in al.entries if "*" in e.rules]
    all_fps = [e for e in al.entries if "*" in e.fingerprints]
    no_expiry = [e for e in al.entries if not e.expires]

    res.examined = (f"`{rel}` を読み、有効 {len(al.entries)} 件／無効 {len(al.problems)} 件を判定"
                    f"（広すぎるパス {len(broad)} / 全ルール除外 {len(all_rules)} / "
                    f"指紋指定なし {len(all_fps)} / 期限なし {len(no_expiry)}）")

    for p in al.problems:
        observe(res, HIGH, f"allowlist に不備がある: {p}",
                "不備を直す。直るまで除外は適用されない（fail closed のため検出は増える側に振れる）",
                [rel], key=f"allowlist-problem:{p[:40]}")
    for e in broad:
        observe(res, HIGH, f"allowlist の対象パスが広すぎる（`{e.path}`）。リポジトリ全体の検出を無効化しうる",
                "対象をファイル単位まで絞る", [rel], key=f"allowlist-broad-path:{e.path}")
    for e in all_rules:
        observe(res, HIGH, f"allowlist が `{e.path}` の**全ルール**を除外している",
                "除外するルールを列挙して限定する", [rel], key=f"allowlist-all-rules:{e.path}")
    for e in all_fps:
        observe(res, MEDIUM, f"allowlist が `{e.path}` で指紋を指定していない"
                             f"（そのパスの将来の混入も自動で除外される）",
                "検出済みの値の指紋を列挙し、新しい値は再び検出させる", [rel],
                key=f"allowlist-wildcard-fp:{e.path}")
    for e in no_expiry:
        observe(res, LOW, f"allowlist の `{e.path}` に期限が無い（一度の例外が恒久化する）",
                "expires を付け、期限が来たら再判断する", [rel], key=f"allowlist-no-expiry:{e.path}")

    # allowlist 自体が人間のコミットで入ったかを見る（AIが自分で例外を書ける状態か）
    log = ctx.git(["log", "-3", "--format=%an|%ae|%h", "--", rel]) or ""
    authors = [l for l in log.strip().split("\n") if l]
    if authors:
        res.examined += f"。直近の変更者: {', '.join(a.split('|')[0] for a in authors)}"
        ai_like = [a for a in authors if any(k in a.lower() for k in ("claude", "codex", "bot", "agent", "ai"))]
        for a in ai_like:
            observe(res, HIGH, f"allowlist が人間以外の名義で変更されている（`{a.split('|')[0]}`）。"
                               f"AIが自分に対する例外を書ける状態",
                    "allowlist の変更は人間のコミットに限る（CODEOWNERS とレビュー必須で強制する）",
                    [f"{rel} @ {a.split('|')[2]}"], key=f"allowlist-ai-authored:{a.split('|')[2]}")


@procedure("D7-03", "監査の独立性", "過去の監査調書が改変されていないか（ハッシュ連鎖）")
def d7_03(ctx: Context, res: ProcedureResult) -> None:
    from .. import workpaper

    items = workpaper.history(ctx.repo)
    if not items:
        res.examined = f"`{workpaper.REPORT_DIR}` を確認（調書なし）。初回監査として扱う"
        return

    problems = workpaper.verify_chain(ctx.repo)
    res.examined = (f"`{workpaper.REPORT_DIR}` の調書 {len(items)} 件について、"
                    f"自己ハッシュと前後の連鎖を検証（不整合 {len(problems)} 件）")

    for p in problems:
        observe(res, CRITICAL, f"監査調書の完全性が損なわれている: {p}",
                "改変された調書を復元する。復元できない場合は、その期間の監査結果を"
                "無効として扱い、再監査する",
                [os.path.join(workpaper.REPORT_DIR, p.split(":")[0])], key=f"workpaper-broken:{p[:50]}")

    # 追記専用であることの傍証: git 上で調書が「変更」されていないか
    log = ctx.git(["log", "--diff-filter=M", "--format=%h %an", "--", workpaper.REPORT_DIR]) or ""
    modified = [l for l in log.strip().split("\n") if l]
    if modified:
        observe(res, CRITICAL,
                f"調書ファイルが git 上で変更されている（追記専用のはずが {len(modified)} 回の変更）",
                "調書は追記のみ。変更した経緯を人間が説明し、該当期間を再監査する",
                [f"変更コミット: {', '.join(m.split()[0] for m in modified[:5])}"], key="workpaper-modified-in-git")
