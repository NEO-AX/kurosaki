"""領域3・5 —— 機械ゲートと不可逆操作。

ここが「文章の規律」と「機械の規律」を分ける層。
フックが置いてあることではなく、**git が実際に実行する場所に、実行可能な形であるか**を見る。
"""

from __future__ import annotations

import json
import os
import re

from ..comments import strip_comments
from ..rules import CRITICAL, HIGH, LOW, MEDIUM
from ._shared import hook_bodies, hook_dirs, is_executable
from .base import Context, ProcedureResult, observe, procedure, unverifiable

REQUIRED_HOOKS = ("pre-commit", "pre-push")


@procedure("D3-01", "機械ゲート", "git が実行するフックが実在し、実行可能か")
def d3_01(ctx: Context, res: ProcedureResult) -> None:
    if not ctx.is_git:
        unverifiable(res, "git リポジトリではないためフックを検査できない", examined="git 判定")
        return
    cfg = (ctx.git(["config", "--get", "core.hooksPath"]) or "").strip()
    active_dir = cfg or os.path.join(".git", "hooks")
    present, missing, not_exec = [], [], []
    for h in REQUIRED_HOOKS:
        rel = os.path.join(active_dir, h)
        if os.path.isfile(ctx.path(rel)):
            present.append(rel)
            if not is_executable(ctx, rel):
                not_exec.append(rel)
        else:
            missing.append(rel)

    # 置いてあるのに git が見ていない場所（典型的な失敗）
    orphan = []
    if not cfg and os.path.isdir(ctx.path(".githooks")):
        for h in REQUIRED_HOOKS:
            if os.path.isfile(ctx.path(os.path.join(".githooks", h))):
                orphan.append(os.path.join(".githooks", h))

    res.examined = (f"`core.hooksPath`={cfg or '未設定（既定 .git/hooks）'} を読み、"
                    f"{active_dir} 配下の {', '.join(REQUIRED_HOOKS)} の実在と実行権限を確認"
                    f"（実在 {len(present)} / 欠落 {len(missing)} / 実行不可 {len(not_exec)}）")

    for rel in missing:
        observe(res, HIGH, f"git が実行する位置に `{os.path.basename(rel)}` が無い（機械ゲートが不在）",
                "本ツールを呼ぶフックを配置し、`core.hooksPath` を設定して git に実行させる",
                [rel], key=f"hook-missing:{os.path.basename(rel)}")
    for rel in not_exec:
        observe(res, HIGH, f"`{rel}` に実行権限が無く、git はこれを実行しない",
                "chmod +x で実行可能にする", [rel], key=f"hook-not-exec:{rel}")
    for rel in orphan:
        observe(res, HIGH, f"`{rel}` が置かれているが `core.hooksPath` が未設定のため git は実行しない"
                           f"（フックがあるという見かけだけが残っている）",
                "git config core.hooksPath .githooks を設定する", [rel],
                key=f"hook-orphan:{rel}")


# 本ツールを呼んでいると認める呼び出し形。名前を変えても追随できるよう複数持つ。
TOOL_CALL_PATTERNS = (r"\bkurosaki\b", r"scan_pii\.py", r"kurosaki\.cli", r"KUROSAKI_HOME")


@procedure("D3-02", "機械ゲート", "フックが本ツールの検査を実際に呼んでいるか")
def d3_02(ctx: Context, res: ProcedureResult) -> None:
    bodies = hook_bodies(ctx)
    if not bodies:
        # フック不在は D3-01 の所見。ここで二重に数えない（重大度の膨張を避ける）。
        res.examined = "フックが1本も存在しないため、呼び出し内容の検査対象が無い（不在自体は D3-01 の所見）"
        return

    active = set(hook_dirs(ctx))
    calling, silent = [], []
    for rel, body in sorted(bodies.items()):
        d = os.path.dirname(rel)
        hits = any(re.search(p, body) for p in TOOL_CALL_PATTERNS)
        (calling if hits else silent).append(rel)

    res.examined = (f"フック {len(bodies)} 本の本文を読み、{len(TOOL_CALL_PATTERNS)} 種の呼び出し形を照合"
                    f"（呼んでいる: {calling or 'なし'} / 呼んでいない: {silent or 'なし'}）")

    for rel in silent:
        in_active = os.path.dirname(rel) in active
        name = os.path.basename(rel)
        if name not in REQUIRED_HOOKS:
            continue
        observe(res, HIGH,
                f"`{rel}` は存在するが監査の検査を呼んでいない"
                f"（{'git が実行する位置にある' if in_active else 'git が実行しない位置にある'}）",
                "フック本文から本ツールを呼び、非ゼロ終了で commit / push を止める",
                [rel], key=f"hook-not-calling:{name}")

    # 呼んでいても、結果を無視していれば同じこと（`|| true` は D3-04 で見るが、
    # フック単位での取り消しはここで見る）
    for rel in calling:
        body = bodies[rel]
        if re.search(r"kurosaki[^\n]*\|\|\s*true", body) or re.search(r"kurosaki[^\n]*;\s*exit\s+0", body):
            observe(res, CRITICAL, f"`{rel}` は本ツールを呼んでいるが、結果を捨てて必ず成功させている",
                    "終了コードをそのまま伝播させる（`|| true` と `exit 0` を外す）",
                    [rel], key=f"hook-neutralized:{os.path.basename(rel)}")


# CI 定義の置き場。GitHub 以外でも「定義があるか」「監査を呼んでいるか」は同じ観点で見る。
CI_LOCATIONS = (
    (".github/workflows", "dir"), (".gitlab-ci.yml", "file"), (".circleci/config.yml", "file"),
    ("Jenkinsfile", "file"), ("azure-pipelines.yml", "file"), (".buildkite", "dir"),
)


def _ci_files(ctx: Context) -> dict:
    out = {}
    for loc, kind in CI_LOCATIONS:
        if kind == "file":
            if ctx.exists(loc):
                out[loc] = ctx.read(loc) or ""
            continue
        base = ctx.path(loc)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if name.endswith((".yml", ".yaml")):
                rel = os.path.join(loc, name)
                out[rel] = ctx.read(rel) or ""
    return out


@procedure("D3-03", "機械ゲート", "CI 定義が実在し、その中で監査の検査が走るか")
def d3_03(ctx: Context, res: ProcedureResult) -> None:
    files = _ci_files(ctx)
    calling = [rel for rel, body in files.items() if any(re.search(p, body) for p in TOOL_CALL_PATTERNS)]
    res.examined = (f"CI 定義の置き場 {len(CI_LOCATIONS)} 箇所を確認し、見つかった {len(files)} 本の定義本文へ"
                    f"監査呼び出しを照合（定義: {sorted(files) or 'なし'} / 呼んでいる: {calling or 'なし'}）")

    if not files:
        observe(res, HIGH, "CI 定義が1本も無い。フックを外して push すれば何の検査も走らない",
                "監査を実行するCIを置き、pull_request と push で走らせる",
                ["リポジトリ全体（CI定義の置き場すべて）"], key="no-ci")
        return
    if not calling:
        observe(res, HIGH, f"CI 定義は {len(files)} 本あるが、どれも監査の検査を呼んでいない",
                "既存のCIに監査ジョブを足し、非ゼロ終了でジョブを落とす",
                sorted(files)[:8], key="ci-without-audit")

    # ローカルフックは `--no-verify` で飛ぶ。CI が唯一の最終防衛線であることを事実として記録する。
    if calling and not hook_bodies(ctx):
        observe(res, MEDIUM, "CI では検査が走るが、ローカルのフックが無いため commit 時点では止まらない"
                             "（push まで検出が遅れる）",
                "pre-commit フックも配置し、混入を commit 時点で止める", calling[:4], key="ci-only-no-hooks")


# 監査を「置いたまま効かなくする」定番手口。文言ではなく形で捕まえる。
NEUTRALIZE_PATTERNS = (
    # 順序に意味がある。1行に複数当たった場合、**具体的な手口の説明を優先**する。
    (r"KUROSAKI_(SKIP|DISABLE|BYPASS)", "環境変数で監査を無効化する経路がある"),
    (r"--no-verify", "`--no-verify` がスクリプト/CI に書かれている（フックを飛ばす経路）"),
    (r"continue-on-error\s*:\s*true", "continue-on-error: true でジョブの失敗が無視される"),
    (r"\|\|\s*true", "`|| true` で失敗が握り潰される"),
    (r"\|\|\s*:\s*$", "`|| :` で失敗が握り潰される"),
    (r"set\s+\+e", "`set +e` で以降の失敗が無視される"),
    (r"if\s*:\s*false", "`if: false` でステップが無効化されている"),
    # 検査の呼び出しと同じ行で結果を捨てる形だけを見る。
    # フック末尾の素の `exit 0` は「検査に通ったので push を許す」正常な処理であり、
    # これを無効化と数えると正しい雛形が Critical になる（自分の雛形で実測した）。
    (r"(?:kurosaki|scan_pii)[^\n]*;\s*exit\s+0", "検査の直後に `exit 0` で終了コードを潰している"),
)

# 「--no-verify を使うな」と書いた警告文を bypass と数えないための除外。
# 実際の抜け道は「コマンドとして実行している」場合だけ。
_RE_MESSAGE_LINE = re.compile(r"^\s*(?:echo|printf|print|#|//|--|\*|['\"])")


def _audit_related(rel: str, body: str) -> bool:
    """監査に関わる定義かどうか。監査自身の無効化は Critical、無関係なCIは Medium にする。"""
    if any(re.search(p, body) for p in TOOL_CALL_PATTERNS):
        return True
    return bool(re.search(r"audit|monitor|security|scan", rel, re.I))


@procedure("D3-04", "機械ゲート", "監査を無効化する記述（continue-on-error 等）が混入していないか")
def d3_04(ctx: Context, res: ProcedureResult) -> None:
    subjects = dict(_ci_files(ctx))
    subjects.update(hook_bodies(ctx))
    for extra in (".audit/allowlist.yml", "package.json", "Makefile"):
        if ctx.exists(extra):
            subjects[extra] = ctx.read(extra) or ""

    res.examined = (f"CI 定義・フック・{'package.json/Makefile' } を合わせた {len(subjects)} 本について、"
                    f"{len(NEUTRALIZE_PATTERNS)} 種の無効化パターンを行単位で照合"
                    f"（対象: {sorted(subjects) or 'なし'}）")
    if not subjects:
        return

    for rel, body in sorted(subjects.items()):
        audit_related = _audit_related(rel, body)
        for lineno, line in enumerate(body.split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _RE_MESSAGE_LINE.match(line):
                continue   # 画面へ出す文言。実行される抜け道ではない
            for pat, why in NEUTRALIZE_PATTERNS:
                if re.search(pat, stripped, re.M):
                    sev = CRITICAL if audit_related else MEDIUM
                    observe(res, sev,
                            f"{why}（{'監査に関わる定義' if audit_related else '監査以外の定義'}）",
                            "無効化を外す。例外が必要なら人間の承認記録とともに allowlist へ限定して書く",
                            [f"{rel}:{lineno}"], key=f"neutralize:{rel}:{pat}")
                    break


_RE_GH_SLUG = re.compile(r"github\.com[:/]+([^/\s]+)/([^/\s.]+)")


def _github_remotes(ctx: Context) -> dict:
    """リモート名 → owner/repo。GitHub 以外は対象外として返さない。"""
    out = {}
    for line in (ctx.git(["remote", "-v"]) or "").split("\n"):
        parts = line.split()
        if len(parts) < 2:
            continue
        m = _RE_GH_SLUG.search(parts[1])
        if m:
            out[parts[0]] = f"{m.group(1)}/{m.group(2)}"
    return out


@procedure("D3-05", "機械ゲート", "既定ブランチが保護され、監査の合格が必須になっているか")
def d3_05(ctx: Context, res: ProcedureResult) -> None:
    remotes = _github_remotes(ctx)
    if not remotes:
        unverifiable(res, "GitHub のリモートが無いため、ブランチ保護をAPIで確認できない",
                     examined="`git remote -v` を読み、GitHub のリモートを探索")
        return

    checked, findings, blocked = [], [], []
    for name, slug in sorted(remotes.items()):
        branch = (ctx.git(["symbolic-ref", "--quiet", "--short", "HEAD"]) or "main").strip() or "main"
        out, err = ctx.gh(["api", f"repos/{slug}/branches/{branch}/protection"])
        checked.append(f"{name}={slug}@{branch}")
        if out is None:
            # 応答の意味を区別する。ここを混ぜると過小報告になる:
            #   404 "Branch not protected" → **保護されていないことが確定した**（所見）
            #   403 "Upgrade to GitHub Pro" → プラン制限で**確認できない**（検査不能）
            #   404 "Not Found"           → 公開リポジトリで枝が実在するなら保護なしと確定できる
            e = (err or "").lower()
            if "not protected" in e:
                findings.append((HIGH, f"`{slug}` の `{branch}` はブランチ保護が設定されていない"
                                       f"（force push もCI無視のマージも止まらない）",
                                 f"unprotected-branch:{slug}"))
                continue
            if "403" in e or "upgrade to github" in e or "forbidden" in e:
                blocked.append(f"{name}={slug}: プラン制限または権限不足で確認できない（{err[:60]}）")
                continue
            if "not found" in e or "404" in e:
                vis_out, _vis_err = ctx.gh(["repo", "view", slug, "--json", "visibility"])
                if vis_out and '"PUBLIC"' in vis_out.upper():
                    findings.append((HIGH, f"`{slug}`（公開）の `{branch}` にブランチ保護が無い"
                                           f"（保護APIは公開リポジトリで利用可能。応答は未保護を意味する）",
                                     f"unprotected-branch:{slug}"))
                else:
                    blocked.append(f"{name}={slug}: 保護設定を取得できない（{err[:60]}）")
                continue
            blocked.append(f"{name}={slug}: {err}")
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            blocked.append(f"{name}={slug}: 応答を解釈できない")
            continue
        checks = ((data.get("required_status_checks") or {}).get("contexts")
                  or (data.get("required_status_checks") or {}).get("checks") or [])
        reviews = data.get("required_pull_request_reviews")
        if not checks:
            findings.append((HIGH, f"`{slug}` の `{branch}` に必須ステータスチェックが無い"
                                  f"（CIが落ちてもマージできる）", f"no-required-checks:{slug}"))
        if not reviews:
            findings.append((HIGH, f"`{slug}` の `{branch}` に人間のレビュー必須設定が無い",
                             f"no-required-review:{slug}"))

    res.examined = (f"リモート {len(remotes)} 件（{', '.join(checked)}）について GitHub の"
                    f"ブランチ保護APIを照会。取得できた {len(remotes) - len(blocked)} 件を判定")

    for sev, fact, key in findings:
        observe(res, sev, fact, "監査ジョブを required status check にし、人間のレビューを必須にする",
                ["GitHub ブランチ保護設定"], key=key)

    if blocked:
        # 「保護されているか分からない」を「保護されている」と読み替えない。
        unverifiable(res, "ブランチ保護を確認できないリモートがある（プラン制限・権限不足・未認証）: "
                          + " / ".join(blocked[:3]),
                     examined=res.examined)


@procedure("D3-06", "機械ゲート", "公開リモートの有無と、そこへ何が届く構造になっているか")
def d3_06(ctx: Context, res: ProcedureResult) -> None:
    remotes = _github_remotes(ctx)
    all_remotes = sorted({l.split()[0] for l in (ctx.git(["remote", "-v"]) or "").split("\n") if l.split()})
    if not all_remotes:
        res.examined = "`git remote -v` を読み、リモートが存在しないことを確認（公開経路なし）"
        return

    public, private, unknown = [], [], []
    for name, slug in sorted(remotes.items()):
        out, err = ctx.gh(["repo", "view", slug, "--json", "visibility,isPrivate"])
        if out is None:
            unknown.append(f"{name}={slug}({err[:40]})")
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            unknown.append(f"{name}={slug}(応答不正)")
            continue
        (public if not data.get("isPrivate") else private).append(f"{name}={slug}")

    non_github = [r for r in all_remotes if r not in remotes]
    res.examined = (f"リモート {len(all_remotes)} 件を列挙し、GitHub の {len(remotes)} 件について公開状態を照会"
                    f"（公開: {public or 'なし'} / 非公開: {private or 'なし'} / 不明: {unknown or 'なし'}"
                    f"{' / GitHub以外: ' + str(non_github) if non_github else ''}）")

    for r in public:
        observe(res, HIGH,
                f"公開リモート `{r}` がある。ここへ push されたものは即時に公開される"
                f"（履歴に入れば削除しても公開済みの事実は消えない）",
                "公開先を持つ必要があるなら、公開先へ push する前段に監査の合格を必須にする。"
                "不要なら公開リモートを外す（リポジトリ設定の変更は人間が行う）",
                ["git remote -v"], key=f"public-remote:{r}")

    if len(remotes) > 1:
        observe(res, MEDIUM,
                f"リモートが {len(remotes)} 件ある（公開と非公開が混在しうる）。"
                f"push 先を1つ間違えるだけで公開範囲が変わる",
                "既定の push 先を1つに固定し、他方への push は明示操作のみに限る",
                [f"remotes={sorted(remotes)}"], key="multi-remote")

    # GitHub 以外のホストは API で公開状態を判定できない。「分からない」を
    # 「公開されていない」と読み替えないため、検査不能として意見へ反映する。
    if unknown or non_github:
        detail = list(unknown[:3]) + [f"{r}(GitHub以外のホスト)" for r in non_github[:3]]
        unverifiable(res, "公開状態を確認できないリモートがある: " + " / ".join(detail), examined=res.examined)


# 不可逆操作一覧に**必ず載っていなければならない**項目。
# ここに挙げた操作は、機械検査と監査を通過しても人間の承認なしに実行してはならない。
REQUIRED_IRREVERSIBLE = (
    ("force push / 履歴改変", (r"force[- ]?push", r"--force", r"filter-repo", r"filter-branch", r"履歴改変")),
    ("本番DBへの書き込み・DDL", (r"本番.*(DB|データベース|DDL|DML)", r"production.*(db|database|migrat)", r"drop\s+table")),
    ("行レベル権限の削除・無効化", (r"RLS", r"row level security", r"ポリシー.*(削除|無効)")),
    ("リポジトリ公開範囲の変更", (r"公開範囲", r"visibility", r"public.*(変更|切替)", r"private.*(変更|切替)")),
    ("本番環境変数の変更・デプロイ", (r"環境変数", r"env.*(変更|更新)", r"deploy", r"デプロイ")),
    ("データの削除", (r"(データ|レコード|テーブル).*削除", r"delete\s+from", r"truncate", r"rm\s+-rf")),
)


@procedure("D5-01", "不可逆操作", "不可逆操作の一覧と承認手順が文書として実在し、必須項目を網羅しているか")
def d5_01(ctx: Context, res: ProcedureResult) -> None:
    candidates = (os.path.join(".audit", "IRREVERSIBLE_OPS.md"), "IRREVERSIBLE_OPS.md",
                  os.path.join("docs", "IRREVERSIBLE_OPS.md"))
    found = next((c for c in candidates if ctx.exists(c)), None)
    if not found:
        res.examined = f"不可逆操作一覧の候補 {len(candidates)} 箇所を確認し、いずれも存在しないことを確認"
        observe(res, HIGH,
                "不可逆操作の一覧が無い。何が「実行してはならない操作」なのかが体制として定義されていない",
                ".audit/IRREVERSIBLE_OPS.md を置き、操作ごとに承認者と手順を明記する",
                [c for c in candidates], key="no-irreversible-list")
        return

    body = ctx.read(found) or ""
    missing = [label for label, pats in REQUIRED_IRREVERSIBLE
               if not any(re.search(p, body, re.I) for p in pats)]
    has_approver = bool(re.search(r"(承認|approver|approved_by|人間|human)", body, re.I))

    res.examined = (f"`{found}`（{len(body)} 文字）を読み、必須 {len(REQUIRED_IRREVERSIBLE)} 項目の記載と"
                    f"承認者の明記を照合（欠落 {len(missing)} 項目 / 承認者記載 {'有' if has_approver else '無'}）")

    for label in missing:
        observe(res, HIGH, f"不可逆操作一覧に「{label}」の記載が無い",
                f"「{label}」を一覧へ追加し、承認者と手順を書く", [found], key=f"irreversible-missing:{label}")
    if not has_approver:
        observe(res, HIGH, f"`{found}` に承認者（誰が承認するのか）の記載が無い。一覧だけあっても手順にならない",
                "操作ごとに承認者と承認の記録方法を書く", [found], key="irreversible-no-approver")


# 本番・不可逆へ到達するスクリプト名。package.json / Makefile の入口を見る。
PROD_SCRIPT_PATTERNS = (
    (r"deploy.*prod|prod.*deploy|deploy:production", "本番デプロイ"),
    (r"migrat.*prod|prod.*migrat", "本番マイグレーション"),
    (r"db:(reset|restore|drop)", "DBの初期化・復元"),
    (r"remove|delete|purge|truncate", "データ削除"),
    (r"push.*force|force.*push", "force push"),
)
# 人間の確認を伴っていると認める形。**機構だけを見る。**
# 「確認」「問い」のような語句一致にしていたところ、`// 確認なしで流す` という
# コメントで人間ゲートありと誤認した。コメントに一語書けば通る判定は判定ではない。
CONFIRM_PATTERNS = (
    r"/dev/tty",                       # 端末から直接読む（非対話セッションでは失敗する＝AI単独では通らない）
    r"readline\s*\.\s*createInterface", r"createInterface\s*\(",
    r"process\.stdin", r"prompts?\s*\(", r"confirm\s*\(", r"inquirer", r"questionary",
    r"\binput\s*\(", r"read\s+-[rp]", r"select\s+.*\bin\b.*yes",
)
# AIに渡すと不可逆操作へ到達しうる許可パターン
DANGEROUS_ALLOW = (
    (r"^Bash\(\*\)$|^Bash$", "Bash 全許可"),
    (r"git\s+push", "git push"),
    (r"--force", "force 付きコマンド"),
    (r"deploy", "デプロイ"),
    (r"production", "本番向けコマンド"),
    (r"psql|supabase|vercel", "本番基盤のCLI"),
    (r"rm\s+-rf|rm\(", "再帰削除"),
    (r"gh\s+(repo|api)", "リポジトリ設定を変えうるGitHub操作"),
)


@procedure("D5-02", "不可逆操作", "本番・不可逆へ到達する経路に人間ゲートがあるか（AIへ渡した権限も含む）")
def d5_02(ctx: Context, res: ProcedureResult) -> None:
    examined = []

    # (1) package.json の入口
    pkg_raw = ctx.read("package.json")
    prod_scripts = {}
    if pkg_raw:
        try:
            scripts = (json.loads(pkg_raw).get("scripts") or {})
        except json.JSONDecodeError:
            scripts = {}
            observe(res, MEDIUM, "package.json を解釈できないため、本番到達スクリプトを列挙できない",
                    "package.json の構文を直す", ["package.json"], key="pkg-unparsable")
        for name, cmd in scripts.items():
            for pat, label in PROD_SCRIPT_PATTERNS:
                if re.search(pat, f"{name} {cmd}", re.I):
                    prod_scripts[name] = (cmd, label)
                    break
        examined.append(f"package.json の scripts {len(scripts)} 件から本番到達候補 {len(prod_scripts)} 件を抽出")

    for name, (cmd, label) in sorted(prod_scripts.items()):
        # 実体スクリプトの中身に人間確認があるかを見る
        target = re.search(r"([\w./-]+\.(?:ts|js|mjs|sh|py))", cmd)
        body = ctx.read(target.group(1)) if target else None
        has_confirm = False
        if body:
            # コメントを潰してから機構を探す（コメントの文言を根拠に採らない）
            code = strip_comments(body, os.path.splitext(target.group(1))[1])
            has_confirm = any(re.search(p, code, re.I) for p in CONFIRM_PATTERNS)
        if not has_confirm:
            observe(res, HIGH,
                    f"`pnpm {name}`（{label}）は人間の確認なしに実行できる"
                    f"{'（実体 ' + target.group(1) + ' に確認処理が無い）' if target else '（実体を特定できない）'}",
                    "実行前に TTY 経由の確認を要求する。AIが自分で設定できる環境変数での解除にしない",
                    [f"package.json scripts.{name}"] + ([target.group(1)] if target else []),
                    key=f"prod-script-no-gate:{name}")

    # (2) AIへ渡した許可（実装AIが自分で書き換えられる場所なので、ゲートとしては数えない）
    for settings_rel in (os.path.join(".claude", "settings.local.json"),
                         os.path.join(".claude", "settings.json")):
        raw = ctx.read(settings_rel)
        if not raw:
            continue
        try:
            allow = ((json.loads(raw).get("permissions") or {}).get("allow") or [])
        except json.JSONDecodeError:
            observe(res, MEDIUM, f"`{settings_rel}` を解釈できないため、AIへ渡した権限を列挙できない",
                    "JSON の構文を直す", [settings_rel], key=f"settings-unparsable:{settings_rel}")
            continue
        examined.append(f"{settings_rel} の allow {len(allow)} 件を危険パターン {len(DANGEROUS_ALLOW)} 種へ突合")
        for entry in allow:
            for pat, label in DANGEROUS_ALLOW:
                if re.search(pat, str(entry), re.I):
                    observe(res, HIGH,
                            f"AIに `{label}` に相当する許可が与えられている（`{str(entry)[:60]}`）。"
                            f"不可逆操作へAI単独で到達できる",
                            "許可を取り消し、不可逆操作は人間が実行する手順（IRREVERSIBLE_OPS）へ移す",
                            [settings_rel], key=f"dangerous-allow:{label}")
                    break

    if not examined:
        unverifiable(res, "package.json も .claude/settings*.json も無く、本番到達経路を列挙できない",
                     examined="package.json / .claude/settings*.json の実在確認")
        return
    res.examined = "。".join(examined)
