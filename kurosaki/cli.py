"""kurosaki の入口。

    kurosaki scan    [--repo R] [--staged|--worktree|--changed-vs REF|--history|--paths F...]
    kurosaki install [--repo R]        監査基盤を対象リポジトリへ配置する（Layer 3）
    kurosaki verify  [--repo R]        配置済み監査基盤が改変されていないか照合する（P2）
    kurosaki audit   [--repo R]        独立監査AIを起動する（Layer 2）
    kurosaki selftest                  すり抜け試験（Phase 5）
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import allowlist as allowlist_mod
from . import gitio, install as install_mod, opinion, report, review as review_mod, workpaper
from .checks import base as checks_base
from .checks import data as _d, gates as _g, independence as _i, structure as _s  # noqa: F401 —— 手続の登録
from .scan import Scanner
from . import opinion_report

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_repo(arg: str | None) -> str:
    repo = os.path.abspath(arg or os.getcwd())
    if not os.path.isdir(repo):
        sys.stderr.write(f"対象が見つからない: {repo}\n")
        raise SystemExit(2)
    return repo


def _load_allow(repo: str, override: str | None):
    path = override or os.path.join(repo, ".audit", "allowlist.yml")
    return allowlist_mod.load(path)


def cmd_scan(args) -> int:
    repo = _resolve_repo(args.repo)
    allow = _load_allow(repo, args.allowlist)
    corpus = allowlist_mod.faker_ja_jp_corpus()
    mode = "paths"
    scanner = Scanner(repo, allow=allow, faker_corpus=corpus)

    if args.paths:
        result = scanner.scan_paths(args.paths)
    else:
        if not gitio.is_repo(repo):
            sys.stderr.write(f"{repo} は git リポジトリではない。--paths でファイルを直接指定するか、"
                             f"対象リポジトリを --repo で指定する。\n")
            return 2
        if args.staged:
            mode, scanner.origin = "staged", "staged"
            result = scanner.scan_staged()
        elif args.changed_vs:
            mode, scanner.origin = f"changed-vs {args.changed_vs}", f"changed-vs:{args.changed_vs}"
            result = scanner.scan_changed_vs(args.changed_vs)
        elif args.history:
            mode = "history"
            result = scanner.scan_history(limit=args.limit)
        else:
            mode = "worktree" + ("+untracked" if args.include_untracked else "")
            result = scanner.scan_worktree(include_untracked=args.include_untracked)

    meta = {"mode": mode, "repo": repo, "head": gitio.head_sha(repo) if gitio.is_repo(repo) else None,
            "strict": bool(args.strict)}
    text = report.render_json(result, meta) if args.format == "json" else report.render_text(result, meta)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        if not args.quiet:
            sys.stderr.write(f"報告を書き出した: {args.out}\n")
    if not args.quiet or args.format == "json" and not args.out:
        print(text)
    return report.exit_code(result, strict=args.strict)


def cmd_audit(args) -> int:
    """監査を実施し、意見を出し、調書を残す。

    被監査リポジトリへ書き込むのは調書（`.audit/reports/`）だけで、それも追記のみ。
    `--no-save` を付ければ一切書かない（他人のリポジトリを読むだけの監査ができる）。
    """
    repo = _resolve_repo(args.repo)
    ctx = checks_base.Context(repo, TOOL_ROOT, opts={"history": bool(args.history)})
    results = checks_base.run(ctx, only=args.only)
    if not results:
        sys.stderr.write(f"該当する手続が無い（--only {args.only}）\n")
        return 2

    op = opinion.form(results, total_registered=len(checks_base.registry()))
    obs = [o for r in results for o in r.observations]
    repeats = workpaper.repeated(repo, obs)

    payload = {
        "schema": "kurosaki.audit/1",
        "tool": f"kurosaki/{__version__}",
        "repo": repo,
        "head": ctx.head() if ctx.is_git else "no-git",
        "opinion": op,
        "procedures": [r.to_dict() for r in results],
        "observations": [dict(o.to_dict(), repeat_count=repeats.get(o.fingerprint, 0)) for o in obs],
    }

    saved = None
    if not args.no_save and ctx.is_git:
        try:
            saved = workpaper.save(repo, payload)
            payload["workpaper"] = saved
        except OSError as exc:
            sys.stderr.write(f"調書を保存できなかった: {exc}\n")

    text = (json.dumps(payload, ensure_ascii=False, indent=2) if args.format == "json"
            else opinion_report.render(payload, repeats))
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if not args.quiet:
        print(text)
    if saved and not args.quiet and args.format != "json":
        print(f"\n調書: {saved}")
    return opinion.exit_code(op)


def cmd_install(args) -> int:
    repo = _resolve_repo(args.repo)
    if not gitio.is_repo(repo):
        sys.stderr.write(f"{repo} は git リポジトリではない。監査基盤はリポジトリに対して配置する。\n")
        return 2
    result = install_mod.install(repo, TOOL_ROOT, force=args.force)
    print(f"監査基盤を配置した: {repo}")
    for kind, what in result["actions"]:
        print(f"  [{kind}] {what}")
    print("\n次にすること:")
    print(f"  1. kurosaki audit --repo {repo}   ← 意見を確認する")
    print("  2. 配置されたファイルを**人間のコミット**として記録する")
    print("  3. CI のリポジトリ変数 KUROSAKI_REPO に監査ツールの取得先を設定する")
    return 0


def cmd_install_global(args) -> int:
    result = install_mod.install_global(TOOL_ROOT, args.bin_dir)
    for kind, what in result["actions"]:
        print(f"  [{kind}] {what}")
    if not result["on_path"]:
        print(f"\n注意: {result['bin_dir']} が PATH に入っていない。次を shell 設定へ追加する:")
        print(f'  export PATH="{result["bin_dir"]}:$PATH"')
    else:
        print(f"\n{result['bin_dir']} は PATH 上にある。どのフォルダからでも `kurosaki` で呼べる。")
    return 0


def cmd_review(args) -> int:
    """Layer 2 —— 独立監査AIによる差分審査。"""
    repo = _resolve_repo(args.repo)
    try:
        result = review_mod.review(repo, TOOL_ROOT, ref=args.ref, model=args.model,
                                  save=not args.no_save, dry_run=args.dry_run)
    except review_mod.ReviewError as exc:
        sys.stderr.write(f"監査AIによる審査を実施できなかった: {exc}\n")
        sys.stderr.write("（実施できなかったことを『問題なし』として扱わない。非ゼロで終了する）\n")
        return 2

    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return result["exit"]

    meta = result["meta"]
    print("独立監査AIによる差分審査")
    print(f"  対象: {meta['repo']}" + (f" （{meta['ref']}...HEAD）" if meta.get("ref") else " （未コミットの変更）"))
    print(f"  作業領域: {meta['workspace']}（リポジトリ外。実装用 CLAUDE.md を持ち込まない）")
    print(f"  与えた文脈: {', '.join(os.path.basename(s) for s in meta['context_sources'])} のみ")
    print(f"  入力: {meta['subject_files']} ファイル / {meta['input_bytes']} バイト"
          + (f" / 内容を渡せなかったファイル {meta['truncated_files']}" if meta.get("truncated_files") else ""))
    if meta.get("dry_run"):
        print("  --dry-run のため監査AIは起動していない。起動コマンドの骨格:")
        print("    " + " ".join(meta["argv"]))
        return 0

    body = result["body"]
    print(f"\n結論: {body['conclusion']}")
    print(f"実施した検査項目 {len(body['checks_performed'])} 件:")
    for c in body["checks_performed"]:
        print(f"  - [{c['result']}] {c['item']}: {c['how'][:110]}")
    findings = body.get("findings") or []
    print(f"\n所見 {len(findings)} 件:")
    for f in findings:
        print(f"  [{f['severity']}] {f['file']}:{f['line']} {f['rule']}")
        print(f"      根拠: {f['evidence']}")
        print(f"      要求する是正: {f['required_remediation']}")
    if meta.get("redacted"):
        print(f"\n注意: 監査AIの出力に生の個人情報が {meta['redacted']} 件混ざっていたため伏せた。")
    if result.get("workpaper"):
        print(f"\n調書: {result['workpaper']}")
    return result["exit"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kurosaki", description="独立監査ツール（金融庁の黒崎）")
    p.add_argument("--version", action="version", version=f"kurosaki {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="PII走査（Layer 1）")
    s.add_argument("--repo", help="対象リポジトリ（既定: カレント）")
    s.add_argument("--staged", action="store_true", help="ステージ済みの内容を走査（pre-commit用）")
    s.add_argument("--worktree", action="store_true", help="追跡ファイル全体を走査（既定）")
    s.add_argument("--include-untracked", action="store_true", help="未追跡ファイルも走査する")
    s.add_argument("--changed-vs", metavar="REF", help="REF と比べて変更されたファイルの全内容を走査")
    s.add_argument("--history", action="store_true", help="履歴の全ブロブを走査（週次用）")
    s.add_argument("--limit", type=int, help="履歴走査のブロブ上限")
    s.add_argument("--paths", nargs="+", help="走査するファイルを直接指定（gitを使わない）")
    s.add_argument("--allowlist", help="allowlist.yml のパス（既定: <repo>/.audit/allowlist.yml）")
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument("--out", help="報告の書き出し先")
    s.add_argument("--strict", action="store_true", help="Medium も FAIL 扱いにする")
    s.add_argument("--quiet", action="store_true", help="標準出力へ出さない（--out と併用）")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("audit", help="体制監査（全領域）を実施し、意見と調書を出す")
    a.add_argument("--repo", help="被監査リポジトリ（既定: カレント）")
    a.add_argument("--only", nargs="+", metavar="ID|領域",
                   help="実施する手続を限定（例: --only D3 D7-01 / --only 機械ゲート）")
    a.add_argument("--history", action="store_true", help="PII走査を履歴全ブロブに広げる（重い）")
    a.add_argument("--format", choices=("text", "json"), default="text")
    a.add_argument("--out", help="報告の書き出し先")
    a.add_argument("--no-save", action="store_true", help="調書を保存しない（読み取りのみの監査）")
    a.add_argument("--quiet", action="store_true")
    a.set_defaults(func=cmd_audit)

    i = sub.add_parser("install", help="監査基盤を対象リポジトリへ配置する")
    i.add_argument("--repo", help="配置先リポジトリ（既定: カレント）")
    i.add_argument("--force", action="store_true", help="既存の allowlist も雛形で上書きする")
    i.set_defaults(func=cmd_install)

    g = sub.add_parser("install-global", help="PATH 上に入口を作る（どこからでも呼べるようにする）")
    g.add_argument("--bin-dir", help="配置先（既定: ~/.local/bin）")
    g.set_defaults(func=cmd_install_global)

    v = sub.add_parser("review", help="独立監査AIによる差分審査（Layer 2）")
    v.add_argument("--repo", help="被監査リポジトリ（既定: カレント）")
    v.add_argument("--ref", help="比較対象の ref（既定: 未コミットの変更、無ければ HEAD）")
    v.add_argument("--model", help="監査AIのモデル（既定: claude の既定）")
    v.add_argument("--format", choices=("text", "json"), default="text")
    v.add_argument("--no-save", action="store_true", help="調書を保存しない")
    v.add_argument("--dry-run", action="store_true", help="起動せず、渡す文脈と起動条件だけを表示する")
    v.set_defaults(func=cmd_review)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
