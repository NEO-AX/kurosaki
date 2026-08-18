#!/bin/sh
# 金融庁の黒崎 —— Layer 2（独立監査AI）の起動口。仕様 3-6 のパス。
#
# 実体は Python 側（kurosaki/review.py）にある。ここが薄いのは、
# 監査AIの起動条件（作業領域・システムプロンプト・ツール無効化・スキーマ強制）を
# シェルとPythonの2箇所に分けて書くと、片方だけ緩む事故が起きるため。
#
# 使い方:
#   run_audit.sh <被監査リポジトリ> [比較ref] [--dry-run]
#
# 独立性について（`claude --help` 2.1.47 で実在を確認したフラグのみ使用）:
#   --system-prompt      既定のシステムプロンプトを監査基準書＋監査人プロンプトへ置換
#   --tools ""           全ツール無効。監査AIは追加のファイルを読めない
#   --setting-sources    project / local の設定継承を切る（空が不可なら user へ落とす）
#   --disable-slash-commands / --strict-mcp-config / --no-session-persistence
#   --json-schema        出力を固定スキーマへ強制（散文を受け付けない）
# 作業領域は mktemp -d で**リポジトリの外**に作る。実装用 CLAUDE.md を持ち込まない。
#
# Claude Code セッションの内側からは起動できない（ランタイムが入れ子を禁じている）。
# 通常のシェルから実行すること。
set -eu

repo=${1:-}
if [ -z "$repo" ]; then
  echo "使い方: run_audit.sh <被監査リポジトリ> [比較ref] [--dry-run]" >&2
  exit 2
fi
shift

ref=""
dry=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry="--dry-run" ;;
    *) ref="$arg" ;;
  esac
done

here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
exec "$here/bin/kurosaki" review --repo "$repo" ${ref:+--ref "$ref"} ${dry:+--dry-run}
