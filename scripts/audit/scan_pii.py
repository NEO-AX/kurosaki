#!/usr/bin/env python3
"""仕様書 3-1 のパス。実体は `kurosaki` パッケージ（このファイルは薄い入口）。

対象リポジトリへコピーして使うことも、ツール側から直接呼ぶこともできる。
どちらの場合も検出ロジックの正本はツール側にある（P2）。
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOL_ROOT = os.path.dirname(os.path.dirname(_HERE))
if os.path.isdir(os.path.join(_TOOL_ROOT, "kurosaki")):
    sys.path.insert(0, _TOOL_ROOT)
elif os.environ.get("KUROSAKI_HOME"):
    sys.path.insert(0, os.environ["KUROSAKI_HOME"])
else:
    sys.stderr.write(
        "kurosaki パッケージが見つからない。KUROSAKI_HOME にツールの場所を設定するか、"
        "ツール同梱の scripts/audit/scan_pii.py から実行すること。\n")
    raise SystemExit(2)

from kurosaki.cli import main  # noqa: E402

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-"):
        argv = ["scan"] + argv
    raise SystemExit(main(argv))
