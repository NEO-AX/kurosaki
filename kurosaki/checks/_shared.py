"""検査手続が共有する読み取りヘルパ。"""

from __future__ import annotations

import os

from .base import Context


def hook_dirs(ctx: Context) -> list:
    """有効なフック置き場。`core.hooksPath` の指定を尊重する。

    `.githooks/` にフックを置いても `core.hooksPath` を設定していなければ
    git は一切実行しない。「置いてあるのに動いていない」を見抜くため、
    設定値と実体を分けて返す。
    """
    cfg = (ctx.git(["config", "--get", "core.hooksPath"]) or "").strip()
    return [cfg] if cfg else [os.path.join(".git", "hooks")]


def hook_bodies(ctx: Context) -> dict:
    out = {}
    dirs = hook_dirs(ctx) + [d for d in (".githooks",) if d not in hook_dirs(ctx)]
    for d in dirs:
        base = ctx.path(d)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if name.endswith(".sample"):
                continue
            p = os.path.join(base, name)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    out[os.path.join(d, name)] = fh.read(64 * 1024)
            except OSError:
                continue
    return out


def is_executable(ctx: Context, rel: str) -> bool:
    return os.access(ctx.path(rel), os.X_OK)
