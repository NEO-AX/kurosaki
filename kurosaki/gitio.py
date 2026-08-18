"""git との入出力。対象リポジトリの中では何も変更しない（読み取りのみ）。"""

from __future__ import annotations

import subprocess


class GitError(Exception):
    pass


def run(repo: str, args: list, binary: bool = False, check: bool = True):
    proc = subprocess.run(["git", "-C", repo] + args, capture_output=True)
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args[:3])}...: {proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout if binary else proc.stdout.decode("utf-8", "replace")


def is_repo(repo: str) -> bool:
    try:
        return run(repo, ["rev-parse", "--is-inside-work-tree"]).strip() == "true"
    except GitError:
        return False


def toplevel(repo: str) -> str:
    return run(repo, ["rev-parse", "--show-toplevel"]).strip()


def tracked_files(repo: str) -> list:
    return [p for p in run(repo, ["ls-files", "-z"]).split("\0") if p]


def untracked_files(repo: str) -> list:
    return [p for p in run(repo, ["ls-files", "-z", "--others", "--exclude-standard"]).split("\0") if p]


def staged_files(repo: str) -> list:
    out = run(repo, ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"])
    return [p for p in out.split("\0") if p]


def changed_vs(repo: str, ref: str) -> list:
    out = run(repo, ["diff", "--name-only", "--diff-filter=ACMR", "-z", ref])
    return [p for p in out.split("\0") if p]


def read_staged(repo: str, path: str) -> bytes:
    return run(repo, ["show", f":{path}"], binary=True, check=False)


def read_rev(repo: str, rev: str, path: str) -> bytes:
    return run(repo, ["show", f"{rev}:{path}"], binary=True, check=False)


def read_blob(repo: str, sha: str) -> bytes:
    return run(repo, ["cat-file", "blob", sha], binary=True, check=False)


def head_sha(repo: str) -> str:
    try:
        return run(repo, ["rev-parse", "--short", "HEAD"]).strip()
    except GitError:
        return "unknown"


def all_blobs(repo: str):
    """履歴全体のブロブを (sha, path) で列挙する。同じ内容は1回だけ返す。

    ジョブC（週次の履歴全走査）用。過去に混入して後で消したファイルは
    作業ツリーには無いが、履歴に残っていれば公開されたままである。
    """
    out = run(repo, ["rev-list", "--objects", "--all"])
    seen = set()
    for line in out.split("\n"):
        line = line.strip()
        if not line or " " not in line:
            continue
        sha, path = line.split(" ", 1)
        if sha in seen:
            continue
        seen.add(sha)
        yield sha, path


def commits_touching(repo: str, path: str, limit: int = 3) -> list:
    out = run(repo, ["log", f"-{limit}", "--format=%h %ad %an", "--date=short", "--", path], check=False)
    return [l for l in out.strip().split("\n") if l]
