"""監査基盤の配置。

被監査リポジトリへ書き込む唯一の経路。配るのは**フック・CI・基準書・allowlist**だけで、
検出ロジックは配らない（正本を1つに保つため）。配ったファイルのハッシュは
`.audit/MANIFEST.sha256` に記録し、以後 D7-01 が改変を検知する。

冪等。2回実行しても差分は出ない。人間が承認した allowlist は上書きしない。
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess

# (雛形の相対パス, 配置先の相対パス, 実行権限, 既存を上書きするか)
PLAN = (
    (".githooks/pre-commit", ".githooks/pre-commit", True, True),
    (".githooks/pre-push", ".githooks/pre-push", True, True),
    (".github/workflows/audit.yml", ".github/workflows/audit.yml", False, True),
    (".audit/AUDIT_CHARTER.md", ".audit/AUDIT_CHARTER.md", False, True),
    (".audit/IRREVERSIBLE_OPS.md", ".audit/IRREVERSIBLE_OPS.md", False, True),
    (".audit/allowlist.yml", ".audit/allowlist.yml", False, False),   # 人間の承認記録なので上書きしない
)
CLAUDE_FRAGMENT = "CLAUDE.audit-section.md"
MARK_BEGIN = "<!-- kurosaki:begin"
MARK_END = "<!-- kurosaki:end -->"
# マニフェストに載せる（＝改変を検知する）文書。存在するものだけ。
GUARDED_DOCS = ("CLAUDE.md", "AGENTS.md", "SUPERVISOR.md", "GEMINI.md", "CODEOWNERS", ".github/CODEOWNERS")


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write(dst: str, body: str, executable: bool) -> None:
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    if executable:
        os.chmod(dst, os.stat(dst).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def merge_claude_section(repo: str, tool_root: str, actions: list) -> None:
    """CLAUDE.md へ監査区画を差し込む。既にあれば区画だけ差し替える（他の記述は触らない）。"""
    frag_path = os.path.join(tool_root, "templates", CLAUDE_FRAGMENT)
    if not os.path.isfile(frag_path):
        return
    with open(frag_path, "r", encoding="utf-8") as fh:
        frag = fh.read().rstrip() + "\n"
    target = os.path.join(repo, "CLAUDE.md")
    if not os.path.exists(target):
        _write(target, "# CLAUDE.md\n\n" + frag, False)
        actions.append(("作成", "CLAUDE.md（監査区画のみ）"))
        return
    with open(target, "r", encoding="utf-8") as fh:
        cur = fh.read()
    if MARK_BEGIN in cur and MARK_END in cur:
        head = cur[:cur.index(MARK_BEGIN)]
        tail = cur[cur.index(MARK_END) + len(MARK_END):]
        new = head + frag.rstrip() + tail
        if new != cur:
            _write(target, new, False)
            actions.append(("更新", "CLAUDE.md の監査区画"))
        else:
            actions.append(("変更なし", "CLAUDE.md の監査区画"))
    else:
        _write(target, cur.rstrip() + "\n\n" + frag, False)
        actions.append(("追記", "CLAUDE.md へ監査区画"))


def install(repo: str, tool_root: str, force: bool = False, keep=()) -> dict:
    """`keep` に挙げたパスは配置し直さないが、マニフェストの照合対象には含める。

    対象が独自のCI定義を持つ場合（監査法人自身がその例）、雛形で上書きすると
    そのリポジトリ固有の検査が消える。上書きしないが**改変検知はする**。
    """
    actions, manifest_targets = [], []
    keep = set(keep or ())
    for src_rel, dst_rel, executable, overwrite in PLAN:
        if dst_rel in keep and os.path.exists(os.path.join(repo, dst_rel)):
            actions.append(("保持", f"{dst_rel}（このリポジトリ固有のため上書きしない）"))
            manifest_targets.append(dst_rel)
            continue
        src = os.path.join(tool_root, "templates", src_rel)
        if not os.path.isfile(src):
            actions.append(("欠落", f"雛形が無い: templates/{src_rel}"))
            continue
        dst = os.path.join(repo, dst_rel)
        with open(src, "r", encoding="utf-8") as fh:
            body = fh.read()
        if os.path.exists(dst) and not overwrite and not force:
            actions.append(("保持", f"{dst_rel}（既存を尊重。上書きするには --force）"))
        elif os.path.exists(dst) and sha256(dst) == hashlib.sha256(body.encode()).hexdigest():
            actions.append(("変更なし", dst_rel))
        else:
            _write(dst, body, executable)
            actions.append(("配置", dst_rel))
        manifest_targets.append(dst_rel)

    # フックが「どの監査ツールを呼ぶか」を、環境変数ではなくファイルで固定する。
    # このファイル自身も MANIFEST に載るので、書き換えれば D7-01 が検知する。
    tool_bin = os.path.join(tool_root, "bin", "kurosaki")
    _write(os.path.join(repo, ".audit", "TOOL_PATH"), tool_bin + "\n", False)
    manifest_targets.append(".audit/TOOL_PATH")
    actions.append(("記録", f".audit/TOOL_PATH → {tool_bin}"))

    merge_claude_section(repo, tool_root, actions)

    # git に実行させる位置をフックへ向ける（設定しなければフックは一切動かない）
    hooks_set = subprocess.run(["git", "-C", repo, "config", "core.hooksPath", ".githooks"],
                               capture_output=True)
    actions.append(("設定" if hooks_set.returncode == 0 else "失敗", "core.hooksPath=.githooks"))

    for doc in GUARDED_DOCS:
        if os.path.exists(os.path.join(repo, doc)):
            manifest_targets.append(doc)

    lines = ["# 監査基盤の正本ハッシュ。書き換えは D7-01 で検知される。",
             "# 生成: kurosaki install"]
    for rel in sorted(set(manifest_targets)):
        p = os.path.join(repo, rel)
        if os.path.isfile(p):
            lines.append(f"{sha256(p)}  {rel}")
    _write(os.path.join(repo, ".audit", "MANIFEST.sha256"), "\n".join(lines) + "\n", False)
    actions.append(("生成", f".audit/MANIFEST.sha256（{len(lines) - 2} 件）"))

    os.makedirs(os.path.join(repo, ".audit", "reports"), exist_ok=True)
    return {"actions": actions, "manifest_entries": len(lines) - 2}


def install_global(tool_root: str, bin_dir: str | None = None) -> dict:
    """PATH 上に入口を作る。どのフォルダ・どのリポジトリからでも呼べるようにする。"""
    bin_dir = os.path.expanduser(bin_dir or os.path.join("~", ".local", "bin"))
    os.makedirs(bin_dir, exist_ok=True)
    link = os.path.join(bin_dir, "kurosaki")
    target = os.path.join(tool_root, "bin", "kurosaki")
    status = []
    if os.path.islink(link) and os.path.realpath(link) == os.path.realpath(target):
        status.append(("変更なし", link))
    else:
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(target, link)
        status.append(("作成", f"{link} → {target}"))
    on_path = bin_dir in os.environ.get("PATH", "").split(os.pathsep)
    return {"actions": status, "bin_dir": bin_dir, "on_path": on_path, "link": link}
