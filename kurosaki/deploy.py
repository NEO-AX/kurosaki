"""デプロイ証跡ゲート。

なぜ要るか（実測に基づく）:
`vercel --prod` は git の ref ではなく**作業ディレクトリ**を送る。したがって
本番に出るのは「リポジトリの中身」ではなく「その瞬間の作業ツリー」であり、
未コミット・未追跡のファイルも一緒に出る。実測した対象では、本番へ40回出しながら
一度も push しておらず、**何を出したのかを事後に突き合わせる材料が無かった**。

このゲートがやること:
1. **実際に送られるファイル**を列挙する（`.vercelignore` を解釈する。
   追跡状態ではなくアップロード対象で判断する）
2. それを機械検査にかける（Critical/High があれば出さない）
3. 出所を記録する（コミット・作業ツリーの汚れ・未pushの有無・送信先）
4. 汚れた作業ツリー／未pushがある状態は、端末からの人間承認なしに通さない
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import sys

from . import allowlist as allowlist_mod
from . import gitio, workpaper
from .rules import CRITICAL, HIGH
from .scan import Scanner

DEPLOY_DIR = os.path.join(".audit", "deploys")
ALWAYS_SKIP = (".git/",)


def read_vercelignore(repo: str) -> list:
    """`.vercelignore` を読む。無ければ Vercel CLI は `.gitignore` を使う。"""
    for name in (".vercelignore", ".gitignore"):
        p = os.path.join(repo, name)
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                pats = [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
            return pats
    return []


def _ignored(rel: str, patterns: list) -> bool:
    parts = rel.split("/")
    for pat in patterns:
        pat = pat.rstrip("/")
        if not pat or pat.startswith("!"):
            continue
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
            return True
        if pat in parts:                       # ディレクトリ名の一致
            return True
        if rel.startswith(pat + "/"):
            return True
    return False


def uploaded_files(repo: str) -> dict:
    """実際にアップロードされるファイルを列挙する。追跡状態では判断しない。"""
    patterns = read_vercelignore(repo)
    tracked = set(gitio.tracked_files(repo)) if gitio.is_repo(repo) else set()
    files, untracked = [], []
    for root, dirs, names in os.walk(repo):
        rel_root = os.path.relpath(root, repo)
        rel_root = "" if rel_root == "." else rel_root + "/"
        dirs[:] = [d for d in dirs if not _ignored(f"{rel_root}{d}", patterns) and d != ".git"]
        for n in names:
            rel = f"{rel_root}{n}"
            if _ignored(rel, patterns):
                continue
            files.append(rel)
            if rel not in tracked:
                untracked.append(rel)
    return {"files": sorted(files), "untracked": sorted(untracked), "patterns": patterns}


def tree_state(repo: str) -> dict:
    """作業ツリーの状態。本番へ出るものが repo の何と違うのかを数える。"""
    if not gitio.is_repo(repo):
        return {"git": False}
    porcelain = [l for l in (gitio.run(repo, ["status", "--porcelain"], check=False) or "").split("\n") if l]
    modified = [l[3:] for l in porcelain if not l.startswith("??")]
    untracked = [l[3:] for l in porcelain if l.startswith("??")]
    upstream = (gitio.run(repo, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
                          check=False) or "").strip()
    ahead = 0
    if upstream:
        out = gitio.run(repo, ["rev-list", "--count", f"{upstream}..HEAD"], check=False) or "0"
        ahead = int(out.strip() or 0)
    return {"git": True, "head": gitio.head_sha(repo),
            "branch": (gitio.run(repo, ["rev-parse", "--abbrev-ref", "HEAD"], check=False) or "").strip(),
            "modified": modified, "untracked": untracked, "upstream": upstream, "ahead": ahead,
            "dirty": bool(modified or untracked)}


def content_digest(repo: str, rels: list) -> str:
    """送るものの指紋。後から「同じものを出したか」を突き合わせるために残す。"""
    h = hashlib.sha256()
    for rel in sorted(rels):
        p = os.path.join(repo, rel)
        try:
            with open(p, "rb") as fh:
                h.update(rel.encode("utf-8"))
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
        except OSError:
            continue
    return h.hexdigest()[:32]


def target_of(repo: str) -> dict:
    p = os.path.join(repo, ".vercel", "project.json")
    try:
        with open(p, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return {"projectName": d.get("projectName"),
                "orgFingerprint": hashlib.sha256(str(d.get("orgId")).encode()).hexdigest()[:12],
                "projectFingerprint": hashlib.sha256(str(d.get("projectId")).encode()).hexdigest()[:12]}
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


def human_gate(reason: str, detail: str) -> bool:
    """端末からの承認。AIの実行環境には端末が無いので、そこで確実に止まる。"""
    sys.stderr.write(f"\n■ 人間の承認が必要: {reason}\n{detail}\n")
    if not os.path.exists("/dev/tty"):
        sys.stderr.write("端末が無いため承認を取れない。デプロイを中止する。\n")
        return False
    try:
        with open("/dev/tty", "r+") as tty:
            word = f"deploy-{hashlib.sha256(detail.encode()).hexdigest()[:6]}"
            tty.write(f"  続行するには次を入力（中止は Enter のみ）:\n    {word}\n  > ")
            tty.flush()
            answer = tty.readline().strip()
        return answer == word
    except OSError:
        sys.stderr.write("端末を開けない。デプロイを中止する。\n")
        return False


def gate(repo: str, allow_dirty: bool = False, save: bool = True) -> dict:
    """デプロイ前の関門。戻り値の `ok` が False なら出してはならない。"""
    repo = os.path.abspath(repo)
    up = uploaded_files(repo)
    state = tree_state(repo)
    target = target_of(repo)

    allow = allowlist_mod.load(os.path.join(repo, ".audit", "allowlist.yml"))
    scanner = Scanner(repo, allow=allow, faker_corpus=allowlist_mod.faker_ja_jp_corpus(),
                      origin="deploy")
    result = scanner.scan_paths(up["files"])
    blocking = [f for f in result.active if f.severity in (CRITICAL, HIGH)]

    record = {
        "kind": "deploy-gate",
        "head": state.get("head", "no-git"),
        "branch": state.get("branch"),
        "target": target,
        "uploaded_files": len(up["files"]),
        "uploaded_untracked": len(up["untracked"]),
        "untracked_sample": up["untracked"][:20],
        "modified": state.get("modified", [])[:20],
        "unpushed_commits": state.get("ahead", 0),
        "upstream": state.get("upstream"),
        "content_digest": content_digest(repo, up["files"]),
        "scan": {"critical": result.count(CRITICAL), "high": result.count(HIGH),
                 "medium": result.count("Medium"), "files_scanned": result.scanned},
        "blocking_findings": [{"file": f.file, "line": f.line, "rule": f.rule,
                               "severity": f.severity, "evidence": f.evidence} for f in blocking[:40]],
    }

    reasons = []
    if blocking:
        reasons.append(f"送信対象に Critical/High が {len(blocking)} 件ある")
    ok = not blocking

    # 本番デプロイは不可逆操作の一覧に載っている（IRREVERSIBLE_OPS）。
    # したがって、作業ツリーが綺麗でも**毎回**人間の承認を要求する。
    needs_human = [f"本番へ出す（{target.get('projectName') or '送信先不明'}）—— 不可逆操作"]
    if state.get("dirty"):
        needs_human.append(f"作業ツリーが汚れている（変更 {len(state['modified'])} / 未追跡 {len(state['untracked'])}）"
                           f" —— リポジトリに存在しないものが本番へ出る")
    if state.get("ahead"):
        needs_human.append(f"未pushのコミットが {state['ahead']} 件ある —— 本番に出る内容が GitHub に無い")
    if not target.get("projectName"):
        needs_human.append("送信先（.vercel/project.json）を読めない")

    if ok and needs_human:
        if allow_dirty:
            record["human_approval"] = "スキップ（--allow-dirty）"
        else:
            approved = human_gate("リポジトリと一致しない内容を本番へ出そうとしている",
                                  "\n".join("  - " + n for n in needs_human))
            record["human_approval"] = "承認あり" if approved else "承認なし"
            if not approved:
                ok = False
                reasons.append("人間の承認が取れなかった")

    record["result"] = "許可" if ok else "拒否"
    record["reasons"] = reasons
    record["needs_human"] = needs_human

    if save:
        d = os.path.join(repo, DEPLOY_DIR)
        os.makedirs(d, exist_ok=True)
        record["observations"] = [{"fingerprint": f"deploy:{record['content_digest']}",
                                   "severity": CRITICAL if blocking else "Low",
                                   "fact": f"デプロイ{record['result']}（{record['uploaded_files']}ファイル）"}]
        saved = workpaper.save(repo, record)
        # 調書と同じ連鎖に載せたうえで、デプロイ専用の索引にも残す
        with open(os.path.join(d, os.path.basename(saved)), "w", encoding="utf-8") as fh:
            json.dump(record, fh, ensure_ascii=False, indent=2)
        record["workpaper"] = saved
    return {"ok": ok, "record": record, "scan_result": result}
