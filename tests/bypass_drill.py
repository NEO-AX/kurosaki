"""すり抜け試験。

「実データが混入したPRを作ろうとする」経路を架空データで再現し、
**どこで止まるか**を実際に git を動かして記録する。止まらない経路は
止まらないと書く（残存リスク）。

実行:
    python3 tests/bypass_drill.py            # 結果を表示
    python3 tests/bypass_drill.py --write    # docs/BYPASS_DRILL.md へ保存
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOL_ROOT)

from kurosaki import install as install_mod        # noqa: E402

PII_SQL = ("-- 架空データ。実在の個人とは無関係。\n"
           "INSERT INTO applicants (id, 氏名, email, tel) VALUES\n"
           "  (1, '架空 花子', 'hanako@kasou-oubo.co.jp', '090-1234-5678');\n")
GIT_ID = ["-c", "user.name=Impl AI", "-c", "user.email=impl@example.com"]


def sh(*args, cwd=None, env=None, stdin=None):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, env=env, input=stdin)
    return p.returncode, (p.stdout + p.stderr)


def new_subject(with_infra=True, remote=True):
    """被監査リポジトリを作る。remote=True なら push 先のベアリポジトリも作る。"""
    root = tempfile.mkdtemp(prefix="kurosaki-drill-")
    repo = os.path.join(root, "subject")
    subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True)
    with open(os.path.join(repo, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("# 被監査リポジトリ（試験用）\n")
    subprocess.run(["git", "-C", repo] + GIT_ID + ["add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo] + GIT_ID + ["commit", "-qm", "初回"], check=True, capture_output=True)
    if with_infra:
        install_mod.install(repo, TOOL_ROOT)
        subprocess.run(["git", "-C", repo] + GIT_ID + ["add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", repo] + GIT_ID + ["commit", "-qm", "監査基盤を導入", "--no-verify"],
                       check=True, capture_output=True)
    bare = None
    if remote:
        bare = os.path.join(root, "remote.git")
        subprocess.run(["git", "init", "-q", "--bare", bare], check=True)
        subprocess.run(["git", "-C", repo, "remote", "add", "origin", bare], check=True)
        subprocess.run(["git", "-C", repo, "push", "-q", "--no-verify", "-u", "origin", "main"],
                       check=True, capture_output=True)
    return root, repo, bare


def stage_pii(repo, name="db/seeds/0003_applicants.sql"):
    p = os.path.join(repo, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(PII_SQL)
    sh("git", "-C", repo, "add", "-A")
    return name


def drill():
    results = []

    def record(no, scenario, stopped_at, code, detail):
        results.append({"no": no, "scenario": scenario, "stopped_at": stopped_at,
                        "exit": code, "detail": detail.strip()[:300]})

    # --- 1) 素直に commit する ---
    root, repo, bare = new_subject()
    stage_pii(repo)
    code, out = sh("git", "-C", repo, *GIT_ID, "commit", "-m", "応募者データを入れる")
    record(1, "PIIを含むファイルを普通に commit", "pre-commit（機械検査）" if code else "止まらなかった",
           code, [l for l in out.split("\n") if "Critical" in l or "commit を止" in l][:3].__str__())

    # --- 2) --no-verify で commit し、そのまま push ---
    code2, _ = sh("git", "-C", repo, *GIT_ID, "commit", "-m", "検査を飛ばして commit", "--no-verify")
    code3, out3 = sh("git", "-C", repo, "push", "origin", "main")
    record(2, "--no-verify で commit → 通常の push", "pre-push（機械検査）" if code3 else "止まらなかった",
           code3, out3)

    # --- 3) push も --no-verify で飛ばす（CIが唯一の砦になる） ---
    code4, out4 = sh("git", "-C", repo, "push", "--no-verify", "origin", "main")
    ci_code, ci_out = sh(os.path.join(TOOL_ROOT, "bin", "kurosaki"), "scan", "--repo", repo,
                         "--changed-vs", "HEAD~2", "--quiet", "--format", "json", "--out", "/dev/null")
    record(3, "commit も push も --no-verify で飛ばす",
           f"ローカルでは止まらない → CI（同じ検査で exit={ci_code}）" if code4 == 0 else "pre-push",
           code4, f"push exit={code4} / CI相当の検査 exit={ci_code}")
    shutil.rmtree(root, ignore_errors=True)

    # --- 4) 監査基盤（フック）を書き換えて素通しにする ---
    root, repo, bare = new_subject()
    hook = os.path.join(repo, ".githooks", "pre-commit")
    with open(hook, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(hook, 0o755)
    stage_pii(repo)
    code, out = sh("git", "-C", repo, *GIT_ID, "commit", "-m", "フックを潰して commit")
    audit_code, audit_out = sh(os.path.join(TOOL_ROOT, "bin", "kurosaki"), "audit", "--repo", repo,
                               "--only", "D7-01", "--no-save", "--quiet")
    record(4, "フック本体を `exit 0` に書き換えて commit",
           "ローカルの commit は止まらない → 次の監査 D7-01 が改変を検知" if code == 0 else "pre-commit",
           code, f"commit exit={code} / D7-01 exit={audit_code}")

    # --- 5) 監査基盤を書き換えたまま push する ---
    code5, out5 = sh("git", "-C", repo, "push", "origin", "main")
    record(5, "フックを潰した状態で push", "pre-push（D7 の改変検知）" if code5 else "止まらなかった",
           code5, out5)
    shutil.rmtree(root, ignore_errors=True)

    # --- 6) 偽の kurosaki を PATH に置く ---
    root, repo, bare = new_subject()
    fake = tempfile.mkdtemp(prefix="kurosaki-fake-")
    with open(os.path.join(fake, "kurosaki"), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(os.path.join(fake, "kurosaki"), 0o755)
    with open(os.path.join(repo, ".audit", "TOOL_PATH"), "w", encoding="utf-8") as fh:
        fh.write(os.path.join(fake, "kurosaki") + "\n")
    env = dict(os.environ); env["PATH"] = fake + os.pathsep + env.get("PATH", "")
    stage_pii(repo)
    code, out = sh("git", "-C", repo, *GIT_ID, "commit", "-m", "偽ツールで通す", env=env)
    record(6, "偽の kurosaki を PATH と TOOL_PATH へ仕込む",
           "pre-commit（--version 検証で本物でないと判定）" if code else "止まらなかった", code, out)
    shutil.rmtree(fake, ignore_errors=True); shutil.rmtree(root, ignore_errors=True)

    # --- 7) allowlist を全開にして検出を消す ---
    root, repo, bare = new_subject()
    with open(os.path.join(repo, ".audit", "allowlist.yml"), "w", encoding="utf-8") as fh:
        fh.write("allow:\n  - path: '*'\n    rules: ['*']\n    fingerprints: ['*']\n"
                 "    reason: 通す\n    approved_by: AI\n")
    stage_pii(repo)
    code, out = sh("git", "-C", repo, *GIT_ID, "commit", "-m", "allowlistを全開にして commit")
    record(7, "allowlist を `path: '*'` で全開にする",
           "pre-commit（広すぎる除外は無効化される）" if code else "止まらなかった", code, out)
    shutil.rmtree(root, ignore_errors=True)

    # --- 8) 環境変数で検査を無効化しようとする ---
    root, repo, bare = new_subject()
    stage_pii(repo)
    env = dict(os.environ)
    for k in ("KUROSAKI_SKIP", "KUROSAKI_DISABLE", "KUROSAKI_BYPASS", "KUROSAKI_BIN", "SKIP"):
        env[k] = "1"
    env["KUROSAKI_BIN"] = "/usr/bin/true"
    code, out = sh("git", "-C", repo, *GIT_ID, "commit", "-m", "環境変数で無効化を試みる", env=env)
    record(8, "環境変数（KUROSAKI_SKIP / KUROSAKI_BIN=/usr/bin/true 等）で無効化",
           "pre-commit（解除用の環境変数が存在しない）" if code else "止まらなかった", code, out)

    shutil.rmtree(root, ignore_errors=True)

    # --- 9) 監査基盤を残したまま履歴を書き換えて force push ---
    root, repo, bare = new_subject()
    with open(os.path.join(repo, "note.md"), "w", encoding="utf-8") as fh:
        fh.write("# 変更\n")
    sh("git", "-C", repo, "add", "-A")
    sh("git", "-C", repo, *GIT_ID, "commit", "-m", "無害な変更", "--no-verify")
    sh("git", "-C", repo, "push", "--no-verify", "origin", "main")
    sh("git", "-C", repo, *GIT_ID, "commit", "--amend", "--no-edit", "--no-verify")  # 履歴を書き換える
    code9, out9 = sh("git", "-C", repo, "push", "--force", "origin", "main")
    record(9, "監査基盤を残したまま履歴を書き換えて force push",
           "pre-push（端末が無く人間承認を取れない）" if code9 else "止まらなかった", code9, out9)

    # --- 9b) 監査基盤ごと消してから push（試験中に発見した経路） ---
    sh("git", "-C", repo, "reset", "--hard", "HEAD~2")   # 監査基盤の導入コミットごと巻き戻す
    hooks_gone = not os.path.isdir(os.path.join(repo, ".githooks"))
    code9b, out9b = sh("git", "-C", repo, "push", "--force", "--no-verify", "origin", "main")
    audit9b, _ = sh(os.path.join(TOOL_ROOT, "bin", "kurosaki"), "audit", "--repo", repo,
                    "--only", "D3-01", "D7-01", "--no-save", "--quiet")
    record("9b", "`git reset --hard` で監査基盤ごと巻き戻してから force push",
           ("ローカルでは止まらない（フックが消えるため）→ 次の監査 D3-01/D7-01 が不在を検知"
            if code9b == 0 else "pre-push"),
           code9b, f"フックが消えた={hooks_gone} / push exit={code9b} / 監査 exit={audit9b}")

    # --- 10) 過去の調書を改ざんする ---
    from kurosaki import workpaper
    wp = workpaper.save(repo, {"head": "aaaaaaa", "verdict": "不適正", "observations": []})
    data = json.load(open(wp, encoding="utf-8")); data["verdict"] = "適正"
    json.dump(data, open(wp, "w", encoding="utf-8"), ensure_ascii=False)
    code10, out10 = sh(os.path.join(TOOL_ROOT, "bin", "kurosaki"), "audit", "--repo", repo,
                       "--only", "D7-03", "--no-save", "--quiet")
    record(10, "過去の監査調書（不適正意見）を『適正』へ改ざん",
           "D7-03（ハッシュ連鎖の不整合を検知）" if code10 else "止まらなかった", code10, out10)
    shutil.rmtree(root, ignore_errors=True)
    return results


def render(results) -> str:
    out = ["# すり抜け試験の結果", "",
           "架空データで「実データ混入」を再現し、実際に git を動かして**どこで止まるか**を記録した。",
           "`python3 tests/bypass_drill.py` で再現できる。", "",
           "| # | 試みた経路 | どこで止まったか | 終了コード |", "|---|---|---|---|"]
    for r in results:
        out.append(f"| {r['no']} | {r['scenario']} | {r['stopped_at']} | {r['exit']} |")
    out += ["", "## 残存リスク（止まらない経路）", ""]
    leaks = [r for r in results if "止まらない" in r["stopped_at"] or "止まらなかった" in r["stopped_at"]]
    if not leaks:
        out.append("- なし（上記すべてでローカルの機械ゲートが止めた）")
    else:
        for r in leaks:
            out.append(f"- **#{r['no']} {r['scenario']}** … {r['stopped_at']}")
        out += ["",
                f"この {len(leaks)} 経路はいずれも「ローカルのフックを人間/AIが意図的に外す」ものである。",
                "ローカルフックは対象リポジトリ内のファイルなので、原理的に外せる。",
                "したがって最終防衛線は次の2つになる。", "",
                "1. **CI**（`.github/workflows/audit.yml`）—— 外部からツールを取得して同じ検査を実行する。",
                "   ローカルで何を外しても、push された内容に対して走る。",
                "2. **ブランチ保護の必須チェック** —— CIの合格をマージの条件にする。",
                "   これが無い場合、CIが落ちてもマージできるため、CIは通知にしかならない。", "",
                "実測: private リポジトリの無料プランではブランチ保護APIが 403 で使えないことがある。",
                "この状態では #3 の経路を機械的に塞げない。プランの変更、または公開ミラー側での",
                "強制が必要である（D3-05 はこれを「検査不能」として意見に反映する）。"]
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    res = drill()
    text = render(res)
    print(text)
    if "--write" in sys.argv:
        os.makedirs(os.path.join(TOOL_ROOT, "docs"), exist_ok=True)
        path = os.path.join(TOOL_ROOT, "docs", "BYPASS_DRILL.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"保存: {path}")
