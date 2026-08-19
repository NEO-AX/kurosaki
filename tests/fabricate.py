"""被監査リポジトリを合成する。

手続ごとに壊れたリポジトリを作ると20個以上の生成コードになる。そこで
**欠陥を全部入れた1個**と**健全な1個**を作り、全手続を同じ2個へ当てる。
所見が「壊れた側で出る」「健全な側で出ない」ことを1本のテストで固定する。

架空データのみを使う。実在の個人・組織とは無関係。
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git(repo, *args, allow_fail=False):
    p = subprocess.run(["git", "-C", repo] + list(args), capture_output=True)
    if p.returncode != 0 and not allow_fail:
        raise RuntimeError(f"git {args}: {p.stderr.decode()[:200]}")
    return p


def _w(repo, rel, body, executable=False):
    p = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    if executable:
        os.chmod(p, 0o755)
    return p


def _commit(repo, msg, name="Human Dev", email="human@example.com"):
    _git(repo, "add", "-A")
    _git(repo, "-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-qm", msg)


def broken(root: str) -> str:
    """欠陥を全部入れた被監査リポジトリ。各手続が所見を出すべき対象。"""
    repo = os.path.join(root, "broken")
    os.makedirs(repo, exist_ok=True)
    _git(repo, "init", "-q", ".") if False else subprocess.run(["git", "init", "-q", repo], check=True)

    # D1: 規律文書なし・上位文書なし（何も置かない）

    # D2-01: 実データ候補を作業ツリーに置き、.gitignore だけで守る
    _w(repo, ".gitignore", "お顔データ/\n*.xlsx\n")
    _w(repo, "お顔データ/applicant_photo.png", "PNGではないが名前で人物を示す")
    _w(repo, "候補者名簿.xlsx", "表計算の中身の代わり")

    # D2-02: .env と private と production 投入データと生成物を追跡下へ
    _w(repo, ".env.production", "ANTHROPIC_API_KEY=sk-ant-" + "0" * 24 + "\n")
    _w(repo, "db/private/legacy/dump.sql", "-- 架空\n")
    _w(repo, "db/seeds/0002_season.production.sql", "INSERT INTO seasons (id, label) VALUES (1, '1期');\n")
    _w(repo, "dist/bundle.js", "console.log(1)\n")

    # D3-01: フックを .githooks に置くが hooksPath 未設定（git は実行しない）
    # D3-02/04: 監査を呼んでいるが `|| true` で結果を捨てている
    _w(repo, ".githooks/pre-commit", "#!/bin/sh\nkurosaki scan --staged || true\n", executable=True)

    # D3-03: CI はあるが監査を呼ばない
    _w(repo, ".github/workflows/ci.yml",
       "name: ci\njobs:\n  test:\n    steps:\n      - run: pnpm test\n")

    # D5-01: 不可逆操作一覧なし
    # D5-02: 本番到達スクリプトに人間ゲートなし＋AIへ危険な許可
    _w(repo, "package.json", json.dumps({"scripts": {
        "deploy:production": "node scripts/deploy.ts", "db:reset": "node scripts/reset.ts"}}, indent=2))
    _w(repo, "scripts/deploy.ts", "await deployToProduction()\n")
    _w(repo, "scripts/reset.ts", "await dropAll()\n")
    _w(repo, ".claude/settings.local.json", json.dumps({"permissions": {"allow": [
        "Bash(git push:*)", "Bash(vercel deploy:*)", "Bash(rm -rf:*)"]}}, indent=2))

    # D6-01: 架空PIIを seed に入れる（構造で当たる形）
    _w(repo, "db/seeds/0003_applicants.sql",
       "-- 架空データ。実在の個人とは無関係。\n"
       "INSERT INTO applicants (id, 氏名, email, tel, 生年月日, 住所) VALUES\n"
       "  (1, '架空 花子', 'hanako@kasou-oubo.co.jp', '090-1234-5678', '1998-04-01', '東京都架空区架空町1-2-3');\n")
    # D6-02: 確定パターンの秘密（架空）
    _w(repo, "src/config.ts", 'export const key = "AKIA' + "Z" * 16 + '"\n')

    # D7-02: 全部除外の allowlist を AI 名義で入れる
    _w(repo, ".audit/allowlist.yml",
       "allow:\n  - path: '*'\n    rules: ['*']\n    fingerprints: ['*']\n"
       "    reason: とりあえず通す\n    approved_by: AI\n")

    _commit(repo, "初回", name="Claude", email="claude@example.com")

    # D7-03: 調書を保存し、その後で改ざんする
    sys.path.insert(0, TOOL_ROOT)
    from kurosaki import workpaper
    p = workpaper.save(repo, {"head": "deadbee", "verdict": "不適正", "observations": []})
    data = json.load(open(p, encoding="utf-8"))
    data["verdict"] = "適正"
    json.dump(data, open(p, "w", encoding="utf-8"), ensure_ascii=False)
    return repo


def healthy(root: str) -> str:
    """監査基盤を正しく導入した被監査リポジトリ。所見が出てはならない対象。"""
    repo = os.path.join(root, "healthy")
    subprocess.run(["git", "init", "-q", repo], check=True)

    _w(repo, "CLAUDE.md", "# CLAUDE.md\n\n## 実装規律\n- ダミーは Faker(ja_JP) で作る\n")
    _w(repo, "SUPERVISOR.md", "# SUPERVISOR.md\n\n実装担当は本書を変更できない。\n")
    _w(repo, "CODEOWNERS", "* @human-owner\nCLAUDE.md @human-owner\nSUPERVISOR.md @human-owner\n")
    _w(repo, "db/seeds/0001_reference.sql",
       "-- ダミーのみ。人物データは入れない。\n"
       "INSERT INTO seasons (id, label) VALUES (1, '1期');\n")
    _w(repo, "package.json", json.dumps({"scripts": {
        "deploy:production": "node scripts/deploy.ts", "test": "node --test"}}, indent=2))
    _w(repo, "scripts/deploy.ts",
       "const rl = readline.createInterface({ input: fs.createReadStream('/dev/tty') })\n"
       "spawnSync(toolPath, ['deploy-gate', '--repo', process.cwd()])\n"
       "await confirmThenDeploy(rl)\n")
    _w(repo, ".claude/settings.local.json", json.dumps({"permissions": {"allow": ["Bash(pnpm test)"]}}, indent=2))

    sys.path.insert(0, TOOL_ROOT)
    from kurosaki import install as install_mod
    install_mod.install(repo, TOOL_ROOT)
    # 過去にゲートを通した記録があること（D5-03 は記録ゼロを所見にする）
    import json as _json, os as _os
    _os.makedirs(_os.path.join(repo, ".audit", "deploys"), exist_ok=True)
    with open(_os.path.join(repo, ".audit", "deploys", "2026-01-01-abc1234.json"), "w",
              encoding="utf-8") as fh:
        _json.dump({"kind": "deploy-gate", "result": "許可", "head": "abc1234",
                    "content_digest": "0" * 32}, fh, ensure_ascii=False)
    _commit(repo, "監査基盤を導入", name="Human Dev", email="human@example.com")
    return repo


if __name__ == "__main__":
    import tempfile
    root = tempfile.mkdtemp()
    print("broken :", broken(root))
    print("healthy:", healthy(root))
