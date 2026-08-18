"""調書（監査の記録）。追記専用・ハッシュ連鎖・前回比較。

なぜ連鎖させるか: 過去の監査結果を書き換えられるなら、監査は成り立たない。
各調書は直前の調書のハッシュを持ち、`D7-03` がその連鎖を検証する。

なぜ前回比較をするか: 同じ指摘が繰り返されている事実そのものが、体制の所見になる。
「毎回指摘されているが毎回直っていない」を数える。
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
from datetime import datetime, timezone

REPORT_DIR = os.path.join(".audit", "reports")


def _digest(payload: dict) -> str:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def history(repo: str) -> list:
    """古い順の調書。壊れている調書は読み飛ばさず、印を付けて返す。"""
    out = []
    for path in sorted(glob.glob(os.path.join(repo, REPORT_DIR, "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                out.append({"path": path, "data": json.load(fh), "broken": None})
        except (OSError, json.JSONDecodeError) as exc:
            out.append({"path": path, "data": None, "broken": str(exc)})
    return out


def verify_chain(repo: str) -> list:
    """連鎖の検証。切れていれば理由の一覧を返す（空なら健全）。"""
    problems, prev = [], None
    for item in history(repo):
        name = os.path.basename(item["path"])
        if item["broken"]:
            problems.append(f"{name}: 読めない（{item['broken']}）")
            prev = None
            continue
        d = item["data"]
        body = {k: v for k, v in d.items() if k not in ("self_digest",)}
        if d.get("self_digest") and d["self_digest"] != _digest(body):
            problems.append(f"{name}: 内容が保存後に書き換えられている（自己ハッシュ不一致）")
        if prev is not None and d.get("prev_digest") != prev:
            problems.append(f"{name}: 直前の調書とのハッシュ連鎖が切れている")
        prev = d.get("self_digest")
    return problems


def repeated(repo: str, current_obs: list) -> dict:
    """所見ごとに、過去何回同じ指摘が出ているかを数える。"""
    counts: dict = {}
    for item in history(repo):
        if not item["data"]:
            continue
        for o in item["data"].get("observations", []):
            fp = o.get("fingerprint")
            if fp:
                counts[fp] = counts.get(fp, 0) + 1
    return {o.fingerprint: counts.get(o.fingerprint, 0) for o in current_obs}


def save(repo: str, payload: dict) -> str:
    """追記専用で保存する。既存ファイルは上書きしない（衝突時は連番を足す）。"""
    d = os.path.join(repo, REPORT_DIR)
    os.makedirs(d, exist_ok=True)
    prev = None
    for item in history(repo):
        if item["data"]:
            prev = item["data"].get("self_digest")
    payload = dict(payload)
    payload["prev_digest"] = prev
    payload["saved_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload["self_digest"] = _digest(payload)

    stamp = payload["saved_at"][:10]
    base = f"{stamp}-{payload.get('head', 'unknown')}"
    path = os.path.join(d, base + ".json")
    n = 1
    while os.path.exists(path):
        path = os.path.join(d, f"{base}-{n:02d}.json")
        n += 1
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return path
