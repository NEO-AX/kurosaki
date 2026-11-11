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


def _name_key(path: str) -> tuple:
    """ファイル名の予備の鍵。`<日付>-<head>.json` と衝突時の `<日付>-<head>-NN.json`。

    素の辞書順だと `-`(0x2D) < `.`(0x2E) のため連番付きが無印より先に来る。
    連番を数値として読み、無印を 0 番として扱う。
    """
    name = os.path.basename(path)
    stem = name[:-5] if name.endswith(".json") else name
    base, seq = stem, 0
    if len(stem) > 3 and stem[-3] == "-" and stem[-2:].isdigit():
        base, seq = stem[:-3], int(stem[-2:])
    return (base, seq, name)


def _saved_key(item: dict) -> float:
    """保存時刻（UTC の秒）。無い・読めない調書は先頭側（-inf）に置く。"""
    raw = (item["data"] or {}).get("saved_at")
    if not isinstance(raw, str):
        return float("-inf")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return float("-inf")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _chain_order(items: list) -> list:
    """調書を連鎖の順に並べる。

    並びはファイル名に頼らない。ファイル名の head（コミットハッシュ）は時系列に並ばず、
    衝突時の連番 `-01` は無印より辞書順で前に来る。ファイル名順に検証すると、
    改ざんが無くても連鎖が切れて見える（誤検知の Critical）。

    1. 予備の順: 保存時刻 `saved_at` → ファイル名（連番は数値）。
    2. 本順: 各調書の `prev_digest` が指す調書（`self_digest` が一致するもの）の後ろに置く。
       親の後ろに子が来る限り、残りは予備の順で選ぶ（Kahn のトポロジカル順）。

    連鎖の検証そのもの（自己ハッシュ・直前とのハッシュ）は `verify_chain` が行う。
    ここで並べ替えても、改ざん・欠落・分岐はどの順でも「直前と一致しない」か
    「自己ハッシュ不一致」として必ず残る（並びは切れ目を作らないが、消しもしない）。
    """
    base = sorted(items, key=lambda it: (_saved_key(it), _name_key(it["path"])))
    rank = {id(it): i for i, it in enumerate(base)}
    by_digest: dict = {}
    for it in base:
        dg = (it["data"] or {}).get("self_digest")
        if dg and dg not in by_digest:
            by_digest[dg] = it
    parent = {}
    for it in base:
        pd = (it["data"] or {}).get("prev_digest")
        par = by_digest.get(pd) if pd else None
        if par is not None and par is not it:
            parent[id(it)] = par
    children: dict = {}
    for it in base:
        par = parent.get(id(it))
        if par is not None:
            children.setdefault(id(par), []).append(it)

    out, placed = [], set()
    ready = [it for it in base if id(it) not in parent]
    while ready:
        ready.sort(key=lambda it: rank[id(it)])
        it = ready.pop(0)
        out.append(it)
        placed.add(id(it))
        ready.extend(children.get(id(it), []))
    # 循環（ハッシュの衝突が無い限り起きない）で置けなかったものは予備の順で末尾へ。
    # 黙って落とさない: 末尾に置けば verify_chain が切れ目として報告する。
    out.extend(it for it in base if id(it) not in placed)
    return out


def history(repo: str) -> list:
    """連鎖の順（古い順）の調書。壊れている調書は読み飛ばさず、印を付けて返す。"""
    out = []
    for path in sorted(glob.glob(os.path.join(repo, REPORT_DIR, "*.json")), key=_name_key):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("調書が JSON オブジェクトではない")
            out.append({"path": path, "data": data, "broken": None})
        except (OSError, ValueError) as exc:
            out.append({"path": path, "data": None, "broken": str(exc)})
    return _chain_order(out)


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
