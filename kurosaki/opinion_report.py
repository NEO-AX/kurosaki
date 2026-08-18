"""監査意見の描画。

監査報告として成立させるために、次を必ず載せる:
1. 意見（4種のいずれか）と、その理由
2. 実施した手続の**全列挙**と、各手続が何を見たか（「適正」の根拠になる）
3. 実施できなかった手続と理由（検査していない範囲を隠さない）
4. 所見（重大度順）と、要求する是正、そして**同じ指摘が何回目か**
"""

from __future__ import annotations

from .rules import CRITICAL, HIGH, LOW, MEDIUM

_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
_MARK = {CRITICAL: "×", HIGH: "×", MEDIUM: "△", LOW: "・"}


def render(payload: dict, repeats: dict | None = None) -> str:
    repeats = repeats or {}
    op = payload["opinion"]
    t = op["tally"]
    out = []

    out.append("=" * 78)
    if op.get("scope_limited"):
        out.append("※ 限定範囲の監査（--only 指定）。全体についての意見ではない。")
    out.append(f"監査意見: 【{op['verdict']}】")
    out.append(f"  理由: {op['reason']}")
    out.append(f"  対象: {payload['repo']} @ {payload['head']}")
    out.append(f"  実施: {t['procedures_done']}/{t['procedures']} 手続"
               f"（実施不能 {t['procedures_unverifiable']} 件 = {op['unverifiable_ratio']:.0%}）")
    out.append(f"  所見: Critical {t['critical']} / High {t['high']} / Medium {t['medium']} / Low {t['low']}")
    out.append("=" * 78)

    obs = sorted(payload["observations"], key=lambda o: (_ORDER.get(o["severity"], 9), o["id"]))
    if obs:
        out.append("")
        out.append("── 所見（重大度順）")
        for o in obs:
            n = o.get("repeat_count", repeats.get(o.get("fingerprint"), 0))
            again = f"  ★過去{n}回同じ指摘" if n else ""
            out.append(f"{_MARK.get(o['severity'], '?')} [{o['severity']}] {o['id']}  {o['fact']}{again}")
            for e in o.get("evidence", [])[:6]:
                out.append(f"      根拠: {e}")
            out.append(f"      要求する是正: {o['remediation']}")

    done = [r for r in payload["procedures"] if r["status"] == "done"]
    undone = [r for r in payload["procedures"] if r["status"] != "done"]

    out.append("")
    out.append(f"── 実施した手続 {len(done)} 件（各手続が何を見たか。これが意見の根拠）")
    for r in done:
        n = len(r["observations"])
        out.append(f"  {r['id']} [{r['domain']}] {r['title']}  → 所見 {n} 件")
        out.append(f"      検査した内容: {r['examined']}")

    if undone:
        out.append("")
        out.append(f"── 実施できなかった手続 {len(undone)} 件（**この範囲は検査していない。安全だと言っていない**）")
        for r in undone:
            out.append(f"  {r['id']} [{r['domain']}] {r['title']}")
            out.append(f"      理由: {r['reason']}")

    out.append("")
    if op["verdict"] == "不適正":
        out.append("→ この体制でのマージ・push・デプロイを認めない。Critical を解消してから再監査すること。")
    elif op["verdict"] == "限定付適正":
        out.append("→ 限定事項（High）を承知の上で進めるか、解消してから再監査すること。")
    elif op["verdict"] == "意見不表明":
        out.append("→ 検査できない範囲が広く、意見を表明できない。検査可能な状態にしてから再監査すること。")
    else:
        out.append("→ 実施した手続の範囲では所見なし。上の「実施した手続」の一覧が、この意見の根拠の全部である。")
    return "\n".join(out)
