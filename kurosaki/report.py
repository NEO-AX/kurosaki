"""報告の描画。**ここを通る文字列に生値は無い**（scan.Finding が既にマスク済み）。"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__
from .rules import CRITICAL, HIGH, LOW, MEDIUM

SCHEMA = "kurosaki.scan/1"
_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
_MARK = {CRITICAL: "×", HIGH: "×", MEDIUM: "△", LOW: "・"}


def summary(result) -> dict:
    return {
        "critical": result.count(CRITICAL),
        "high": result.count(HIGH),
        "medium": result.count(MEDIUM),
        "low": result.count(LOW),
        "allowlisted": sum(1 for f in result.findings if f.allowlisted),
        "files_scanned": result.scanned,
        "files_skipped": len(result.skipped),
        "files_unchecked": len(result.unchecked),
    }


def exit_code(result, strict: bool = False) -> int:
    if result.blocking:
        return 1
    if strict and result.count(MEDIUM):
        return 1
    return 0


def render_json(result, meta: dict) -> str:
    payload = {
        "schema": SCHEMA,
        "tool": f"kurosaki/{__version__}",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "meta": {**result.meta, **meta},
        "summary": summary(result),
        "findings": [f.to_dict() for f in sorted(result.findings, key=lambda f: (_ORDER.get(f.severity, 9), f.file, f.line))],
        "skipped": result.skipped,
        "unchecked": result.unchecked,
        "notes": result.notes,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _group(findings):
    counts = {}
    for f in findings:
        counts[(f.file, f.rule)] = counts.get((f.file, f.rule), 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0][0]))


def render_text(result, meta: dict, detail_limit: int = 60) -> str:
    s = summary(result)
    out = []
    out.append(f"金融庁の黒崎 —— PII走査  [{meta.get('mode', '?')}]  対象: {meta.get('repo', '?')}")
    out.append(f"検査 {s['files_scanned']} ファイル / 除外 {s['files_skipped']} / 未検査 {s['files_unchecked']}")
    out.append("")

    active = sorted(result.active, key=lambda f: (_ORDER.get(f.severity, 9), f.file, f.line))
    detailed = [f for f in active if f.severity in (CRITICAL, HIGH)]
    weaker = [f for f in active if f.severity in (MEDIUM, LOW)]

    if detailed:
        out.append(f"── Critical / High（{len(detailed)} 件。1件でも残っていれば通してはならない）")
        cur = None
        shown = 0
        for f in detailed:
            if shown >= detail_limit:
                break
            if f.file != cur:
                cur = f.file
                out.append(f"■ {f.file}")
            path_note = "重点パス" if f.critical_path else "-"
            out.append(f"  {_MARK.get(f.severity, '?')} {f.severity:<8} L{f.line:<5} {f.rule:<15} {f.evidence:<8} "
                       f"len={f.length:<4} [{path_note}] {f.why}")
            shown += 1
        if len(detailed) > shown:
            out.append(f"  … 残り {len(detailed) - shown} 件は行単位の表示を省略した（内訳は下、全件は --format json）")
            for (fl, rule), n in _group(detailed[shown:]):
                out.append(f"    {n:>4} 件  {rule:<20} {fl}")
        out.append("")

    if weaker:
        out.append(f"── Medium / Low（{len(weaker)} 件。断定できないが黙って捨てていない。ファイル単位で集計）")
        for (fl, rule), n in _group(weaker):
            out.append(f"  {n:>4} 件  {rule:<22} {fl}")
        out.append("")

    if not active:
        out.append("検出: なし（下の「未検査」と「除外」を必ず読むこと。走査していない範囲は無罪の証明にならない）")
        out.append("")

    allowed = [f for f in result.findings if f.allowlisted]
    if allowed:
        out.append(f"allowlist で除外した検出: {len(allowed)} 件")
        for f in allowed[:20]:
            out.append(f"  - {f.file}:{f.line} {f.rule} {f.evidence} … {f.allow_reason}")
        if len(allowed) > 20:
            out.append(f"  （ほか {len(allowed) - 20} 件）")
        out.append("")

    if result.unchecked:
        out.append(f"未検査 {len(result.unchecked)} 件（**中身を見ていない。安全だと言っていない**）")
        for u in result.unchecked[:15]:
            out.append(f"  - {u['file']}: {u['reason']}")
        if len(result.unchecked) > 15:
            out.append(f"  （ほか {len(result.unchecked) - 15} 件）")
        out.append("")

    if result.notes:
        out.append("注記")
        for n in result.notes:
            out.append(f"  - {n}")
        out.append("")

    out.append(f"判定: Critical {s['critical']} / High {s['high']} / Medium {s['medium']} / Low {s['low']}"
               f" / 除外 {s['allowlisted']}")
    if result.blocking:
        out.append("→ FAIL。Critical/High が残っている限り、コミット・マージ・pushを通してはならない。")
    else:
        out.append("→ 機械検査は通過。ただしこれは「Layer 1 のルールに当たらなかった」だけであり、"
                   "安全の証明ではない（Layer 2 の監査を必ず通すこと）。")
    return "\n".join(out)
