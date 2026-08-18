"""監査意見の形成。

意見は4つしかない。「だいたい大丈夫」は存在しない。
- 不適正        : Critical が1件以上
- 限定付適正    : High が1件以上（限定事項を列挙する）
- 意見不表明    : 実施できなかった手続が全体の20%以上（検査していない範囲が広すぎる）
- 適正          : 上記に当たらない。**ただし実施手続の全列挙を添付して初めて成立する**

「意見不表明」を用意しているのは、走査できなかったことを「問題なし」と言い換える経路を
塞ぐため。安全側の立証責任は安全だと主張する側にある（P3）。
"""

from __future__ import annotations

from .checks.base import DONE, UNVERIFIABLE
from .rules import CRITICAL, HIGH, LOW, MEDIUM

ADVERSE = "不適正"
QUALIFIED = "限定付適正"
DISCLAIMED = "意見不表明"
CLEAN = "適正"

UNVERIFIABLE_LIMIT = 0.20


def tally(results: list) -> dict:
    obs = [o for r in results for o in r.observations]
    return {
        "critical": sum(1 for o in obs if o.severity == CRITICAL),
        "high": sum(1 for o in obs if o.severity == HIGH),
        "medium": sum(1 for o in obs if o.severity == MEDIUM),
        "low": sum(1 for o in obs if o.severity == LOW),
        "procedures": len(results),
        "procedures_done": sum(1 for r in results if r.status == DONE),
        "procedures_unverifiable": sum(1 for r in results if r.status == UNVERIFIABLE),
    }


def form(results: list, total_registered: int | None = None) -> dict:
    """意見を形成する。

    `total_registered` を渡すと、実施した手続が全手続より少ない場合に
    **限定範囲の監査**であることを意見に刻む。`--only` で1手続だけ回して
    「適正」と表示できる状態を残すと、部分監査が全体の意見として使われる。
    """
    t = tally(results)
    ratio = (t["procedures_unverifiable"] / t["procedures"]) if t["procedures"] else 1.0
    if t["critical"]:
        verdict, why = ADVERSE, f"Critical {t['critical']} 件。構造的な欠陥が現に残っている。"
    elif ratio >= UNVERIFIABLE_LIMIT:
        verdict, why = DISCLAIMED, (f"実施できなかった手続が {t['procedures_unverifiable']}/{t['procedures']} "
                                    f"（{ratio:.0%}）。検査していない範囲が広く、意見を表明できない。")
    elif t["high"]:
        verdict, why = QUALIFIED, f"High {t['high']} 件。限定事項として列挙する。"
    else:
        verdict, why = CLEAN, "実施したすべての手続で Critical / High の所見が無い。"
    scope_limited = bool(total_registered and t["procedures"] < total_registered)
    if scope_limited:
        why = (f"{why}（**限定範囲**: 全 {total_registered} 手続のうち {t['procedures']} 手続のみ実施。"
               f"これは全体についての意見ではない）")
    return {
        "verdict": verdict,
        "reason": why,
        "scope_limited": scope_limited,
        "procedures_registered": total_registered,
        "tally": t,
        "unverifiable_ratio": round(ratio, 3),
        "blocking": verdict in (ADVERSE, QUALIFIED, DISCLAIMED),
    }


def exit_code(op: dict) -> int:
    """Critical/High/意見不表明は非ゼロ。CI とフックはこれで止まる。"""
    return 0 if op["verdict"] == CLEAN else 1
