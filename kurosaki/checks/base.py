"""検査手続の土台。

監査人の心得をコードの形にしてある:
- 手続は「実施した」か「実施できなかった（理由付き）」のどちらかしか返せない。
  黙って落ちる経路を作らない（`status` が必須）。
- 手続は自分が**何を見たか**を `examined` に書く。これが無いと「適正」意見の根拠にならない。
- 所見は事実・根拠・要求する是正の3点セット。実装者の説明は根拠に採らない（P3）。
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass, field, asdict

from ..rules import CRITICAL, HIGH, LOW, MEDIUM

DONE, UNVERIFIABLE = "done", "unverifiable"


@dataclass
class Observation:
    id: str                       # 手続ID（D3-04 など）
    severity: str
    fact: str                     # 観測した事実
    evidence: list = field(default_factory=list)   # 根拠（パス・コマンド・行番号）
    remediation: str = ""         # 要求する是正
    key: str = ""                 # 反復追跡の同一性キー（前回調書との突合に使う）

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d

    @property
    def fingerprint(self) -> str:
        base = f"{self.id}|{self.key or self.fact}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


@dataclass
class ProcedureResult:
    id: str
    domain: str
    title: str
    status: str = DONE
    examined: str = ""            # 何を見たか（適正意見の根拠になる）
    reason: str | None = None     # 実施できなかった理由
    observations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"id": self.id, "domain": self.domain, "title": self.title, "status": self.status,
                "examined": self.examined, "reason": self.reason,
                "observations": [o.to_dict() for o in self.observations]}


class Context:
    """被監査リポジトリへの読み取り専用の窓。

    監査中に対象へ書き込む経路をここに作らない。git は読み取りコマンドのみ、
    `gh` は失敗を「検査不能」として扱い、握り潰さない。
    """

    def __init__(self, repo: str, tool_root: str, opts: dict | None = None):
        self.repo = os.path.abspath(repo)
        self.tool_root = tool_root
        self.opts = opts or {}
        self._cache: dict = {}

    # -------------------------------------------------- ファイル

    def path(self, rel: str) -> str:
        return os.path.join(self.repo, rel)

    def exists(self, rel: str) -> bool:
        return os.path.exists(self.path(rel))

    def read(self, rel: str, limit: int = 512 * 1024) -> str | None:
        try:
            with open(self.path(rel), "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(limit)
        except OSError:
            return None

    def listdir(self, rel: str = "") -> list:
        try:
            return sorted(os.listdir(self.path(rel)))
        except OSError:
            return []

    # -------------------------------------------------- git

    def git(self, args: list, check: bool = False):
        key = ("git", tuple(args))
        if key in self._cache:
            return self._cache[key]
        try:
            proc = subprocess.run(["git", "-C", self.repo] + args, capture_output=True, timeout=120)
            out = proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 or not check else None
        except (OSError, subprocess.SubprocessError):
            out = None
        self._cache[key] = out
        return out

    @property
    def is_git(self) -> bool:
        return (self.git(["rev-parse", "--is-inside-work-tree"]) or "").strip() == "true"

    def tracked(self) -> list:
        out = self.git(["ls-files", "-z"]) or ""
        return [p for p in out.split("\0") if p]

    def head(self) -> str:
        return (self.git(["rev-parse", "--short", "HEAD"]) or "unknown").strip()

    # -------------------------------------------------- gh（失敗は検査不能）

    def gh(self, args: list):
        key = ("gh", tuple(args))
        if key in self._cache:
            return self._cache[key]
        res = (None, "gh コマンドが無い")
        try:
            proc = subprocess.run(["gh"] + args, capture_output=True, timeout=60)
            if proc.returncode == 0:
                res = (proc.stdout.decode("utf-8", "replace"), None)
            else:
                res = (None, proc.stderr.decode("utf-8", "replace").strip()[:200] or f"exit {proc.returncode}")
        except FileNotFoundError:
            res = (None, "gh コマンドが無い")
        except (OSError, subprocess.SubprocessError) as exc:
            res = (None, f"gh 実行に失敗: {exc}")
        self._cache[key] = res
        return res


# ---------------------------------------------------------------- 登録

_REGISTRY: list = []


def procedure(pid: str, domain: str, title: str):
    """検査手続を登録する。ID順が実施順になる。"""
    def deco(fn):
        _REGISTRY.append({"id": pid, "domain": domain, "title": title, "fn": fn})
        return fn
    return deco


def registry() -> list:
    return sorted(_REGISTRY, key=lambda p: p["id"])


def run(ctx: Context, only: list | None = None) -> list:
    """全手続を実施する。例外は握り潰さず「実施できなかった」として記録する。"""
    results = []
    for p in registry():
        if only and not any(p["id"].startswith(o) or p["domain"] == o for o in only):
            continue
        res = ProcedureResult(id=p["id"], domain=p["domain"], title=p["title"])
        try:
            p["fn"](ctx, res)
        except Exception as exc:                        # noqa: BLE001
            res.status = UNVERIFIABLE
            res.reason = f"手続が例外で中断した: {type(exc).__name__}: {exc}"
        if res.status == DONE and not res.examined:
            # 何を見たか書かない手続は「実施した」と認めない。
            res.status = UNVERIFIABLE
            res.reason = "何を検査したのかを記録していないため、実施したと認めない"
        results.append(res)
    return results


def unverifiable(res: ProcedureResult, reason: str, examined: str = "") -> None:
    res.status = UNVERIFIABLE
    res.reason = reason
    if examined:
        res.examined = examined


def observe(res: ProcedureResult, severity: str, fact: str, remediation: str,
            evidence=None, key: str = "") -> None:
    res.observations.append(Observation(id=res.id, severity=severity, fact=fact,
                                        evidence=list(evidence or []), remediation=remediation, key=key))
