"""Risk aggregation, policy, and verdict."""
from __future__ import annotations

from dataclasses import dataclass, field

from .findings import Category, ScanResult, Severity

BASE_WEIGHTS = {
    Severity.CRITICAL: 55,
    Severity.HIGH: 22,
    Severity.MEDIUM: 8,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.7, "low": 0.4}

# Diminishing returns: the 9th MEDIUM finding tells you less than the 1st.
DECAY = 0.65

@dataclass
class Policy:
    """Deployment-tunable thresholds. Load from YAML/JSON in real use."""
    fail_on: Severity = Severity.HIGH
    block_score: int = 60
    review_score: int = 20
    allow_pickle: bool = False
    allow_remote_code: bool = False
    allowlist_repos: set[str] = field(default_factory=set)
    ignore_rules: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        return cls(
            fail_on=Severity(d.get("fail_on", "HIGH").upper()),
            block_score=int(d.get("block_score", 60)),
            review_score=int(d.get("review_score", 20)),
            allow_pickle=bool(d.get("allow_pickle", False)),
            allow_remote_code=bool(d.get("allow_remote_code", False)),
            allowlist_repos=set(d.get("allowlist_repos", [])),
            ignore_rules=set(d.get("ignore_rules", [])),
        )


def apply_policy(result: ScanResult, policy: Policy) -> None:
    """Filter findings, compute score and verdict. Mutates `result`."""
    if result.target.identifier in policy.allowlist_repos:
        result.findings = []
        result.risk_score = 0
        result.verdict = "ALLOW (policy allowlist)"
        return

    kept = []
    for f in result.findings:
        if f.rule_id in policy.ignore_rules:
            continue
        if policy.allow_pickle and f.rule_id == "MLSC-FMT-001":
            continue
        if policy.allow_remote_code and f.rule_id in {"MLSC-CFG-001", "MLSC-PRV-005"}:
            continue
        kept.append(f)
    result.findings = kept

    result.risk_score = compute_score(kept)
    result.verdict = verdict_for(result, policy)


def compute_score(findings) -> int:
    """0-100. Severity-weighted with per-severity diminishing returns."""
    buckets: dict[Severity, list[float]] = {s: [] for s in Severity}
    for f in findings:
        buckets[f.severity].append(CONFIDENCE_FACTOR.get(f.confidence, 1.0))

    total = 0.0
    for sev, factors in buckets.items():
        w = BASE_WEIGHTS[sev]
        for i, cf in enumerate(sorted(factors, reverse=True)):
            total += w * cf * (DECAY ** i)
    return int(min(100, round(total)))


def verdict_for(result: ScanResult, policy: Policy) -> str:
    mx = result.max_severity()
    if mx is Severity.CRITICAL or result.risk_score >= policy.block_score:
        return "BLOCK"
    if mx.rank >= policy.fail_on.rank or result.risk_score >= policy.review_score:
        return "REVIEW"
    return "ALLOW"


def exit_code(result: ScanResult, policy: Policy) -> int:
    """CI-friendly: 0 clean, 1 review, 2 block, 3 scan error."""
    if result.errors and not result.findings:
        return 3
    return {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}.get(result.verdict.split()[0], 0)
