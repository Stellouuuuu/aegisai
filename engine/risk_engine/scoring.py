"""Risk scoring: impact x exploitability x confidence, in [0, 10] (ARCHITECTURE.md 3.7)."""

from __future__ import annotations

from collections.abc import Iterable

from engine.core.models import Confidence, Finding, Severity

IMPACT = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
}
CONFIDENCE = {
    Confidence.CONFIRMED: 1.0,
    Confidence.NEEDS_REVIEW: 0.5,
    Confidence.REJECTED: 0.0,
}


def exploitability(finding: Finding) -> float:
    """1.0 when the first payload worked; decreases with the number of tries
    needed, and with unstable reproduction."""
    tried = max(1, int(finding.extra.get("payloads_tried", 1)))
    hits = finding.extra.get("replay_hits")
    attempts = finding.extra.get("replay_attempts")
    # The original observation counts as one success: 0 hits out of 3 replays is 1/4.
    stability = ((hits + 1) / (attempts + 1)) if attempts else 1.0
    return round(stability / (1 + 0.25 * (tried - 1)), 3)


def assess(findings: Iterable[Finding]) -> list[Finding]:
    """Fill exploitability and risk_score on each finding (in place)."""
    out = []
    for f in findings:
        f.exploitability = exploitability(f)
        f.risk_score = round(IMPACT[f.severity] * f.exploitability * CONFIDENCE[f.confidence], 2)
        out.append(f)
    return out


def security_score(findings: Iterable[Finding]) -> int:
    """Global score out of 100: 100 minus 2 points per risk point, floored at 0."""
    total = sum(f.risk_score or 0.0 for f in findings)
    return max(0, round(100 - 2 * total))
