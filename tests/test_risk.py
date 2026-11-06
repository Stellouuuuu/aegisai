from engine.core import Confidence, Finding, Severity
from engine.risk_engine import assess, security_score


def finding(sev: Severity, conf: Confidence, tried: int = 1, hits: int = 3) -> Finding:
    return Finding(
        id="X", category="c", owasp="LLM01:2025", severity=sev, confidence=conf,
        scenario="s", request="q", response="r", evidence="e",
        safety_rule_violated="r", recommendation="fix",
        extra={"payloads_tried": tried, "replay_hits": hits, "replay_attempts": 3},
    )


def test_risk_scoring() -> None:
    crit = assess([finding(Severity.CRITICAL, Confidence.CONFIRMED)])[0]
    assert crit.risk_score == 10.0 and crit.exploitability == 1.0
    review = assess([finding(Severity.CRITICAL, Confidence.NEEDS_REVIEW)])[0]
    assert review.risk_score == 5.0
    harder = assess([finding(Severity.HIGH, Confidence.CONFIRMED, tried=5)])[0]
    assert harder.exploitability == 0.5 and harder.risk_score == 3.75
    flaky = assess([finding(Severity.HIGH, Confidence.NEEDS_REVIEW, hits=1)])[0]
    assert flaky.exploitability == 0.5  # (1 + 1) / (3 + 1): the first hit counts
    never = assess([finding(Severity.CRITICAL, Confidence.NEEDS_REVIEW, hits=0)])[0]
    assert never.risk_score == 1.25  # observed once: not zero


def test_security_score_bounds() -> None:
    assert security_score([]) == 100
    many = assess([finding(Severity.CRITICAL, Confidence.CONFIRMED) for _ in range(10)])
    assert security_score(many) == 0
