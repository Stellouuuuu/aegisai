"""Sequential runner: Connector -> payloads -> detector -> evaluator -> Finding.

The full orchestrator (profiles, depth, concurrency) will call these functions.
"""

from __future__ import annotations

from collections.abc import Iterable

from engine.connector import ConnectorError, HttpConnector
from engine.core.models import AppProfile, Confidence, Finding
from engine.core.module import AttackModule
from engine.evaluators.replay import baseline_violates, replay

BASELINE_PROMPT = "Bonjour, peux-tu m'aider ?"


def run_module(
    connector: HttpConnector,
    module: AttackModule,
    profile: AppProfile | None = None,
    repeats: int = 3,
) -> list[Finding]:
    profile = profile or AppProfile()
    baseline = connector.send(BASELINE_PROMPT)

    findings: dict[str, Finding] = {}
    tried: dict[str, int] = {}
    for payload in module.generate_payloads(profile):
        sid = payload.scenario_id
        if sid in findings or baseline_violates(module, sid, baseline):
            continue  # one proven finding per scenario is enough
        tried[sid] = tried.get(sid, 0) + 1
        try:
            response = connector.send(payload.text)
        except ConnectorError:
            continue
        verdict = module.detect(payload, response)
        if not verdict.violated:
            continue

        rep = replay(connector, module, payload, repeats)
        # Deterministic evidence + reliable reproduction => confirmed; otherwise a human decides.
        confirmed = verdict.deterministic and rep.stable
        sc = module.scenario(sid)
        findings[sid] = Finding(
            id=sid,
            category=module.id,
            owasp=sc.owasp,
            atlas=sc.atlas,
            severity=sc.severity,
            confidence=Confidence.CONFIRMED if confirmed else Confidence.NEEDS_REVIEW,
            scenario=sc.title,
            request=payload.text,
            response=response.text,
            evidence=verdict.evidence,
            safety_rule_violated=sc.rule_violated,
            recommendation=sc.recommendation,
            reproducible=rep.reproducible,
            extra={"replay_hits": rep.hits, "replay_attempts": rep.attempts,
                   "success_rate": round(rep.success_rate, 3),
                   "payloads_tried": tried[sid],
                   "tool_calls": list(response.tool_calls)},
        )
    return list(findings.values())


def run_scan(
    connector: HttpConnector, modules: Iterable[AttackModule], repeats: int = 3
) -> list[Finding]:
    out: list[Finding] = []
    for m in modules:
        out.extend(run_module(connector, m, repeats=repeats))
    return out


def detection_metrics(findings: Iterable[Finding], expected_ids: Iterable[str]) -> dict[str, float]:
    """Recall/precision against ground truth (only non-rejected findings count)."""
    found = {f.id for f in findings if f.confidence is not Confidence.REJECTED}
    expected = set(expected_ids)
    tp = len(found & expected)
    return {
        "recall": tp / len(expected) if expected else 1.0,
        "precision": tp / len(found) if found else 1.0,
        "false_positives": len(found - expected),
        "missed": len(expected - found),
    }
