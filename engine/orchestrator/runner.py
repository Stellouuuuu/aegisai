"""Runner: Connector -> payloads -> detector -> evaluator -> Finding."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor

from engine.connector import ConnectorError, HttpConnector
from engine.core.models import AppProfile, Confidence, Finding
from engine.core.module import AttackModule
from engine.evaluators.replay import baseline_violates, replay

BASELINE_PROMPT = "Bonjour, peux-tu m'aider ?"
StopCheck = Callable[[], bool]


def run_module(
    connector: HttpConnector,
    module: AttackModule,
    profile: AppProfile | None = None,
    repeats: int = 3,
    should_stop: StopCheck | None = None,
) -> list[Finding]:
    """Run one module. `should_stop` is polled between requests: when it returns True the
    run ends cleanly and the findings proven so far are returned."""
    stop = should_stop or (lambda: False)
    profile = profile or AppProfile()
    if stop():
        return []
    baseline = connector.send(BASELINE_PROMPT)

    findings: dict[str, Finding] = {}
    tried: dict[str, int] = {}
    for payload in module.generate_payloads(profile):
        if stop():
            break
        sid = payload.scenario_id
        if sid in findings or baseline_violates(module, sid, baseline):
            continue
        if payload.turns and not connector.supports_conversation:
            continue
        needs_peer = payload.plant or payload.as_other_user or payload.documents_by_other_user
        if needs_peer and connector.peer is None:
            continue
        if payload.documents and not connector.supports_ingest:
            continue
        tried[sid] = tried.get(sid, 0) + 1
        try:
            response = connector.send_payload(payload)
        except ConnectorError:
            continue
        verdict = module.detect(payload, response)
        if not verdict.violated:
            continue

        rep = replay(connector, module, payload, repeats)
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
    connector: HttpConnector,
    modules: Iterable[AttackModule],
    repeats: int = 3,
    should_stop: StopCheck | None = None,
    workers: int = 1,
) -> list[Finding]:
    """Run the modules sequentially or `workers` at a time; findings keep module order."""
    mods = list(modules)

    def one(m: AttackModule) -> list[Finding]:
        return run_module(connector, m, repeats=repeats, should_stop=should_stop)

    if workers <= 1 or len(mods) <= 1:
        out: list[Finding] = []
        for m in mods:
            if should_stop and should_stop():
                break
            out.extend(one(m))
        return out
    with ThreadPoolExecutor(max_workers=min(workers, len(mods))) as pool:
        return [f for found in pool.map(one, mods) for f in found]


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
