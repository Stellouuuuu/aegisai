"""Bridges the REST layer and the engine: runs assessments and retests."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from backend.ssrf import TargetPolicy
from backend.storage import Storage, now
from engine.attacks.registry import build_modules, module_class_by_id
from engine.connector import AuthConfig, HttpConnector, TargetConfig
from engine.core.models import Finding
from engine.orchestrator import run_module
from engine.reporting import build_report
from engine.risk_engine import assess, security_score

DEPTH_REPEATS = {"quick": 1, "standard": 3, "deep": 5}
ClientFactory = Callable[[], httpx.Client]


def target_config(cfg: dict[str, Any]) -> TargetConfig:
    return TargetConfig(
        url=cfg["url"],
        method=cfg.get("method", "POST"),
        request_template=cfg.get("request_template", {"message": "{{PROMPT}}"}),
        response_path=cfg.get("response_path", "$.reply"),
        tool_calls_path=cfg.get("tool_calls_path"),
        auth=AuthConfig(**cfg.get("auth", {})),
        min_interval=float(cfg.get("min_interval", 0.2)),
    )


def make_connector(cfg: dict[str, Any], client_factory: ClientFactory | None) -> HttpConnector:
    return HttpConnector(target_config(cfg), client=client_factory() if client_factory else None)


def run_assessment(
    storage: Storage,
    assessment_id: int,
    client_factory: ClientFactory | None,
    policy: TargetPolicy | None = None,
) -> None:
    a = storage.get_assessment(assessment_id)
    assert a is not None
    storage.update_assessment(assessment_id, status="running", progress=0)
    start = time.monotonic()
    connector = None
    try:
        if policy:
            policy.check(a["config"]["url"])  # re-checked right before connecting
        connector = make_connector(a["config"], client_factory)
        ok, msg = connector.test_connection()
        if not ok:
            raise RuntimeError(f"Connection test failed: {msg}")
        modules = build_modules(a["modules"])
        findings: list[Finding] = []
        for i, module in enumerate(modules, 1):
            findings += run_module(connector, module, repeats=DEPTH_REPEATS[a["depth"]])
            storage.update_assessment(assessment_id, progress=round(100 * i / len(modules)))
        assess(findings)
        storage.add_findings(assessment_id, [f.to_dict() for f in findings])
        storage.update_assessment(
            assessment_id, status="completed", progress=100,
            security_score=security_score(findings),
            requests_sent=len(connector.history),
            duration_seconds=round(time.monotonic() - start, 2), finished_at=now(),
        )
    except Exception as e:  # any failure must end the assessment, not hang it in 'running'
        storage.update_assessment(
            assessment_id, status="failed", error=str(e)[:500],
            requests_sent=len(connector.history) if connector else 0,
            duration_seconds=round(time.monotonic() - start, 2), finished_at=now(),
        )


def open_findings(storage: Storage, assessment_id: int) -> list[Finding]:
    return [
        Finding.from_dict(row["data"])
        for row in storage.list_findings(assessment_id)
        if row["status"] == "open"
    ]


def retest_finding(
    storage: Storage,
    finding_id: int,
    client_factory: ClientFactory | None,
    policy: TargetPolicy | None = None,
) -> dict[str, Any]:
    """Re-run the finding's module; the finding is 'resolved' if its scenario no longer hits."""
    row = storage.get_finding(finding_id)
    assert row is not None
    a = storage.get_assessment(row["assessment_id"])
    assert a is not None
    if policy:
        policy.check(a["config"]["url"])
    module = module_class_by_id(row["data"]["category"])()
    connector = make_connector(a["config"], client_factory)
    still = [
        f for f in assess(run_module(
            connector, module, repeats=DEPTH_REPEATS[a["depth"]]
        )) if f.id == row["scenario_id"]
    ]
    if still:
        storage.update_finding(finding_id, still[0].to_dict(), "open")
        status = "open"
    else:
        storage.update_finding(finding_id, None, "resolved")
        status = "resolved"
    storage.update_assessment(
        a["id"], security_score=security_score(open_findings(storage, a["id"]))
    )
    return {"finding_id": finding_id, "status": status}


def assessment_report(storage: Storage, assessment_id: int) -> dict[str, Any]:
    a = storage.get_assessment(assessment_id)
    assert a is not None
    report = build_report(
        a["config"]["url"], open_findings(storage, assessment_id), a["modules"],
        a["depth"], a["duration_seconds"] or 0.0, a["requests_sent"],
    )
    report["resolved_findings"] = [
        r["scenario_id"] for r in storage.list_findings(assessment_id) if r["status"] == "resolved"
    ]
    return report
