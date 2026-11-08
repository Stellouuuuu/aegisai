"""Bridges the REST layer and the engine: runs assessments and retests."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import httpx

from backend.ssrf import TargetPolicy
from backend.storage import Storage, now
from engine.attacks.registry import build_modules, module_class_by_id
from engine.connector import AuthConfig, HttpConnector, TargetConfig
from engine.core.models import Finding
from engine.orchestrator import run_module, run_scan
from engine.profiler import profile_target
from engine.reporting import build_report
from engine.risk_engine import assess, security_score

DEPTH_REPEATS = {"quick": 1, "standard": 3, "deep": 5}
ClientFactory = Callable[[], httpx.Client]


class CancelRegistry:
    """Assessment ids whose cancellation was requested. The running scan polls it between
    requests, so it stops cleanly instead of being killed mid-write."""

    def __init__(self) -> None:
        self._ids: set[int] = set()
        self._lock = threading.Lock()

    def request(self, assessment_id: int) -> None:
        with self._lock:
            self._ids.add(assessment_id)

    def is_requested(self, assessment_id: int) -> bool:
        with self._lock:
            return assessment_id in self._ids

    def clear(self, assessment_id: int) -> None:
        with self._lock:
            self._ids.discard(assessment_id)


def target_config(cfg: dict[str, Any]) -> TargetConfig:
    return TargetConfig(
        url=cfg["url"],
        method=cfg.get("method", "POST"),
        request_template=cfg.get("request_template", {"message": "{{PROMPT}}"}),
        response_path=cfg.get("response_path", "$.reply"),
        tool_calls_path=cfg.get("tool_calls_path"),
        auth=AuthConfig(**cfg.get("auth", {})),
        min_interval=float(cfg.get("min_interval", 0.2)),
        timeout=float(cfg.get("timeout", 30)),
        stream=bool(cfg.get("stream", False)),
    )


def make_connector(cfg: dict[str, Any], client_factory: ClientFactory | None) -> HttpConnector:
    return HttpConnector(target_config(cfg), client=client_factory() if client_factory else None)


def run_assessment(
    storage: Storage,
    assessment_id: int,
    client_factory: ClientFactory | None,
    policy: TargetPolicy | None = None,
    cancel: CancelRegistry | None = None,
) -> None:
    cancel = cancel or CancelRegistry()

    def stopped() -> bool:
        return cancel.is_requested(assessment_id)

    a = storage.get_assessment(assessment_id)
    assert a is not None
    if stopped():  # cancelled before it even started
        storage.update_assessment(assessment_id, status="cancelled", finished_at=now())
        cancel.clear(assessment_id)
        return
    storage.update_assessment(assessment_id, status="running", progress=0)
    start = time.monotonic()
    connector = None
    try:
        if policy:
            policy.check(a["config"]["url"])  # re-checked right before connecting
        connector = make_connector(a["config"], client_factory)
        if a["config"].get("second_auth"):
            connector.peer = make_connector(
                {**a["config"], "auth": a["config"]["second_auth"]}, client_factory
            )
        ok, msg = connector.test_connection()
        if not ok:
            raise RuntimeError(f"Connection test failed: {msg}")
        options = a["config"].get("options", {})
        allowed = tuple(options.get("allowed_tools") or ())
        module_options: dict[str, dict[str, Any]] = {}
        if allowed:
            module_options["tool_abuse"] = {"allowed_tools": allowed}
        if options.get("rule_checks"):
            module_options["prompt_injection"] = {"rule_checks": options["rule_checks"]}
        if options.get("fact_checks"):
            module_options["output"] = {"fact_checks": options["fact_checks"]}
        modules = build_modules(a["modules"], module_options)
        workers = int(options.get("workers", 1))
        repeats = DEPTH_REPEATS[a["depth"]]
        findings: list[Finding] = []
        if workers > 1:  # modules run together, so there is no per-module progress to report
            findings = run_scan(connector, modules, repeats, should_stop=stopped, workers=workers)
        else:
            for i, module in enumerate(modules, 1):
                findings += run_module(connector, module, repeats=repeats, should_stop=stopped)
                if stopped():
                    break
                storage.update_assessment(assessment_id, progress=round(100 * i / len(modules)))
        cancelled = stopped()
        assess(findings)
        storage.add_findings(assessment_id, [f.to_dict() for f in findings])
        storage.update_assessment(
            assessment_id, status="cancelled" if cancelled else "completed",
            **({} if cancelled else {"progress": 100}),
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
    finally:
        cancel.clear(assessment_id)


def profile_config(
    cfg: dict[str, Any],
    client_factory: ClientFactory | None,
    policy: TargetPolicy | None = None,
) -> dict[str, Any]:
    """Probe a target with harmless questions and return its guessed profile."""
    if policy:
        policy.check(cfg["url"])
    return profile_target(make_connector(cfg, client_factory)).to_dict()


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
