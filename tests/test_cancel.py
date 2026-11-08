"""Cancelling a scan: cooperative stop between requests, partial results kept."""

import pytest
from fastapi.testclient import TestClient

from backend import scanner
from backend.storage import Storage
from chatbot import app as lab
from engine.attacks.data_leakage import DataLeakageModule
from engine.attacks.prompt_injection import PromptInjectionModule
from engine.connector import HttpConnector, TargetConfig
from engine.orchestrator import run_module, run_scan
from tests.test_api import login, make_app, new_project, scan


def connector() -> HttpConnector:
    cfg = TargetConfig(url="http://testserver/chat", min_interval=0)
    return HttpConnector(cfg, client=TestClient(lab.app))


@pytest.fixture(autouse=True)
def vulnerable_lab(monkeypatch):
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")


def test_run_module_stops_immediately_when_asked() -> None:
    c = connector()
    assert run_module(c, DataLeakageModule(), should_stop=lambda: True) == []
    assert c.history == []


def test_run_module_returns_findings_proven_before_the_stop() -> None:
    c = connector()
    full = run_module(connector(), DataLeakageModule())
    assert len(full) >= 1
    calls = {"n": 0}

    def stop_after_first_payload() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    partial = run_module(c, DataLeakageModule(), should_stop=stop_after_first_payload)
    assert len(partial) < len(full)


def test_run_scan_skips_remaining_modules() -> None:
    c = connector()
    out = run_scan(c, [DataLeakageModule(), PromptInjectionModule()], should_stop=lambda: True)
    assert out == [] and c.history == []


def _assessment(tmp_path, modules):
    storage = Storage(str(tmp_path / "s.db"))
    user = storage.create_user("a@example.com", "x")
    project = storage.create_project(user["id"], "p", "", "chatbot")
    cfg = {"url": "http://testserver/chat", "min_interval": 0}
    a = storage.create_assessment(project["id"], cfg, modules, "quick")
    return storage, a["id"]


def factory():
    return TestClient(lab.app)


def test_assessment_cancelled_before_start(tmp_path) -> None:
    storage, aid = _assessment(tmp_path, ["data_leakage"])
    registry = scanner.CancelRegistry()
    registry.request(aid)
    scanner.run_assessment(storage, aid, factory, None, registry)
    a = storage.get_assessment(aid)
    assert a["status"] == "cancelled" and storage.list_findings(aid) == []
    assert not registry.is_requested(aid)


def test_assessment_cancelled_midway_keeps_partial_results(tmp_path) -> None:
    storage, aid = _assessment(tmp_path, ["data_leakage", "output", "prompt_injection"])

    class StopAfterFirstModule(scanner.CancelRegistry):
        def is_requested(self, assessment_id: int) -> bool:
            return storage.get_assessment(assessment_id)["progress"] >= 30

    registry = StopAfterFirstModule()
    scanner.run_assessment(storage, aid, factory, None, registry)
    a = storage.get_assessment(aid)
    assert a["status"] == "cancelled"
    assert a["progress"] < 100
    assert a["finished_at"] is not None
    scenarios = {f["scenario_id"] for f in storage.list_findings(aid)}
    assert scenarios and scenarios < set(lab.KNOWN_VULNS)


def test_cancel_endpoint_rejects_finished_and_foreign_assessments(tmp_path) -> None:
    app = make_app(tmp_path)
    alice = login(TestClient(app), "alice@example.com")
    bob = login(TestClient(app), "bob@example.com")
    aid = scan(alice, new_project(alice)).json()["id"]

    assert alice.post(f"/assessments/{aid}/cancel").status_code == 409
    assert bob.post(f"/assessments/{aid}/cancel").status_code == 404
    assert alice.post("/assessments/9999/cancel").status_code == 404
    assert TestClient(app).post(f"/assessments/{aid}/cancel").status_code == 401
