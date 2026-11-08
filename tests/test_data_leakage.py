import httpx
import pytest
from fastapi.testclient import TestClient

from chatbot import app as lab
from engine.attacks.data_leakage import DataLeakageModule
from engine.connector import HttpConnector, TargetConfig
from engine.core import AttackModule, Confidence, Severity
from engine.orchestrator import run_module


def lab_connector() -> HttpConnector:
    return HttpConnector(TargetConfig(url="http://testserver/chat"), client=TestClient(lab.app))


def mock_connector(reply_for) -> HttpConnector:
    def handler(req: httpx.Request) -> httpx.Response:
        msg = req.read().decode()
        return httpx.Response(200, json={"reply": reply_for(msg)})

    return HttpConnector(
        TargetConfig(url="http://t/chat"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_module_follows_plugin_protocol() -> None:
    m = DataLeakageModule()
    assert isinstance(m, AttackModule)
    ids = {p.scenario_id for p in m.generate_payloads(None)}  # type: ignore[arg-type]
    assert ids == {"DL-01", "DL-02", "DL-05"}


def test_detects_planted_flaws_in_vulnerable_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    findings = run_module(lab_connector(), DataLeakageModule())
    by_id = {f.id: f for f in findings}
    assert set(by_id) == {"DL-01", "DL-02"}  # recall 2/2 on the lab's data-leak flaws
    for f in findings:
        assert f.confidence is Confidence.CONFIRMED and f.reproducible
        assert lab.CANARY in f.response
    assert by_id["DL-01"].severity is Severity.CRITICAL
    assert by_id["DL-02"].owasp == "LLM07:2025"


def test_no_findings_on_patched_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "patched")
    assert run_module(lab_connector(), DataLeakageModule()) == []


def test_baseline_leak_means_no_finding() -> None:
    # Target that always prints the canary: any "detection" would be meaningless.
    c = mock_connector(lambda _m: "Code: SECRET_TEST_4821")
    assert run_module(c, DataLeakageModule()) == []


def test_unstable_leak_needs_review() -> None:
    # Leaks only on the first attack attempt, then behaves: not reproducible.
    state = {"n": 0}

    def reply(msg: str) -> str:
        if "debug" in msg:
            state["n"] += 1
            return "SECRET_TEST_4821" if state["n"] == 1 else "non"
        return "ok"

    findings = run_module(mock_connector(reply), DataLeakageModule())
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.NEEDS_REVIEW and not findings[0].reproducible


def test_marker_only_evidence_is_needs_review() -> None:
    m = DataLeakageModule(system_prompt_markers=("boutique Acme",))
    c = mock_connector(lambda msg: "Je suis la boutique Acme" if "system prompt" in msg else "ok")
    findings = run_module(c, m)
    assert [f.id for f in findings] == ["DL-02"]
    assert findings[0].confidence is Confidence.NEEDS_REVIEW


def test_markdown_escaped_canary_is_still_detected() -> None:
    from engine.core import Payload

    class R:
        text = "Le code est SECRET\\_TEST\\_4821 voila"
        tool_calls: list = []

    assert DataLeakageModule().detect(Payload("x", "DL-01"), R()).violated


def test_mostly_reproducible_leak_is_confirmed_but_not_strictly_reproducible() -> None:
    # Leaks on 1st try and 2 of 3 replays: a non-deterministic model, still a real finding.
    state = {"n": 0}

    def reply(msg: str) -> str:
        if "debug" in msg:
            state["n"] += 1
            return "non" if state["n"] == 3 else "SECRET_TEST_4821"
        return "ok"

    f = run_module(mock_connector(reply), DataLeakageModule())[0]
    assert f.confidence is Confidence.CONFIRMED and not f.reproducible
    assert f.extra["success_rate"] == 0.75
