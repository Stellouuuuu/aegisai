"""End-to-end: all MVP modules vs. the lab's ground truth (KNOWN_VULNS)."""

import pytest
from fastapi.testclient import TestClient

from chatbot import app as lab
from engine.attacks.data_leakage import DataLeakageModule
from engine.attacks.output_handling import OutputSecurityModule
from engine.attacks.prompt_injection import PromptInjectionModule
from engine.attacks.tool_abuse import ToolSecurityModule
from engine.connector import HttpConnector, TargetConfig
from engine.core import AttackModule, Confidence
from engine.orchestrator import detection_metrics, run_scan


def connector() -> HttpConnector:
    cfg = TargetConfig(url="http://testserver/chat", tool_calls_path="$.tool_calls")
    return HttpConnector(cfg, client=TestClient(lab.app))


def modules() -> list[AttackModule]:
    return [
        PromptInjectionModule(),
        DataLeakageModule(),
        OutputSecurityModule(),
        ToolSecurityModule(),
    ]


def test_all_modules_follow_protocol() -> None:
    assert all(isinstance(m, AttackModule) for m in modules())


def test_vulnerable_lab_full_recall(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    findings = run_scan(connector(), modules())
    m = detection_metrics(findings, lab.KNOWN_VULNS)
    assert m == {"recall": 1.0, "precision": 1.0, "false_positives": 0, "missed": 0}
    assert all(f.confidence is Confidence.CONFIRMED and f.reproducible for f in findings)


def test_patched_lab_has_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "patched")
    assert run_scan(connector(), modules()) == []


class _Reply:
    tool_calls: list = []

    def __init__(self, text: str) -> None:
        self.text = text


@pytest.mark.parametrize("text", [
    "<script>alert(1)</script>",
    '<img src=x onerror="alert(1)">',
    '<a href="javascript:alert(1)">x</a>',
    "<BODY ONLOAD = 'x()'>",
])
def test_output_module_flags_active_content(text: str) -> None:
    from engine.core import Payload

    assert OutputSecurityModule().detect(Payload("x", "OS-01"), _Reply(text)).violated


@pytest.mark.parametrize("text", [
    "&lt;script&gt;alert(1)&lt;/script&gt;",  # escaped by the application
    "Use the onload = handler of the body element.",  # prose, no tag
    "Write javascript: in the address bar to run code.",  # prose, no attribute
    "Bonjour, comment puis-je vous aider ?",
])
def test_output_module_ignores_escaped_or_plain_text(text: str) -> None:
    from engine.core import Payload

    assert not OutputSecurityModule().detect(Payload("x", "OS-01"), _Reply(text)).violated
