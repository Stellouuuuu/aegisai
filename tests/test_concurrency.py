"""Parallel module execution keeps results identical and the rate limit global."""

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from chatbot import app as lab
from engine.attacks.data_leakage import DataLeakageModule
from engine.attacks.output_handling import OutputSecurityModule
from engine.attacks.prompt_injection import PromptInjectionModule
from engine.attacks.tool_abuse import ToolSecurityModule
from engine.cli import main
from engine.connector import HttpConnector, TargetConfig
from engine.orchestrator import run_scan


def mods():
    return [PromptInjectionModule(), DataLeakageModule(), OutputSecurityModule(),
            ToolSecurityModule()]


def connector(min_interval: float = 0.0, **kw) -> HttpConnector:
    cfg = TargetConfig(url="http://testserver/chat", tool_calls_path="$.tool_calls",
                       min_interval=min_interval)
    return HttpConnector(cfg, client=kw.get("client") or TestClient(lab.app))


@pytest.fixture(autouse=True)
def vulnerable(monkeypatch):
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")


def test_parallel_run_finds_the_same_things_in_the_same_order() -> None:
    serial = run_scan(connector(), mods())
    parallel = run_scan(connector(), mods(), workers=4)
    assert [f.id for f in parallel] == [f.id for f in serial]
    assert {f.id for f in parallel} == set(lab.KNOWN_VULNS)


def test_history_counts_every_request_when_parallel() -> None:
    c = connector()
    run_scan(c, mods(), workers=4)
    assert len(c.history) > 20
    assert all("status" in h for h in c.history)


def test_min_interval_is_a_global_limit_across_threads() -> None:
    stamps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        stamps.append(time.monotonic())
        return httpx.Response(200, json={"reply": "ok", "tool_calls": []})

    c = connector(0.05, client=httpx.Client(transport=httpx.MockTransport(handler)))
    run_scan(c, mods(), workers=4, repeats=1)
    gaps = [b - a for a, b in zip(stamps, stamps[1:], strict=False)]
    assert len(stamps) > 8
    assert min(gaps) >= 0.04  # 0.05 s requested, small timer slack allowed


def test_stop_check_ends_parallel_runs_too() -> None:
    c = connector()
    assert run_scan(c, mods(), workers=4, should_stop=lambda: True) == []
    assert c.history == []


def test_cli_workers_option(tmp_path) -> None:
    base = ["scan", "--url", "http://testserver/chat", "--tool-calls-path", "$.tool_calls",
            "--min-interval", "0", "--confirm-authorized", "--out", str(tmp_path / "r.json")]
    assert main(base + ["--workers", "4"], TestClient(lab.app)) == 0
    with pytest.raises(SystemExit):  # argparse rejects values outside 1..8
        main(base + ["--workers", "99"], TestClient(lab.app))
