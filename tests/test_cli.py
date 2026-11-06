import json

import pytest
from fastapi.testclient import TestClient

from chatbot import app as lab
from engine.cli import main

BASE = ["scan", "--url", "http://testserver/chat", "--tool-calls-path", "$.tool_calls",
        "--min-interval", "0", "--confirm-authorized"]


def test_cli_refuses_without_authorization(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--url", "http://testserver/chat"], TestClient(lab.app)) == 2
    assert "confirm-authorized" in capsys.readouterr().err


def test_cli_scan_vulnerable_lab(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    out = tmp_path / "r.json"
    code = main(BASE + ["--out", str(out), "--fail-on-findings"], TestClient(lab.app))
    assert code == 1
    report = json.loads(out.read_text())
    assert {f["id"] for f in report["findings"]} == set(lab.KNOWN_VULNS)
    assert report["security_score"] < 100 and report["summary"]["critical"] == 2
    assert all(f["risk_score"] is not None for f in report["findings"])
    assert "Security score" in capsys.readouterr().out
    assert main(["report", str(out)]) == 0


def test_cli_scan_patched_lab_is_clean(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "patched")
    out = tmp_path / "r.json"
    assert main(BASE + ["--out", str(out), "--fail-on-findings"], TestClient(lab.app)) == 0
    assert json.loads(out.read_text())["security_score"] == 100


def test_cli_config_file_and_module_selection(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    cfg = tmp_path / "t.yaml"
    cfg.write_text("url: http://testserver/chat\nmin_interval: 0\nmodules: [data_leakage]\n")
    out = tmp_path / "r.json"
    assert main(["scan", "--config", str(cfg), "--out", str(out), "--confirm-authorized"],
                TestClient(lab.app)) == 0
    assert {f["id"] for f in json.loads(out.read_text())["findings"]} == {"DL-01", "DL-02"}


def test_cli_unknown_module(capsys) -> None:
    assert main(BASE + ["--modules", "nope"], TestClient(lab.app)) == 2


def test_cli_demo_target_end_to_end(tmp_path, capsys) -> None:
    pytest.importorskip("uvicorn")
    out = tmp_path / "demo.json"
    assert main(["scan", "--target", "demo:vulnerable-chatbot", "--min-interval", "0",
                 "--out", str(out)]) == 0
    assert {f["id"] for f in json.loads(out.read_text())["findings"]} == set(lab.KNOWN_VULNS)


def test_cli_unknown_demo_target(capsys) -> None:
    assert main(["scan", "--target", "demo:nope"]) == 2


def test_pdf_report_from_scan(tmp_path, monkeypatch) -> None:
    pytest.importorskip("reportlab")
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    js = tmp_path / "r.json"
    main(BASE + ["--out", str(js)], TestClient(lab.app))
    pdf = tmp_path / "r.pdf"
    assert main(["report", str(js), "--format", "pdf", "-o", str(pdf)]) == 0
    data = pdf.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 3000
