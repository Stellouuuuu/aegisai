import pytest


def test_pdf_report_handles_hostile_content_and_no_findings(tmp_path) -> None:
    pytest.importorskip("reportlab")
    from engine.reporting.pdf_report import render_pdf

    report = {
        "target": "http://x/<b>", "generated_at": "now", "duration_seconds": 1,
        "requests_sent": 3, "depth": "quick", "modules": ["output"], "security_score": 60,
        "summary": {"high": 1},
        "findings": [{
            "id": "OS-01", "severity": "high", "scenario": "XSS <i>", "owasp": "LLM05:2025",
            "atlas": None, "risk_score": 7.5, "confidence": "confirmed", "reproducible": True,
            "evidence": "<script>", "safety_rule_violated": "r & s",
            "request": "q ≥ 中", "response": "<script>alert(1)</script>" * 20,
            "recommendation": "escape",
        }],
    }
    assert render_pdf(report, tmp_path / "a.pdf").stat().st_size > 1000
    report["findings"], report["summary"] = [], {}
    assert render_pdf(report, tmp_path / "b.pdf").stat().st_size > 1000
