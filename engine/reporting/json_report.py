"""Pivot report: Finding list -> versioned JSON (other formats derive from it)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from engine.core.models import Finding
from engine.risk_engine import security_score

REPORT_VERSION = "1"


def build_report(
    target_url: str,
    findings: Iterable[Finding],
    modules: list[str],
    depth: str,
    duration_s: float,
    requests_sent: int,
) -> dict[str, Any]:
    items = sorted(findings, key=lambda f: f.risk_score or 0.0, reverse=True)
    return {
        "report_version": REPORT_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": target_url,
        "modules": modules,
        "depth": depth,
        "duration_seconds": round(duration_s, 2),
        "requests_sent": requests_sent,
        "security_score": security_score(items),
        "summary": dict(Counter(f.severity.value for f in items)),
        "findings": [f.to_dict() for f in items],
    }


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        f"Target: {report['target']}",
        f"Security score: {report['security_score']}/100",
        f"Findings: {len(report['findings'])} "
        f"({', '.join(f'{k}={v}' for k, v in report['summary'].items()) or 'none'})",
    ]
    for f in report["findings"]:
        lines.append(
            f"  [{f['severity'].upper():8}] {f['id']} {f['scenario']} "
            f"(risk {f['risk_score']}, {f['confidence']})"
        )
    return "\n".join(lines)
