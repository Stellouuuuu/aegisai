"""SARIF 2.1.0 export, so findings show up in GitHub code scanning and other SARIF viewers.

A black-box finding has no source file: it is attached to the scanned URL as a logical location,
and a code-scanning upload needs a file, so `anchor` (default `README.md`) gives GitHub a place to
show it. A static finding from `aegis audit-code` carries its real file and line.
"""

from __future__ import annotations

from typing import Any

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Stellouuuuu/aegisai"

_LEVELS = {
    "critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note",
}
# GitHub ranks results by this number: 9.0+ critical, 7.0+ high, 4.0+ medium, below is low.
_SECURITY_SEVERITY = {
    "critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "1.0",
}


def _rule(finding: dict[str, Any]) -> dict[str, Any]:
    severity = str(finding.get("severity", "medium"))
    tags = ["security", "llm"]
    if finding.get("owasp"):
        tags.append(str(finding["owasp"]))
    if finding.get("atlas"):
        tags.append(str(finding["atlas"]))
    rule: dict[str, Any] = {
        "id": finding["id"],
        "name": finding["id"],
        "shortDescription": {"text": finding.get("scenario") or finding["id"]},
        "fullDescription": {
            "text": finding.get("safety_rule_violated") or finding.get("scenario", ""),
        },
        "help": {"text": finding.get("recommendation") or ""},
        "defaultConfiguration": {"level": _LEVELS.get(severity, "warning")},
        "properties": {"tags": tags, "security-severity": _SECURITY_SEVERITY.get(severity, "5.0")},
    }
    return rule


def _result(finding: dict[str, Any], target: str, anchor: str) -> dict[str, Any]:
    severity = str(finding.get("severity", "medium"))
    extra = finding.get("extra") or {}
    location = finding.get("location")
    if location:  # a static finding: a real file and line
        physical: dict[str, Any] = {"artifactLocation": {"uri": location["file"]}}
        if location.get("line"):
            physical["region"] = {"startLine": int(location["line"])}
        locations = [{"physicalLocation": physical}]
    else:
        locations = [{
            "physicalLocation": {"artifactLocation": {"uri": anchor}},
            "logicalLocations": [{"name": target, "kind": "resource"}],
        }]
    text = finding.get("evidence") or finding.get("scenario") or finding["id"]
    return {
        "ruleId": finding["id"],
        "level": _LEVELS.get(severity, "warning"),
        "message": {"text": text},
        "locations": locations,
        "properties": {
            "confidence": finding.get("confidence"),
            "reproducible": finding.get("reproducible"),
            "risk_score": finding.get("risk_score"),
            "replay": f"{extra.get('replay_hits')}/{extra.get('replay_attempts')}"
            if extra.get("replay_attempts") else None,
            "attack": str(finding.get("request", ""))[:500],
        },
    }


def to_sarif(report: dict[str, Any], anchor: str = "README.md") -> dict[str, Any]:
    """Convert a JSON report (from `aegis scan` or `aegis audit-code`) to a SARIF log."""
    findings = [f for f in report.get("findings", []) if f.get("confidence") != "rejected"]
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rules.setdefault(finding["id"], _rule(finding))
    target = str(report.get("target", "unknown"))
    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "AegisAI",
                "informationUri": INFORMATION_URI,
                "rules": list(rules.values()),
            }},
            "automationDetails": {"id": f"aegisai/{report.get('kind', 'scan')}/"},
            "results": [_result(f, target, anchor) for f in findings],
        }],
    }
