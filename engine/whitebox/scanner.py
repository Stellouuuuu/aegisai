"""Walk a source tree and apply the static rules."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from engine.core.models import Confidence, Finding
from engine.whitebox.rules import RULES, Rule

SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", ".next", "coverage",
    ".mypy_cache", ".ruff_cache", ".pytest_cache",
}
TEST_MARKERS = ("test_", ".test.", ".spec.", "_test.py", "/tests/", "/__tests__/", "/fixtures/")
MAX_FILE_BYTES = 500_000
IGNORE_MARK = "aegis-ignore"


def _is_test(path: str) -> bool:
    low = "/" + path.replace("\\", "/").lower()
    return any(marker in low or low.endswith(marker.strip("/")) for marker in TEST_MARKERS)


def _iter_files(root: Path, include_tests: bool) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if not include_tests and _is_test(str(path.relative_to(root))):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        yield path


def _scan_text(rule: Rule, text: str) -> Iterable[tuple[int, str]]:
    if rule.file_exempt and rule.file_exempt.search(text):
        return
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        if IGNORE_MARK in line or not rule.line.search(line):
            continue
        if rule.context is not None:
            around = "\n".join(lines[max(0, number - 1 - rule.window): number + rule.window])
            if not rule.context.search(around):
                continue
        yield number, line.strip()[:200]


def audit_code(
    root: str | Path, include_tests: bool = False
) -> list[tuple[Finding, dict[str, Any]]]:
    """Findings with their location, for every rule match under `root`."""
    base = Path(root)
    found: list[tuple[Finding, dict[str, Any]]] = []
    for path in _iter_files(base, include_tests):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        shown = str(path.relative_to(base)) if base.is_dir() else path.name
        for rule in RULES:
            for number, line in _scan_text(rule, text):
                finding = Finding(
                    id=rule.id, category="static_analysis", owasp=rule.owasp, atlas=None,
                    severity=rule.severity, confidence=Confidence.NEEDS_REVIEW,
                    scenario=rule.title, request="", response=line,
                    evidence=f"{shown}:{number}: {line}",
                    safety_rule_violated=rule.rule_violated, recommendation=rule.recommendation,
                    reproducible=True, extra={},
                )
                found.append((finding, {"file": shown.replace("\\", "/"), "line": number}))
    return found


def build_code_report(
    root: str | Path, results: list[tuple[Finding, dict[str, Any]]], duration_s: float
) -> dict[str, Any]:
    items = []
    for finding, location in results:
        data = finding.to_dict()
        data["location"] = location
        items.append(data)
    return {
        "report_version": "1",
        "kind": "code",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": str(root),
        "duration_seconds": round(duration_s, 2),
        "summary": dict(Counter(f["severity"] for f in items)),
        "findings": items,
    }


def timed_audit(root: str | Path, include_tests: bool = False) -> dict[str, Any]:
    start = time.monotonic()
    results = audit_code(root, include_tests)
    return build_code_report(root, results, time.monotonic() - start)
