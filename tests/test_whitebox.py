import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.reporting.sarif import to_sarif
from engine.whitebox import audit_code, build_code_report

FIXTURES = Path(__file__).parent / "fixtures" / "whitebox"


def hits(name: str) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for finding, location in audit_code(FIXTURES / name):
        out.setdefault(finding.id, []).append(location["line"])
    return out


def test_python_rules_fire_on_the_right_lines() -> None:
    found = hits("vulnerable_app.py")
    assert found["AC-01"] == [12, 13]  # eval and subprocess shell=True on model output
    assert found["AC-03"] == [15]  # SQL built from the model's answer
    assert found["AC-04"] == [7]  # hard coded key
    assert found["AC-05"] == [21]  # destructive tool, no confirmation anywhere in the file
    assert found["AC-06"] == [16]  # user input inside the system prompt


def test_typescript_rules_fire() -> None:
    found = hits("vulnerable_ui.tsx")
    assert found["AC-02"] == [2, 6]
    assert found["AC-01"] == [7]
    assert found["AC-05"] == [11]


def test_clean_code_has_no_finding() -> None:
    assert hits("clean_app.py") == {}


def test_inline_ignore_mark_is_respected() -> None:
    text = (FIXTURES / "clean_app.py").read_text()
    assert "eval(code)  # aegis-ignore" in text  # a real match that the mark silences
    assert hits("clean_app.py") == {}


def test_test_files_are_skipped_in_a_folder_scan_unless_asked() -> None:
    assert audit_code(FIXTURES.parent.parent) == [] or all(
        "fixtures" not in loc["file"] for _, loc in audit_code(FIXTURES.parent.parent)
    )
    with_tests = audit_code(FIXTURES, include_tests=True)
    assert with_tests  # the fixtures folder itself is not skipped when it is the root


def test_findings_are_never_reported_as_confirmed() -> None:
    results = audit_code(FIXTURES / "vulnerable_app.py")
    assert results and all(f.confidence.value == "needs_review" for f, _ in results)


def test_sarif_points_at_real_files_and_lines() -> None:
    results = audit_code(FIXTURES / "vulnerable_app.py")
    sarif = to_sarif(build_code_report(FIXTURES, results, 0.1))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {"AC-01", "AC-03", "AC-04"}
    first = next(r for r in run["results"] if r["ruleId"] == "AC-04")
    region = first["locations"][0]["physicalLocation"]
    assert region["artifactLocation"]["uri"] == "vulnerable_app.py"
    assert region["region"]["startLine"] == 7
    assert first["level"] == "error"
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "AC-04")
    assert rule["properties"]["security-severity"] == "8.0"


def test_cli_audit_code_writes_json_and_sarif(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out, sarif = tmp_path / "r.json", tmp_path / "r.sarif"
    code = main(["audit-code", str(FIXTURES / "vulnerable_app.py"), "--out", str(out),
                 "--sarif", str(sarif), "--fail-on-findings"])
    assert code == 1
    assert json.loads(out.read_text())["kind"] == "code"
    assert json.loads(sarif.read_text())["runs"][0]["results"]
    assert "AC-04" in capsys.readouterr().out
    assert main(["audit-code", str(FIXTURES / "clean_app.py"), "--out", str(out),
                 "--fail-on-findings"]) == 0
    assert main(["audit-code", str(tmp_path / "missing"), "--out", str(out)]) == 2
