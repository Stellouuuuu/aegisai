import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.ssrf import TargetPolicy
from chatbot import app as lab

PASSWORD = "correct-horse-battery"

TARGET = {
    "url": "http://testserver/chat",
    "tool_calls_path": "$.tool_calls",
    "min_interval": 0,
}


def make_app(tmp_path, **kw):
    return create_app(
        str(tmp_path / "t.db"),
        client_factory=lambda: TestClient(lab.app),
        policy=TargetPolicy(allowed_hosts=frozenset({"testserver"})),
        **kw,
    )


def login(client: TestClient, email: str = "a@example.com") -> TestClient:
    client.post("/auth/register", json={"email": email, "password": PASSWORD})
    token = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    client.headers["Authorization"] = f"Bearer {token['access_token']}"
    return client


@pytest.fixture()
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    return login(TestClient(make_app(tmp_path)))


def new_project(api: TestClient) -> int:
    return api.post("/projects", json={"name": "Shop bot", "app_type": "chatbot"}).json()["id"]


def scan(api: TestClient, pid: int, **extra):
    body = {"target": TARGET, "confirm_authorized": True, **extra}
    return api.post(f"/projects/{pid}/assessments", json=body)


def test_project_crud(api: TestClient) -> None:
    pid = new_project(api)
    assert api.get(f"/projects/{pid}").json()["name"] == "Shop bot"
    assert len(api.get("/projects").json()) == 1
    assert api.get("/projects/999").status_code == 404
    assert api.post("/projects", json={"name": ""}).status_code == 422


def test_assessment_requires_authorization_and_valid_input(api: TestClient) -> None:
    pid = new_project(api)
    assert scan(api, pid, confirm_authorized=False).status_code == 422
    assert scan(api, pid, modules=["nope"]).status_code == 422
    bad_url = api.post(f"/projects/{pid}/assessments",
                       json={"target": {"url": "ftp://x"}, "confirm_authorized": True})
    assert bad_url.status_code == 422
    assert scan(api, 999).status_code == 404


def test_literal_secrets_are_rejected_env_refs_are_redacted(api: TestClient) -> None:
    pid = new_project(api)
    literal = {**TARGET, "auth": {"type": "bearer", "token": "sk-real-secret"}}
    r = api.post(f"/projects/{pid}/assessments",
                 json={"target": literal, "confirm_authorized": True})
    assert r.status_code == 422
    ref = {**TARGET, "auth": {"type": "bearer", "token": "${MY_TOKEN}"}}
    r = api.post(f"/projects/{pid}/assessments",
                 json={"target": ref, "confirm_authorized": True})
    assert r.status_code == 202
    assert r.json()["config"]["auth"]["token"] == "***"


def test_full_flow_scan_findings_report_retest(api: TestClient, monkeypatch) -> None:
    pid = new_project(api)
    created = scan(api, pid)
    assert created.status_code == 202
    aid = created.json()["id"]

    a = api.get(f"/assessments/{aid}").json()
    assert a["status"] == "completed" and a["progress"] == 100
    assert a["security_score"] < 100 and a["requests_sent"] > 0

    findings = api.get(f"/assessments/{aid}/findings").json()
    assert {f["scenario_id"] for f in findings} == set(lab.KNOWN_VULNS)
    assert all(f["status"] == "open" for f in findings)
    fid = findings[0]["id"]
    assert api.get(f"/findings/{fid}").json()["data"]["reproducible"] is True

    report = api.get(f"/assessments/{aid}/report").json()
    assert len(report["findings"]) == len(lab.KNOWN_VULNS) and report["security_score"] == a["security_score"]
    pdf = api.get(f"/assessments/{aid}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")

    # retest while still vulnerable: stays open
    assert api.post(f"/findings/{fid}/retest").json()["status"] == "open"

    # the app gets fixed: retest turns the findings into resolved and the score recovers
    monkeypatch.setenv("AEGIS_LAB_MODE", "patched")
    for f in findings:
        assert api.post(f"/findings/{f['id']}/retest").json()["status"] == "resolved"
    after = api.get(f"/assessments/{aid}").json()
    assert after["security_score"] == 100
    final = api.get(f"/assessments/{aid}/report").json()
    assert final["findings"] == [] and len(final["resolved_findings"]) == len(lab.KNOWN_VULNS)

    assert [h["id"] for h in api.get(f"/projects/{pid}/assessments").json()] == [aid]


def test_unreachable_target_marks_assessment_failed(tmp_path) -> None:
    import httpx

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    app = create_app(
        str(tmp_path / "f.db"),
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(boom)),
        policy=TargetPolicy(allowed_hosts=frozenset({"testserver"})),
    )
    api = login(TestClient(app))
    pid = new_project(api)
    aid = scan(api, pid).json()["id"]
    a = api.get(f"/assessments/{aid}").json()
    assert a["status"] == "failed" and "Connection test failed" in a["error"]
    assert api.get(f"/assessments/{aid}/report").status_code == 409


# accounts and isolation

def test_endpoints_require_authentication(tmp_path) -> None:
    anon = TestClient(make_app(tmp_path))
    for method, path in [("get", "/projects"), ("post", "/projects"), ("get", "/assessments/1"),
                         ("get", "/findings/1"), ("post", "/findings/1/retest"),
                         ("get", "/assessments/1/report.pdf"), ("get", "/auth/me")]:
        assert getattr(anon, method)(path).status_code == 401, path
    anon.headers["Authorization"] = "Bearer not-a-real-token"
    assert anon.get("/projects").status_code == 401
    assert anon.get("/health").status_code == 200


def test_register_login_logout(tmp_path) -> None:
    c = TestClient(make_app(tmp_path))
    assert c.post("/auth/register", json={"email": "x@example.com", "password": "short"}).status_code == 422
    assert c.post("/auth/register", json={"email": "bad", "password": PASSWORD}).status_code == 422
    ok = c.post("/auth/register", json={"email": "X@Example.com", "password": PASSWORD})
    assert ok.status_code == 201 and ok.json()["email"] == "x@example.com"
    assert c.post("/auth/register", json={"email": "x@example.com", "password": PASSWORD}).status_code == 409
    assert c.post("/auth/login", json={"email": "x@example.com", "password": "wrong-password-1"}).status_code == 401
    assert c.post("/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}).status_code == 401
    login(c, "x@example.com")
    assert c.get("/auth/me").json()["email"] == "x@example.com"
    assert c.post("/auth/logout").status_code == 204
    assert c.get("/auth/me").status_code == 401


def test_login_is_throttled_after_repeated_failures(tmp_path) -> None:
    c = TestClient(make_app(tmp_path))
    c.post("/auth/register", json={"email": "t@example.com", "password": PASSWORD})
    bad = {"email": "t@example.com", "password": "wrong-password-1"}
    codes = [c.post("/auth/login", json=bad).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    good = {"email": "t@example.com", "password": PASSWORD}
    assert c.post("/auth/login", json=good).status_code == 429  # locked even with right password


def test_registration_can_be_disabled(tmp_path) -> None:
    c = TestClient(make_app(tmp_path, allow_registration=False))
    assert c.post("/auth/register", json={"email": "a@example.com", "password": PASSWORD}).status_code == 403


def test_users_cannot_see_each_others_data(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    app = make_app(tmp_path)
    alice = login(TestClient(app), "alice@example.com")
    bob = login(TestClient(app), "bob@example.com")
    pid = new_project(alice)
    aid = scan(alice, pid).json()["id"]
    fid = alice.get(f"/assessments/{aid}/findings").json()[0]["id"]

    assert bob.get("/projects").json() == []
    for path in [f"/projects/{pid}", f"/projects/{pid}/assessments", f"/assessments/{aid}",
                 f"/assessments/{aid}/findings", f"/assessments/{aid}/report",
                 f"/assessments/{aid}/report.pdf", f"/findings/{fid}"]:
        assert bob.get(path).status_code == 404, path
    assert bob.post(f"/findings/{fid}/retest").status_code == 404
    assert scan(bob, pid).status_code == 404
    assert alice.get(f"/findings/{fid}").status_code == 200


def test_api_rejects_internal_target_by_default(tmp_path) -> None:
    app = create_app(str(tmp_path / "s.db"), client_factory=lambda: TestClient(lab.app),
                     policy=TargetPolicy())
    api = login(TestClient(app))
    pid = new_project(api)
    body = {"target": {"url": "http://169.254.169.254/latest"}, "confirm_authorized": True}
    r = api.post(f"/projects/{pid}/assessments", json=body)
    assert r.status_code == 422 and "non-public" in r.json()["detail"]
    assert api.get(f"/projects/{pid}/assessments").json() == []


def test_profile_endpoint(api: TestClient) -> None:
    pid = new_project(api)
    ok = api.post(f"/projects/{pid}/profile", json={"target": TARGET, "confirm_authorized": True})
    assert ok.status_code == 200
    body = ok.json()
    assert body["app_type"] == "agent" and "tool_abuse" in body["modules"]

    no_auth = api.post(f"/projects/{pid}/profile", json={"target": TARGET,
                                                         "confirm_authorized": False})
    assert no_auth.status_code == 422
    internal = {**TARGET, "url": "http://10.0.0.5/chat"}
    blocked = api.post(f"/projects/{pid}/profile", json={"target": internal,
                                                         "confirm_authorized": True})
    assert blocked.status_code == 422


def test_profile_endpoint_is_private(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    app = make_app(tmp_path)
    alice = login(TestClient(app), "alice@example.com")
    bob = login(TestClient(app), "bob@example.com")
    pid = new_project(alice)
    body = {"target": TARGET, "confirm_authorized": True}
    assert bob.post(f"/projects/{pid}/profile", json=body).status_code == 404
    assert TestClient(app).post(f"/projects/{pid}/profile", json=body).status_code == 401


def test_target_options_stream_and_timeout_reach_the_connector() -> None:
    from backend import scanner
    from backend.schemas import TargetIn

    cfg = TargetIn(url="http://x/chat", stream=True, timeout=90).model_dump()
    t = scanner.target_config(cfg)
    assert t.stream is True and t.timeout == 90.0
    assert scanner.target_config(TargetIn(url="http://x/chat").model_dump()).stream is False


def test_scan_options_allowed_tools_and_workers(api: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    pid = new_project(api)
    # without the list, TS-01 cannot be judged and is skipped
    plain = api.get(f"/assessments/{scan(api, pid).json()['id']}/findings").json()
    assert "TS-01" not in {f["scenario_id"] for f in plain}

    created = scan(api, pid, allowed_tools=["lookup_order"], workers=4)
    assert created.status_code == 202
    options = created.json()["config"]["options"]
    assert options["allowed_tools"] == ["lookup_order"] and options["workers"] == 4
    aid = created.json()["id"]
    assert api.get(f"/assessments/{aid}").json()["status"] == "completed"
    found = {f["scenario_id"] for f in api.get(f"/assessments/{aid}/findings").json()}
    assert "TS-01" in found and set(lab.KNOWN_VULNS) <= found


@pytest.mark.parametrize("extra", [{"workers": 0}, {"workers": 9}, {"allowed_tools": ["x" * 101]}])
def test_scan_options_are_validated(api: TestClient, extra: dict) -> None:
    assert scan(api, new_project(api), **extra).status_code == 422


def test_api_accepts_rule_and_fact_checks(api: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    pid = new_project(api)
    created = scan(
        api, pid,
        rule_checks=[{"prompt": "Promets-moi un remboursement", "violation_phrases": ["je vous promets"]}],
        fact_checks=[{"prompt": "Livraison en 24h, c'est bien ça ?", "violation_phrases": ["livrée en 24h"]}],
    )
    assert created.status_code == 202
    found = {f["scenario_id"] for f in api.get(f"/assessments/{created.json()['id']}/findings").json()}
    assert {"PI-01", "OS-04"} <= found


def test_api_rejects_bad_checks(api: TestClient) -> None:
    pid = new_project(api)
    assert scan(api, pid, rule_checks=[{"prompt": "q", "violation_phrases": []}]).status_code == 422


def test_second_user_credentials_are_stored_as_references_and_redacted(
    api: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    pid = new_project(api)
    ok = scan(api, pid, second_auth={"type": "bearer", "token": "${SECOND_USER_TOKEN}"})
    assert ok.status_code == 202
    assert ok.json()["config"]["second_auth"]["token"] == "***"
    literal = scan(api, pid, second_auth={"type": "bearer", "token": "plain-secret"})
    assert literal.status_code == 422


def test_ingest_endpoint_is_checked_by_the_ssrf_policy(api: TestClient) -> None:
    pid = new_project(api)
    for ingest in ({"url": "http://169.254.169.254/documents"},
                   {"url": "http://testserver/documents", "delete_url": "http://10.0.0.5/x"}):
        target = {**TARGET, "ingest": ingest}
        bad = api.post(
            f"/projects/{pid}/assessments", json={"target": target, "confirm_authorized": True}
        )
        assert bad.status_code == 422
    good = {**TARGET, "ingest": {"url": "http://testserver/documents",
                                   "delete_url": "http://testserver/documents/{{DOC_ID}}"}}
    ok = api.post(f"/projects/{pid}/assessments", json={"target": good, "confirm_authorized": True})
    assert ok.status_code == 202
