"""FastAPI application. Resources owned by another user return 404, never 403."""

from __future__ import annotations

import copy
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend import scanner
from backend.schemas import AssessmentIn, CredentialsIn, ProfileIn, ProjectIn
from backend.security import (
    DUMMY_HASH,
    LoginThrottle,
    hash_password,
    hash_token,
    new_token,
    verify_password,
)
from backend.ssrf import TargetNotAllowedError, TargetPolicy
from backend.storage import Storage
from engine.connector import ConnectorError

SESSION_HOURS = 12
_bearer = HTTPBearer(auto_error=False)


def _redact(assessment: dict[str, Any]) -> dict[str, Any]:
    a = copy.deepcopy(assessment)
    auth = a["config"].get("auth", {})
    if auth.get("token"):
        auth["token"] = "***"
    auth["headers"] = {k: "***" for k in auth.get("headers", {})}
    other = a["config"].get("second_auth")
    if other:
        if other.get("token"):
            other["token"] = "***"
        other["headers"] = {k: "***" for k in other.get("headers", {})}
    return a


def create_app(
    db_path: str | None = None,
    client_factory: scanner.ClientFactory | None = None,
    policy: TargetPolicy | None = None,
    allow_registration: bool | None = None,
) -> FastAPI:
    storage = Storage(db_path or os.environ.get("AEGIS_DB", "aegis.db"))
    policy = policy or TargetPolicy.from_env()
    if allow_registration is None:
        allow_registration = os.environ.get("AEGIS_ALLOW_REGISTRATION", "1") == "1"
    throttle = LoginThrottle()
    cancel = scanner.CancelRegistry()
    app = FastAPI(title="AegisAI API", version="0.1.0")

    def current_user(
        creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> dict[str, Any]:
        user = storage.user_for_session(hash_token(creds.credentials)) if creds else None
        if not user:
            raise HTTPException(401, "authentication required", {"WWW-Authenticate": "Bearer"})
        return user

    def need(value: Any, what: str) -> Any:
        if value is None:
            raise HTTPException(404, f"{what} not found")
        return value

    def own_project(project_id: int, user: dict[str, Any]) -> dict[str, Any]:
        p = storage.get_project(project_id)
        return need(p if p and p["user_id"] == user["id"] else None, "project")

    def own_assessment(assessment_id: int, user: dict[str, Any]) -> dict[str, Any]:
        a = need(storage.get_assessment(assessment_id), "assessment")
        own_project(a["project_id"], user)
        return a

    def own_finding(finding_id: int, user: dict[str, Any]) -> dict[str, Any]:
        f = need(storage.get_finding(finding_id), "finding")
        own_assessment(f["assessment_id"], user)
        return f

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/auth/register", status_code=201)
    def register(body: CredentialsIn) -> dict[str, Any]:
        if not allow_registration:
            raise HTTPException(403, "registration is disabled")
        user = storage.create_user(body.email, hash_password(body.password))
        if user is None:
            raise HTTPException(409, "email already registered")
        return {"id": user["id"], "email": user["email"]}

    @app.post("/auth/login")
    def login(body: CredentialsIn) -> dict[str, Any]:
        if throttle.is_locked(body.email):
            raise HTTPException(429, "too many failed attempts, try again later")
        user = storage.get_user_by_email(body.email)
        ok = verify_password(body.password, user["password_hash"] if user else DUMMY_HASH)
        if not user or not ok:
            throttle.failure(body.email)
            raise HTTPException(401, "invalid credentials")
        throttle.success(body.email)
        token = new_token()
        expires = datetime.now(UTC) + timedelta(hours=SESSION_HOURS)
        storage.create_session(user["id"], hash_token(token), expires.isoformat())
        return {"access_token": token, "token_type": "bearer", "expires_at": expires.isoformat()}

    @app.post("/auth/logout", status_code=204)
    def logout(
        creds: HTTPAuthorizationCredentials = Depends(_bearer),
        user: dict[str, Any] = Depends(current_user),
    ) -> Response:
        storage.delete_session(hash_token(creds.credentials))
        return Response(status_code=204)

    @app.get("/auth/me")
    def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        return {"id": user["id"], "email": user["email"]}

    @app.post("/projects", status_code=201)
    def create_project(
        body: ProjectIn, user: dict[str, Any] = Depends(current_user)
    ) -> dict[str, Any]:
        return storage.create_project(user["id"], body.name, body.description, body.app_type)

    @app.get("/projects")
    def list_projects(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
        return storage.list_projects(user["id"])

    @app.get("/projects/{project_id}")
    def get_project(
        project_id: int, user: dict[str, Any] = Depends(current_user)
    ) -> dict[str, Any]:
        return own_project(project_id, user)

    @app.post("/projects/{project_id}/assessments", status_code=202)
    def create_assessment(
        project_id: int,
        body: AssessmentIn,
        background: BackgroundTasks,
        user: dict[str, Any] = Depends(current_user),
    ) -> dict[str, Any]:
        own_project(project_id, user)
        try:
            policy.check(body.target.url)
            if body.target.ingest:
                policy.check(body.target.ingest.url)
                if body.target.ingest.delete_url:
                    policy.check(body.target.ingest.delete_url)
        except TargetNotAllowedError as e:
            raise HTTPException(422, str(e)) from e
        config = body.target.model_dump()
        if body.second_auth:
            config["second_auth"] = body.second_auth.model_dump()
        config["options"] = {
            "allowed_tools": body.allowed_tools, "workers": body.workers,
            "adversarial_rounds": body.adversarial_rounds,
            "rule_checks": body.rule_checks, "fact_checks": body.fact_checks,
        }
        a = storage.create_assessment(project_id, config, body.modules, body.depth)
        background.add_task(
            scanner.run_assessment, storage, a["id"], client_factory, policy, cancel
        )
        return _redact(a)

    @app.post("/projects/{project_id}/profile")
    def profile_project(
        project_id: int, body: ProfileIn, user: dict[str, Any] = Depends(current_user)
    ) -> dict[str, Any]:
        own_project(project_id, user)
        try:
            return scanner.profile_config(body.target.model_dump(), client_factory, policy)
        except TargetNotAllowedError as e:
            raise HTTPException(422, str(e)) from e
        except ConnectorError as e:
            raise HTTPException(502, f"Could not reach the target: {e}") from e

    @app.get("/projects/{project_id}/assessments")
    def history(
        project_id: int, user: dict[str, Any] = Depends(current_user)
    ) -> list[dict[str, Any]]:
        own_project(project_id, user)
        return [_redact(a) for a in storage.list_assessments(project_id)]

    @app.get("/assessments/{assessment_id}")
    def get_assessment(
        assessment_id: int, user: dict[str, Any] = Depends(current_user)
    ) -> dict[str, Any]:
        return _redact(own_assessment(assessment_id, user))

    @app.post("/assessments/{assessment_id}/cancel", status_code=202)
    def cancel_assessment(
        assessment_id: int, user: dict[str, Any] = Depends(current_user)
    ) -> dict[str, Any]:
        a = own_assessment(assessment_id, user)
        if a["status"] not in ("pending", "running"):
            raise HTTPException(409, f"assessment is already {a['status']}")
        cancel.request(assessment_id)
        return _redact(a)

    @app.get("/assessments/{assessment_id}/findings")
    def list_findings(
        assessment_id: int, user: dict[str, Any] = Depends(current_user)
    ) -> list[dict[str, Any]]:
        own_assessment(assessment_id, user)
        return storage.list_findings(assessment_id)

    @app.get("/findings/{finding_id}")
    def get_finding(
        finding_id: int, user: dict[str, Any] = Depends(current_user)
    ) -> dict[str, Any]:
        return own_finding(finding_id, user)

    @app.post("/findings/{finding_id}/retest")
    def retest(finding_id: int, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        own_finding(finding_id, user)
        try:
            return scanner.retest_finding(storage, finding_id, client_factory, policy)
        except TargetNotAllowedError as e:
            raise HTTPException(422, str(e)) from e

    def build_report(assessment_id: int, user: dict[str, Any]) -> dict[str, Any]:
        a = own_assessment(assessment_id, user)
        if a["status"] != "completed":
            raise HTTPException(409, f"assessment is {a['status']}, report not available")
        return scanner.assessment_report(storage, assessment_id)

    @app.get("/assessments/{assessment_id}/report")
    def report_json(
        assessment_id: int, user: dict[str, Any] = Depends(current_user)
    ) -> dict[str, Any]:
        return build_report(assessment_id, user)

    @app.get("/assessments/{assessment_id}/report.pdf")
    def report_pdf(assessment_id: int, user: dict[str, Any] = Depends(current_user)) -> Response:
        report = build_report(assessment_id, user)
        try:
            from engine.reporting.pdf_report import render_pdf
        except ImportError:
            raise HTTPException(501, 'PDF export needs: pip install "aegisai[pdf]"') from None
        with tempfile.TemporaryDirectory() as d:
            data = render_pdf(report, Path(d) / "report.pdf").read_bytes()
        return Response(data, media_type="application/pdf")

    return app


def default_app() -> FastAPI:
    return create_app()
