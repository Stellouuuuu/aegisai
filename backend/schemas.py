"""Request validation. Secrets must be ${ENV_VAR} references so they never reach the database."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from engine.attacks.custom_checks import parse_checks
from engine.attacks.registry import MODULES

_ENV_REF = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$")


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class CredentialsIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=10, max_length=256)

    @field_validator("email")
    @classmethod
    def valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL.match(v):
            raise ValueError("invalid email address")
        return v


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    app_type: Literal["chatbot", "rag", "agent", "api", "other"] = "chatbot"


class AuthIn(BaseModel):
    type: Literal["none", "api_key", "bearer", "custom_headers"] = "none"
    token: str = ""
    header_name: str = "X-API-Key"
    headers: dict[str, str] = {}

    @model_validator(mode="after")
    def secrets_are_env_refs(self) -> AuthIn:
        values = [self.token] if self.token else []
        values += list(self.headers.values())
        for v in values:
            if not _ENV_REF.match(v):
                raise ValueError(
                    "secrets must be environment references like ${MY_TOKEN}; "
                    "literal secrets are never stored"
                )
        return self


class TargetIn(BaseModel):
    url: str = Field(pattern=r"^https?://")
    method: Literal["POST", "PUT", "GET"] = "POST"
    request_template: Any = {"message": "{{PROMPT}}"}
    response_path: str = "$.reply"
    tool_calls_path: str | None = None
    auth: AuthIn = AuthIn()
    min_interval: float = Field(default=0.2, ge=0, le=60)
    timeout: float = Field(default=30, gt=0, le=300)
    stream: bool = False


class ProfileIn(BaseModel):
    target: TargetIn
    confirm_authorized: bool

    @field_validator("confirm_authorized")
    @classmethod
    def must_confirm(cls, v: bool) -> bool:
        if not v:
            raise ValueError("you must confirm you own the target or are authorized to test it")
        return v


class AssessmentIn(BaseModel):
    target: TargetIn
    modules: list[str] = Field(default_factory=lambda: list(MODULES))
    depth: Literal["quick", "standard", "deep"] = "standard"
    # Tools the application is meant to use: needed to judge TS-01 (tool outside the list).
    allowed_tools: list[str] = Field(default_factory=list, max_length=50)
    # Modules run at once; the rate limit stays global, so it only helps hosted APIs.
    workers: int = Field(default=1, ge=1, le=8)
    # Credentials of a second user of the same application: needed to test isolation (DL-04).
    second_auth: AuthIn | None = None
    # Ground truth only the owner has: PI-01 (a system prompt rule to contradict) and OS-04
    # (a false claim to get confirmed). Each check is {"prompt", "violation_phrases"}.
    rule_checks: list[dict[str, Any]] = Field(default_factory=list)
    fact_checks: list[dict[str, Any]] = Field(default_factory=list)
    confirm_authorized: bool

    @field_validator("rule_checks", "fact_checks")
    @classmethod
    def valid_checks(cls, v: list[dict[str, Any]], info: Any) -> list[dict[str, Any]]:
        parse_checks(v, info.field_name)  # raises ValueError with a clear message
        return v

    @field_validator("allowed_tools")
    @classmethod
    def clean_tools(cls, v: list[str]) -> list[str]:
        tools = [t.strip() for t in v if t.strip()]
        if any(len(t) > 100 for t in tools):
            raise ValueError("tool names must be at most 100 characters")
        return tools

    @field_validator("modules")
    @classmethod
    def known_modules(cls, v: list[str]) -> list[str]:
        unknown = [m for m in v if m not in MODULES]
        if unknown or not v:
            raise ValueError(f"unknown or empty modules: {unknown}. Available: {list(MODULES)}")
        return v

    @field_validator("confirm_authorized")
    @classmethod
    def must_confirm(cls, v: bool) -> bool:
        if not v:
            raise ValueError("you must confirm you own the target or are authorized to test it")
        return v
