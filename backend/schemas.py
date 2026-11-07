"""Request validation. Secrets must be ${ENV_VAR} references so they never reach the database."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

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
    confirm_authorized: bool

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
