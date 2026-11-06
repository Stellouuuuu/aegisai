"""Plugin interface for attack modules (ADR-03)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from engine.core.models import AppProfile, Payload, SafetyRule, Scenario, Verdict


class ResponseLike(Protocol):
    text: str
    tool_calls: list[Any]


@runtime_checkable
class AttackModule(Protocol):
    id: str  # e.g. "prompt_injection"
    owasp_ref: str  # e.g. "LLM01:2025"
    atlas_ref: str | None  # e.g. "AML.T0051"

    def generate_payloads(self, profile: AppProfile) -> list[Payload]: ...

    def expected_safe_behavior(self) -> SafetyRule: ...

    def scenario(self, scenario_id: str) -> Scenario: ...

    def detect(self, payload: Payload, response: ResponseLike) -> Verdict: ...
