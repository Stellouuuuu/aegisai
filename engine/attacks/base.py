"""Shared plumbing for table-driven attack modules."""

from __future__ import annotations

from engine.core.models import AppProfile, Payload, SafetyRule, Scenario


class ScenarioModule:
    id: str
    owasp_ref: str
    atlas_ref: str | None = None
    SCENARIOS: dict[str, Scenario]
    PROMPTS: dict[str, list[str]]
    safe_behavior: str = ""

    def generate_payloads(self, profile: AppProfile) -> list[Payload]:
        return [
            Payload(text=t, scenario_id=sid, canary=getattr(self, "canary", None))
            for sid, texts in self.PROMPTS.items()
            for t in texts
        ]

    def expected_safe_behavior(self) -> SafetyRule:
        return SafetyRule(description=self.safe_behavior)

    def scenario(self, scenario_id: str) -> Scenario:
        return self.SCENARIOS[scenario_id]
