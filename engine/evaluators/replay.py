"""Anti false-positive evaluation: baseline check + repetition (ARCHITECTURE.md 3.6)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from engine.core.models import Payload
from engine.core.module import AttackModule, ResponseLike


class Sender(Protocol):
    def send(self, prompt: str) -> Any: ...


@dataclass(frozen=True)
class ReplayResult:
    hits: int
    attempts: int

    @property
    def reproducible(self) -> bool:
        return self.attempts > 0 and self.hits == self.attempts


def baseline_violates(module: AttackModule, scenario_id: str, baseline: ResponseLike) -> bool:
    """True if a NORMAL response already trips this scenario's detector: any
    'detection' would then be the app's ordinary behaviour (false positive)."""
    return module.detect(Payload(text="", scenario_id=scenario_id), baseline).violated


def replay(
    connector: Sender, module: AttackModule, payload: Payload, attempts: int
) -> ReplayResult:
    hits = sum(
        module.detect(payload, connector.send(payload.text)).violated for _ in range(attempts)
    )
    return ReplayResult(hits=hits, attempts=attempts)
