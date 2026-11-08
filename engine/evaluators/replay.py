"""Anti false-positive evaluation: baseline check + repetition (ARCHITECTURE.md 3.6)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from engine.core.models import Payload
from engine.core.module import AttackModule, ResponseLike


class Sender(Protocol):
    def send(self, prompt: str) -> Any: ...

    def send_payload(self, payload: Payload) -> Any: ...


STABLE_RATE = 0.75  # with 3 replays: at least 2 of 3 must reproduce


@dataclass(frozen=True)
class ReplayResult:
    hits: int
    attempts: int

    @property
    def reproducible(self) -> bool:
        """Strict: every replay reproduced the proof (always true on deterministic targets)."""
        return self.attempts > 0 and self.hits == self.attempts

    @property
    def success_rate(self) -> float:
        """Share of tries that produced the proof, counting the original observation.

        The first hit is itself evidence, so 0 hits out of 3 replays is 1/4, not 0.
        """
        return (self.hits + 1) / (self.attempts + 1)

    @property
    def stable(self) -> bool:
        """Majority-reliable: enough for a confirmed finding on a non-deterministic model."""
        return self.success_rate >= STABLE_RATE


def baseline_violates(module: AttackModule, scenario_id: str, baseline: ResponseLike) -> bool:
    """True if a NORMAL response already trips this scenario's detector: any
    'detection' would then be the app's ordinary behaviour (false positive)."""
    return module.detect(Payload(text="", scenario_id=scenario_id), baseline).violated


def replay(
    connector: Sender, module: AttackModule, payload: Payload, attempts: int
) -> ReplayResult:
    hits = sum(
        module.detect(payload, connector.send_payload(payload)).violated for _ in range(attempts)
    )
    return ReplayResult(hits=hits, attempts=attempts)
