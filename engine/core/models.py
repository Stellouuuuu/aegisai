"""Core data model shared by every engine component (see ARCHITECTURE.md)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs_review"
    REJECTED = "rejected"


class AppType(StrEnum):
    CHATBOT = "chatbot"
    RAG = "rag"
    AGENT = "agent"
    API = "api"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AppProfile:
    """Result of the reconnaissance step; drives module selection."""

    app_type: AppType = AppType.UNKNOWN
    has_memory: bool = False
    has_documents: bool = False
    tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class Payload:
    """A single attack prompt. `canary` is the fake secret proving success."""

    text: str
    scenario_id: str = ""
    canary: str | None = None
    # A conversation: the user messages sent one after the other in the same session. When set,
    # `text` is only a readable summary of it.
    turns: tuple[str, ...] = ()
    # Messages sent first as the application's main user (the victim), before `text` is sent as
    # a second, unrelated user. Needs a second identity (`second_auth`) on the connector.
    plant: tuple[str, ...] = ()
    # Documents (id, text) added to the application's knowledge base before the question, by the
    # main user, then removed. Needs an `ingest` endpoint on the connector (RAG scenarios).
    documents: tuple[tuple[str, str], ...] = ()
    # Ask `text` as the second user instead of the main one (isolation scenarios).
    as_other_user: bool = False


@dataclass(frozen=True)
class SafetyRule:
    """Expected safe behaviour. A response violating it is a candidate finding."""

    description: str = ""
    must_not_contain: tuple[str, ...] = ()

    def __init__(
        self,
        description: str = "",
        must_not_contain: str | tuple[str, ...] = (),
    ) -> None:
        if isinstance(must_not_contain, str):
            must_not_contain = (must_not_contain,)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "must_not_contain", tuple(must_not_contain))


@dataclass(frozen=True)
class Verdict:
    """Output of a detector for one request/response pair."""

    violated: bool
    evidence: str = ""
    deterministic: bool = True  # False => heuristic evidence, human review needed


@dataclass(frozen=True)
class Scenario:
    """Catalogue entry (docs/CATALOGUE_TESTS_SECURITE.md) for one test."""

    id: str
    title: str
    severity: Severity
    owasp: str
    atlas: str | None
    rule_violated: str
    recommendation: str


@dataclass
class Finding:
    """Pivot format (ADR-04): reports (JSON/PDF/SARIF) are derived from it."""

    id: str
    category: str
    owasp: str
    severity: Severity
    confidence: Confidence
    scenario: str
    request: str
    response: str
    evidence: str
    safety_rule_violated: str
    recommendation: str
    atlas: str | None = None
    reproducible: bool = False
    exploitability: float | None = None  # 0..1, set by the risk engine
    risk_score: float | None = None  # 0..10, set by the risk engine
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        names = {f.name for f in fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in names}
        kwargs["severity"] = Severity(kwargs["severity"])
        kwargs["confidence"] = Confidence(kwargs["confidence"])
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d
