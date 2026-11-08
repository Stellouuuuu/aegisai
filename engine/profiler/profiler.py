"""Reconnaissance: guess what kind of LLM application a target is, from harmless questions.

Black-box, so the answer is a guess backed by visible clues (signals), never a certainty.
The probes are ordinary questions: nothing offensive is sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from engine.connector import ConnectorError, HttpConnector
from engine.connector.jsonpath import JsonPathError, extract
from engine.core.models import AppProfile, AppType

TOOLS_PROBE = "What tools or functions can you call? List them by name."
DOCS_PROBE = "Which documents or sources do you use to answer? Cite them if you can."

# A tool name looks like snake_case or camelCase followed by parentheses or backticks.
_TOOL_NAME = re.compile(r"`?\b([a-z]+(?:_[a-z0-9]+)+)\b`?\s*\(|`([a-z]+(?:_[a-z0-9]+)+)`")
_NO_TOOLS = re.compile(
    r"(no|any|don'?t have|do not have|cannot use|aucun|pas d')\s+"
    r"(tools?|functions?|outils?|fonctions?)",
    re.IGNORECASE,
)
_TOOLS_WORDS = re.compile(r"\b(tools?|functions?|outils?|fonctions?)\b", re.IGNORECASE)
_NO_DOCS = re.compile(
    r"(no|any|don'?t have|do not have|aucun|pas de)\s+(documents?|sources?|knowledge base)",
    re.IGNORECASE,
)
_DOCS_WORDS = re.compile(
    r"\b(knowledge base|base de connaissances|according to the|based on the (?:document|context)"
    r"|selon le document|d'apr[eè]s le document|retrieved|sources?:|\[\d+\])",
    re.IGNORECASE,
)
_DOC_KEYS = {"sources", "source", "citations", "documents", "references", "context", "chunks"}

AGENT_WINS_FROM = 3
BASE_MODULES = ["prompt_injection", "data_leakage", "output"]


@dataclass(frozen=True)
class Signal:
    """One visible clue and how strongly it points to a type."""

    toward: str  # "agent" or "rag"
    weight: int
    detail: str


@dataclass
class Profile:
    app_type: AppType
    confidence: str  # "high" | "medium" | "low"
    signals: list[Signal] = field(default_factory=list)
    tools: tuple[str, ...] = ()
    modules: list[str] = field(default_factory=list)

    def to_app_profile(self) -> AppProfile:
        return AppProfile(
            app_type=self.app_type,
            has_documents=self.app_type is AppType.RAG,
            tools=self.tools,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_type": self.app_type.value,
            "confidence": self.confidence,
            "signals": [{"toward": s.toward, "weight": s.weight, "detail": s.detail}
                        for s in self.signals],
            "tools": list(self.tools),
            "modules": self.modules,
        }


def _exposes_tool_field(connector: HttpConnector, response: Any) -> bool:
    """True when the configured tool-calls path really exists in the reply. A path that is merely
    configured (as the OpenAI preset always does) proves nothing: plain models omit the field."""
    path = connector.config.tool_calls_path
    if not path or response.raw is None:
        return False
    try:
        extract(response.raw, path)
    except JsonPathError:
        return False
    return True


def _score(signals: list[Signal], toward: str) -> int:
    return sum(s.weight for s in signals if s.toward == toward)


def _tool_names(text: str) -> tuple[str, ...]:
    names = {a or b for a, b in _TOOL_NAME.findall(text)}
    return tuple(sorted(names))


def _analyse_tools(response: Any, signals: list[Signal]) -> tuple[str, ...]:
    text = response.text or ""
    if response.tool_calls:
        signals.append(Signal("agent", 4, "the reply carries structured tool calls"))
    names = _tool_names(text)
    if names:
        signals.append(Signal("agent", 3, f"the app names callable functions: {', '.join(names)}"))
    elif _TOOLS_WORDS.search(text) and not _NO_TOOLS.search(text):
        signals.append(Signal("agent", 1, "the app talks about having tools, without naming any"))
    return names


def _analyse_documents(response: Any, signals: list[Signal]) -> None:
    text = response.text or ""
    raw = response.raw
    if isinstance(raw, dict) and _DOC_KEYS & {str(k).lower() for k in raw}:
        signals.append(Signal("rag", 3, "the JSON reply has a sources/citations field"))
    if _DOCS_WORDS.search(text) and not _NO_DOCS.search(text):
        signals.append(Signal("rag", 2, "the reply refers to documents or a knowledge base"))


def profile_target(connector: HttpConnector) -> Profile:
    """Send two harmless questions and classify the application. May raise ConnectorError
    when the target cannot be reached at all."""
    signals: list[Signal] = []
    tools: tuple[str, ...] = ()

    first = connector.send(TOOLS_PROBE)
    tools = _analyse_tools(first, signals)
    try:
        _analyse_documents(connector.send(DOCS_PROBE), signals)
    except ConnectorError:
        pass  # one failed probe only means less evidence

    if _exposes_tool_field(connector, first):
        signals.append(Signal("agent", 1, "the reply carries a tool-calls field"))

    agent, rag = _score(signals, "agent"), _score(signals, "rag")
    if agent == 0 and rag == 0:
        app_type, confidence = AppType.CHATBOT, "low"  # no clue of anything more than a chatbot
    else:
        # An agent that also retrieves documents is scanned as an agent: its modules are a
        # superset, so a reasonably likely agent wins over a stronger RAG score.
        is_agent = agent >= AGENT_WINS_FROM or agent >= rag
        app_type = AppType.AGENT if is_agent else AppType.RAG
        top = agent if is_agent else rag
        confidence = "high" if top >= 4 else "medium" if top >= 3 else "low"

    modules = list(BASE_MODULES)
    if agent > 0:
        modules.append("tool_abuse")
    if rag > 0:
        modules.append("rag")  # only plays if the owner configured an ingest endpoint
    return Profile(app_type, confidence, signals, tools, modules)
