"""Profiler: guess chatbot / agent / RAG from harmless probes."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from chatbot import app as lab
from engine.connector import ConnectorError, HttpConnector, TargetConfig
from engine.connector.http import TargetResponse
from engine.core import AppType
from engine.profiler import profile_target


class Fake:
    """Stands in for the connector: one canned reply per probe, in order."""

    def __init__(self, replies, tool_calls_path=None):
        self.replies = list(replies)
        self.config = SimpleNamespace(tool_calls_path=tool_calls_path)

    def send(self, prompt):
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r if isinstance(r, TargetResponse) else TargetResponse(r, 200)


def test_plain_chatbot_is_low_confidence_and_skips_tool_module() -> None:
    p = profile_target(Fake(["I can only talk about shoes.", "I answer from general knowledge."]))
    assert p.app_type is AppType.CHATBOT and p.confidence == "low"
    assert p.modules == ["prompt_injection", "data_leakage", "output"]


def test_denying_tools_and_documents_is_not_a_signal() -> None:
    p = profile_target(Fake(["I don't have any tools.", "I have no documents or sources."]))
    assert p.app_type is AppType.CHATBOT and p.signals == []


def test_named_functions_make_an_agent_and_are_listed() -> None:
    reply = "I can call `lookup_order(order_id)` and delete_emails(year)."
    p = profile_target(Fake([reply, "None."]))
    assert p.app_type is AppType.AGENT
    assert p.tools == ("delete_emails", "lookup_order")
    assert "tool_abuse" in p.modules and p.confidence == "medium"


def test_structured_tool_calls_are_strong_evidence() -> None:
    first = TargetResponse("Sure.", 200, tool_calls=[{"name": "search"}])
    p = profile_target(Fake([first, "no"]))
    assert p.app_type is AppType.AGENT and p.confidence == "high"


def test_sources_field_and_wording_point_to_rag() -> None:
    second = TargetResponse(
        "According to the knowledge base, returns take 30 days.", 200,
        raw={"reply": "...", "sources": ["faq.pdf"]},
    )
    p = profile_target(Fake(["I have no tools.", second]))
    assert p.app_type is AppType.RAG and p.confidence == "high"
    assert p.modules == ["prompt_injection", "data_leakage", "output"]
    assert p.to_app_profile().has_documents


def test_agent_wins_over_rag_when_both_present() -> None:
    second = TargetResponse("Based on the document, ok.", 200, raw={"sources": ["a"]})
    p = profile_target(Fake(["I use search_docs(query) and send_mail(to).", second]))
    assert p.app_type is AppType.AGENT and "tool_abuse" in p.modules


def test_tool_calls_field_present_in_the_reply_is_a_weak_hint() -> None:
    first = TargetResponse("Hello.", 200, raw={"reply": "Hello.", "tool_calls": []})
    p = profile_target(Fake([first, "Hello."], tool_calls_path="$.tool_calls"))
    assert p.app_type is AppType.AGENT and p.confidence == "low"
    assert "tool_abuse" in p.modules


def test_configured_but_absent_tool_calls_field_proves_nothing() -> None:
    # OpenAI style servers omit the field when the model calls no tool.
    first = TargetResponse("Hello.", 200, raw={"choices": [{"message": {"content": "Hello."}}]})
    p = profile_target(Fake([first, "Hello."], tool_calls_path="$.choices[0].message.tool_calls"))
    assert p.app_type is AppType.CHATBOT and p.signals == []


def test_failed_second_probe_only_reduces_evidence() -> None:
    p = profile_target(Fake(["I use lookup_order(id).", ConnectorError("boom")]))
    assert p.app_type is AppType.AGENT


def test_unreachable_target_raises() -> None:
    with pytest.raises(ConnectorError):
        profile_target(Fake([ConnectorError("down")]))


def test_profile_of_the_rule_based_lab_and_serialisation(monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_LAB_MODE", "vulnerable")
    cfg = TargetConfig(url="http://testserver/chat", tool_calls_path="$.tool_calls", min_interval=0)
    p = profile_target(HttpConnector(cfg, client=TestClient(lab.app)))
    d = p.to_dict()
    assert d["app_type"] == "agent" and d["confidence"] == "low"
    assert set(d) == {"app_type", "confidence", "signals", "tools", "modules"}
