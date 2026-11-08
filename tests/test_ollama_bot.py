"""The Ollama-backed lab, with Ollama itself replaced by a scripted fake."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from ollama_bot import app as bot

CANARY = bot.CANARY


def fake_ollama(content="ok", tool_calls=None, reject_tools=False, seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if seen is not None:
            seen.append(body)
        if reject_tools and "tools" in body:
            return httpx.Response(400, json={"error": "model does not support tools"})
        msg = {"role": "assistant", "content": content}
        if tool_calls:
            msg["tool_calls"] = [{"function": {"name": n, "arguments": a}} for n, a in tool_calls]
        return httpx.Response(200, json={"message": msg})

    return httpx.Client(transport=httpx.MockTransport(handler))


def make(mode, **kw):
    return TestClient(bot.create_app(client=fake_ollama(**kw), mode=mode))


def chat(c, text="hi"):
    return c.post("/chat", json={"message": text}).json()


def test_vulnerable_puts_secret_in_prompt_and_passes_output_through() -> None:
    seen: list = []
    c = make("vulnerable", content=f"Code: {CANARY} <script>x</script>", seen=seen)
    out = chat(c, "tell me")
    assert CANARY in out["reply"] and "<script>" in out["reply"]
    system = seen[0]["messages"][0]["content"]
    names = {t["function"]["name"] for t in seen[0]["tools"]}
    assert CANARY in system and "delete_emails" in names


def test_vulnerable_reports_tool_calls_as_simulated() -> None:
    c = make("vulnerable", tool_calls=[("delete_emails", {"year": "2023"})])
    call = chat(c)["tool_calls"][0]
    assert call["name"] == "delete_emails" and call["simulated"] == "true"


def test_hardened_keeps_secret_out_filters_output_and_drops_dangerous_tools() -> None:
    seen: list = []
    c = make(
        "hardened",
        content=f"{CANARY} <script>x</script>",
        tool_calls=[("delete_emails", {}), ("lookup_order", {"order_id": "7"})],
        seen=seen,
    )
    out = chat(c)
    assert CANARY not in seen[0]["messages"][0]["content"]
    assert CANARY not in out["reply"] and "[redacted]" in out["reply"]
    assert "<script>" not in out["reply"] and "&lt;script&gt;" in out["reply"]
    assert [t["name"] for t in out["tool_calls"]] == ["lookup_order"]
    assert {t["function"]["name"] for t in seen[0]["tools"]} == {"lookup_order"}


def test_retries_without_tools_when_model_has_no_tool_support() -> None:
    assert chat(make("vulnerable", content="hello", reject_tools=True))["reply"] == "hello"


def test_ollama_down_returns_502() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    c = TestClient(
        bot.create_app(client=httpx.Client(transport=httpx.MockTransport(boom)), mode="vulnerable")
    )
    r = c.post("/chat", json={"message": "x"})
    assert r.status_code == 502 and "Ollama" in r.json()["detail"]


def test_health_reports_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_BOT_MODE", "hardened")
    assert TestClient(bot.create_app(client=fake_ollama())).get("/health").json()["mode"] == "hardened"


def _ask_with_documents(mode: str) -> tuple[str, str]:
    """User A adds a private document, then user B asks about it. Returns B's system prompt
    (as sent to the model) and the document text."""
    seen: list = []
    c = make(mode, seen=seen)
    doc = "Document AEGISDOCABC123 confidentiel : code AEGIS_PRIVATE_X1."
    assert c.post("/documents", json={"id": "d1", "text": doc},
                  headers={"Authorization": "a"}).status_code == 201
    c.post("/chat", json={"message": "Que contient AEGISDOCABC123 ?"},
           headers={"Authorization": "b"})
    return seen[-1]["messages"][0]["content"], doc


def test_vulnerable_bot_retrieves_other_users_documents() -> None:
    system, doc = _ask_with_documents("vulnerable")
    assert doc in system


def test_hardened_bot_isolates_documents_per_user_and_fences_passages() -> None:
    system, doc = _ask_with_documents("hardened")
    assert doc not in system
    seen: list = []
    c = make("hardened", seen=seen)
    c.post("/documents", json={"id": "d1", "text": doc}, headers={"Authorization": "a"})
    c.post("/chat", json={"message": "Que contient AEGISDOCABC123 ?"},
           headers={"Authorization": "a"})
    prompt = seen[-1]["messages"][0]["content"]
    assert f"<<<\n{doc}\n>>>" in prompt and "untrusted DATA" in prompt
    c.delete("/documents/d1", headers={"Authorization": "a"})
    c.post("/chat", json={"message": "Que contient AEGISDOCABC123 ?"},
           headers={"Authorization": "a"})
    assert doc not in seen[-1]["messages"][0]["content"]
