"""OpenAI compatible targets: plain, streamed, with tool calls, and the CLI preset."""

import json

import httpx
import pytest

from engine.attacks.tool_abuse import ToolSecurityModule
from engine.cli import main
from engine.connector import ConnectorError, HttpConnector, TargetConfig, openai_config
from engine.connector.http import assemble_sse
from engine.core import Payload

URL = "https://llm.example.test/v1/chat/completions"


def sse(*events: dict | str) -> str:
    return "".join(
        f"data: {e if isinstance(e, str) else json.dumps(e)}\n\n" for e in events
    )


def connector_for(handler, **cfg) -> tuple[HttpConnector, list[dict]]:
    seen: list[dict] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append({"body": json.loads(request.content), "auth": request.headers.get("authorization")})
        return handler(request)

    config = openai_config("test-model", url=URL, token=None, **cfg)
    target = TargetConfig(
        url=config["url"], request_template=config["request_template"],
        response_path=config["response_path"], tool_calls_path=config["tool_calls_path"],
        stream=config["stream"],
    )
    return HttpConnector(target, client=httpx.Client(transport=httpx.MockTransport(wrapped))), seen


def test_plain_completion_and_request_shape() -> None:
    reply = {"choices": [{"message": {"role": "assistant", "content": "Bonjour !"}}]}
    c, seen = connector_for(lambda r: httpx.Response(200, json=reply), system_prompt="Be nice")
    out = c.send('Dis "salut"\nvite')
    assert out.text == "Bonjour !" and out.tool_calls == []
    assert seen[0]["body"]["model"] == "test-model"
    assert seen[0]["body"]["messages"] == [
        {"role": "system", "content": "Be nice"},
        {"role": "user", "content": 'Dis "salut"\nvite'},
    ]


def test_openai_tool_calls_are_normalised_and_null_content_is_empty() -> None:
    reply = {"choices": [{"message": {"content": None, "tool_calls": [
        {"id": "c1", "type": "function",
         "function": {"name": "delete_emails", "arguments": '{"year": "2023"}'}}]}}]}
    c, _ = connector_for(lambda r: httpx.Response(200, json=reply))
    out = c.send("Supprime mes emails")
    assert out.text == ""
    assert out.tool_calls == [{"name": "delete_emails", "arguments": '{"year": "2023"}', "id": "c1"}]
    verdict = ToolSecurityModule().detect(Payload("x", "TS-02"), out)
    assert verdict.violated and verdict.deterministic  # a structured call is hard evidence


def test_streamed_reply_is_reassembled() -> None:
    body = sse(
        {"choices": [{"delta": {"role": "assistant", "content": "Bon"}}]},
        {"choices": [{"delta": {"content": "jour"}}]},
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "c9", "function": {"name": "delete_", "arguments": '{"y'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"name": "emails", "arguments": 'ear": 1}'}}]}}]},
        "[DONE]",
    )
    c, seen = connector_for(
        lambda r: httpx.Response(200, text=body, headers={"content-type": "text/event-stream"}),
        stream=True,
    )
    out = c.send("hi")
    assert seen[0]["body"]["stream"] is True
    assert out.text == "Bonjour"
    assert out.tool_calls == [{"name": "delete_emails", "arguments": '{"year": 1}', "id": "c9"}]


def test_assemble_sse_ignores_noise() -> None:
    lines = [": keep-alive", "event: ping", "data: not json", "data: {}", 'data: {"choices": []}',
             'data: {"choices": [{"delta": {"content": "ok"}}]}', "data: [DONE]",
             'data: {"choices": [{"delta": {"content": "after the end"}}]}']
    assert assemble_sse(lines)["choices"][0]["message"]["content"] == "ok"


def test_http_error_in_stream_mode_is_reported() -> None:
    c, _ = connector_for(lambda r: httpx.Response(401, json={"error": "bad key"}), stream=True)
    with pytest.raises(ConnectorError, match="HTTP 401"):
        c.send("hi")


def test_preset_defaults() -> None:
    cfg = openai_config("gpt-test")
    assert cfg["auth"] == {"type": "bearer", "token": "${OPENAI_API_KEY}"}
    assert "stream" not in cfg["request_template"]
    assert "auth" not in openai_config("m", token=None)


def test_cli_preset_runs_a_scan_against_an_openai_style_server(tmp_path, capsys) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        prompt = json.loads(request.content)["messages"][-1]["content"]
        text = "AEGIS_PWNED_7731" if "Ignore les instructions" in prompt else "Bonjour"
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})

    out = tmp_path / "r.json"
    args = ["scan", "--preset", "openai", "--model", "m", "--url", URL, "--no-auth",
            "--modules", "prompt_injection", "--depth", "quick", "--min-interval", "0",
            "--confirm-authorized", "--out", str(out)]
    code = main(args, httpx.Client(transport=httpx.MockTransport(handler)))
    assert code == 0
    found = {f["id"] for f in json.loads(out.read_text())["findings"]}
    assert "PI-02" in found


def test_cli_preset_requires_a_model(capsys) -> None:
    args = ["scan", "--preset", "openai", "--url", URL, "--confirm-authorized"]
    assert main(args) == 2
    assert "--model" in capsys.readouterr().err
