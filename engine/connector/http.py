"""Generic HTTP connector: talks to any chat API via a configurable template."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import httpx

from engine.connector.jsonpath import JsonPathError, extract

log = logging.getLogger("aegis.connector")

PLACEHOLDER = "{{PROMPT}}"
SESSION_PLACEHOLDER = "{{SESSION}}"
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConnectorError(RuntimeError):
    pass


def expand_env(value: str) -> str:
    """Replace ${VAR} with environment values (secrets stay out of config files)."""

    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in os.environ:
            raise ConnectorError(f"Environment variable {name} is not set")
        return os.environ[name]

    return _ENV.sub(sub, value)


@dataclass(frozen=True)
class AuthConfig:
    type: Literal["none", "api_key", "bearer", "custom_headers"] = "none"
    token: str = ""
    header_name: str = "X-API-Key"  # used by api_key
    headers: dict[str, str] = field(default_factory=dict)  # used by custom_headers

    def build_headers(self) -> dict[str, str]:
        if self.type == "none":
            return {}
        if self.type == "bearer":
            return {"Authorization": f"Bearer {expand_env(self.token)}"}
        if self.type == "api_key":
            return {self.header_name: expand_env(self.token)}
        if self.type == "custom_headers":
            return {k: expand_env(v) for k, v in self.headers.items()}
        raise ConnectorError(f"Unknown auth type: {self.type}")


@dataclass(frozen=True)
class TargetConfig:
    url: str
    method: str = "POST"
    request_template: Any = field(default_factory=lambda: {"message": PLACEHOLDER})
    response_path: str = "$.reply"
    tool_calls_path: str | None = None  # optional: where the app reports tool calls
    auth: AuthConfig = field(default_factory=AuthConfig)
    timeout: float = 30.0
    min_interval: float = 0.0  # seconds between requests (rate limiting, ENF-03)
    # Server-sent events (OpenAI style "stream": true). The stream is reassembled into the
    # ordinary non-streaming shape, so response_path stays the same.
    stream: bool = False


@dataclass(frozen=True)
class TargetResponse:
    text: str
    status_code: int
    tool_calls: list[Any] = field(default_factory=list)
    raw: Any = None


@dataclass(frozen=True)
class ConversationResponse(TargetResponse):
    """The outcome of a multi-turn attack: `text` joins every reply, `replies` keeps them apart
    so a detector can reason turn by turn."""

    replies: tuple[str, ...] = ()


def normalize_tool_call(call: Any) -> Any:
    """OpenAI style {"function": {"name", "arguments"}} -> {"name", "arguments"}: one shape for
    every module. Anything else is returned unchanged."""
    if isinstance(call, dict) and isinstance(call.get("function"), dict):
        fn = call["function"]
        out = {"name": fn.get("name", ""), "arguments": fn.get("arguments", "")}
        if "id" in call:
            out["id"] = call["id"]
        return out
    return call


def assemble_sse(lines: Any) -> dict[str, Any]:
    """Rebuild a chat-completion response from OpenAI style SSE lines ("data: {json}")."""
    text: list[str] = []
    calls: dict[int, dict[str, Any]] = {}
    for line in lines:
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            break
        try:
            choice = json.loads(payload)["choices"][0]
        except (ValueError, KeyError, IndexError, TypeError):
            continue
        delta = choice.get("delta") or {}
        if delta.get("content"):
            text.append(delta["content"])
        for tc in delta.get("tool_calls") or []:
            slot = calls.setdefault(tc.get("index", 0), {"function": {"name": "", "arguments": ""}})
            fn = tc.get("function") or {}
            slot["function"]["name"] += fn.get("name") or ""
            slot["function"]["arguments"] += fn.get("arguments") or ""
            if tc.get("id"):
                slot["id"] = tc["id"]
    message: dict[str, Any] = {"role": "assistant", "content": "".join(text)}
    if calls:
        message["tool_calls"] = [calls[i] for i in sorted(calls)]
    return {"choices": [{"message": message}]}


def render_template(template: Any, prompt: str, session: str = "") -> Any:
    """Substitute {{PROMPT}} (and {{SESSION}}, a conversation id) in every string of a
    JSON-like template.

    Working on the parsed structure (not on raw text) means the prompt can
    contain quotes/newlines without breaking the JSON body.
    """
    if isinstance(template, str):
        if template.lstrip().startswith(("{", "[")):
            try:
                return render_template(json.loads(template), prompt, session)
            except json.JSONDecodeError:
                pass
        return template.replace(SESSION_PLACEHOLDER, session).replace(PLACEHOLDER, prompt)
    if isinstance(template, dict):
        return {k: render_template(v, prompt, session) for k, v in template.items()}
    if isinstance(template, list):
        return [render_template(v, prompt, session) for v in template]
    return template


def _messages_list(template: Any) -> list[Any] | None:
    """The OpenAI style "messages" list of a request template, if it has a user message."""
    data = template
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return None
    msgs = data.get("messages") if isinstance(data, dict) else None
    if isinstance(msgs, list) and any(
        isinstance(m, dict) and m.get("role") == "user" for m in msgs
    ):
        return msgs
    return None


class HttpConnector:
    def __init__(self, config: TargetConfig, client: httpx.Client | None = None) -> None:
        self.config = config
        self._client = client or httpx.Client(timeout=config.timeout)
        self._last_sent = 0.0
        self._lock = threading.Lock()  # one rate limit and one audit trail for all threads
        self.history: list[dict[str, Any]] = []  # structured audit trail (ENF-05)

    def _throttle(self) -> None:
        # Holding the lock while sleeping serialises request starts, so min_interval is a
        # global limit even when several modules run in parallel.
        with self._lock:
            wait = self.config.min_interval - (time.monotonic() - self._last_sent)
            if wait > 0:
                time.sleep(wait)
            self._last_sent = time.monotonic()

    def _record(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.history.append(record)

    @property
    def supports_conversation(self) -> bool:
        """True if earlier turns can be carried over: an OpenAI style "messages" list (the
        history is replayed in it) or a {{SESSION}} id that the application keeps state for."""
        tpl = self.config.request_template
        in_template = SESSION_PLACEHOLDER in (tpl if isinstance(tpl, str) else json.dumps(tpl))
        return in_template or _messages_list(tpl) is not None

    def converse(self, turns: tuple[str, ...] | list[str]) -> ConversationResponse:
        """Send `turns` one after the other in a fresh conversation."""
        if not self.supports_conversation:
            raise ConnectorError(
                "This target cannot hold a conversation: use an OpenAI style 'messages' "
                "template, or add a {{SESSION}} placeholder the application keeps state for."
            )
        session = uuid.uuid4().hex
        history: list[tuple[str, str]] = []
        replies: list[TargetResponse] = []
        for turn in turns:
            r = self.send(turn, history=history, session=session)
            history.append((turn, r.text))
            replies.append(r)
        return ConversationResponse(
            text="\n---\n".join(r.text for r in replies),
            status_code=replies[-1].status_code if replies else 0,
            tool_calls=[c for r in replies for c in r.tool_calls],
            raw=[r.raw for r in replies],
            replies=tuple(r.text for r in replies),
        )

    def send_payload(self, payload: Any) -> TargetResponse:
        """One request, or a whole conversation when the payload has turns."""
        if getattr(payload, "turns", ()):
            return self.converse(payload.turns)
        return self.send(payload.text)

    def send(
        self,
        prompt: str,
        history: list[tuple[str, str]] | None = None,
        session: str = "",
    ) -> TargetResponse:
        cfg = self.config
        self._throttle()
        body = render_template(cfg.request_template, prompt, session)
        if history:
            msgs = body.get("messages") if isinstance(body, dict) else None
            if isinstance(msgs, list):  # replay the earlier turns just before the new question
                users = [
                    i for i, m in enumerate(msgs) if isinstance(m, dict) and m.get("role") == "user"
                ]
                last_user = users[-1] if users else len(msgs)
                past = [
                    {"role": role, "content": text}
                    for user, reply in history
                    for role, text in (("user", user), ("assistant", reply))
                ]
                body = {**body, "messages": msgs[:last_user] + past + msgs[last_user:]}
        headers = cfg.auth.build_headers()
        record: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "url": cfg.url,
            "method": cfg.method,
            "prompt": prompt,
        }
        stream_data: dict[str, Any] | None = None
        try:
            if cfg.stream:
                with self._client.stream(
                    cfg.method, cfg.url, json=body, headers=headers, timeout=cfg.timeout
                ) as r:
                    if r.status_code < 400:
                        stream_data = assemble_sse(r.iter_lines())
                    else:
                        r.read()
            else:
                r = self._client.request(
                    cfg.method, cfg.url, json=body, headers=headers, timeout=cfg.timeout
                )
        except httpx.HTTPError as e:
            record["error"] = str(e)
            self._record(record)
            log.warning("request failed: %s", e)
            raise ConnectorError(f"Request to {cfg.url} failed: {e}") from e

        record["status"] = r.status_code
        self._record(record)
        log.info("%s %s -> %s", cfg.method, cfg.url, r.status_code)
        if r.status_code >= 400:
            raise ConnectorError(f"Target returned HTTP {r.status_code}: {r.text[:200]}")
        try:
            data = stream_data if stream_data is not None else r.json()
        except ValueError:
            kind = r.headers.get("content-type", "unknown type")
            snippet = " ".join(r.text[:80].split())
            raise ConnectorError(
                f"The target answered HTTP {r.status_code} but not with JSON "
                f"(content-type: {kind}, starts with: {snippet!r}). The URL probably points "
                "to a web page instead of the chat API endpoint: check the real API route "
                "(browser dev tools, Network tab) and the request body format."
            ) from None
        try:
            text = extract(data, cfg.response_path)
        except JsonPathError as e:
            keys = f" Top-level keys: {sorted(data)[:8]}." if isinstance(data, dict) else ""
            raise ConnectorError(
                f"The reply was not found with {cfg.response_path!r}.{keys} {e}"
            ) from e

        tool_calls: list[Any] = []
        if cfg.tool_calls_path:
            try:
                found = extract(data, cfg.tool_calls_path)
                tool_calls = [normalize_tool_call(c) for c in
                              (found if isinstance(found, list) else [found])]
            except JsonPathError:
                pass
        if text is None:  # a reply made only of tool calls has "content": null
            text = ""
        return TargetResponse(
            text=text if isinstance(text, str) else json.dumps(text),
            status_code=r.status_code,
            tool_calls=tool_calls,
            raw=data,
        )

    def test_connection(self) -> tuple[bool, str]:
        """UC-03 'Test Connection': send a harmless message, report the outcome."""
        try:
            resp = self.send("Hello")
        except ConnectorError as e:
            return False, str(e)
        return True, f"OK (HTTP {resp.status_code}), sample reply: {resp.text[:80]!r}"
