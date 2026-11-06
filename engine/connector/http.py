"""Generic HTTP connector: talks to any chat API via a configurable template."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import httpx

from engine.connector.jsonpath import JsonPathError, extract

log = logging.getLogger("aegis.connector")

PLACEHOLDER = "{{PROMPT}}"
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


@dataclass(frozen=True)
class TargetResponse:
    text: str
    status_code: int
    tool_calls: list[Any] = field(default_factory=list)
    raw: Any = None


def render_template(template: Any, prompt: str) -> Any:
    """Substitute {{PROMPT}} in every string of a JSON-like template.

    Working on the parsed structure (not on raw text) means the prompt can
    contain quotes/newlines without breaking the JSON body.
    """
    if isinstance(template, str):
        if template.lstrip().startswith(("{", "[")):
            try:
                return render_template(json.loads(template), prompt)
            except json.JSONDecodeError:
                pass
        return template.replace(PLACEHOLDER, prompt)
    if isinstance(template, dict):
        return {k: render_template(v, prompt) for k, v in template.items()}
    if isinstance(template, list):
        return [render_template(v, prompt) for v in template]
    return template


class HttpConnector:
    def __init__(self, config: TargetConfig, client: httpx.Client | None = None) -> None:
        self.config = config
        self._client = client or httpx.Client(timeout=config.timeout)
        self._last_sent = 0.0
        self.history: list[dict[str, Any]] = []  # structured audit trail (ENF-05)

    def _throttle(self) -> None:
        wait = self.config.min_interval - (time.monotonic() - self._last_sent)
        if wait > 0:
            time.sleep(wait)
        self._last_sent = time.monotonic()

    def send(self, prompt: str) -> TargetResponse:
        cfg = self.config
        self._throttle()
        body = render_template(cfg.request_template, prompt)
        headers = cfg.auth.build_headers()
        record: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "url": cfg.url,
            "method": cfg.method,
            "prompt": prompt,
        }
        try:
            r = self._client.request(
                cfg.method, cfg.url, json=body, headers=headers, timeout=cfg.timeout
            )
        except httpx.HTTPError as e:
            record["error"] = str(e)
            self.history.append(record)
            log.warning("request failed: %s", e)
            raise ConnectorError(f"Request to {cfg.url} failed: {e}") from e

        record["status"] = r.status_code
        self.history.append(record)
        log.info("%s %s -> %s", cfg.method, cfg.url, r.status_code)
        if r.status_code >= 400:
            raise ConnectorError(f"Target returned HTTP {r.status_code}: {r.text[:200]}")
        try:
            data = r.json()
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
                tool_calls = found if isinstance(found, list) else [found]
            except JsonPathError:
                pass
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
