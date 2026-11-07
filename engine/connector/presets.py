"""Ready-made target configurations for common chat APIs."""

from __future__ import annotations

from typing import Any

OPENAI_URL = "https://api.openai.com/v1/chat/completions"


def openai_config(
    model: str,
    url: str = OPENAI_URL,
    token: str | None = "${OPENAI_API_KEY}",
    system_prompt: str | None = None,
    stream: bool = False,
) -> dict[str, Any]:
    """Target config for an OpenAI compatible /chat/completions endpoint (OpenAI, Azure OpenAI
    gateways, vLLM, LiteLLM, Ollama's /v1 API...). `token` is an ${ENV_VAR} reference, or None
    for servers that need no key."""
    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": "{{PROMPT}}"})
    body: dict[str, Any] = {"model": model, "messages": messages}
    if stream:
        body["stream"] = True
    cfg: dict[str, Any] = {
        "url": url,
        "request_template": body,
        "response_path": "$.choices[0].message.content",
        "tool_calls_path": "$.choices[0].message.tool_calls",
        "stream": stream,
    }
    if token:
        cfg["auth"] = {"type": "bearer", "token": token}
    return cfg
