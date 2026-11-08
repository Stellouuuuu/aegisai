"""App-specific checks supplied by the person who knows the application.

Some scenarios cannot be generic: contradicting a precise system prompt rule (PI-01) or stating
something false about the business (OS-04) both need a ground truth only the owner has. A check
is a prompt plus the phrases that, if they appear in the reply, prove the application misbehaved.

Phrases are plain case-insensitive text, never regular expressions, so a check cannot hang the
scanner. Pick phrases specific to the violation: a refusal that quotes the phrase would match.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAX_CHECKS = 20
MAX_PROMPT = 2000
MAX_PHRASE = 200


@dataclass(frozen=True)
class CustomCheck:
    prompt: str
    phrases: tuple[str, ...]

    def matched(self, text: str) -> str | None:
        low = text.lower()
        return next((p for p in self.phrases if p.lower() in low), None)


def parse_checks(raw: Any, kind: str) -> tuple[CustomCheck, ...]:
    """Validate checks coming from a config file or the API. Raises ValueError on bad input."""
    if not raw:
        return ()
    if not isinstance(raw, (list, tuple)) or len(raw) > MAX_CHECKS:
        raise ValueError(f"{kind}: expected a list of at most {MAX_CHECKS} checks")
    out = []
    for i, item in enumerate(raw, 1):
        if isinstance(item, CustomCheck):
            out.append(item)
            continue
        prompt = item.get("prompt", "") if isinstance(item, dict) else ""
        phrases = item.get("violation_phrases", []) if isinstance(item, dict) else []
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT:
            raise ValueError(f"{kind} #{i}: 'prompt' must be a non-empty text")
        if (
            not isinstance(phrases, (list, tuple))
            or not phrases
            or any(not isinstance(p, str) or not p.strip() or len(p) > MAX_PHRASE for p in phrases)
        ):
            raise ValueError(f"{kind} #{i}: 'violation_phrases' must list non-empty phrases")
        out.append(CustomCheck(prompt.strip(), tuple(p.strip() for p in phrases)))
    return tuple(out)


def judge(checks: tuple[CustomCheck, ...], prompt: str, text: str) -> str | None:
    """The phrase that proves a violation, or None. An empty prompt is the baseline request:
    it is judged against every check so that an app which always says the phrase is skipped."""
    for c in checks:
        if not prompt or c.prompt == prompt:
            hit = c.matched(text)
            if hit:
                return hit
    return None
