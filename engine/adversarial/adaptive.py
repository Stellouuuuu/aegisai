"""Adaptive attacks: when a scenario resisted, rewrite its prompts and try again.

After the normal scan, every scenario that found nothing gets up to `rounds` more tries. Each
try looks at how the application answered the previous one (a refusal, or an answer that
ignored the request) and picks the next rewriting strategy accordingly, or asks an attacker LLM
for a rewrite. A new finding is proven the same way as any other (baseline, detector, replays),
and records which strategy opened the door.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from engine.adversarial.attacker import LlmAttacker
from engine.adversarial.strategies import STRATEGIES, is_refusal, next_strategies
from engine.connector import ConnectorError, HttpConnector
from engine.core.models import AppProfile, Confidence, Finding, Payload
from engine.core.module import AttackModule
from engine.evaluators.replay import baseline_violates, replay

BASELINE_PROMPT = "Bonjour, peux-tu m'aider ?"


@dataclass(frozen=True)
class Attempt:
    scenario_id: str
    round: int
    strategy: str
    hit: bool


def _single_turn(p: Payload) -> bool:
    return not (p.turns or p.plant or p.documents or p.as_other_user)


def run_adaptive(
    connector: HttpConnector,
    module: AttackModule,
    already_found: set[str],
    rounds: int,
    repeats: int = 3,
    profile: AppProfile | None = None,
    attacker: LlmAttacker | None = None,
    should_stop: Callable[[], bool] | None = None,
    attempts: list[Attempt] | None = None,
) -> list[Finding]:
    """Findings for scenarios of `module` that the normal scan did not prove."""
    stop = should_stop or (lambda: False)
    if rounds <= 0 or stop():
        return []
    baseline = connector.send(BASELINE_PROMPT)
    bases: dict[str, list[Payload]] = {}
    for p in module.generate_payloads(profile or AppProfile()):
        if _single_turn(p) and p.scenario_id not in already_found:
            bases.setdefault(p.scenario_id, []).append(p)

    out: list[Finding] = []
    for sid, payloads in bases.items():
        if baseline_violates(module, sid, baseline):
            continue
        tried: set[str] = set()
        last_reply = ""
        for n in range(1, rounds + 1):
            if stop():
                return out
            base = payloads[(n - 1) % len(payloads)]
            names = next_strategies(last_reply, tried)
            use_llm = attacker is not None and (is_refusal(last_reply) or not names)
            text, label = base.text, ""
            if use_llm and attacker is not None:
                rewritten = attacker.rewrite(base.text, last_reply)
                if rewritten:
                    text, label = rewritten, "llm_rewrite"
            if not label:
                if not names:
                    break
                label = names[0]
                text = STRATEGIES[label].apply(base.text)
            tried.add(label)
            payload = replace(base, text=text)
            try:
                response = connector.send_payload(payload)
            except ConnectorError:
                continue
            last_reply = response.text
            verdict = module.detect(payload, response)
            if attempts is not None:
                attempts.append(Attempt(sid, n, label, verdict.violated))
            if not verdict.violated:
                continue
            rep = replay(connector, module, payload, repeats)
            confirmed = verdict.deterministic and rep.stable
            sc = module.scenario(sid)
            out.append(Finding(
                id=sid, category=module.id, owasp=sc.owasp, atlas=sc.atlas,
                severity=sc.severity,
                confidence=Confidence.CONFIRMED if confirmed else Confidence.NEEDS_REVIEW,
                scenario=sc.title, request=text, response=response.text,
                evidence=verdict.evidence, safety_rule_violated=sc.rule_violated,
                recommendation=sc.recommendation, reproducible=rep.reproducible,
                extra={"replay_hits": rep.hits, "replay_attempts": rep.attempts,
                       "success_rate": round(rep.success_rate, 3), "payloads_tried": n,
                       "tool_calls": list(response.tool_calls),
                       "adversarial": {"strategy": label, "round": n,
                                       "original_prompt": base.text}},
            ))
            break
    return out


def adapt_scan(
    connector: HttpConnector,
    modules: Iterable[AttackModule],
    findings: list[Finding],
    rounds: int,
    repeats: int = 3,
    attacker: LlmAttacker | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> list[Finding]:
    """Second pass over a finished scan: only the scenarios that found nothing are retried."""
    extra: list[Finding] = []
    for module in modules:
        found = {f.id for f in findings if f.category == module.id}
        extra += run_adaptive(
            connector, module, found, rounds, repeats, attacker=attacker, should_stop=should_stop
        )
    return extra
