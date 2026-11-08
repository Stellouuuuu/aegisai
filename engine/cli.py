"""Command line interface: `aegis scan`, `aegis profile` and `aegis report`."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from engine.adversarial import LlmAttacker, adapt_scan
from engine.attacks.registry import MODULES, build_modules
from engine.connector import AuthConfig, ConnectorError, HttpConnector, IngestConfig, TargetConfig
from engine.connector.presets import OPENAI_URL, openai_config
from engine.demo import DemoUnavailableError, start_demo_lab
from engine.orchestrator import run_scan
from engine.profiler import profile_target
from engine.reporting import build_report, render_summary
from engine.risk_engine import assess

DEPTH_REPEATS = {"quick": 1, "standard": 3, "deep": 5}
LEGAL = (
    "AegisAI is an offensive security tool. Only scan applications you own or are "
    "explicitly authorized to test."
)


def load_config(path: str) -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith((".yaml", ".yml")):
        import yaml

        return yaml.safe_load(text) or {}
    return json.loads(text)


def _attacker(args: argparse.Namespace, client: httpx.Client | None) -> LlmAttacker | None:
    """An LLM that rewrites resisted prompts, if --attacker-model was given."""
    if not args.attacker_model:
        return None
    cfg = openai_config(
        args.attacker_model,
        url=args.attacker_url or "http://localhost:11434/v1/chat/completions",
        token=args.attacker_token,
        system_prompt=None,
    )
    target = TargetConfig(
        url=cfg["url"], request_template=cfg["request_template"],
        response_path=cfg["response_path"], timeout=args.timeout or 120, min_interval=0,
        auth=AuthConfig(**cfg.get("auth", {})),
    )
    return LlmAttacker(HttpConnector(target, client=client))


def _peer_from(
    cfg: dict[str, Any], client: httpx.Client | None
) -> HttpConnector | None:
    """The connector of a second user (same application, other credentials), if configured."""
    if not cfg.get("second_auth"):
        return None
    other = {**cfg, "auth": cfg["second_auth"]}
    return HttpConnector(_target_from(other), client=client)


def _target_from(cfg: dict[str, Any]) -> TargetConfig:
    auth = AuthConfig(**cfg.get("auth", {}))
    return TargetConfig(
        url=cfg["url"],
        method=cfg.get("method", "POST"),
        request_template=cfg.get("request_template", {"message": "{{PROMPT}}"}),
        response_path=cfg.get("response_path", "$.reply"),
        tool_calls_path=cfg.get("tool_calls_path"),
        auth=auth,
        timeout=float(cfg.get("timeout", 30)),
        min_interval=float(cfg.get("min_interval", 0.2)),
        stream=bool(cfg.get("stream", False)),
        ingest=IngestConfig(**cfg["ingest"]) if cfg.get("ingest") else None,
    )


def _module_options(args: argparse.Namespace, cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Tell the data leakage module which fake secret was planted in the target's context."""
    opts: dict[str, Any] = {}
    canary = args.canary or cfg.get("canary")
    markers = args.system_prompt_marker or cfg.get("system_prompt_markers")
    if canary:
        opts["canary"] = canary
    if markers:
        opts["system_prompt_markers"] = tuple(markers)
    out: dict[str, dict[str, Any]] = {"data_leakage": opts} if opts else {}
    allowed = args.allowed_tools or cfg.get("allowed_tools")
    if allowed:
        out["tool_abuse"] = {
            "allowed_tools": tuple(allowed.split(",") if isinstance(allowed, str) else allowed)
        }
    if canary:
        out["rag"] = {"canary": canary}
    if cfg.get("rule_checks"):
        out["prompt_injection"] = {"rule_checks": cfg["rule_checks"]}
    if cfg.get("fact_checks"):
        out["output"] = {"fact_checks": cfg["fact_checks"]}
    return out


def _config_from_args(args: argparse.Namespace) -> dict[str, Any]:
    cfg: dict[str, Any] = load_config(args.config) if args.config else {}
    if args.preset == "openai":
        if not args.model:
            raise KeyError("--preset openai needs --model")
        cfg.update(openai_config(
            model=args.model, url=args.url or OPENAI_URL,
            system_prompt=args.system_prompt, stream=args.stream,
        ))
    if args.url:
        cfg["url"] = args.url
    if args.request_template:
        cfg["request_template"] = args.request_template
    if args.response_path:
        cfg["response_path"] = args.response_path
    if args.tool_calls_path:
        cfg["tool_calls_path"] = args.tool_calls_path
    if args.no_auth:
        cfg["auth"] = {"type": "none"}
    if args.auth_bearer:
        cfg["auth"] = {"type": "bearer", "token": args.auth_bearer}
    if args.second_auth_bearer:
        cfg["second_auth"] = {"type": "bearer", "token": args.second_auth_bearer}
    if args.min_interval is not None:
        cfg["min_interval"] = args.min_interval
    if args.timeout is not None:
        cfg["timeout"] = args.timeout
    return cfg


def cmd_scan(args: argparse.Namespace, client: httpx.Client | None) -> int:
    print(LEGAL, file=sys.stderr)
    if args.target:
        try:
            args.url, stop = start_demo_lab(args.target)
        except DemoUnavailableError as e:
            print(f"Demo error: {e}", file=sys.stderr)
            return 2
        args.tool_calls_path = args.tool_calls_path or "$.tool_calls"
        args.confirm_authorized = True
        try:
            return _scan(args, client)
        finally:
            stop()
    return _scan(args, client)


def _scan(args: argparse.Namespace, client: httpx.Client | None) -> int:
    if not args.confirm_authorized:
        print("Refusing to scan: pass --confirm-authorized to confirm you are "
              "allowed to test this target.", file=sys.stderr)
        return 2
    try:
        cfg = _config_from_args(args)
    except KeyError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2
    if "url" not in cfg:
        print("Missing target: use --url or a --config file with 'url'.", file=sys.stderr)
        return 2
    auto = args.modules == "auto"
    module_names = (args.modules.split(",") if args.modules and not auto
                    else cfg.get("modules") or list(MODULES))
    try:
        connector = HttpConnector(_target_from(cfg), client=client)
        connector.peer = _peer_from(cfg, client)
        if not auto:
            modules = build_modules(module_names, _module_options(args, cfg))
    except (KeyError, TypeError) as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2

    ok, msg = connector.test_connection()
    if not ok:
        print(f"Connection test failed: {msg}", file=sys.stderr)
        return 3
    if auto:
        profile = profile_target(connector)
        module_names = profile.modules
        print(f"Profile: {profile.app_type.value} ({profile.confidence} confidence)",
              file=sys.stderr)
        modules = build_modules(module_names, _module_options(args, cfg))
    print(f"Connection OK. Running modules: {', '.join(module_names)} ({args.depth})",
          file=sys.stderr)

    start = time.monotonic()
    findings = run_scan(connector, modules, repeats=DEPTH_REPEATS[args.depth],
                        workers=args.workers)
    if args.adversarial:
        attacker = _attacker(args, client)
        extra = adapt_scan(connector, modules, findings, args.adversarial,
                           repeats=DEPTH_REPEATS[args.depth], attacker=attacker)
        print(f"Adaptive pass: {len(extra)} more finding(s) after rewriting resisted attacks.",
              file=sys.stderr)
        findings += extra
    findings = assess(findings)
    report = build_report(
        cfg["url"], findings, module_names, args.depth,
        time.monotonic() - start, len(connector.history),
    )
    Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(render_summary(report))
    print(f"Report written to {args.out}")
    return 1 if args.fail_on_findings and findings else 0


def cmd_profile(args: argparse.Namespace, client: httpx.Client | None) -> int:
    print(LEGAL, file=sys.stderr)
    if not args.confirm_authorized:
        print("Refusing to probe: pass --confirm-authorized to confirm you are "
              "allowed to test this target.", file=sys.stderr)
        return 2
    try:
        cfg = _config_from_args(args)
    except KeyError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2
    if "url" not in cfg:
        print("Missing target: use --url or a --config file with 'url'.", file=sys.stderr)
        return 2
    try:
        connector = HttpConnector(_target_from(cfg), client=client)
    except (KeyError, TypeError) as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2
    ok, msg = connector.test_connection()
    if not ok:
        print(f"Connection test failed: {msg}", file=sys.stderr)
        return 3
    profile = profile_target(connector)
    print(f"Application type: {profile.app_type.value} ({profile.confidence} confidence)")
    for sig in profile.signals:
        print(f"  - toward {sig.toward} (+{sig.weight}): {sig.detail}")
    if not profile.signals:
        print("  - no sign of tools or documents: treated as a plain chatbot")
    print(f"Recommended modules: {','.join(profile.modules)}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = json.loads(Path(args.file).read_text(encoding="utf-8"))
    if args.format == "pdf":
        try:
            from engine.reporting.pdf_report import render_pdf
        except ImportError:
            print('PDF export needs: pip install "aegisai[pdf]"', file=sys.stderr)
            return 2
        out = args.output or str(Path(args.file).with_suffix(".pdf"))
        render_pdf(report, out)
        print(f"PDF report written to {out}")
        return 0
    print(render_summary(report))
    return 0


def _add_target_args(p: argparse.ArgumentParser) -> None:
    """Options that describe how to reach the target, shared by `scan` and `profile`."""
    p.add_argument("--config", help="JSON or YAML target configuration")
    p.add_argument("--url")
    p.add_argument(
        "--request-template",
        help='JSON body with {{PROMPT}}, e.g. \'{"message": "{{PROMPT}}"}\'',
    )
    p.add_argument("--response-path", help="JSONPath of the reply, e.g. $.reply")
    p.add_argument("--tool-calls-path", help="JSONPath of reported tool calls")
    p.add_argument("--auth-bearer", help="Bearer token, or ${ENV_VAR}")
    p.add_argument(
        "--second-auth-bearer",
        help="Bearer token (or ${ENV_VAR}) of a second user, to test isolation between users",
    )
    p.add_argument("--no-auth", action="store_true", help="send no credentials (local servers)")
    p.add_argument(
        "--preset", choices=["openai"],
        help="ready-made config for OpenAI compatible /chat/completions APIs",
    )
    p.add_argument("--model", help="model name, for --preset openai")
    p.add_argument("--system-prompt", help="system prompt to send, for --preset openai")
    p.add_argument("--stream", action="store_true", help="use server-sent events (stream: true)")
    p.add_argument("--min-interval", type=float, help="seconds between requests")
    p.add_argument("--timeout", type=float, help="seconds to wait for each reply (slow models)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="AI application security scanner")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a target application")
    _add_target_args(s)
    s.add_argument(
        "--target", help="built-in demo lab: demo:vulnerable-chatbot or demo:patched-chatbot"
    )
    s.add_argument(
        "--modules", help=f"comma separated: {','.join(MODULES)}, or 'auto' to profile the target"
    )
    s.add_argument(
        "--canary", help="fake secret planted in the app's context (default SECRET_TEST_4821)"
    )
    s.add_argument(
        "--system-prompt-marker", action="append",
        help="distinctive fragment of the app's system prompt (repeatable); weak evidence only",
    )
    s.add_argument(
        "--allowed-tools",
        help="comma separated tools the app is meant to use; enables scenario TS-01",
    )
    s.add_argument("--depth", choices=list(DEPTH_REPEATS), default="standard")
    s.add_argument(
        "--workers", type=int, default=1, choices=range(1, 9), metavar="N",
        help="run up to N modules in parallel (1 to 8); --min-interval still applies globally. "
        "Useful for hosted APIs; a single-GPU local model gains nothing from it",
    )
    s.add_argument(
        "--adversarial", type=int, default=0, choices=range(0, 21), metavar="ROUNDS",
        help="after the scan, retry every scenario that found nothing with up to ROUNDS "
        "rewritten prompts (0 = off). The strategy that worked is recorded in the finding",
    )
    s.add_argument("--attacker-model", help="model of an OpenAI compatible API that rewrites "
                   "resisted prompts during the adaptive pass")
    s.add_argument("--attacker-url", help="its chat completions URL "
                   "(default: local Ollama, http://localhost:11434/v1/chat/completions)")
    s.add_argument("--attacker-token", default=None,
                   help="its API key as ${ENV_VAR} (omit for servers without a key)")
    s.add_argument("--out", default="aegis-report.json")
    s.add_argument("--confirm-authorized", action="store_true",
                   help="confirm you own the target or have written authorization")
    s.add_argument("--fail-on-findings", action="store_true", help="exit 1 if findings exist (CI)")

    pr = sub.add_parser("profile", help="guess the application type (chatbot, agent, RAG)")
    _add_target_args(pr)
    pr.add_argument("--confirm-authorized", action="store_true",
                    help="confirm you own the target or have written authorization")

    r = sub.add_parser("report", help="summarize a JSON report, or export it as PDF")
    r.add_argument("file")
    r.add_argument("--format", choices=["text", "pdf"], default="text")
    r.add_argument("-o", "--output", help="output path for --format pdf")
    return p


def main(argv: list[str] | None = None, client: httpx.Client | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args, client)
        if args.command == "profile":
            return cmd_profile(args, client)
        return cmd_report(args)
    except ConnectorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
