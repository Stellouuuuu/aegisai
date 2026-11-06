"""Command line interface: `aegis scan` and `aegis report`."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from engine.attacks.registry import MODULES, build_modules
from engine.connector import AuthConfig, ConnectorError, HttpConnector, TargetConfig
from engine.demo import DemoUnavailableError, start_demo_lab
from engine.orchestrator import run_scan
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
    )


def _config_from_args(args: argparse.Namespace) -> dict[str, Any]:
    cfg: dict[str, Any] = load_config(args.config) if args.config else {}
    if args.url:
        cfg["url"] = args.url
    if args.request_template:
        cfg["request_template"] = args.request_template
    if args.response_path:
        cfg["response_path"] = args.response_path
    if args.tool_calls_path:
        cfg["tool_calls_path"] = args.tool_calls_path
    if args.auth_bearer:
        cfg["auth"] = {"type": "bearer", "token": args.auth_bearer}
    if args.min_interval is not None:
        cfg["min_interval"] = args.min_interval
    return cfg


def cmd_scan(args: argparse.Namespace, client: httpx.Client | None) -> int:
    print(LEGAL, file=sys.stderr)
    if args.target:
        # The bundled lab is our own deliberately vulnerable app: no authorization needed.
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
    cfg = _config_from_args(args)
    if "url" not in cfg:
        print("Missing target: use --url or a --config file with 'url'.", file=sys.stderr)
        return 2
    module_names = (args.modules.split(",") if args.modules
                    else cfg.get("modules") or list(MODULES))
    try:
        modules = build_modules(module_names)
        connector = HttpConnector(_target_from(cfg), client=client)
    except (KeyError, TypeError) as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2

    ok, msg = connector.test_connection()
    if not ok:
        print(f"Connection test failed: {msg}", file=sys.stderr)
        return 3
    print(f"Connection OK. Running modules: {', '.join(module_names)} ({args.depth})",
          file=sys.stderr)

    start = time.monotonic()
    findings = assess(run_scan(connector, modules, repeats=DEPTH_REPEATS[args.depth]))
    report = build_report(
        cfg["url"], findings, module_names, args.depth,
        time.monotonic() - start, len(connector.history),
    )
    Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(render_summary(report))
    print(f"Report written to {args.out}")
    return 1 if args.fail_on_findings and findings else 0


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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="AI application security scanner")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a target application")
    s.add_argument("--config", help="JSON or YAML target configuration")
    s.add_argument("--url")
    s.add_argument(
        "--target", help="built-in demo lab: demo:vulnerable-chatbot or demo:patched-chatbot"
    )
    s.add_argument(
        "--request-template",
        help='JSON body with {{PROMPT}}, e.g. \'{"message": "{{PROMPT}}"}\'',
    )
    s.add_argument("--response-path", help="JSONPath of the reply, e.g. $.reply")
    s.add_argument("--tool-calls-path", help="JSONPath of reported tool calls")
    s.add_argument("--auth-bearer", help="Bearer token, or ${ENV_VAR}")
    s.add_argument("--modules", help=f"comma separated: {','.join(MODULES)}")
    s.add_argument("--depth", choices=list(DEPTH_REPEATS), default="standard")
    s.add_argument("--min-interval", type=float, help="seconds between requests")
    s.add_argument("--out", default="aegis-report.json")
    s.add_argument("--confirm-authorized", action="store_true",
                   help="confirm you own the target or have written authorization")
    s.add_argument("--fail-on-findings", action="store_true", help="exit 1 if findings exist (CI)")

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
        return cmd_report(args)
    except ConnectorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
