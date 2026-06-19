from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from fuzzmock.config import FuzzConfig, load_config
from fuzzmock.har_loader import load_har
from fuzzmock.mutators import Mutator
from fuzzmock.reporter import CALLBACK_PATH, Reporter
from fuzzmock.server import MockServer


def _cmd_serve(args: argparse.Namespace) -> int:
    exchanges = load_har(args.har)
    if not exchanges:
        print(f"No HTTP entries found in HAR: {args.har}", file=sys.stderr)
        return 2
    config = load_config(args.rules)
    if args.seed is not None:
        config.seed = args.seed
    if args.no_mutation:
        for rule in ("integers", "floats", "strings", "booleans", "drop_fields", "arrays", "nullify", "type_confusion"):
            setattr(getattr(config, rule), "enabled", False)
    reporter = Reporter(verbose=args.verbose)
    mutator = Mutator(config)
    server = MockServer(exchanges, mutator, reporter, host=args.host, port=args.port, match_mode=args.match_mode)

    if args.list:
        _print_exchanges(exchanges)
        return 0

    reporter.banner(args.host, args.port, str(args.har), str(args.rules) if args.rules else None)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        reporter.summary()
    finally:
        server.shutdown()
    return 0


def _cmd_parse(args: argparse.Namespace) -> int:
    exchanges = load_har(args.har)
    _print_exchanges(exchanges)
    return 0


def _cmd_mutate(args: argparse.Namespace) -> int:
    exchanges = load_har(args.har)
    if not exchanges:
        print(f"No HTTP entries found in HAR: {args.har}", file=sys.stderr)
        return 2
    config = load_config(args.rules)
    if args.seed is not None:
        config.seed = args.seed
    mutator = Mutator(config)
    console = Console()
    for idx, ex in enumerate(exchanges):
        if args.index is not None and idx != args.index:
            continue
        applied = mutator.mutate(ex)
        console.print(f"[bold cyan]#[{idx}][/] {ex.method} {ex.path}  status={ex.status}  ct={ex.content_type}")
        console.print("[dim]original body:[/]")
        console.print(ex.response_body[:400].decode("utf-8", "replace"))
        console.print("[magenta]mutated body:[/]")
        console.print(applied.body[:400].decode("utf-8", "replace"))
        if applied.mutations:
            t = Table(title=f"mutations #{idx}")
            t.add_column("path", style="cyan", overflow="fold")
            t.add_column("type", style="magenta")
            t.add_column("strategy", style="green")
            t.add_column("original -> mutated", overflow="fold")
            for m in applied.mutations:
                detail = m.brief().split(": ", 1)[-1] if ": " in m.brief() else m.brief()
                t.add_row(m.path, m.field_type, m.strategy, detail)
            console.print(t)
        console.print()
    return 0


def _print_exchanges(exchanges) -> None:
    console = Console()
    table = Table(title=f"HAR exchanges ({len(exchanges)})")
    table.add_column("#", justify="right", style="bold")
    table.add_column("method", style="cyan")
    table.add_column("path", style="white", overflow="fold")
    table.add_column("status", justify="right", style="green")
    table.add_column("content-type", style="magenta", overflow="fold")
    table.add_column("body bytes", justify="right")
    for i, ex in enumerate(exchanges):
        table.add_row(
            str(i),
            ex.method,
            ex.path,
            str(ex.status),
            ex.content_type,
            str(len(ex.response_body)),
        )
    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzmock",
        description="Mock + fuzz proxy: replays HAR responses with configurable mutations and reports client crashes.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="Start the mock+fuzz proxy server (default).")
    p_serve.add_argument("--har", required=True, help="Path to the HAR file exported from a browser/capture tool.")
    p_serve.add_argument("--rules", default=None, help="Path to a YAML fuzz-rules file (defaults are used if omitted).")
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind address.")
    p_serve.add_argument("--port", type=int, default=8080, help="Bind port.")
    p_serve.add_argument("--match-mode", choices=["path", "query"], default="path", help="How to match requests to HAR entries.")
    p_serve.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible mutations.")
    p_serve.add_argument("--no-mutation", action="store_true", help="Pass through original responses (baseline).")
    p_serve.add_argument("--verbose", action="store_true", help="Print every applied mutation per request.")
    p_serve.add_argument("--list", action="store_true", help="List parsed HAR entries and exit (do not serve).")
    p_serve.set_defaults(func=_cmd_serve)

    p_parse = sub.add_parser("parse", help="Inspect the HTTP exchanges parsed from a HAR file.")
    p_parse.add_argument("--har", required=True, help="Path to the HAR file.")
    p_parse.set_defaults(func=_cmd_parse)

    p_mutate = sub.add_parser("mutate", help="Mutate HAR responses offline and print the result (no server).")
    p_mutate.add_argument("--har", required=True, help="Path to the HAR file.")
    p_mutate.add_argument("--rules", default=None, help="Path to a YAML fuzz-rules file.")
    p_mutate.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible mutations.")
    p_mutate.add_argument("--index", type=int, default=None, help="Only mutate the HAR entry at this 0-based index.")
    p_mutate.set_defaults(func=_cmd_mutate)

    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
