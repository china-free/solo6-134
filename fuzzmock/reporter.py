from __future__ import annotations

import threading

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from fuzzmock.models import CallbackEvent, CrashEvent, Mutation, RequestEvent

CALLBACK_PATH = "/__fuzz_report__"


class Reporter:
    def __init__(self, console: Console | None = None, verbose: bool = False):
        self.console = console or Console()
        self.verbose = verbose
        self._lock = threading.Lock()
        self.requests = 0
        self.mutations = 0
        self.crashes = 0
        self.callbacks = 0
        self.unmatched = 0

    def info(self, message: str) -> None:
        with self._lock:
            self.console.print(Panel(message, title="FuzzMock", border_style="cyan"))

    def banner(self, host: str, port: int, har_path: str, rules_path: str | None) -> None:
        lines = [
            f"[bold green]FuzzMock[/] mock + fuzz proxy is listening on [cyan]http://{host}:{port}[/]",
            f"HAR source   : [dim]{har_path}[/]",
            f"Fuzz rules   : [dim]{rules_path or '<built-in defaults>'}[/]",
            f"Crash detect : [dim]connection-level heuristic + POST {CALLBACK_PATH} callback[/]",
            "[dim]Press Ctrl+C to stop and print a summary.[/]",
        ]
        with self._lock:
            self.console.print(Panel("\n".join(lines), border_style="cyan"))

    def log_request(self, event: RequestEvent) -> None:
        with self._lock:
            self.requests += 1
            self.mutations += len(event.mutations)
            if not event.matched:
                self.unmatched += 1
                self.console.print(
                    f"[yellow]?[/] {event.method} {event.path}  [dim]unmatched -> {event.status_sent}[/]"
                )
                return
            head = f"[green]->[/] [bold]{event.method}[/] {event.path}  [dim]-> {event.status_sent}[/]  [magenta]{len(event.mutations)} mutations[/]"
            self.console.print(head)
            if self.verbose:
                for m in event.mutations:
                    self.console.print(f"     [dim]-[/] {m.brief()}")

    def log_unmatched(self, method: str, path: str) -> None:
        with self._lock:
            self.unmatched += 1
            self.console.print(f"[yellow]?[/] {method} {path}  [dim]unmatched -> 404[/]")

    def log_crash(self, event: CrashEvent) -> None:
        with self._lock:
            self.crashes += 1
            body = Text()
            body.append(f"{event.method or '?'} {event.path or '?'}\n", style="bold")
            body.append(f"source : {event.source}\n", style="yellow")
            body.append(f"reason : {event.reason}\n", style="yellow")
            if event.mutations:
                body.append("likely-causing mutations:\n", style="red")
                for m in event.mutations:
                    body.append(f"  - {m.brief()}\n", style="white")
            else:
                body.append("(no mutation recorded for this connection)\n", style="dim")
            self.console.print(Panel(body, title="[bold red]CRASH / DISCONNECT detected", border_style="red"))

    def log_callback(self, event: CallbackEvent) -> None:
        with self._lock:
            self.callbacks += 1
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_row("[yellow]path[/]", str(event.path))
            err = event.payload.get("error") or event.payload.get("message") or "<no message>"
            stack = event.payload.get("stack") or event.payload.get("trace") or ""
            table.add_row("[yellow]error[/]", str(err))
            if stack:
                table.add_row("[yellow]stack[/]", str(stack))
            panel_body = table
            if event.mutations:
                mt = Table(title="matched mutations", box=None, padding=(0, 1))
                mt.add_column("path", style="cyan", overflow="fold")
                mt.add_column("type", style="magenta")
                mt.add_column("strategy", style="green")
                mt.add_column("original -> mutated", overflow="fold")
                for m in event.mutations:
                    mt.add_row(m.path, m.field_type, m.strategy, m.brief().split(": ", 1)[-1] if ": " in m.brief() else m.brief())
                panel_body = table
            self.console.print(
                Panel(
                    panel_body,
                    title=f"[bold yellow]CLIENT ERROR reported ({event.status_sent})",
                    border_style="yellow",
                )
            )
            if event.mutations:
                self.console.print(mt)

    def summary(self) -> None:
        with self._lock:
            table = Table(title="FuzzMock summary", border_style="cyan")
            table.add_column("metric", style="bold")
            table.add_column("value", justify="right")
            table.add_row("requests served", str(self.requests))
            table.add_row("unmatched", str(self.unmatched))
            table.add_row("mutations applied", str(self.mutations))
            table.add_row("crashes detected", str(self.crashes))
            table.add_row("client errors reported", str(self.callbacks))
            self.console.print(table)
