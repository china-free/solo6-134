from __future__ import annotations

import json
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from fuzzmock.models import (
    AppliedMutations,
    CallbackEvent,
    CrashEvent,
    HttpExchange,
    Mutation,
    RequestEvent,
)
from fuzzmock.mutators import Mutator
from fuzzmock.reporter import CALLBACK_PATH, Reporter

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_STRIPPED_RESPONSE_HEADERS = _HOP_BY_HOP | {
    "content-length",
    "content-encoding",
}


class _MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, *args: Any, **kwargs: Any) -> None:
        return

    def handle(self) -> None:
        self._last_method: str | None = None
        self._last_path: str | None = None
        self._last_mutations: list[Mutation] = []
        self._served = False
        try:
            super().handle()
        except (ConnectionError, BrokenPipeError, OSError) as exc:
            self.server.mock_server.reporter.log_crash(
                CrashEvent(
                    method=self._last_method,
                    path=self._last_path,
                    mutations=self._last_mutations,
                    reason=f"{type(exc).__name__}: {exc}",
                    source="connection",
                )
            )

    def _route(self) -> None:
        parsed = urlparse(self.path)
        path_only = parsed.path
        if path_only == CALLBACK_PATH and self.command == "POST":
            self._handle_callback()
            return

        server: MockServer = self.server.mock_server
        exchange = server.match(self.command, parsed)
        if exchange is None:
            body = json.dumps({"error": "no matching HAR entry", "method": self.command, "path": path_only}).encode()
            self._send(404, "application/json", body)
            server.reporter.log_request(
                RequestEvent(method=self.command, path=path_only, matched=False, mutations=[], status_sent=404)
            )
            return

        applied = server.mutator.mutate(exchange)
        self._last_method = self.command
        self._last_path = path_only
        self._last_mutations = applied.mutations
        self._served = True
        server.record_served(path_only, applied)
        server.reporter.log_request(
            RequestEvent(
                method=self.command,
                path=path_only,
                matched=True,
                mutations=applied.mutations,
                status_sent=exchange.status,
            )
        )
        self._send(
            exchange.status,
            applied.content_type or "application/octet-stream",
            applied.body,
            exchange.response_headers,
        )

    do_GET = _route
    do_POST = _route
    do_PUT = _route
    do_PATCH = _route
    do_DELETE = _route
    do_HEAD = _route
    do_OPTIONS = _route

    def _send(self, status: int, content_type: str, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        sent_ct = False
        for key, value in (headers or {}).items():
            kl = key.lower()
            if kl in _STRIPPED_RESPONSE_HEADERS:
                continue
            if kl == "content-type":
                sent_ct = True
            self.send_header(key, value)
        if not sent_ct:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle_callback(self) -> None:
        server: MockServer = self.server.mock_server
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        payload: dict[str, Any]
        try:
            payload = json.loads(raw.decode("utf-8", "replace")) if raw else {}
            if not isinstance(payload, dict):
                payload = {"raw": payload}
        except Exception:
            payload = {"raw": raw.decode("utf-8", "replace")}

        path = payload.get("path") or self.headers.get("X-Fuzz-Path")
        mutations = server.find_recent(path) if path else []
        ack = b'{"status":"received"}'
        self._send_plain(200, "application/json", ack)
        server.reporter.log_callback(
            CallbackEvent(path=path, payload=payload, mutations=mutations, status_sent=200)
        )

    def _send_plain(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockServer:
    def __init__(
        self,
        exchanges: list[HttpExchange],
        mutator: Mutator,
        reporter: Reporter,
        host: str = "127.0.0.1",
        port: int = 8080,
        match_mode: str = "path",
    ) -> None:
        self.exchanges = exchanges
        self.mutator = mutator
        self.reporter = reporter
        self.host = host
        self.port = port
        self.match_mode = match_mode
        self._index: dict[tuple[str, str], HttpExchange] = {}
        self._query_index: dict[tuple[str, str, frozenset], HttpExchange] = {}
        for ex in exchanges:
            self._index.setdefault((ex.method, ex.path), ex)
            qkey = (ex.method, ex.path, frozenset((k, tuple(v)) for k, v in ex.query.items()))
            self._query_index.setdefault(qkey, ex)
        self._recent: deque[tuple[float, str, list[Mutation]]] = deque(maxlen=200)
        self._recent_lock = threading.Lock()
        self._httpd = _HTTPServer((host, port), _MockHandler)
        self._httpd.mock_server = self

    def match(self, method: str, parsed) -> HttpExchange | None:
        path = parsed.path
        if self.match_mode == "query":
            q = parse_qs(parsed.query, keep_blank_values=True)
            qkey = (method, path, frozenset((k, tuple(v)) for k, v in q.items()))
            exact = self._query_index.get(qkey)
            if exact:
                return exact
        return self._index.get((method, path))

    def record_served(self, path: str, applied: AppliedMutations) -> None:
        with self._recent_lock:
            self._recent.append((time.time(), path, list(applied.mutations)))

    def find_recent(self, path: str | None) -> list[Mutation]:
        if not path:
            return []
        with self._recent_lock:
            for _ts, p, muts in reversed(self._recent):
                if p == path:
                    return muts
        return []

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
