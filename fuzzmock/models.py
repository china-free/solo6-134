from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class HttpExchange:
    method: str
    url: str
    path: str
    query: dict[str, list[str]]
    request_headers: dict[str, str]
    request_body: Optional[bytes]
    status: int
    response_headers: dict[str, str]
    response_body: bytes
    content_type: str = ""
    started_at: str = ""


@dataclass
class Mutation:
    path: str
    field_type: str
    strategy: str
    original: Any
    mutated: Any

    def brief(self, max_len: int = 60) -> str:
        def fmt(value: Any) -> str:
            if value is None:
                return "<dropped>"
            text = repr(value) if not isinstance(value, str) else value
            if len(text) > max_len:
                text = text[: max_len - 3] + "..."
            return text

        return f"{self.path} ({self.field_type}/{self.strategy}): {fmt(self.original)} -> {fmt(self.mutated)}"


@dataclass
class AppliedMutations:
    body: bytes
    mutations: list[Mutation] = field(default_factory=list)
    content_type: str = ""


@dataclass
class RequestEvent:
    method: str
    path: str
    matched: bool
    mutations: list[Mutation]
    status_sent: int


@dataclass
class CrashEvent:
    method: Optional[str]
    path: Optional[str]
    mutations: list[Mutation]
    reason: str
    source: str


@dataclass
class CallbackEvent:
    path: Optional[str]
    payload: dict[str, Any]
    mutations: list[Mutation]
    status_sent: int
