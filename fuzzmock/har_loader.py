from __future__ import annotations

import base64
import gzip
import json
import zlib
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from fuzzmock.models import HttpExchange

try:
    import brotli  # type: ignore

    _HAS_BROTLI = True
except ImportError:
    _HAS_BROTLI = False


def _headers_to_dict(headers: list[dict[str, Any]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for h in headers or []:
        name = h.get("name")
        value = h.get("value")
        if name is None:
            continue
        out[str(name)] = "" if value is None else str(value)
    return out


def _decode_content(content: dict[str, Any]) -> tuple[bytes, str]:
    text = content.get("text")
    mime = content.get("mimeType", "") or ""
    encoding = content.get("encoding", "")
    if text is None:
        return b"", mime
    if encoding == "base64":
        try:
            return base64.b64decode(text), mime
        except Exception:
            return text.encode("utf-8", "replace"), mime
    if isinstance(text, str):
        return text.encode("utf-8", "replace"), mime
    return bytes(text), mime


def _decompress_body(body: bytes, content_encoding: str) -> bytes:
    encodings = [e.strip().lower() for e in content_encoding.split(",") if e.strip()]
    result = body
    for enc in reversed(encodings):
        if enc == "gzip" or enc == "x-gzip":
            try:
                result = gzip.decompress(result)
            except OSError:
                return body
        elif enc == "deflate":
            try:
                result = zlib.decompress(result)
            except zlib.error:
                try:
                    result = zlib.decompress(result, -zlib.MAX_WBITS)
                except zlib.error:
                    return body
        elif enc == "br":
            if not _HAS_BROTLI:
                return body
            try:
                result = brotli.decompress(result)
            except Exception:
                return body
        elif enc == "identity" or enc == "":
            pass
        else:
            return body
    return result


def _strip_transfer_headers(headers: dict[str, str]) -> dict[str, str]:
    stripped: dict[str, str] = {}
    removed = {"content-encoding", "transfer-encoding"}
    for k, v in headers.items():
        if k.lower() in removed:
            continue
        stripped[k] = v
    return stripped


def _request_body(entry: dict[str, Any]) -> Optional[bytes]:
    post = entry.get("request", {}).get("postData")
    if not post:
        return None
    text = post.get("text")
    if text is None:
        return None
    encoding = post.get("encoding", "")
    if encoding == "base64":
        try:
            return base64.b64decode(text)
        except Exception:
            return text.encode("utf-8", "replace")
    return text.encode("utf-8", "replace") if isinstance(text, str) else bytes(text)


def _build_exchange(entry: dict[str, Any]) -> Optional[HttpExchange]:
    req = entry.get("request") or {}
    resp = entry.get("response") or {}
    if not req:
        return None

    url = req.get("url", "") or ""
    parsed = urlparse(url)
    method = (req.get("method") or "GET").upper()
    query = parse_qs(parsed.query, keep_blank_values=True)

    content = resp.get("content") or {}
    body, content_type = _decode_content(content)

    response_headers = _headers_to_dict(resp.get("headers", []))
    ce = response_headers.get("Content-Encoding") or response_headers.get("content-encoding") or ""
    if ce:
        body = _decompress_body(body, ce)
    response_headers = _strip_transfer_headers(response_headers)

    return HttpExchange(
        method=method,
        url=url,
        path=parsed.path or "/",
        query=query,
        request_headers=_headers_to_dict(req.get("headers", [])),
        request_body=_request_body(entry),
        status=int(resp.get("status", 200) or 200),
        response_headers=response_headers,
        response_body=body,
        content_type=content_type,
        started_at=entry.get("startedDateTime", "") or "",
    )


def load_har(path: str | Path) -> list[HttpExchange]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", []) if isinstance(data, dict) else []
    exchanges: list[HttpExchange] = []
    for entry in entries:
        ex = _build_exchange(entry)
        if ex is not None:
            exchanges.append(ex)
    return exchanges
