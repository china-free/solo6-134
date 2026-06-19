from __future__ import annotations

import json
import random
import threading
from typing import Any
from urllib.parse import parse_qs, urlencode

from fuzzmock.config import FuzzConfig
from fuzzmock.models import AppliedMutations, HttpExchange, Mutation


_STRING_TABLE: dict[str, Any] = {
    "empty": "",
    "long_text": None,
    "special_chars": "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./`~",
    "unicode": "\u00e9\u4e2d\u6587\U0001f600\U0001f4a9\u00c5\u00e6\u0153\u2211\u221e",
    "format_string": "%n%n%n%s%s%s%d%d%d{x}{x}",
    "sql_injection": "' OR '1'='1' -- ",
    "null_bytes": "foo\x00bar\x00baz\x00",
    "control_chars": "".join(chr(c) for c in range(1, 32)),
    "overflow_num": "9" * 40,
    "xss": "<script>alert(1)</script><img src=x onerror=alert(1)>",
}


def _truncate(value: Any, max_len: int = 80) -> str:
    if value is None:
        return "<dropped>"
    text = value if isinstance(value, str) else repr(value)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


class Mutator:
    def __init__(self, config: FuzzConfig):
        self.config = config
        seed = config.seed
        self._rng = random.Random(seed)
        self._lock = threading.Lock()

    def mutate(self, exchange: HttpExchange) -> AppliedMutations:
        with self._lock:
            return self._mutate(exchange)

    def _mutate(self, exchange: HttpExchange) -> AppliedMutations:
        ct = (exchange.content_type or "").lower()
        body = exchange.response_body or b""
        if not body:
            return AppliedMutations(body=b"", mutations=[], content_type=exchange.content_type)

        if "json" in ct:
            result = self._mutate_json(body, exchange.content_type)
            if result is not None:
                return result
        if "x-www-form-urlencoded" in ct:
            result = self._mutate_form(body, exchange.content_type)
            if result is not None:
                return result
        if ct.startswith("text/") or "xml" in ct or "html" in ct:
            return self._mutate_text(body, exchange.content_type)
        return AppliedMutations(body=body, mutations=[], content_type=exchange.content_type)

    def _mutate_json(self, body: bytes, content_type: str) -> AppliedMutations | None:
        try:
            obj = json.loads(body.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        new_obj, mutations = self._mutate_value(obj, "$")
        new_body = json.dumps(new_obj, ensure_ascii=False).encode("utf-8")
        return AppliedMutations(body=new_body, mutations=mutations, content_type=content_type)

    def _mutate_form(self, body: bytes, content_type: str) -> AppliedMutations | None:
        try:
            parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        except Exception:
            return None
        mutations: list[Mutation] = []
        new_flat: dict[str, str] = {}
        for key, values in parsed.items():
            original = values[0] if values else ""
            path = f"$.{key}"
            new_value, m = self._mutate_string(original, path)
            new_flat[key] = new_value
            mutations.extend(m)
        new_body = urlencode(new_flat).encode("utf-8")
        return AppliedMutations(body=new_body, mutations=mutations, content_type=content_type)

    def _mutate_text(self, body: bytes, content_type: str) -> AppliedMutations:
        text = body.decode("utf-8", "replace")
        new_text, mutations = self._mutate_string(text, "$")
        return AppliedMutations(
            body=new_text.encode("utf-8", "replace"),
            mutations=mutations,
            content_type=content_type,
        )

    def _maybe(self) -> bool:
        return self._rng.random() < self.config.mutation_probability

    def _mutate_value(self, obj: Any, path: str) -> tuple[Any, list[Mutation]]:
        if isinstance(obj, dict):
            return self._mutate_dict(obj, path)
        if isinstance(obj, list):
            return self._mutate_list(obj, path)
        return self._mutate_leaf(obj, path)

    def _mutate_dict(self, obj: dict, path: str) -> tuple[dict, list[Mutation]]:
        result: dict = {}
        mutations: list[Mutation] = []
        for key, value in obj.items():
            child = f"{path}.{key}"
            if self.config.drop_fields.enabled and not isinstance(value, (dict, list)):
                if self._rng.random() < self.config.drop_fields.probability:
                    mutations.append(
                        Mutation(child, type(value).__name__, "drop_field", _truncate(value), None)
                    )
                    continue
            new_value, sub = self._mutate_value(value, child)
            result[key] = new_value
            mutations.extend(sub)
        return result, mutations

    def _mutate_list(self, obj: list, path: str) -> tuple[list, list[Mutation]]:
        cfg = self.config.arrays
        if cfg.enabled and self._maybe():
            strat = self._rng.choice(cfg.strategies)
            if strat == "empty":
                return [], [Mutation(path, "array", "array_empty", f"len={len(obj)}", "[]")]
            if strat == "huge":
                base = obj[0] if obj else 0
                huge = [base] * cfg.huge_size
                return huge, [Mutation(path, "array", "array_huge", f"len={len(obj)}", f"len={cfg.huge_size}")]
            if strat == "null_element" and obj:
                idx = self._rng.randrange(len(obj))
                new_list = list(obj)
                new_list[idx] = None
                m = [Mutation(f"{path}[{idx}]", type(obj[idx]).__name__, "null_element", _truncate(obj[idx]), None)]
                new_list, sub = self._mutate_elements(new_list, path)
                return new_list, m + sub
            if strat == "duplicate":
                new_list, sub = self._mutate_elements(obj * 2, path)
                return new_list, [Mutation(path, "array", "array_duplicate", f"len={len(obj)}", f"len={len(obj)*2}")] + sub
        return self._mutate_elements(obj, path)

    def _mutate_elements(self, obj: list, path: str) -> tuple[list, list[Mutation]]:
        new_list: list = []
        mutations: list[Mutation] = []
        for i, item in enumerate(obj):
            new_item, sub = self._mutate_value(item, f"{path}[{i}]")
            new_list.append(new_item)
            mutations.extend(sub)
        return new_list, mutations

    def _mutate_leaf(self, value: Any, path: str) -> tuple[Any, list[Mutation]]:
        if value is None:
            if self.config.nullify.enabled and self._rng.random() < self.config.nullify.probability:
                replacement = self._rng.choice(["null", 0, "", False, []])
                return replacement, [Mutation(path, "null", "null_replace", None, _truncate(replacement))]
            return None, []
        if isinstance(value, bool):
            if self.config.booleans.enabled and self._maybe():
                return (not value), [Mutation(path, "bool", "bool_flip", value, (not value))]
            return value, []
        if isinstance(value, int) and not isinstance(value, bool):
            if self.config.integers.enabled and self._maybe():
                nv = self._rng.choice(self.config.integers.replacements)
                return nv, [Mutation(path, "integer", "int_replace", value, nv)]
            return value, []
        if isinstance(value, float):
            if self.config.floats.enabled and self._maybe():
                nv = self._rng.choice(self.config.floats.replacements)
                return nv, [Mutation(path, "float", "float_replace", value, _truncate(nv))]
            return value, []
        if isinstance(value, str):
            if self.config.strings.enabled and self._maybe():
                return self._mutate_string(value, path)
            return value, []
        if self.config.type_confusion.enabled and self._maybe():
            return self._type_confuse(value, path)
        return value, []

    def _mutate_string(self, value: str, path: str) -> tuple[str, list[Mutation]]:
        strat = self._rng.choice(self.config.strings.strategies)
        if strat == "long_text":
            nv = "A" * self.config.strings.long_text_length
        else:
            nv = _STRING_TABLE.get(strat, value)
            if nv is None:
                nv = "A" * self.config.strings.long_text_length
        return nv, [Mutation(path, "string", f"str_{strat}", _truncate(value), _truncate(nv))]

    def _type_confuse(self, value: Any, path: str) -> tuple[Any, list[Mutation]]:
        choice = self._rng.choice(["int_as_str", "str_as_int", "bool_as_int", "int_as_bool"])
        if choice == "int_as_str" and isinstance(value, int):
            return str(value), [Mutation(path, "integer", "type_confuse", value, str(value))]
        if choice == "str_as_int" and isinstance(value, str):
            return 0, [Mutation(path, "string", "type_confuse", _truncate(value), 0)]
        if choice == "bool_as_int" and isinstance(value, bool):
            return int(value), [Mutation(path, "bool", "type_confuse", value, int(value))]
        if choice == "int_as_bool" and isinstance(value, int):
            return bool(value), [Mutation(path, "integer", "type_confuse", value, bool(value))]
        return value, []
