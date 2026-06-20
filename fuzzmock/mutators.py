from __future__ import annotations

import json
import random
import threading
from typing import Any
from urllib.parse import parse_qs, urlencode

from fuzzmock.config import FuzzConfig, StrategyRef
from fuzzmock.models import AppliedMutations, HttpExchange, Mutation
from fuzzmock.strategies import (
    MutationStrategy,
    StrategyContext,
    StrategyRegistry,
    build_registry_from_config,
)


def _truncate(value: Any, max_len: int = 80) -> str:
    if value is None:
        return "<dropped>"
    text = value if isinstance(value, str) else repr(value)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


class Mutator:
    def __init__(self, config: FuzzConfig, registry: StrategyRegistry | None = None):
        self.config = config
        self.registry: StrategyRegistry = registry or build_registry_from_config(
            config.custom_strategies
        )
        seed = config.seed
        self._rng = random.Random(seed)
        self._lock = threading.Lock()
        self._context = StrategyContext(rng=self._rng, config=config)
        self._string_strategies = self._build_cached_strategies(config.strings.strategies)
        self._integer_strategies = self._build_cached_strategies(config.integers.strategies)
        self._float_strategies = self._build_cached_strategies(config.floats.strategies)
        self._bool_strategies = self._build_cached_strategies(config.booleans.strategies)
        self._nullify_strategies = self._build_cached_strategies(config.nullify.strategies)

    def _build_cached_strategies(
        self, refs: list[StrategyRef]
    ) -> list[tuple[MutationStrategy, str]]:
        out: list[tuple[MutationStrategy, str]] = []
        for ref in refs:
            params = dict(ref.params)
            if ref.name == "long_text" and "length" not in params:
                params["length"] = self.config.strings.long_text_length
            if ref.name == "int_replace" and "values" not in params:
                params["values"] = list(self.config.integers.replacements)
            if ref.name == "float_replace" and "values" not in params:
                params["values"] = list(self.config.floats.replacements)
            strategy = self.registry.create(ref.name, params)
            out.append((strategy, ref.name))
        return out

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
                    ref = self.config.drop_fields.strategy
                    try:
                        strategy = self.registry.create(ref.name, ref.params)
                        mutated = strategy.apply(value, self._context)
                    except Exception:
                        mutated = None
                    mutations.append(
                        Mutation(
                            child,
                            type(value).__name__,
                            ref.name,
                            _truncate(value),
                            _truncate(mutated) if mutated is not None else None,
                        )
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
                return huge, [
                    Mutation(path, "array", "array_huge", f"len={len(obj)}", f"len={cfg.huge_size}")
                ]
            if strat == "null_element" and obj:
                idx = self._rng.randrange(len(obj))
                new_list = list(obj)
                new_list[idx] = None
                m = [
                    Mutation(
                        f"{path}[{idx}]",
                        type(obj[idx]).__name__,
                        "null_element",
                        _truncate(obj[idx]),
                        None,
                    )
                ]
                new_list, sub = self._mutate_elements(new_list, path)
                return new_list, m + sub
            if strat == "duplicate":
                new_list, sub = self._mutate_elements(obj * 2, path)
                return new_list, [
                    Mutation(path, "array", "array_duplicate", f"len={len(obj)}", f"len={len(obj)*2}")
                ] + sub
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
                return self._apply_strategies(value, path, self._nullify_strategies, "null")
            return None, []
        if isinstance(value, bool):
            if self.config.booleans.enabled and self._maybe():
                return self._apply_strategies(value, path, self._bool_strategies, "bool")
            return value, []
        if isinstance(value, int) and not isinstance(value, bool):
            if self.config.integers.enabled and self._maybe():
                return self._apply_strategies(value, path, self._integer_strategies, "integer")
            return value, []
        if isinstance(value, float):
            if self.config.floats.enabled and self._maybe():
                return self._apply_strategies(value, path, self._float_strategies, "float")
            return value, []
        if isinstance(value, str):
            if self.config.strings.enabled and self._maybe():
                return self._mutate_string(value, path)
            return value, []
        if self.config.type_confusion.enabled and self._maybe():
            return self._type_confuse(value, path)
        return value, []

    def _mutate_string(self, value: str, path: str) -> tuple[str, list[Mutation]]:
        if not self._string_strategies:
            return value, []
        idx = self._rng.randrange(len(self._string_strategies))
        strategy, strat_name = self._string_strategies[idx]
        if not strategy.can_handle(value):
            return value, []
        try:
            mutated = strategy.apply(value, self._context)
        except Exception:
            return value, []
        return str(mutated), [
            Mutation(path, "string", f"str_{strat_name}", _truncate(value), _truncate(mutated))
        ]

    def _apply_strategies(
        self,
        value: Any,
        path: str,
        strategies: list[tuple[MutationStrategy, str]],
        type_label: str,
    ) -> tuple[Any, list[Mutation]]:
        if not strategies:
            return value, []
        idx = self._rng.randrange(len(strategies))
        strategy, strat_name = strategies[idx]
        if not strategy.can_handle(value):
            return value, []
        try:
            mutated = strategy.apply(value, self._context)
        except Exception:
            return value, []
        return mutated, [
            Mutation(path, type_label, strat_name, _truncate(value), _truncate(mutated))
        ]

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
