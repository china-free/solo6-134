from __future__ import annotations

import importlib
import math
import random
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


@dataclass
class StrategyContext:
    rng: random.Random
    config: Any


class MutationStrategy(ABC):
    name: str = ""
    target_types: tuple[type, ...] = ()

    def __init__(self, params: dict[str, Any] | None = None) -> None:
        self.params = params or {}

    @abstractmethod
    def apply(self, value: Any, context: StrategyContext) -> Any: ...

    def can_handle(self, value: Any) -> bool:
        if not self.target_types:
            return True
        return isinstance(value, self.target_types)


class StringMutationStrategy(MutationStrategy):
    target_types = (str,)


class IntegerMutationStrategy(MutationStrategy):
    target_types = (int,)

    def can_handle(self, value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)


class FloatMutationStrategy(MutationStrategy):
    target_types = (float,)


class BoolMutationStrategy(MutationStrategy):
    target_types = (bool,)


class EmptyString(StringMutationStrategy):
    name = "empty"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        return ""


class LongText(StringMutationStrategy):
    name = "long_text"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        length = int(self.params.get("length", 100000))
        char = str(self.params.get("char", "A"))
        return char * length


class SpecialChars(StringMutationStrategy):
    name = "special_chars"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        return str(
            self.params.get(
                "payload",
                "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./`~",
            )
        )


class UnicodeString(StringMutationStrategy):
    name = "unicode"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        return str(
            self.params.get(
                "payload",
                "\u00e9\u4e2d\u6587\U0001f600\U0001f4a9\u00c5\u00e6\u0153\u2211\u221e",
            )
        )


class FormatString(StringMutationStrategy):
    name = "format_string"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        return str(self.params.get("payload", "%n%n%n%s%s%s%d%d%d{x}{x}"))


class SqlInjection(StringMutationStrategy):
    name = "sql_injection"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        payloads: list[str] = self.params.get(
            "payloads",
            [
                "' OR '1'='1' -- ",
                "'; DROP TABLE users; -- ",
                "' UNION SELECT NULL,NULL,NULL -- ",
            ],
        )
        return context.rng.choice(payloads)


class NullBytes(StringMutationStrategy):
    name = "null_bytes"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        return str(self.params.get("payload", "foo\x00bar\x00baz\x00"))


class ControlChars(StringMutationStrategy):
    name = "control_chars"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        return str(self.params.get("payload", "".join(chr(c) for c in range(1, 32))))


class OverflowNum(StringMutationStrategy):
    name = "overflow_num"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        length = int(self.params.get("length", 40))
        digit = str(self.params.get("digit", "9"))
        return digit * length


class XssPayload(StringMutationStrategy):
    name = "xss"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        payloads: list[str] = self.params.get(
            "payloads",
            [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><svg onload=alert(1)>",
            ],
        )
        return context.rng.choice(payloads)


class RegexReplace(StringMutationStrategy):
    name = "regex_replace"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        pattern = str(self.params.get("pattern", "."))
        replacement = str(self.params.get("replacement", "X"))
        count = int(self.params.get("count", 0))
        return re.sub(pattern, replacement, str(value), count=count)


class PayloadFromWordlist(StringMutationStrategy):
    name = "wordlist"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        wordlist: list[str] | None = self.params.get("words")
        if not wordlist:
            path = self.params.get("path")
            if path:
                text = Path(path).read_text(encoding="utf-8", errors="replace")
                wordlist = [line.strip() for line in text.splitlines() if line.strip()]
        if not wordlist:
            return value
        return context.rng.choice(wordlist)


class IntegerReplace(IntegerMutationStrategy):
    name = "int_replace"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        replacements: list[int] = self.params.get(
            "values", [0, -1, 2147483647, -2147483648, 4294967295, 999999999]
        )
        return context.rng.choice(replacements)


class IntegerRandomRange(IntegerMutationStrategy):
    name = "int_range"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        lo = int(self.params.get("min", -(2**31)))
        hi = int(self.params.get("max", 2**31 - 1))
        return context.rng.randint(lo, hi)


class IntegerNormalDistribution(IntegerMutationStrategy):
    name = "int_normal"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        mu = float(self.params.get("mu", float(value) if isinstance(value, (int, float)) else 0))
        sigma = float(self.params.get("sigma", 100))
        return int(round(context.rng.gauss(mu, sigma)))


class FloatReplace(FloatMutationStrategy):
    name = "float_replace"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        replacements: list[float] = self.params.get(
            "values",
            [0.0, -1.0, math.inf, -math.inf, math.nan, 1e308, -1e308],
        )
        return context.rng.choice(replacements)


class BoolFlip(BoolMutationStrategy):
    name = "bool_flip"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        return not bool(value)


class NullReplace(MutationStrategy):
    name = "null_replace"
    target_types = (type(None),)

    def apply(self, value: Any, context: StrategyContext) -> Any:
        candidates: list[Any] = self.params.get("values", ["null", 0, "", False, []])
        return context.rng.choice(candidates)


class DropField(MutationStrategy):
    name = "drop_field"

    def apply(self, value: Any, context: StrategyContext) -> Any:
        return None

    def can_handle(self, value: Any) -> bool:
        return not isinstance(value, (dict, list))


_BUILTIN_STRATEGIES: list[type[MutationStrategy]] = [
    EmptyString,
    LongText,
    SpecialChars,
    UnicodeString,
    FormatString,
    SqlInjection,
    NullBytes,
    ControlChars,
    OverflowNum,
    XssPayload,
    RegexReplace,
    PayloadFromWordlist,
    IntegerReplace,
    IntegerRandomRange,
    IntegerNormalDistribution,
    FloatReplace,
    BoolFlip,
    NullReplace,
    DropField,
]


@dataclass
class StrategyRegistry:
    strategies: dict[str, type[MutationStrategy]] = field(default_factory=dict)
    default_params: dict[str, dict[str, Any]] = field(default_factory=dict)

    def register(
        self, cls: type[MutationStrategy], default_params: dict[str, Any] | None = None
    ) -> type[MutationStrategy]:
        if not cls.name:
            raise ValueError(f"strategy class {cls.__name__} has empty 'name'")
        self.strategies[cls.name] = cls
        if default_params:
            self.default_params[cls.name] = dict(default_params)
        return cls

    def has(self, name: str) -> bool:
        return name in self.strategies

    def create(self, name: str, params: dict[str, Any] | None = None) -> MutationStrategy:
        cls = self.strategies.get(name)
        if cls is None:
            raise KeyError(f"unknown mutation strategy: {name}")
        merged: dict[str, Any] = dict(self.default_params.get(name, {}))
        if params:
            merged.update(params)
        return cls(params=merged)


def default_registry() -> StrategyRegistry:
    registry = StrategyRegistry()
    for cls in _BUILTIN_STRATEGIES:
        registry.register(cls)
    return registry


def _import_class(spec: str) -> type[MutationStrategy]:
    module_path, class_name = spec.rsplit(":", 1)
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    if not (isinstance(cls, type) and issubclass(cls, MutationStrategy)):
        raise TypeError(f"{spec} is not a MutationStrategy subclass")
    return cls


def build_registry_from_config(custom: list[dict[str, Any]] | None) -> StrategyRegistry:
    registry = default_registry()
    for entry in custom or []:
        module_spec = entry.get("module") or entry.get("class")
        if module_spec and ":" in str(module_spec):
            cls = _import_class(str(module_spec))
            params = {k: v for k, v in entry.items() if k not in ("name", "module", "class", "type")}
            registry.register(cls, default_params=params or None)
            continue
        payload = entry.get("payload")
        regex_cfg = entry.get("regex")
        wordlist = entry.get("wordlist")
        name = entry.get("name")
        if not name:
            raise ValueError(f"custom strategy entry is missing 'name': {entry}")
        params = {k: v for k, v in entry.items() if k not in ("name", "module", "class", "type")}
        if payload is not None:
            params.setdefault("payload", payload)
        if regex_cfg and isinstance(regex_cfg, dict):
            params.update(regex_cfg)
            registry.register(
                _make_string_strategy_class(name, RegexReplace), default_params=params
            )
            continue
        if wordlist:
            params["words"] = wordlist
            registry.register(
                _make_string_strategy_class(name, PayloadFromWordlist), default_params=params
            )
            continue
        registry.register(
            _make_string_strategy_class(name, SpecialChars), default_params=params
        )
    return registry


def _make_string_strategy_class(
    name: str, base: type[StringMutationStrategy]
) -> type[StringMutationStrategy]:
    return type(
        f"Custom_{base.__name__}_{name}",
        (base,),
        {"name": name},
    )
