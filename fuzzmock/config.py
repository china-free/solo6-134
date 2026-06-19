from __future__ import annotations

import math
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass
class IntegerRules:
    enabled: bool = True
    replacements: list[int] = field(
        default_factory=lambda: [0, -1, 2147483647, -2147483648, 4294967295, 999999999]
    )


@dataclass
class FloatRules:
    enabled: bool = True
    replacements: list[float] = field(
        default_factory=lambda: [0.0, -1.0, math.inf, -math.inf, math.nan, 1e308, -1e308]
    )


@dataclass
class StringRules:
    enabled: bool = True
    strategies: list[str] = field(
        default_factory=lambda: [
            "empty",
            "long_text",
            "special_chars",
            "unicode",
            "format_string",
            "sql_injection",
            "null_bytes",
            "control_chars",
            "overflow_num",
            "xss",
        ]
    )
    long_text_length: int = 100000


@dataclass
class BoolRules:
    enabled: bool = True


@dataclass
class DropFieldsRules:
    enabled: bool = True
    probability: float = 0.3


@dataclass
class ArrayRules:
    enabled: bool = True
    strategies: list[str] = field(
        default_factory=lambda: ["empty", "duplicate", "huge", "null_element"]
    )
    huge_size: int = 1000


@dataclass
class NullifyRules:
    enabled: bool = True
    probability: float = 0.2


@dataclass
class TypeConfusionRules:
    enabled: bool = False


@dataclass
class FuzzConfig:
    integers: IntegerRules = field(default_factory=IntegerRules)
    floats: FloatRules = field(default_factory=FloatRules)
    strings: StringRules = field(default_factory=StringRules)
    booleans: BoolRules = field(default_factory=BoolRules)
    drop_fields: DropFieldsRules = field(default_factory=DropFieldsRules)
    arrays: ArrayRules = field(default_factory=ArrayRules)
    nullify: NullifyRules = field(default_factory=NullifyRules)
    type_confusion: TypeConfusionRules = field(default_factory=TypeConfusionRules)
    mutation_probability: float = 1.0
    seed: int | None = None


_RULE_DATACLASSES = {
    "integers": IntegerRules,
    "floats": FloatRules,
    "strings": StringRules,
    "booleans": BoolRules,
    "drop_fields": DropFieldsRules,
    "arrays": ArrayRules,
    "nullify": NullifyRules,
    "type_confusion": TypeConfusionRules,
}


def _build_dataclass(cls, data: dict[str, Any] | None):
    if not data:
        return cls()
    valid = {f.name for f in fields(cls)}
    filtered = {k: v for k, v in data.items() if k in valid}
    return cls(**filtered)


def load_config(path: str | Path | None) -> FuzzConfig:
    config = FuzzConfig()
    if not path:
        return config
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("fuzz rules YAML must be a mapping at the top level")
    for key, cls in _RULE_DATACLASSES.items():
        setattr(config, key, _build_dataclass(cls, raw.get(key)))
    for key in ("mutation_probability", "seed"):
        if key in raw:
            setattr(config, key, raw[key])
    return config
