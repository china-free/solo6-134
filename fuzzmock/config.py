from __future__ import annotations

import math
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass
class StrategyRef:
    name: str
    params: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def parse(raw: Any) -> "StrategyRef":
        if isinstance(raw, str):
            return StrategyRef(name=raw)
        if isinstance(raw, dict):
            if "name" not in raw:
                raise ValueError(f"strategy ref dict missing 'name': {raw}")
            params = {k: v for k, v in raw.items() if k != "name"}
            return StrategyRef(name=raw["name"], params=params)
        raise TypeError(f"unsupported strategy reference: {raw!r}")


@dataclass
class IntegerRules:
    enabled: bool = True
    replacements: list[int] = field(
        default_factory=lambda: [0, -1, 2147483647, -2147483648, 4294967295, 999999999]
    )
    strategies: list[StrategyRef] = field(
        default_factory=lambda: [StrategyRef(name="int_replace")]
    )


@dataclass
class FloatRules:
    enabled: bool = True
    replacements: list[float] = field(
        default_factory=lambda: [0.0, -1.0, math.inf, -math.inf, math.nan, 1e308, -1e308]
    )
    strategies: list[StrategyRef] = field(
        default_factory=lambda: [StrategyRef(name="float_replace")]
    )


@dataclass
class StringRules:
    enabled: bool = True
    strategies: list[StrategyRef] = field(
        default_factory=lambda: [
            StrategyRef(name="empty"),
            StrategyRef(name="long_text"),
            StrategyRef(name="special_chars"),
            StrategyRef(name="unicode"),
            StrategyRef(name="format_string"),
            StrategyRef(name="sql_injection"),
            StrategyRef(name="null_bytes"),
            StrategyRef(name="control_chars"),
            StrategyRef(name="overflow_num"),
            StrategyRef(name="xss"),
        ]
    )
    long_text_length: int = 100000


@dataclass
class BoolRules:
    enabled: bool = True
    strategies: list[StrategyRef] = field(
        default_factory=lambda: [StrategyRef(name="bool_flip")]
    )


@dataclass
class DropFieldsRules:
    enabled: bool = True
    probability: float = 0.3
    strategy: StrategyRef = field(default_factory=lambda: StrategyRef(name="drop_field"))


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
    strategies: list[StrategyRef] = field(
        default_factory=lambda: [StrategyRef(name="null_replace")]
    )


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
    custom_strategies: list[dict[str, Any]] = field(default_factory=list)


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


def _coerce_strategies(data: dict[str, Any], key: str) -> list[StrategyRef]:
    raw = data.get(key)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise TypeError(f"{key} must be a list of strategy refs, got {type(raw).__name__}")
    return [StrategyRef.parse(item) for item in raw]


def _build_dataclass(cls, data: dict[str, Any] | None):
    if not data:
        return cls()
    valid = {f.name for f in fields(cls)}
    filtered: dict[str, Any] = {}
    for k, v in data.items():
        if k not in valid:
            continue
        if k == "strategies" and cls in (
            IntegerRules,
            FloatRules,
            StringRules,
            BoolRules,
            NullifyRules,
        ):
            filtered[k] = _coerce_strategies(data, k)
            continue
        if k == "strategy" and cls is DropFieldsRules:
            filtered[k] = StrategyRef.parse(v)
            continue
        filtered[k] = v
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
    if "custom_strategies" in raw:
        cs = raw["custom_strategies"]
        if isinstance(cs, list):
            config.custom_strategies = [dict(item) for item in cs if isinstance(item, dict)]
    return config
