from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs

from fuzzmock.config import FuzzConfig, load_config
from fuzzmock.har_loader import load_har
from fuzzmock.models import HttpExchange
from fuzzmock.mutators import Mutator

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _json_exchange(payload: dict) -> HttpExchange:
    return HttpExchange(
        method="GET",
        url="http://x/test",
        path="/test",
        query={},
        request_headers={},
        request_body=None,
        status=200,
        response_headers={},
        response_body=json.dumps(payload).encode(),
        content_type="application/json",
    )


def test_har_loader_parses_exchanges():
    exchanges = load_har(EXAMPLES / "sample.har")
    assert len(exchanges) == 3
    paths = {ex.path for ex in exchanges}
    assert paths == {"/users/1", "/login", "/health.txt"}
    assert exchanges[0].method == "GET"
    assert exchanges[1].method == "POST"
    assert exchanges[1].request_body == b"username=alice&password=secret"


def test_json_mutation_stays_valid_json():
    mutator = Mutator(FuzzConfig(seed=1))
    applied = mutator.mutate(_json_exchange({"id": 1, "name": "x", "tags": ["a", "b"]}))
    parsed = json.loads(applied.body)
    assert isinstance(parsed, dict)
    assert applied.mutations


def test_integer_replacement_uses_configured_values():
    cfg = FuzzConfig(seed=3)
    cfg.integers.replacements = [777]
    mutator = Mutator(cfg)
    found = False
    for _ in range(20):
        applied = mutator.mutate(_json_exchange({"n": 1}))
        parsed = json.loads(applied.body)
        if parsed.get("n") == 777:
            found = True
            break
    assert found, "integer should eventually be replaced with configured value"


def test_drop_fields_removes_keys():
    cfg = FuzzConfig(seed=5)
    cfg.drop_fields.enabled = True
    cfg.drop_fields.probability = 1.0
    cfg.mutation_probability = 0.0
    mutator = Mutator(cfg)
    applied = mutator.mutate(_json_exchange({"a": 1, "b": 2, "c": 3}))
    parsed = json.loads(applied.body)
    assert parsed == {} or len(parsed) < 3
    assert any(m.strategy == "drop_field" for m in applied.mutations)


def test_no_mutation_passes_through():
    cfg = FuzzConfig(seed=2)
    for rule in ("integers", "floats", "strings", "booleans", "drop_fields", "arrays", "nullify", "type_confusion"):
        getattr(cfg, rule).enabled = False
    mutator = Mutator(cfg)
    payload = {"id": 1, "name": "x", "active": True}
    applied = mutator.mutate(_json_exchange(payload))
    assert json.loads(applied.body) == payload
    assert applied.mutations == []


def test_form_mutation_produces_valid_form_body():
    exchange = HttpExchange(
        method="POST",
        url="http://x/login",
        path="/login",
        query={},
        request_headers={},
        request_body=b"username=alice&password=secret",
        status=200,
        response_headers={},
        response_body=b"token=abc&expires=3600",
        content_type="application/x-www-form-urlencoded",
    )
    mutator = Mutator(FuzzConfig(seed=4))
    applied = mutator.mutate(exchange)
    parsed = parse_qs(applied.body.decode(), keep_blank_values=True)
    assert set(parsed.keys()) == {"token", "expires"}
    assert applied.mutations


def test_yaml_rules_load_and_apply():
    cfg = load_config(EXAMPLES / "fuzz_rules.yaml")
    assert cfg.seed == 42
    assert cfg.strings.long_text_length == 100000
    mutator = Mutator(cfg)
    applied = mutator.mutate(_json_exchange({"id": 1, "name": "alice"}))
    assert applied.mutations
