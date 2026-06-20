from __future__ import annotations

import base64
import gzip
import json
import os
import tempfile
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


def _make_compressed_har(body: dict, encoding: str = "gzip", extra_headers: list[dict] | None = None) -> Path:
    raw = json.dumps(body).encode()
    if encoding == "gzip":
        compressed = gzip.compress(raw)
    else:
        compressed = raw
    encoded = base64.b64encode(compressed).decode()
    headers = [
        {"name": "Content-Type", "value": "application/json"},
        {"name": "Content-Encoding", "value": encoding},
        {"name": "Transfer-Encoding", "value": "chunked"},
    ]
    if extra_headers:
        headers.extend(extra_headers)
    entry = {
        "request": {
            "method": "GET",
            "url": "http://example.com/api/data",
            "headers": [],
        },
        "response": {
            "status": 200,
            "headers": headers,
            "content": {
                "mimeType": "application/json",
                "text": encoded,
                "encoding": "base64",
            },
        },
    }
    har = {"log": {"entries": [entry]}}
    fd, path_str = tempfile.mkstemp(suffix=".har")
    os.close(fd)
    tmp = Path(path_str)
    tmp.write_text(json.dumps(har), encoding="utf-8")
    return tmp


def test_gzip_compressed_har_is_decompressed():
    payload = {"id": 42, "name": "hello", "tags": ["a", "b"]}
    path = _make_compressed_har(payload, encoding="gzip")
    try:
        exchanges = load_har(path)
        assert len(exchanges) == 1
        ex = exchanges[0]
        assert ex.response_body.startswith(b"{")
        parsed = json.loads(ex.response_body)
        assert parsed == payload
    finally:
        path.unlink()


def test_content_encoding_and_transfer_encoding_headers_removed():
    payload = {"ok": True}
    path = _make_compressed_har(payload, encoding="gzip")
    try:
        exchanges = load_har(path)
        ex = exchanges[0]
        header_names = {k.lower() for k in ex.response_headers}
        assert "content-encoding" not in header_names
        assert "transfer-encoding" not in header_names
        assert "content-type" in header_names
    finally:
        path.unlink()


def test_decompressed_json_body_can_be_mutated():
    payload = {"id": 1, "name": "alice", "active": True}
    path = _make_compressed_har(payload, encoding="gzip")
    try:
        exchanges = load_har(path)
        ex = exchanges[0]
        cfg = FuzzConfig(seed=7)
        cfg.mutation_probability = 1.0
        mutator = Mutator(cfg)
        applied = mutator.mutate(ex)
        assert applied.mutations
        parsed = json.loads(applied.body)
        assert isinstance(parsed, dict)
    finally:
        path.unlink()


def test_identity_encoding_passes_through():
    payload = {"x": 1}
    path = _make_compressed_har(payload, encoding="identity")
    try:
        exchanges = load_har(path)
        ex = exchanges[0]
        # body was not gzip'd, so base64 of raw JSON should decode directly
        parsed = json.loads(ex.response_body)
        assert parsed == payload
        header_names = {k.lower() for k in ex.response_headers}
        assert "content-encoding" not in header_names
    finally:
        path.unlink()


def test_server_response_omits_encoding_headers():
    from fuzzmock.server import _STRIPPED_RESPONSE_HEADERS

    assert "content-encoding" in _STRIPPED_RESPONSE_HEADERS
    assert "transfer-encoding" in _STRIPPED_RESPONSE_HEADERS
    assert "content-length" in _STRIPPED_RESPONSE_HEADERS


# ---- strategy registry / factory / custom strategies tests ----


def test_default_registry_has_all_builtin_strategies():
    from fuzzmock.strategies import default_registry

    registry = default_registry()
    for name in (
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
        "regex_replace",
        "wordlist",
        "int_replace",
        "int_range",
        "int_normal",
        "float_replace",
        "bool_flip",
        "null_replace",
        "drop_field",
    ):
        assert registry.has(name), f"missing built-in strategy {name}"


def test_strategy_factory_creates_parameterized_instance():
    from fuzzmock.strategies import StrategyContext, default_registry
    import random

    registry = default_registry()
    strat = registry.create("long_text", {"length": 17, "char": "Z"})
    ctx = StrategyContext(rng=random.Random(0), config=None)
    assert strat.apply("hello", ctx) == "Z" * 17


def test_regex_replace_strategy_applies_pattern():
    from fuzzmock.strategies import StrategyContext, default_registry
    import random

    registry = default_registry()
    strat = registry.create("regex_replace", {"pattern": r"\d", "replacement": "#"})
    ctx = StrategyContext(rng=random.Random(0), config=None)
    assert strat.apply("abc123", ctx) == "abc###"


def test_wordlist_strategy_picks_from_payloads():
    from fuzzmock.strategies import StrategyContext, default_registry
    import random

    registry = default_registry()
    words = ["alpha", "beta", "gamma"]
    strat = registry.create("wordlist", {"words": words})
    ctx = StrategyContext(rng=random.Random(0), config=None)
    for _ in range(20):
        assert strat.apply("anything", ctx) in words


def test_custom_strategy_from_config_payload_inline():
    from fuzzmock.config import load_config
    from fuzzmock.strategies import build_registry_from_config
    import tempfile, random
    from fuzzmock.strategies import StrategyContext

    yaml_text = (
        "custom_strategies:\n"
        "  - name: my_bad_string\n"
        "    payload: '<<<<>>>>'\n"
        "  - name: digits_to_x\n"
        "    regex:\n"
        "      pattern: '\\d'\n"
        "      replacement: 'X'\n"
        "  - name: some_users\n"
        "    wordlist: [admin, root, guest]\n"
        "strings:\n"
        "  strategies:\n"
        "    - my_bad_string\n"
        "    - digits_to_x\n"
        "    - some_users\n"
    )
    fd, p = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    Path(p).write_text(yaml_text, encoding="utf-8")
    try:
        cfg = load_config(p)
        registry = build_registry_from_config(cfg.custom_strategies)
        assert registry.has("my_bad_string")
        assert registry.has("digits_to_x")
        assert registry.has("some_users")
        ctx = StrategyContext(rng=random.Random(1), config=None)
        assert registry.create("my_bad_string").apply("x", ctx) == "<<<<>>>>"
        assert registry.create("digits_to_x").apply("a1b2", ctx) == "aXbX"
        chosen = registry.create("some_users").apply("x", ctx)
        assert chosen in ["admin", "root", "guest"]
    finally:
        Path(p).unlink()


def test_custom_strategy_via_python_module_import():
    from fuzzmock.strategies import (
        MutationStrategy,
        StrategyContext,
        build_registry_from_config,
    )
    import random, shutil, sys

    tmpdir = Path(tempfile.mkdtemp())
    mod_path = tmpdir / "my_strategies.py"
    mod_path.write_text(
        "from fuzzmock.strategies import MutationStrategy\n"
        "class Rot13(MutationStrategy):\n"
        "    name = 'rot13'\n"
        "    target_types = (str,)\n"
        "    def apply(self, value, context):\n"
        "        import codecs\n"
        "        return codecs.encode(str(value), 'rot_13')\n",
        encoding="utf-8",
    )
    sys.path.insert(0, str(tmpdir))
    try:
        if "my_strategies" in sys.modules:
            del sys.modules["my_strategies"]
        custom = [{"name": "rot13", "module": "my_strategies:Rot13"}]
        registry = build_registry_from_config(custom)
        assert registry.has("rot13")
        ctx = StrategyContext(rng=random.Random(0), config=None)
        assert registry.create("rot13").apply("hello", ctx) == "uryyb"
    finally:
        if "my_strategies" in sys.modules:
            del sys.modules["my_strategies"]
        sys.path.pop(0)
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


def test_mutator_uses_registered_custom_string_strategy():
    from fuzzmock.config import FuzzConfig, StrategyRef
    from fuzzmock.strategies import StrategyContext, StringMutationStrategy
    from fuzzmock.mutators import Mutator

    class FixedPayload(StringMutationStrategy):
        name = "fixed_pw"

        def apply(self, value, context):
            return "PAYLOAD"

    cfg = FuzzConfig(seed=0)
    cfg.strings.strategies = [StrategyRef(name="fixed_pw")]
    from fuzzmock.strategies import default_registry

    reg = default_registry()
    reg.register(FixedPayload)
    mutator = Mutator(cfg, registry=reg)
    ex = _json_exchange({"s": "original"})
    applied = mutator.mutate(ex)
    parsed = json.loads(applied.body)
    assert parsed["s"] == "PAYLOAD"
    assert any(m.strategy == "str_fixed_pw" for m in applied.mutations)


def test_strategy_ref_parse_string_and_dict():
    from fuzzmock.config import StrategyRef

    a = StrategyRef.parse("empty")
    assert a.name == "empty"
    assert a.params == {}
    b = StrategyRef.parse({"name": "long_text", "length": 42})
    assert b.name == "long_text"
    assert b.params == {"length": 42}
