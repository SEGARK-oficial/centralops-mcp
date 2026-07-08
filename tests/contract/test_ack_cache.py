from __future__ import annotations

import time

import pytest

from centralops_mcp.ack_cache import ACK_TTL_SECONDS, AckCache, AckTokenError


def test_issue_and_consume_happy_path():
    cache = AckCache()
    rules = {"preprocess": [], "rules": [{"target": "x", "const": 1}]}
    token = cache.issue("def-1", rules)
    cache.consume(token, "def-1", rules)


def test_consume_unknown_token():
    cache = AckCache()
    with pytest.raises(AckTokenError, match="unknown"):
        cache.consume("nope", "def-1", {"rules": []})


def test_consume_with_wrong_definition():
    cache = AckCache()
    rules = {"rules": []}
    token = cache.issue("def-1", rules)
    with pytest.raises(AckTokenError, match="different definition_id"):
        cache.consume(token, "def-2", rules)


def test_consume_with_modified_rules():
    cache = AckCache()
    rules = {"rules": [{"target": "x", "const": 1}]}
    token = cache.issue("def-1", rules)
    with pytest.raises(AckTokenError, match="rules differ"):
        cache.consume(token, "def-1", {"rules": [{"target": "x", "const": 2}]})


def test_consume_is_single_use():
    cache = AckCache()
    rules = {"rules": []}
    token = cache.issue("def-1", rules)
    cache.consume(token, "def-1", rules)
    with pytest.raises(AckTokenError, match="unknown or already consumed"):
        cache.consume(token, "def-1", rules)


def test_expired_token(monkeypatch):
    cache = AckCache()
    rules = {"rules": []}

    real_monotonic = time.monotonic
    base = real_monotonic()
    fake = {"now": base}

    def fake_monotonic():
        return fake["now"]

    monkeypatch.setattr("centralops_mcp.ack_cache.time.monotonic", fake_monotonic)

    token = cache.issue("def-1", rules)
    fake["now"] = base + ACK_TTL_SECONDS + 1
    with pytest.raises(AckTokenError, match="expired"):
        cache.consume(token, "def-1", rules)
