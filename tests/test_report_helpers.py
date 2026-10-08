"""Lightweight tests for the safe web VAPT report primitives."""

from web_vapt import jwt_decode, norm


def test_norm_adds_scheme():
    assert norm("example.com") == "https://example.com"


def test_norm_preserves_https():
    assert norm("https://example.com/") == "https://example.com"


def test_invalid_url():
    try:
        norm("https:///")
    except ValueError:
        return
    raise AssertionError("Expected ValueError")


def test_jwt_decode():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
    decoded = jwt_decode(token)
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["payload"]["sub"] == "123"
