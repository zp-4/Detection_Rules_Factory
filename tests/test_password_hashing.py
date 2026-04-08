"""Tests for PBKDF2 password hashing."""
import pytest

from utils.password_hashing import hash_password, verify_password


def test_verify_round_trip():
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h)
    assert not verify_password("wrong", h)


def test_verify_rejects_empty():
    assert not verify_password("", "anything")
    assert not verify_password("x", "")


def test_verify_rejects_garbage():
    assert not verify_password("x", "not-a-valid-hash")
    assert not verify_password("x", "pbkdf2_sha256$bad")
