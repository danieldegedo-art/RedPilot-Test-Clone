"""Regression tests for app.testing.url_utils.target_identity_key.

This function is what makes the cognitive architecture's persistent
storage (PersistentMemoryStore, CoverageMapper) key by TARGET rather than
by RUN -- see app/testing/runner.py's use of it. Get this wrong and
"cross-session knowledge accumulation" silently stops working again.
"""
from __future__ import annotations

from app.testing.url_utils import target_identity_key


def test_same_host_same_key_regardless_of_scheme():
    a = target_identity_key("https://staging.acme.com/checkout")
    b = target_identity_key("http://staging.acme.com/")
    assert a == b


def test_same_host_same_key_regardless_of_case():
    a = target_identity_key("https://Staging.ACME.com")
    b = target_identity_key("https://staging.acme.com")
    assert a == b


def test_same_host_same_key_regardless_of_path_or_query():
    a = target_identity_key("https://staging.acme.com/api/v1/payments?x=1")
    b = target_identity_key("https://staging.acme.com/entirely/different/path")
    assert a == b


def test_different_hosts_produce_different_keys():
    a = target_identity_key("https://staging.acme.com")
    b = target_identity_key("https://other-target.example.com")
    assert a != b


def test_different_ports_produce_different_keys():
    a = target_identity_key("https://staging.acme.com:8080")
    b = target_identity_key("https://staging.acme.com:9090")
    assert a != b


def test_key_is_filesystem_safe():
    key = target_identity_key("https://staging.acme-payments.com:8080/x?y=1")
    assert all(c.isalnum() or c in "-_." for c in key)
    assert "/" not in key
    assert " " not in key


def test_key_is_stable_across_calls():
    """Same input, called twice, must give the same output -- this is
    the whole point: a second run against the same target must land on
    the same storage path as the first."""
    url = "https://staging.acme.com/api/v1/payments/1"
    assert target_identity_key(url) == target_identity_key(url)
