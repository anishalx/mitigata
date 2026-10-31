from __future__ import annotations

import ipaddress

import pytest

from mitigata.scope import (
    EXCLUDED,
    IN_SCOPE,
    OUT_OF_SCOPE,
    UNRESOLVED,
    ScopeError,
    compile_scope,
)

from .conftest import make_manifest


def test_allowlist_and_exclusions_are_enforced():
    scope = compile_scope(make_manifest())
    assert scope.contains(ipaddress.ip_address("10.10.5.10"))
    assert not scope.contains(ipaddress.ip_address("10.10.5.1"))  # gateway excluded
    assert not scope.contains(ipaddress.ip_address("10.10.5.255"))  # broadcast excluded
    assert not scope.contains(ipaddress.ip_address("10.10.6.10"))


def test_classify_distinguishes_in_scope_excluded_and_foreign():
    scope = compile_scope(make_manifest())
    assert scope.classify("10.10.5.42") == IN_SCOPE
    assert scope.classify("10.10.5.1") == EXCLUDED
    assert scope.classify("8.8.8.8") == OUT_OF_SCOPE
    # Hardcoded hostnames from a binary are never probed unless explicitly scoped.
    assert scope.classify("db.lab.local") == UNRESOLVED


def test_scoped_domain_classifies_in_scope():
    scope = compile_scope(make_manifest(domains=["app.lab.local"]))
    assert scope.classify("APP.lab.local") == IN_SCOPE
    assert scope.classify("other.lab.local") == UNRESOLVED


def test_exclusion_outside_allowlist_is_refused():
    with pytest.raises(ScopeError, match="outside the authorised ranges"):
        compile_scope(make_manifest(exclude=["10.10.9.9"]))


def test_public_range_requires_explicit_authorisation():
    with pytest.raises(ScopeError, match="allow_public"):
        compile_scope(make_manifest(ipv4=["93.184.216.0/24"], exclude=[], dns_resolver=None))
    scope = compile_scope(
        make_manifest(ipv4=["93.184.216.0/24"], exclude=[], dns_resolver=None, allow_public=True)
    )
    assert scope.contains(ipaddress.ip_address("93.184.216.34"))


def test_host_bits_in_cidr_are_refused_not_masked():
    with pytest.raises(ScopeError, match="not a valid network"):
        compile_scope(make_manifest(ipv4=["10.10.5.7/24"]))


def test_invalid_and_mismatched_families_are_refused():
    with pytest.raises(ScopeError):
        compile_scope(make_manifest(ipv4=["10.10.5.0/33"]))
    with pytest.raises(ScopeError, match="not IPv4"):
        compile_scope(make_manifest(ipv4=["fd00::/64"]))


def test_domain_only_scope_is_unsupported():
    with pytest.raises(ScopeError, match="domain-only"):
        compile_scope(make_manifest(ipv4=[], exclude=[], domains=["app.lab.local"]))


def test_empty_scope_is_refused():
    with pytest.raises(ScopeError, match="no IPv4/IPv6 ranges"):
        compile_scope(make_manifest(ipv4=[], exclude=[]))


def test_dns_resolver_must_be_inside_scope_and_not_excluded():
    with pytest.raises(ScopeError, match="outside the authorised ranges"):
        compile_scope(make_manifest(dns_resolver="8.8.8.8"))
    with pytest.raises(ScopeError, match="is excluded"):
        compile_scope(make_manifest(dns_resolver="10.10.5.1"))
    with pytest.raises(ScopeError, match="dns_resolver"):
        compile_scope(make_manifest(domains=["app.lab.local"], dns_resolver=None))


def test_ipv6_blocked_when_not_authorised():
    scope = compile_scope(make_manifest())
    assert scope.block_ipv6 is True
    scope6 = compile_scope(make_manifest(ipv6=["fd00::/64"]))
    assert scope6.block_ipv6 is False
    assert scope6.contains(ipaddress.ip_address("fd00::1"))


def test_scope_hash_is_stable_and_sensitive():
    first = compile_scope(make_manifest())
    second = compile_scope(make_manifest())
    assert first.scope_hash == second.scope_hash
    assert len(first.scope_hash) == 64
    widened = compile_scope(make_manifest(ipv4=["10.10.5.0/24", "10.10.6.0/24"]))
    assert widened.scope_hash != first.scope_hash
