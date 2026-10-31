from __future__ import annotations

import os

import pytest

from mitigata import policy
from mitigata.scope import compile_scope
from mitigata.tools.runner import Result

from .conftest import make_manifest


def test_ruleset_is_default_drop_with_exclusions_before_allows():
    text = policy.render_nftables(compile_scope(make_manifest()), control_ips=["10.255.255.2"])
    assert "policy drop;" in text
    assert "10.10.5.0/24" in text
    assert "10.10.5.1" in text
    # Exclusions must be dropped before the allow rule can match.
    assert text.index("@blocked_v4 drop") < text.index("@allowed_v4 accept")
    assert "@control_v4 accept" in text
    assert "10.255.255.2" in text


def test_ruleset_omits_ipv6_when_unauthorised():
    text = policy.render_nftables(compile_scope(make_manifest()))
    assert "allowed_v6" not in text
    assert "ip6 daddr @allowed_v6 accept" not in text


def test_ruleset_includes_ipv6_when_authorised():
    text = policy.render_nftables(compile_scope(make_manifest(ipv6=["fd00::/64"])))
    assert "allowed_v6" in text
    assert "fd00::/64" in text


def test_namespace_install_requires_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(policy.PolicyError, match="trusted root initializer"):
        policy.install_in_namespace(compile_scope(make_manifest()), "mitigata0")


def test_namespace_install_requires_tools(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(policy.shutil, "which", lambda _: None)
    with pytest.raises(policy.PolicyError, match="must be installed"):
        policy.install_in_namespace(compile_scope(make_manifest()), "mitigata0")


def _ok(*_args, **_kwargs):
    return Result(argv=("nft",), returncode=0, stdout="", stderr="", timed_out=False, duration_ms=1)


def test_namespace_install_surfaces_nft_failure(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(policy.shutil, "which", lambda _: "/usr/sbin/nft")
    monkeypatch.setattr(policy, "_namespace_prefix", lambda _namespace: ["ip", "netns", "exec", "mitigata0"])

    def fake_run(argv, **kwargs):
        if "-f" in argv:
            return Result(argv=tuple(argv), returncode=1, stdout="", stderr="syntax error", timed_out=False, duration_ms=1)
        return _ok()

    monkeypatch.setattr(policy, "run", fake_run)
    with pytest.raises(policy.PolicyError, match="syntax error"):
        policy.install_in_namespace(compile_scope(make_manifest()), "mitigata0")


def test_namespace_install_requires_verification(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(policy.shutil, "which", lambda _: "/usr/sbin/nft")
    monkeypatch.setattr(policy, "_namespace_prefix", lambda _namespace: ["ip", "netns", "exec", "mitigata0"])

    def fake_run(argv, **kwargs):
        if argv[:2] == ["ip", "netns"] and "list" in argv:
            return Result(argv=tuple(argv), returncode=1, stdout="", stderr="no table", timed_out=False, duration_ms=1)
        return _ok()

    monkeypatch.setattr(policy, "run", fake_run)
    with pytest.raises(policy.PolicyError, match="could not be verified"):
        policy.install_in_namespace(compile_scope(make_manifest()), "mitigata0")


def test_worker_command_drops_to_unprivileged_identity(monkeypatch):
    monkeypatch.setattr(policy, "_namespace_prefix", lambda _namespace: ["ip", "netns", "exec", "mitigata0"])
    monkeypatch.setattr(policy, "run", _ok)
    command = policy.worker_command(
        "mitigata0", compile_scope(make_manifest()), "mitigata.surfaces.network", ["--ip", "10.10.5.2"]
    )
    assert command[:4] == ["ip", "netns", "exec", "mitigata0"]
    assert "--reuid=65534" in command and "--no-new-privs" in command
    assert command[-2:] == ["--ip", "10.10.5.2"]
    assert "--reuid=0" not in command


def test_worker_command_refuses_unknown_module(monkeypatch):
    with pytest.raises(policy.PolicyError, match="unrecognized network worker"):
        policy.worker_command("mitigata0", compile_scope(make_manifest()), "mitigata.surfaces.binary", [])
