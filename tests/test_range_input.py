"""User-chosen discovery ranges stay inside the manifest: expanded when allowed, refused otherwise."""

from __future__ import annotations

import pytest

from mitigata.discovery import resolve_range

from .lab_sim import write_lab_manifest


def test_a_range_inside_the_manifest_scope_is_expanded_to_usable_hosts(tmp_path):
    manifest = write_lab_manifest(tmp_path / "scope.yaml")  # the simulator's scope is 127.0.0.1/32
    assert resolve_range(manifest, "127.0.0.1-1") == ["127.0.0.1"]


def test_a_range_outside_the_manifest_scope_is_refused(tmp_path):
    manifest = write_lab_manifest(tmp_path / "scope.yaml")
    with pytest.raises(ValueError, match="outside the manifest scope"):
        resolve_range(manifest, "10.9.9.0/30")


def test_the_range_size_is_capped_and_a_missing_manifest_is_refused(tmp_path):
    manifest = write_lab_manifest(tmp_path / "scope.yaml")
    with pytest.raises(ValueError, match="limit"):
        resolve_range(manifest, "127.0.0.1-1", limit=0)
    with pytest.raises(ValueError, match="no scope manifest"):
        resolve_range(None, "127.0.0.1-1")
