from __future__ import annotations

import pytest
from pydantic import ValidationError

from mitigata.models import ScopeManifest

from .conftest import manifest_dict


def test_destructive_limits_are_rejected():
    data = manifest_dict()
    data["limits"] = {"destructive": True}
    with pytest.raises(ValidationError, match="destructive"):
        ScopeManifest.model_validate(data)


def test_window_must_be_iso_and_ordered():
    data = manifest_dict()
    data["engagement"]["window"] = "2027-01-01T00:00:00Z/2026-01-01T00:00:00Z"
    with pytest.raises(ValidationError, match="window end must be after start"):
        ScopeManifest.model_validate(data)
    data["engagement"]["window"] = "not-a-window"
    with pytest.raises(ValidationError):
        ScopeManifest.model_validate(data)


def test_window_requires_timezone_on_both_endpoints():
    data = manifest_dict()
    data["engagement"]["window"] = "2026-01-01T00:00:00/2035-01-01T00:00:00Z"
    with pytest.raises(ValidationError, match="timezone offset"):
        ScopeManifest.model_validate(data)


def test_wildcard_domains_rejected():
    data = manifest_dict()
    data["scope"]["domains"] = ["*.lab.local"]
    with pytest.raises(ValidationError, match="wildcard"):
        ScopeManifest.model_validate(data)


def test_flag_patterns_must_compile():
    data = manifest_dict()
    data["flags"]["patterns"] = ["flag{([a-z]+}"]
    with pytest.raises(ValidationError, match="invalid flag pattern"):
        ScopeManifest.model_validate(data)


def test_unknown_manifest_keys_are_rejected():
    data = manifest_dict()
    data["scope"]["allow_all"] = True
    with pytest.raises(ValidationError):
        ScopeManifest.model_validate(data)
