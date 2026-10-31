"""Manifest loading (design §1.2: fail fast on missing authorization)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import ValidationError

from .models import ScopeManifest


class ConfigError(RuntimeError):
    """The scope manifest is missing, unreadable or schema-invalid."""


def load_manifest(path: str | Path) -> tuple[ScopeManifest, bytes]:
    manifest_path = Path(path)
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read scope manifest {manifest_path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"scope manifest is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("scope manifest must be a YAML mapping")
    try:
        manifest = ScopeManifest.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"scope manifest is invalid:\n{exc}") from exc
    return manifest, raw


def manifest_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
