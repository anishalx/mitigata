"""Fail-closed scope compilation (design §1.2, §3.1, §6).

A manifest either compiles into an explicit allowlist or the run is refused.
Nothing here sends traffic; this module only decides what would be permitted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass

from .models import ScopeManifest

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

IN_SCOPE = "in_scope"
EXCLUDED = "excluded"
OUT_OF_SCOPE = "out_of_scope"
UNRESOLVED = "unresolved_domain"


class ScopeError(RuntimeError):
    """The manifest cannot be compiled into a safe allowlist."""


def _parse_networks(entries: list[str], version: int | None, field: str) -> list[IPNetwork]:
    parsed: list[IPNetwork] = []
    for entry in entries:
        try:
            # strict=True on purpose: silently masking host bits would widen scope.
            network = ipaddress.ip_network(entry, strict=field != "exclude")
        except ValueError as exc:
            raise ScopeError(f"{field}: {entry!r} is not a valid network: {exc}") from exc
        if version is not None and network.version != version:
            raise ScopeError(f"{field}: {entry!r} is not IPv{version}")
        parsed.append(network)
    return parsed


def _contains(networks: tuple[IPNetwork, ...], address: IPAddress) -> bool:
    return any(address.version == net.version and address in net for net in networks)


@dataclass(frozen=True)
class CompiledScope:
    """Immutable compiled scope: the only authority on what may be contacted."""

    allowlist: tuple[IPNetwork, ...]
    exclude: tuple[IPNetwork, ...]
    allow_public: bool
    dns_resolver: str | None
    domains: tuple[str, ...]
    block_ipv6: bool
    scope_hash: str

    def is_excluded(self, address: IPAddress) -> bool:
        return any(address.version == net.version and address in net for net in self.exclude)

    def contains(self, address: IPAddress) -> bool:
        return _contains(self.allowlist, address) and not self.is_excluded(address)

    def classify(self, literal: str) -> str:
        """Classify a literal before any use (§3.4 binary endpoint fan-out).

        Hostnames are only in scope when explicitly listed; unresolved names are
        never probed and are stored as ``out_of_scope_literal``.
        """
        try:
            address = ipaddress.ip_address(literal)
        except ValueError:
            return IN_SCOPE if literal.lower() in self.domains else UNRESOLVED
        if self.is_excluded(address):
            return EXCLUDED
        return IN_SCOPE if self.contains(address) else OUT_OF_SCOPE

    def canonical(self) -> dict:
        return {
            "v": 1,
            "allowlist": sorted(str(net) for net in self.allowlist),
            "exclude": sorted(str(net) for net in self.exclude),
            "allow_public": self.allow_public,
            "dns_resolver": self.dns_resolver,
            "domains": sorted(self.domains),
            "block_ipv6": self.block_ipv6,
        }


def compile_scope(manifest: ScopeManifest) -> CompiledScope:
    section = manifest.scope
    allowlist = tuple(_parse_networks(section.ipv4, 4, "scope.ipv4") + _parse_networks(section.ipv6, 6, "scope.ipv6"))
    exclude = tuple(_parse_networks(section.exclude, None, "scope.exclude"))

    if not allowlist and not section.domains:
        raise ScopeError("scope authorises no IPv4/IPv6 ranges")
    if section.domains and not allowlist:
        raise ScopeError("domain-only scope is unsupported in v1; add authorised CIDRs")

    if not section.allow_public:
        public = [net for net in allowlist if not net.is_private]
        if public:
            raise ScopeError(
                f"{public[0]} is not a private range; set scope.allow_public: true only with explicit RoE"
            )

    for net in exclude:
        if not any(net.version == allowed.version and net.subnet_of(allowed) for allowed in allowlist):
            raise ScopeError(f"exclusion {net} lies outside the authorised ranges; refusing to guess intent")

    resolver = section.dns_resolver
    if resolver is not None:
        try:
            resolver_ip = ipaddress.ip_address(resolver)
        except ValueError as exc:
            raise ScopeError(f"scope.dns_resolver must be an IP address: {resolver!r}") from exc
        if not _contains(allowlist, resolver_ip):
            raise ScopeError(f"scope.dns_resolver {resolver} is outside the authorised ranges")
        if any(resolver_ip.version == net.version and resolver_ip in net for net in exclude):
            raise ScopeError(f"scope.dns_resolver {resolver} is excluded")
    elif section.domains:
        raise ScopeError("scope.domains require a pinned dns_resolver inside scope")

    block_ipv6 = not section.ipv6
    canonical = {
        "v": 1,
        "allowlist": sorted(str(net) for net in allowlist),
        "exclude": sorted(str(net) for net in exclude),
        "allow_public": section.allow_public,
        "dns_resolver": resolver,
        "domains": sorted(domain.lower() for domain in section.domains),
        "block_ipv6": block_ipv6,
    }
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    return CompiledScope(
        allowlist=allowlist,
        exclude=exclude,
        allow_public=section.allow_public,
        dns_resolver=resolver,
        domains=tuple(sorted(domain.lower() for domain in section.domains)),
        block_ipv6=block_ipv6,
        scope_hash=digest,
    )
