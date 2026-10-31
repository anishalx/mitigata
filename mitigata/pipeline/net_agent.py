"""Network agent: passive service identification and non-HTTP service leads.

The probe order is deliberately gentle. It connects and reads whatever the
service volunteers (its banner) for at most ``timeout`` seconds before sending
anything. Only a service that stays silent receives a single HTTP GET, which is
how plain web services are recognised. Services that speak first, such as a
passkey-gated protocol, are never sent HTTP or protocol input during
identification.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from typing import Any

from .guard import ScopeGuard
from .web_agent import banner_safe, request


@dataclass(frozen=True)
class Probe:
    kind: str  # banner | http | silent | error
    tls: bool = False
    status: int = 0
    banner: str = ""
    detail: str = ""


def passive_banner(ip: str, port: int, *, guard: ScopeGuard, timeout: float = 1.5, max_bytes: int = 1024) -> bytes:
    """Connect and read one volunteered chunk; sends nothing to the service."""
    guard.require(ip, port=port, purpose="banner read")
    guard.pace(ip)
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        try:
            return sock.recv(max_bytes)
        except socket.timeout:
            return b""


def probe_service(
    ip: str, port: int, *, guard: ScopeGuard, tls_hint: bool = False, timeout: float = 4.0,
) -> Probe:
    try:
        raw = passive_banner(ip, port, guard=guard)
    except OSError as exc:
        return Probe(kind="error", detail=type(exc).__name__)
    if raw:
        return Probe(kind="banner", banner=banner_safe(raw.decode("latin-1")))
    for tls in ([True, False] if tls_hint else [False]):
        try:
            response = request(ip, port, tls=tls, method="GET", target="/", guard=guard,
                               timeout=timeout, purpose="service probe")
        except (OSError, http.client.HTTPException, ValueError, ssl.SSLError):
            continue
        return Probe(kind="http", tls=tls, status=response.status)
    return Probe(kind="silent")


def banner_leads(probe: Probe) -> list[dict[str, Any]]:
    """Turn a pre-authentication banner into unverified candidate leads (no secret values)."""
    if probe.kind != "banner":
        return []
    text = probe.banner
    upper, lower = text.upper(), text.lower()
    leads: list[dict[str, Any]] = []
    if "AUTH" in upper and ("passkey" in lower or "<passkey>" in lower):
        leads.append({
            "class": "passkey_protocol_auth", "surface": "passkey_protocol",
            "claim_detail": "service gates access behind an AUTH passkey",
        })
        leads.append({
            "class": "information_disclosure_banner", "surface": "banner",
            "claim_detail": "pre-authentication banner describes the authentication protocol and where its secret lives",
            "banner_excerpt": text[:400],
        })
    return leads
