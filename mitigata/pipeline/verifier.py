"""Verification agent: bounded, controlled checks that turn leads into confirmed or rejected findings.

Every check pairs its probe with a control that the target must answer
differently (a random credential, a random path, a marker that must not be
reflected). A lead is confirmed only when the probe shows the effect and the
control does not. A check that cannot decide within its limits is
``inconclusive``; it is never silently promoted to a finding.

Authentication checks run only when the manifest sets ``checks.auth_tests``.
Every account is capped at ``limits.max_auth_attempts_per_account``, control
attempts included. A rate-limit or block signal stops that surface at once: the
engine never tries to evade a limit.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import socket
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlencode

from ..surfaces.web import _reflection_evidence
from .guard import ScopeGuard
from .web_agent import Response, _Page, request

DEFAULT_PAIRS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin@123"),
    ("root", "root"),
    ("admin", "123456"),
)
RATE_LIMIT_STATUS = frozenset({423, 429})
RATE_LIMIT_WORDS = ("rate limit", "too many", "temporarily blocked", "you are blocked", "banned", "slow down")
LOGIN_FAILURE_WORDS = (b"invalid", b"incorrect", b"wrong", b"failed", b"denied", b"try again", b"error")
PASSKEY_SUCCESS_WORDS = ("authenticated", "access granted", "authorized", "welcome back", "logged in")
PASSKEY_FAILURE_WORDS = ("invalid", "denied", "wrong", "unknown", "incorrect", "failed", "try again", "bad ")
# The zone protocol spawns a worker and asks for one PIDREQ. The request is fixed to the
# path named in the reply, and the CRC is the documented sum-of-ASCII XOR pid.
_PID_LINE = re.compile(r"PID:\s*(\d+)", re.IGNORECASE)
_PIDREQ_PATH = re.compile(r"(/[A-Za-z0-9_.\-/]*flag[A-Za-z0-9_.\-/]*)", re.IGNORECASE)


@dataclass
class AttemptBudget:
    """Per-account attempt cap shared by every surface in the run."""

    cap: int
    enabled: bool
    used: dict[str, int] = field(default_factory=dict)
    blocked: set[str] = field(default_factory=set)

    def take(self, account: str) -> bool:
        if not self.enabled or account in self.blocked:
            return False
        if self.used.get(account, 0) >= self.cap:
            return False
        self.used[account] = self.used.get(account, 0) + 1
        return True

    def remaining(self, account: str) -> int:
        """Attempts still allowed for this account in the run (0 when disabled or blocked)."""
        if not self.enabled or account in self.blocked:
            return 0
        return max(0, self.cap - self.used.get(account, 0))

    @property
    def total(self) -> int:
        return sum(self.used.values())


@dataclass
class Verdict:
    verdict: str  # confirmed | rejected | inconclusive
    oracle: str
    control: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    accepted_refs: list[str] = field(default_factory=list)
    attempts: int = 0
    #: literal refs this check attempted ("" = a built-in default pair); stored so a later pass does not repeat them
    tried: list[str] = field(default_factory=list)
    #: attempts charged per account during this check, and accounts blocked during it (set by the orchestrator)
    accounts: dict[str, int] = field(default_factory=dict)
    blocked_accounts: list[str] = field(default_factory=list)
    #: HMAC(key, account:value) fingerprints of credentials tested (set by verify_* checks); prevents re-sending
    credential_fingerprints: list[str] = field(default_factory=list)


PASSWORD_KEYWORDS = frozenset({"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
                               "access_token", "auth_token", "basic-auth"})
PASSKEY_KEYWORDS = frozenset({"passkey", "pass_key", "passphrase", "auth_key", "key", "auth", "secret"})


@dataclass
class VerifyContext:
    guard: ScopeGuard
    budget: AttemptBudget
    secrets: dict[str, str]
    literal_refs: list[str]
    flag_patterns: list[re.Pattern[str]]
    timeout: float = 5.0
    #: ref -> {"keyword", "score", "source"}; no values. Orders attempts so junk cannot use up the cap first.
    literal_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: built-in default pairs are tried only when True; recovered literals are limited to ``only_refs`` when set
    include_defaults: bool = True
    only_refs: frozenset[str] | None = None
    #: refs attempted by the check that is running (the check appends; the orchestrator reads and resets it)
    tried_log: list[str] = field(default_factory=list)
    #: HMAC key for credential fingerprints (engagement-wide); None to skip HMAC tracking
    engagement_key: bytes | None = None
    #: Credential fingerprints already tried on any account in the engagement
    tried_fingerprints: frozenset[str] = field(default_factory=frozenset)
    #: Fingerprints tested by the check that is running (the check appends; orchestrator records in verdict)
    tested_fingerprints: list[str] = field(default_factory=list)


def _ordered_refs(ctx: VerifyContext, preferred: frozenset[str]) -> list[str]:
    """Literals whose keyword fits the surface first, then higher score, then binary-derived before page text."""
    def rank(ref: str) -> tuple[int, float, int]:
        info = ctx.literal_meta.get(ref, {})
        return (0 if str(info.get("keyword", "")).lower() in preferred else 1,
                -float(info.get("score", 0.0)),
                0 if info.get("source") == "binary" else 1)
    refs = [ref for ref in ctx.literal_refs if ctx.only_refs is None or ref in ctx.only_refs]
    return sorted(refs, key=rank)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _redact(text: str, values: Iterable[str]) -> str:
    for value in values:
        if value:
            text = text.replace(value, "<redacted>")
    return text


def _pairs(ctx: VerifyContext) -> list[tuple[str, str, str | None]]:
    """Built-in default pairs first (cheap and most common), then binary-derived secrets for ``admin``.

    Defaults go first so a long list of unrelated strings recovered from a binary
    cannot use up the per-account attempt cap before a known default is tried.
    """
    pairs: list[tuple[str, str, str | None]] = (
        [(name, secret, None) for name, secret in DEFAULT_PAIRS] if ctx.include_defaults else []
    )
    for ref in _ordered_refs(ctx, PASSWORD_KEYWORDS):
        # A user:password pair keeps its own user name; a bare recovered password is tried for admin.
        user = str(ctx.literal_meta.get(ref, {}).get("user") or "admin")
        pairs.append((user, ctx.secrets[ref], ref))
    seen: set[tuple[str, str]] = set()
    unique = []
    for name, secret, ref in pairs:
        if (name, secret) not in seen:
            seen.add((name, secret))
            unique.append((name, secret, ref))
    return unique


AUTH_CLASSES = frozenset({"default_credentials", "passkey_protocol_auth"})


def surface_control_key(details: dict[str, Any]) -> str | None:
    """The account a surface's control request is charged to; matches the account keys the verify_* checks use."""
    ip, port = str(details.get("ip", "")), int(details.get("port") or 0)
    if details.get("class") == "passkey_protocol_auth":
        return f"passkey:{ip}:{port}"
    if details.get("class") != "default_credentials":
        return None
    if details.get("surface") == "basic_auth":
        return f"basic:{ip}:{port}{details.get('target', '')}:admin"
    return f"form:{ip}:{port}{details.get('action', '')}:admin"


@dataclass
class PriorAuth:
    """Authentication history rebuilt from the run's stored evidence, so a resumed run keeps its caps and its record."""

    used: dict[str, int] = field(default_factory=dict)
    blocked: set[str] = field(default_factory=set)
    tried: dict[int, set[str]] = field(default_factory=dict)  # candidate id -> refs tried ("" = built-in defaults)
    accepted: dict[str, tuple[int, int]] = field(default_factory=dict)  # ref -> (candidate id, evidence id)


def prior_auth_state(evidence_rows: Iterable[Any], details_by_id: dict[int, dict[str, Any]]) -> PriorAuth:
    prior = PriorAuth()
    for row in evidence_rows:
        if row["type"] != "verification" or row["candidate_id"] is None:
            continue
        cid = int(row["candidate_id"])
        payload = json.loads(row["payload_json"] or "{}")
        for ref in payload.get("accepted_refs") or []:
            prior.accepted.setdefault(ref, (cid, int(row["id"])))
        if "tried_refs" in payload:
            prior.tried.setdefault(cid, set()).update(payload["tried_refs"] or [])
            for account, count in (payload.get("accounts") or {}).items():
                prior.used[account] = prior.used.get(account, 0) + int(count)
            prior.blocked.update(payload.get("blocked_accounts") or [])
        elif int(payload.get("attempts") or 0) > 0:
            # Evidence written before per-account accounting existed: charge every attempt to the surface's control
            # account (the most-used one, so this over-counts rather than under-counts), and treat the built-in
            # defaults as tried, because that check ran before any recovered literal existed.
            details = details_by_id.get(cid, {})
            key = surface_control_key(details)
            if key:
                prior.used[key] = prior.used.get(key, 0) + int(payload["attempts"])
            if details.get("class") == "default_credentials":
                prior.tried.setdefault(cid, set()).add("")
    return prior


@dataclass
class AuthPlan:
    include_defaults: bool
    only_refs: frozenset[str]


def plan_auth_tests(candidates: Iterable[tuple[int, str, str, dict[str, Any]]], prior: PriorAuth,
                    literal_refs: Iterable[str], auth_hosts: set[str]) -> dict[int, AuthPlan]:
    """What each authentication lead still has to try: the built-in defaults if never tried, and each recovered literal not yet tried."""
    literals = list(literal_refs)
    plans: dict[int, AuthPlan] = {}
    for cid, klass, state, details in candidates:
        if klass not in AUTH_CLASSES or state == "confirmed" or str(details.get("ip")) not in auth_hosts:
            continue
        tried = prior.tried.get(cid, set())
        defaults_pending = klass == "default_credentials" and "" not in tried
        pending = frozenset(ref for ref in literals if ref not in tried)
        if state != "candidate" and not defaults_pending and not pending:
            continue  # already tested with every value this run holds
        plans[cid] = AuthPlan(include_defaults=defaults_pending, only_refs=pending)
    return plans


def _is_rate_limited(response: Response) -> bool:
    body = response.body[:4096].decode("utf-8", errors="replace").lower()
    return response.status in RATE_LIMIT_STATUS or any(word in body for word in RATE_LIMIT_WORDS)


# -- HTTP Basic authentication ------------------------------------------------

def verify_basic_auth(ip: str, port: int, tls: bool, candidate: dict[str, Any], ctx: VerifyContext) -> Verdict:
    target = candidate["target"]
    if not ctx.budget.enabled:
        return Verdict("inconclusive", "authentication checks disabled", "",
                       "checks.auth_tests is false in the manifest; no credential was submitted")
    account_base = f"basic:{ip}:{port}{target}"
    control_account = f"{account_base}:admin"
    if ctx.budget.remaining(control_account) < 2:  # a control and one candidate need two attempts
        return Verdict("inconclusive", "attempt cap", "",
                       "fewer than two attempts left for a control and one candidate; no attempt was sent")
    if not ctx.budget.take(control_account):
        return Verdict("inconclusive", "attempt cap", "", "attempt cap reached before the control request")
    wrong = secrets.token_hex(8)
    control = _basic_get(ip, port, tls, target, "admin", wrong, ctx)
    attempts = 1
    if _is_rate_limited(control):
        ctx.budget.blocked.add(control_account)
        return Verdict("inconclusive", "rate limit observed on control", "", "stopped: the surface rate-limited the control attempt", attempts=attempts)
    if 200 <= control.status < 300:
        return Verdict(
            "confirmed", "a random password was accepted by HTTP Basic authentication",
            "random password submitted", "authentication accepts arbitrary credentials",
            evidence={"surface": "basic_auth", "path": candidate["path"], "realm": candidate.get("realm", ""),
                      "control_status": control.status, "probe_status": control.status},
            attempts=attempts,
        )
    if control.status != 401:
        return Verdict("rejected", "no authentication decision on the control request", "",
                       f"control returned {control.status}; no Basic challenge to test", attempts=attempts)

    tested = 0
    for user, secret, ref in _pairs(ctx):
        account = f"{account_base}:{user}"
        # Check if this credential has already been tested in a previous run (engagement-wide)
        if ctx.engagement_key is not None:
            from . import engagement
            fp = engagement.credential_fingerprint(account, secret, ctx.engagement_key)
            if fp in ctx.tried_fingerprints:
                continue  # Already tried this (account, secret) pair; skip it
        if not ctx.budget.take(account):
            continue
        if ctx.engagement_key is not None:
            ctx.tested_fingerprints.append(fp)
        tested += 1
        attempts += 1
        ctx.tried_log.append(ref or "")
        response = _basic_get(ip, port, tls, target, user, secret, ctx)
        if _is_rate_limited(response):
            ctx.budget.blocked.add(account)
            return Verdict("inconclusive", "rate limit observed", "random password rejected with 401",
                           "stopped: the surface rate-limited an attempt; no bypass was attempted",
                           evidence={"surface": "basic_auth", "path": candidate["path"]},
                           credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)
        if 200 <= response.status < 300 and b"authentication required" not in response.body.lower():
            evidence = {"surface": "basic_auth", "path": candidate["path"], "realm": candidate.get("realm", ""),
                        "control_status": control.status, "probe_status": response.status,
                        "probe_sha256": _digest(response.body), "account": user,
                        "credential_source": "recovered literal" if ref else "built-in default"}
            if ref is None:
                evidence["default_password"] = secret
            return Verdict(
                "confirmed", f"{user} with the tested secret is accepted by HTTP Basic authentication",
                "random password rejected with 401", "default or recovered credential works",
                evidence=evidence, accepted_refs=[ref] if ref else [],
                credential_fingerprints=ctx.tested_fingerprints, attempts=attempts,
            )
    if tested == 0:
        return Verdict("inconclusive", "attempt cap", "random password rejected with 401",
                       "attempt cap reached before any credential was tested",
                       credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)
    return Verdict("rejected", "none of the tested credentials was accepted", "random password rejected with 401",
                   f"{attempts} attempts; no tested credential was accepted",
                   credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)


def _basic_get(ip: str, port: int, tls: bool, target: str, user: str, password: str, ctx: VerifyContext) -> Response:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return request(ip, port, tls=tls, method="GET", target=target, guard=ctx.guard,
                   timeout=ctx.timeout, headers={"Authorization": f"Basic {token}"}, purpose="auth check")


# -- HTML login forms -----------------------------------------------------------

def verify_login_form(ip: str, port: int, tls: bool, candidate: dict[str, Any], ctx: VerifyContext) -> Verdict:
    if not ctx.budget.enabled:
        return Verdict("inconclusive", "authentication checks disabled", "",
                       "checks.auth_tests is false in the manifest; no credential was submitted")
    page_target = candidate["target"]
    action = candidate["action"]
    user_field = candidate.get("user_field") or "username"
    pass_field = candidate.get("pass_field") or "password"
    page = request(ip, port, tls=tls, method="GET", target=page_target, guard=ctx.guard,
                   timeout=ctx.timeout, purpose="login form")
    parser = _Page()
    parser.feed(page.body.decode("utf-8", errors="replace"))
    parser.close()
    hidden: dict[str, str] = dict(candidate.get("hidden") or {})
    for form in parser.forms:
        if any(field.get("type") == "password" for field in form["fields"]):
            hidden = {f["name"]: f.get("value", "") for f in form["fields"] if f.get("type") == "hidden"}
            break
    cookie = page.cookies
    account_base = f"form:{ip}:{port}{action}"

    def post(user: str, password: str) -> Response:
        body = urlencode({**hidden, user_field: user, pass_field: password}).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie
        return request(ip, port, tls=tls, method="POST", target=action, guard=ctx.guard, timeout=ctx.timeout,
                       headers=headers, body=body, purpose="login attempt")

    control_account = f"{account_base}:admin"
    if not ctx.budget.take(control_account):
        return Verdict("inconclusive", "attempt cap", "", "attempt cap reached before the control request")
    control = post("admin", secrets.token_hex(8))
    attempts = 1
    if _is_rate_limited(control):
        ctx.budget.blocked.add(control_account)
        return Verdict("inconclusive", "rate limit observed on control", "", "stopped: rate limit observed", attempts=attempts)
    # The control is compared with the logged-out login page: a random password must not log in.
    if _looks_logged_in(control, page):
        return Verdict("confirmed", "a random password was accepted by the login form",
                       "random password submitted", "login form accepts arbitrary credentials",
                       evidence={"surface": "login_form", "action": action, "control_status": control.status},
                       attempts=attempts)

    tested = 0
    for user, secret, ref in _pairs(ctx):
        account = f"{account_base}:{user}"
        # Check if this credential has already been tested in a previous run (engagement-wide)
        if ctx.engagement_key is not None:
            from . import engagement
            fp = engagement.credential_fingerprint(account, secret, ctx.engagement_key)
            if fp in ctx.tried_fingerprints:
                continue  # Already tried this (account, secret) pair; skip it
        if not ctx.budget.take(account):
            continue
        if ctx.engagement_key is not None:
            ctx.tested_fingerprints.append(fp)
        tested += 1
        attempts += 1
        ctx.tried_log.append(ref or "")
        response = post(user, secret)
        if _is_rate_limited(response):
            ctx.budget.blocked.add(account)
            return Verdict("inconclusive", "rate limit observed", "random password rejected",
                           "stopped: the form rate-limited an attempt; no bypass was attempted",
                           credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)
        if _looks_logged_in(response, control):
            evidence = {"surface": "login_form", "action": action, "account": user,
                        "control_status": control.status, "probe_status": response.status,
                        "probe_location": response.header("location")[:200],
                        "credential_source": "recovered literal" if ref else "built-in default"}
            if ref is None:
                evidence["default_password"] = secret
            return Verdict(
                "confirmed", f"{user} with the tested secret logs in through the form",
                "random password rejected by the form", "default or recovered credential works",
                evidence=evidence, accepted_refs=[ref] if ref else [],
                credential_fingerprints=ctx.tested_fingerprints, attempts=attempts,
            )
    if tested == 0:
        return Verdict("inconclusive", "attempt cap", "random password rejected by the form",
                       "attempt cap reached before any credential was tested",
                       credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)
    return Verdict("rejected", "none of the tested credentials logged in", "random password rejected by the form",
                   f"{attempts} attempts; no tested credential was accepted",
                   credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)


def _looks_logged_in(response: Response, control: Response) -> bool:
    still_on_login = b'type="password"' in response.body.lower() or b"type='password'" in response.body.lower()
    if still_on_login:
        return False
    differs = (response.status, response.header("location")) != (control.status, control.header("location")) \
        or _digest(response.body) != _digest(control.body)
    if response.status in (301, 302, 303, 307, 308):
        return differs and "login" not in response.header("location").lower()
    if response.status == 200:
        lowered = response.body.lower()
        return differs and not any(word in lowered for word in LOGIN_FAILURE_WORDS)
    return False


# -- binary-derived passkey on a line protocol --------------------------------------

def _exchange(ip: str, port: int, line: str, ctx: VerifyContext) -> tuple[str, str]:
    """Return (banner, reply) for one connection: read the banner, send one line, read the reply."""
    ctx.guard.require(ip, port=port, purpose="protocol attempt")
    ctx.guard.pace(ip)
    with socket.create_connection((ip, port), timeout=ctx.timeout) as sock:
        sock.settimeout(1.2)
        banner = _drain(sock)
        sock.sendall(line.encode("ascii") + b"\n")
        sock.settimeout(1.5)
        reply = _drain(sock)
    return banner, reply


def _drain(sock: socket.socket, limit: int = 4096) -> str:
    chunks: list[bytes] = []
    total = 0
    try:
        while total < limit:
            data = sock.recv(limit - total)
            if not data:
                break
            chunks.append(data)
            total += len(data)
    except socket.timeout:
        pass
    return b"".join(chunks).decode("latin-1")


def _pidreq_crc(path: str, pid: int) -> str:
    """The zone protocol's documented checksum: sum(ASCII path) XOR pid, lowercase hex."""
    return f"{(sum(path.encode('ascii')) ^ pid) & 0xFFFFFFFF:x}"


def _passkey_session(
    ip: str, port: int, secret: str, ctx: VerifyContext,
) -> tuple[str, str, str, int | None, str | None]:
    """Authenticate and, when the reply advertises the zone protocol, issue one PIDREQ.

    Everything after the one fixed PIDREQ is ignored. No arbitrary command is sent,
    the path comes from the service's own hint, and the connection is bounded by the
    same socket timeouts as the control exchange.
    """
    ctx.guard.require(ip, port=port, purpose="passkey protocol attempt")
    ctx.guard.pace(ip)
    with socket.create_connection((ip, port), timeout=ctx.timeout) as sock:
        sock.settimeout(1.2)
        banner = _drain(sock)
        sock.sendall(f"AUTH {secret}\n".encode("ascii"))
        sock.settimeout(1.5)
        reply = _drain(sock)
        followup = ""
        pid: int | None = None
        path: str | None = None
        pid_match = _PID_LINE.search(reply)
        path_match = _PIDREQ_PATH.search(reply)
        if pid_match and path_match and "pidreq" in reply.lower():
            try:
                pid = int(pid_match.group(1))
                path = path_match.group(1)
                crc = _pidreq_crc(path, pid)
            except (ValueError, UnicodeEncodeError):
                pid, path = None, None
            else:
                sock.settimeout(1.5)
                sock.sendall(f"PIDREQ {pid} {path} {crc}\n".encode("ascii"))
                followup = _drain(sock, limit=8192)
    return banner, reply, followup, pid, path


def verify_passkey(ip: str, port: int, candidate: dict[str, Any], ctx: VerifyContext) -> Verdict:
    if not ctx.budget.enabled:
        return Verdict("inconclusive", "authentication checks disabled", "",
                       "checks.auth_tests is false in the manifest; no passkey was submitted")
    if not _ordered_refs(ctx, PASSKEY_KEYWORDS):
        return Verdict("inconclusive", "no candidate passkey", "",
                       "no authentication literal is available for this service")
    account = f"passkey:{ip}:{port}"
    if ctx.budget.remaining(account) < 2:
        # A control and one candidate need two attempts. With fewer left nothing can be concluded, so none is sent.
        return Verdict("inconclusive", "attempt cap", "",
                       "fewer than two attempts left for a control and one candidate; no attempt was sent")
    if not ctx.budget.take(account):
        return Verdict("inconclusive", "attempt cap", "", "attempt cap reached before the control request")
    control_banner, control_reply = _exchange(ip, port, f"AUTH {secrets.token_hex(12)}", ctx)
    attempts = 1
    if _protocol_rate_limited(control_banner, control_reply):
        ctx.budget.blocked.add(account)
        return Verdict("inconclusive", "rate limit observed on control", "", "stopped: the service blocked the source", attempts=attempts)

    control_flags = _flags(control_reply, ctx)
    ambiguous: list[dict[str, Any]] = []
    tested = 0
    for ref in _ordered_refs(ctx, PASSKEY_KEYWORDS):
        # Check if this passkey has already been tested in a previous run (engagement-wide)
        if ctx.engagement_key is not None:
            from . import engagement
            fp = engagement.credential_fingerprint(account, ctx.secrets[ref], ctx.engagement_key)
            if fp in ctx.tried_fingerprints:
                continue  # Already tried this passkey; skip it
        if not ctx.budget.take(account):
            break
        if ctx.engagement_key is not None:
            ctx.tested_fingerprints.append(fp)
        tested += 1
        attempts += 1
        ctx.tried_log.append(ref)
        secret = ctx.secrets[ref]
        banner, reply, followup, pid, pidreq_path = _passkey_session(ip, port, secret, ctx)
        if _protocol_rate_limited(banner, reply):
            ctx.budget.blocked.add(account)
            return Verdict("inconclusive", "rate limit observed", "", "stopped: the service rate-limited or blocked the source; no bypass attempted",
                           evidence={"surface": "passkey_protocol", "attempts": attempts},
                           credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)
        redacted_reply = _redact(reply, ctx.secrets.values())[:400]
        redacted_followup = _redact(followup, ctx.secrets.values())[:800]
        flags = [flag for flag in _flags(reply + "\n" + followup, ctx) if flag not in control_flags]
        lowered = reply.lower()
        differs = reply.strip() != control_reply.strip()
        success_phrase = any(word in lowered for word in PASSKEY_SUCCESS_WORDS)
        failure_phrase = any(word in lowered for word in PASSKEY_FAILURE_WORDS)
        evidence = {
            "surface": "passkey_protocol", "control_reply_sha256": _digest(control_reply.encode("latin-1")),
            "probe_reply_sha256": _digest(reply.encode("latin-1")), "probe_reply_excerpt": redacted_reply,
            "credential_source": "recovered literal",
            "post_auth_reply_excerpt": redacted_followup,
            "pid": pid, "pidreq_path": pidreq_path,
        }
        if flags or (differs and success_phrase and not failure_phrase):
            if flags and followup:
                summary = "authentication accepted and the post-auth PIDREQ returned the flag"
            elif flags:
                summary = "authentication accepted and a flag was returned"
            else:
                summary = "authentication accepted and output changed"
            return Verdict(
                "confirmed", "a recovered passkey is accepted by the AUTH protocol",
                "random passkey rejected by the same service", summary,
                evidence=evidence, flags=flags, accepted_refs=[ref],
                credential_fingerprints=ctx.tested_fingerprints, attempts=attempts,
            )
        if differs and not failure_phrase:
            ambiguous.append({"ref": ref, "evidence": evidence})
    if tested == 0:
        return Verdict("inconclusive", "attempt cap", "random passkey rejected by the same service",
                       "attempt cap reached before any recovered literal was tested",
                       credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)
    if ambiguous:
        return Verdict("inconclusive", "response changed without a recognised success marker",
                       "random passkey rejected by the same service",
                       "the reply differs from the control but shows no flag or success marker; review the evidence",
                       evidence=ambiguous[0]["evidence"],
                       credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)
    return Verdict("rejected", "no recovered passkey changed the service response",
                   "random passkey rejected by the same service",
                   f"{attempts} attempts; no recovered literal was accepted",
                   credential_fingerprints=ctx.tested_fingerprints, attempts=attempts)


def _protocol_rate_limited(banner: str, reply: str) -> bool:
    # The banner itself warns that abusive sources are rate limited; only the reply counts.
    lowered = reply.lower()
    return any(word in lowered for word in RATE_LIMIT_WORDS)


def _flags(text: str, ctx: VerifyContext) -> list[str]:
    found: list[str] = []
    for pattern in ctx.flag_patterns:
        for match in pattern.finditer(text):
            if match.group(0) not in found:
                found.append(match.group(0))
    return found


# -- raw HTML reflection, exposed paths, banner repeatability ---------------------------

def verify_reflection(ip: str, port: int, tls: bool, candidate: dict[str, Any], ctx: VerifyContext) -> Verdict:
    scheme = "https" if tls else "http"
    url = f"{scheme}://{ip}:{port}{candidate['target']}"
    ctx.guard.require(ip, port=port, purpose="reflection oracle")
    ctx.guard.pace(ip)
    evidence = _reflection_evidence(ipaddress.ip_address(ip), port, tls, url, candidate["parameter"], ctx.timeout)
    if evidence is None:
        return Verdict("rejected", "paired canaries were not reflected raw", "distinct control marker",
                       "the parameter's marker is not reflected unescaped on repeat requests")
    return Verdict("confirmed", "distinct raw HTML canaries reflected by paired GET requests",
                   "distinct control marker not reflected by the control request",
                   f"parameter {candidate['parameter']} is returned unescaped in HTML (script execution not tested)",
                   evidence=evidence, attempts=0)


def verify_exposed_path(ip: str, port: int, tls: bool, candidate: dict[str, Any], ctx: VerifyContext) -> Verdict:
    path = candidate["target"]
    probe = request(ip, port, tls=tls, method="GET", target=path, guard=ctx.guard, timeout=ctx.timeout, purpose="exposure check")
    if probe.status != 200 or not probe.body:
        return Verdict("rejected", "path no longer returns content", "", f"status {probe.status} on re-check")
    control_path = f"/mitigata-control-{secrets.token_hex(6)}"
    control = request(ip, port, tls=tls, method="GET", target=control_path, guard=ctx.guard, timeout=ctx.timeout,
                      purpose="exposure control")
    evidence = {"path": path, "probe_status": probe.status, "probe_length": len(probe.body),
                "probe_sha256": _digest(probe.body), "control_status": control.status}
    if control.status == 200:
        if _digest(control.body) == _digest(probe.body):
            return Verdict("rejected", "catch-all response", "random path request",
                           "the control path returns the same content, so the path is not distinct", evidence=evidence, attempts=0)
        return Verdict("inconclusive", "control path also returns 200", "random path request",
                       "cannot separate a catch-all handler from a real exposure", evidence=evidence, attempts=0)
    return Verdict("confirmed", f"{path} is reachable while random paths return {control.status}",
                   "random path request", f"path {path} returns content without authentication; impact not demonstrated",
                   evidence=evidence, attempts=0)


def verify_banner(ip: str, port: int, candidate: dict[str, Any], ctx: VerifyContext) -> Verdict:
    first_banner, _ = _exchange_banner_only(ip, port, ctx)
    second_banner, _ = _exchange_banner_only(ip, port, ctx)
    repeatable = bool(first_banner) and first_banner[:160] == second_banner[:160]
    evidence = {"banner_sha256": _digest(first_banner.encode("latin-1")), "repeatable": repeatable}
    if repeatable:
        return Verdict("confirmed", "the pre-authentication banner is repeatable across connections",
                       "second connection", "the service discloses information before authentication; impact not demonstrated",
                       evidence=evidence, attempts=0)
    return Verdict("inconclusive", "banner not repeatable", "second connection",
                   "the banner changed between connections; review manually", evidence=evidence, attempts=0)


def _exchange_banner_only(ip: str, port: int, ctx: VerifyContext) -> tuple[str, str]:
    ctx.guard.require(ip, port=port, purpose="banner repeat")
    ctx.guard.pace(ip)
    with socket.create_connection((ip, port), timeout=ctx.timeout) as sock:
        sock.settimeout(1.2)
        return _drain(sock, limit=1024), ""


def static_only(reason: str) -> Verdict:
    return Verdict("inconclusive", "static analysis only", "", reason, attempts=0)


def dispatch(candidate: dict[str, Any], ctx: VerifyContext) -> Verdict:
    """Route one lead to its check; every network-facing check passes the scope guard first."""
    klass = candidate["class"]
    if klass == "static_unsafe_function":
        return static_only("unsafe libc import is a static string; reachability needs dynamic analysis")
    if klass == "hardcoded_secret":
        return static_only("resolved against the auth surfaces after they are tested")
    try:
        ip, port = str(candidate["ip"]), int(candidate["port"])
        tls = bool(candidate.get("tls", False))
        if klass == "default_credentials":
            if candidate["surface"] == "basic_auth":
                return verify_basic_auth(ip, port, tls, candidate, ctx)
            return verify_login_form(ip, port, tls, candidate, ctx)
        if klass == "passkey_protocol_auth":
            return verify_passkey(ip, port, candidate, ctx)
        if klass == "raw_html_reflection":
            return verify_reflection(ip, port, tls, candidate, ctx)
        if klass == "exposed_path":
            return verify_exposed_path(ip, port, tls, candidate, ctx)
        if klass == "information_disclosure_banner":
            return verify_banner(ip, port, candidate, ctx)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return Verdict("inconclusive", "check error", "", f"check could not complete: {type(exc).__name__}")
    return static_only(f"no verification rule for class {klass}")
