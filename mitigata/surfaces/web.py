"""Bounded, unauthenticated HTTP inventory for a single numeric-IP origin."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import math
import secrets
import ssl
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

_MAX_PAGES = 20
_MAX_BYTES = 64 * 1024
_UNSAFE_PATH_PARTS = frozenset(
    {"delete", "remove", "destroy", "logout", "signout", "drop", "reset", "shutdown", "reboot", "purchase", "transfer", "withdraw"}
)
_UNSAFE_ACTIONS = _UNSAFE_PATH_PARTS | {"execute", "run", "create", "update"}
_SECRET_FIELDS = frozenset({"password", "passwd", "pwd", "secret", "token", "api_key", "apikey"})


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        elif tag == "form":
            method = (values.get("method") or "GET").upper()
            self._form = {"action": values.get("action") or "", "method": method, "fields": []} if method in {"GET", "POST"} else None
        elif self._form is not None and tag in {"input", "textarea", "select", "button"}:
            name = values.get("name")
            if name:
                self._form["fields"].append({"name": name, "type": values.get("type") or tag})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def close(self) -> None:
        super().close()
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _same_origin_url(href: str, base: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int, scheme: str) -> str | None:
    if any(ord(char) < 32 or ord(char) == 127 for char in href):
        return None
    try:
        candidate = urlsplit(urljoin(base, href.strip()))
        address = ipaddress.ip_address(candidate.hostname or "")
        candidate_port = candidate.port or (443 if candidate.scheme == "https" else 80)
    except ValueError:
        return None
    if candidate.username is not None or candidate.password is not None:
        return None
    if candidate.scheme != scheme or address != ip or candidate_port != port:
        return None
    authority = f"[{ip}]" if ip.version == 6 else str(ip)
    return urlunsplit((scheme, f"{authority}:{port}", candidate.path or "/", candidate.query, ""))


def _unsafe_get(url: str) -> bool:
    parts = urlsplit(url)
    if any(part.lower() in _UNSAFE_PATH_PARTS for part in parts.path.split("/")):
        return True
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if name.lower() in _SECRET_FIELDS:
            return True
        if name.lower() in {"action", "op", "operation", "cmd"} and value.lower() in _UNSAFE_ACTIONS:
            return True
    return False


def _fetch(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
    tls: bool,
    url: str,
    timeout_s: float,
) -> tuple[int, str, bytes]:
    parts = urlsplit(url)
    target = urlunsplit(("", "", parts.path, parts.query, ""))
    context = ssl._create_unverified_context() if tls else None
    connection = (
        http.client.HTTPSConnection(str(address), port, timeout=timeout_s, context=context)
        if tls else http.client.HTTPConnection(str(address), port, timeout=timeout_s)
    )
    try:
        connection.request("GET", target, headers={"Accept": "text/html", "Connection": "close"})
        response = connection.getresponse()
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        body = b"" if 300 <= response.status < 400 else response.read(_MAX_BYTES)
        return response.status, content_type, body
    finally:
        connection.close()


def _reflection_evidence(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
    tls: bool,
    url: str,
    parameter: str,
    timeout_s: float,
) -> dict | None:
    """Paired harmless GETs prove raw HTML reflection without claiming XSS."""
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs or parameter.lower() in _SECRET_FIELDS:
        return None
    token = secrets.token_hex(8)
    probe_marker = f"<mitigata-canary-{token}>"
    control_marker = f"<mitigata-control-{token}>"

    def marked_url(marker: str) -> str:
        query = urlencode([(name, marker if name == parameter else value) for name, value in pairs])
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))

    probe_url = marked_url(probe_marker)
    control_url = marked_url(control_marker)
    if _unsafe_get(probe_url) or _unsafe_get(control_url):
        return None
    try:
        probe_status, probe_type, probe_body = _fetch(address, port, tls, probe_url, timeout_s)
        control_status, control_type, control_body = _fetch(address, port, tls, control_url, timeout_s)
    except (OSError, http.client.HTTPException, ValueError):
        return None
    if (
        not 200 <= probe_status < 300
        or not 200 <= control_status < 300
        or probe_type not in {"text/html", "application/xhtml+xml"}
        or control_type not in {"text/html", "application/xhtml+xml"}
        or probe_marker.encode() not in probe_body
        or control_marker.encode() not in control_body
    ):
        return None
    return {
        "parameter": parameter,
        "path": parsed.path or "/",
        "probe_status": probe_status,
        "control_status": control_status,
        "probe_sha256": hashlib.sha256(probe_body).hexdigest(),
        "control_sha256": hashlib.sha256(control_body).hexdigest(),
        "oracle": "distinct raw HTML canaries reflected by paired GET requests",
    }


def inspect_site(
    ip: str, port: int, *, tls: bool = False, max_pages: int = 20, timeout_s: float = 5
) -> dict:
    """GET at most 20 same-origin pages; validate at most eight raw reflections."""
    result: dict = {
        "ip": ip, "port": port, "base_url": "", "endpoints": [],
        "forms": [], "candidates": [], "errors": [],
    }
    try:
        address = ipaddress.ip_address(ip)
        if getattr(address, "scope_id", None) is not None:
            raise ValueError("IPv6 zone identifiers are not accepted")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
            raise ValueError("max_pages must be a positive integer")
        if not isinstance(timeout_s, (float, int)) or not math.isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError("timeout must be a positive finite number")
    except ValueError as exc:
        result["errors"].append(f"invalid arguments: {exc}")
        return result

    scheme = "https" if tls else "http"
    authority = f"[{address}]" if address.version == 6 else str(address)
    base_url = f"{scheme}://{authority}:{port}/"
    result["base_url"] = base_url
    pending = [base_url]
    queued = {base_url}
    visited: set[str] = set()
    validation_attempts = 0

    while pending and len(visited) < min(max_pages, _MAX_PAGES):
        url = pending.pop(0)
        visited.add(url)
        parts = urlsplit(url)
        try:
            status, content_type, body = _fetch(address, port, tls, url, timeout_s)
            result["endpoints"].append({"url": url, "method": "GET", "status": status})
            if 300 <= status < 400:
                continue
            if content_type and content_type not in {"text/html", "application/xhtml+xml"}:
                continue
            text = body.decode("utf-8", errors="replace")
            parser = _PageParser()
            parser.feed(text)
            parser.close()
            for form in parser.forms:
                action = _same_origin_url(form["action"], url, address, port, scheme)
                result["forms"].append({
                    "url": url,
                    "action": action if action is not None else form["action"],
                    "method": form["method"],
                    "fields": form["fields"],
                })
            for name in dict.fromkeys(name for name, _ in parse_qsl(parts.query, keep_blank_values=True)):
                if validation_attempts >= 8:
                    break
                validation_attempts += 1
                evidence = _reflection_evidence(address, port, tls, url, name, timeout_s)
                if evidence is not None:
                    result["candidates"].append({
                        "type": "raw_html_reflection", "url": url, "parameter": name,
                        "verified": True, "evidence": evidence,
                    })
            for href in parser.links:
                link = _same_origin_url(href, url, address, port, scheme)
                if link is not None and not _unsafe_get(link) and link not in queued:
                    queued.add(link)
                    pending.append(link)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            safe_path = parts.path or "/"
            result["errors"].append(f"{safe_path}: {type(exc).__name__}")
    return result


class _JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _JSONArgumentParser(description="Inventory an unauthenticated numeric-IP web origin", add_help=False)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5)
    try:
        args = parser.parse_args(argv)
    except ValueError as exc:
        print(json.dumps({"errors": [f"invalid arguments: {exc}"]}))
        return 2
    result = inspect_site(args.ip, args.port, tls=args.tls, max_pages=args.max_pages, timeout_s=args.timeout)
    print(json.dumps(result))
    return 2 if result["errors"] and not result["base_url"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
