"""Web agent: bounded, same-origin HTTP inventory and candidate generation.

The inventory sends GET requests only. It follows same-origin redirects, records
endpoints, login forms and Basic-auth challenges, checks whether a harmless
marker is reflected raw into HTML, and looks at a short list of sensitive paths.
It never follows a link to another origin and never submits a form: credential
submission happens only in the verification agent, behind the manifest's
explicit ``checks.auth_tests`` permission.

Every request passes through the scope guard first.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import secrets
import ssl
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..surfaces.web import _SECRET_FIELDS, _unsafe_get
from .binary_agent import auth_literals
from .guard import ScopeGuard

MAX_BODY = 256 * 1024
MAX_BINARY = 64 * 1024 * 1024
DEFAULT_TIMEOUT = 4.0
DEFAULT_SENSITIVE_TIMEOUT = 2.0
DEFAULT_MAX_SENSITIVE_PATHS = 12
CRAWL_TIMEOUT = 8.0
BINARY_SUFFIXES = (".bin", ".elf", ".exe", ".out", ".dll", ".so", ".run")
BINARY_TYPES = frozenset({"application/octet-stream", "application/x-executable", "application/x-elf",
                          "application/x-msdownload", "application/x-sharedlib"})
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
REDIRECTS = frozenset({301, 302, 303, 307, 308})
SENSITIVE_PATHS = (
    # The first DEFAULT_MAX_SENSITIVE_PATHS entries are always checked; keep the highest-value
    # secrets and the common backup path in that window.
    "/.git/HEAD", "/.git/config", "/.gitignore", "/.env", "/.env.local", "/config.php", "/config.php.bak",
    "/backup", "/backup.zip", "/backup.tar.gz", "/database.sql", "/phpinfo.php",
    # Further version control, configuration and secret files
    "/.git/index", "/.env.backup", "/.env.prod", "/.env.development", "/.env.staging", "/.env.example",
    "/wp-config.php", "/config.json", "/config.yaml", "/config.yml", "/config.php.old", "/web.config",
    "/web.config.bak", "/settings.json", "/secrets.json",
    # Server info exposure
    "/info.php", "/test.php", "/debug.php", "/server-status", "/server-info",
    # Further backup and database files (data exposure)
    "/backup.sql", "/backup.tar", "/dump.sql", "/backup.bak", "/db.backup", "/.backup", "/backups.zip",
    # Application logs (may leak sensitive data)
    "/logs/error.log", "/logs/access.log", "/logs/debug.log", "/error.log", "/debug.log",
    "/var/log/apache2/error.log", "/var/log/apache2/access.log", "/var/log/nginx/error.log",
    # Other sensitive files
    "/.htaccess", "/.htpasswd", "/.htaccess.bak", "/.aws", "/.ssh", "/private",
)
MAX_LITERALS_PER_SERVICE = 12
#: Path segments that name an action on a site or API; GET links with these are never followed.
_ACTION_SEGMENTS = frozenset({
    "action", "actions", "start", "stop", "pause", "resume", "scan", "scans", "spider", "ascan", "clear",
    "set", "add", "remove", "delete", "import", "export", "generate", "install", "update", "upgrade",
    "restart", "reboot", "shutdown", "kill", "exec", "execute", "send", "submit", "post", "purge", "flush",
    "wipe", "reset", "logout", "signout", "upload", "create", "new", "rename", "move", "copy", "edit",
    "save", "write",
})


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    cookies: str

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    @property
    def content_type(self) -> str:
        return self.header("content-type").split(";", 1)[0].strip().lower()


class _Page(HTMLParser):
    """Collects links, forms, password inputs and the page title."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.has_password_input = False
        self.title = ""
        self._form: dict[str, Any] | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: (value or "") for name, value in attrs}
        if tag in ("a", "area") and values.get("href"):
            self.links.append(values["href"])
        elif tag == "form":
            method = values.get("method", "GET").upper()
            self._form = {"action": values.get("action", ""), "method": method if method == "POST" else "GET", "fields": []}
            self.forms.append(self._form)
        elif tag == "title":
            self._in_title = True
        elif tag in ("input", "textarea", "select", "button"):
            kind = values.get("type", tag).lower()
            if kind == "password":
                self.has_password_input = True
            name = values.get("name", "")
            if self._form is not None and name:
                field: dict[str, Any] = {"name": name[:64], "type": kind[:32]}
                if kind == "hidden":
                    field["value"] = values.get("value", "")[:200]
                self._form["fields"].append(field)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 200:
            self.title += data


def request(
    ip: str,
    port: int,
    *,
    tls: bool,
    method: str,
    target: str,
    guard: ScopeGuard | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    purpose: str = "http",
) -> Response:
    """One origin-relative request to a numeric IP; raises ScopeViolation when refused."""
    if not target.startswith("/") or "://" in target or "\r" in target or "\n" in target:
        raise ValueError("request target must be an origin-relative path")
    if guard is not None:
        guard.require(ip, port=port, purpose=f"{purpose} {method} {target.split('?', 1)[0]}")
        guard.pace(ip)
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        raise ValueError("only IPv4 targets are supported in this build")
    if tls:
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            str(address), port, timeout=timeout, context=ssl._create_unverified_context(),
        )
    else:
        connection = http.client.HTTPConnection(str(address), port, timeout=timeout)
    try:
        request_headers = {
            "User-Agent": "mitigata-hackathon/0.2",
            "Accept": "text/html,*/*;q=0.5",
            "Connection": "close",
        }
        request_headers.update(headers or {})
        connection.request(method, target, body=body, headers=request_headers)
        response = connection.getresponse()
        collected: dict[str, str] = {}
        cookies: list[str] = []
        for name, value in response.getheaders():
            lower = name.lower()
            if lower == "set-cookie":
                cookies.append(value.split(";", 1)[0])
            collected.setdefault(lower, value)
        if method == "HEAD" or response.status in (204, 304):
            payload = b""
        else:
            payload = response.read(MAX_BODY)
        return Response(response.status, collected, payload, "; ".join(cookies))
    finally:
        connection.close()


def public_path(target: str) -> str:
    """Path plus query parameter *names*; every value is replaced before storage or display."""
    parts = urlsplit(target)
    names = sorted({re.sub(r"[^A-Za-z0-9_.-]", "", name)[:64] for name, _ in parse_qsl(parts.query, keep_blank_values=True)} - {""})
    query = "&".join(f"{name}=<redacted>" for name in names)
    path = parts.path or "/"
    return path + (f"?{query}" if query else "")


def same_origin_target(href: str, base_target: str, ip: str, port: int, scheme: str) -> str | None:
    """Resolve ``href`` against ``base_target``; None unless it stays on this exact origin."""
    if not href or any(ord(char) < 32 or ord(char) == 127 for char in href):
        return None
    base = f"{scheme}://{ip}:{port}{base_target}"
    try:
        joined = urlsplit(urljoin(base, href.strip()))
        joined_port = joined.port or (443 if joined.scheme == "https" else 80)
    except ValueError:
        return None
    if joined.scheme != scheme or joined.hostname != ip or joined_port != port:
        return None
    if joined.username is not None or joined.password is not None:
        return None
    query = f"?{joined.query}" if joined.query else ""
    return (joined.path or "/") + query


def _with_param(target: str, name: str, value: str) -> str:
    parts = urlsplit(target)
    pairs = [(key, value if key == name else current) for key, current in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit(("", "", parts.path or "/", urlencode(pairs), ""))


_STATE_CHANGING_NAMES = frozenset({
    "del", "delete", "rm", "remove", "destroy", "drop", "reset", "logout", "mkdir", "new", "newfolder",
    "newfile", "create", "rename", "upload", "move", "copy", "chmod", "chown", "edit", "update", "save",
    "write", "exec", "run", "cmd", "shell", "submit",
})


def _state_changing(target: str) -> bool:
    """GET links that look like actions (delete, create, scan, action...) are never followed or probed."""
    if _unsafe_get(target):
        return True
    segments = {segment.lower() for segment in urlsplit(target).path.split("/") if segment}
    if segments & _ACTION_SEGMENTS:
        return True
    names = {name.lower() for name, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True)}
    return bool(names & _STATE_CHANGING_NAMES)


class _TextCollector(HTMLParser):
    """Visible text only: script and style bodies are skipped."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._hidden:
            self._hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self._hidden:
            self.parts.append(data)

    def text(self) -> str:
        return "\n".join(self.parts)


def _credential_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped:
            lines.append((offset, stripped))
        offset += len(line)
    return lines


def _collect_literals(result: dict[str, Any], text: str, path: str) -> None:
    """Credential-like literals in readable page text (handover notes, config snippets) are kept as in-memory values."""
    for literal in auth_literals(_credential_lines(text)):
        if len(result["literals"]) >= MAX_LITERALS_PER_SERVICE:
            return
        if any(item["value"] == literal["value"] for item in result["literals"]):
            continue
        result["literals"].append({**literal, "path": path})


def _realm(challenge: str) -> str:
    match = re.search(r'realm\s*=\s*"?([^",]*)', challenge, re.IGNORECASE)
    return match.group(1).strip()[:80] if match else ""


def _is_binary_body(body: bytes) -> bool:
    return body[:4] == b"\x7fELF" or body[:2] == b"MZ"


def inventory(
    ip: str,
    port: int,
    *,
    tls: bool = False,
    guard: ScopeGuard | None = None,
    max_pages: int = 20,
    timeout: float = DEFAULT_TIMEOUT,
    seeds: tuple[str, ...] = (),
    include_root: bool = True,
    sensitive_timeout: float = DEFAULT_SENSITIVE_TIMEOUT,
    max_sensitive_paths: int = DEFAULT_MAX_SENSITIVE_PATHS,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Crawl one HTTP(S) origin and return endpoints plus unverified candidate leads.

    ``headers`` are sent on every request of this crawl (used after a forwarded-address trust check succeeds).
    """
    scheme = "https" if tls else "http"
    result: dict[str, Any] = {
        "ip": ip, "port": port, "tls": tls, "server": "", "title": "", "cookies": "",
        "endpoints": [], "forms": [], "auth_challenges": [], "candidates": [],
        "binary_links": [], "errors": [], "pages": 0, "literals": [], "hint_text": "",
    }
    queue: deque[tuple[str, int]] = deque(([("/", 0)] if include_root else []) + [(seed, 0) for seed in seeds])
    seen: set[str] = set()
    reflection_checks = 0

    def fetch(target: str, *, request_timeout: float | None = None) -> Response | None:
        try:
            return request(ip, port, tls=tls, method="GET", target=target, guard=guard, headers=headers,
                           timeout=timeout if request_timeout is None else request_timeout, purpose="crawl")
        except (OSError, http.client.HTTPException, ValueError) as exc:
            result["errors"].append(f"{public_path(target)}: {type(exc).__name__}")
            return None

    while queue and result["pages"] < max_pages:
        target, depth = queue.popleft()
        if target in seen or _state_changing(target):
            continue
        seen.add(target)
        response = fetch(target)
        if response is None:
            continue
        result["pages"] += 1
        path = public_path(target)
        if not result["server"]:
            result["server"] = response.header("server")[:120]
        if not result["cookies"] and response.cookies:
            result["cookies"] = response.cookies
        result["endpoints"].append({
            "path": path, "status": response.status,
            "content_type": response.content_type[:60], "length": len(response.body),
        })

        if response.status in REDIRECTS:
            location = same_origin_target(response.header("location"), target, ip, port, scheme)
            if location and depth < 3:
                queue.append((location, depth + 1))
            continue

        if response.status == 401:
            challenge = response.header("www-authenticate")
            if challenge.lower().startswith("basic"):
                realm = _realm(challenge)
                result["auth_challenges"].append({"path": path, "scheme": "basic", "realm": realm})
                result["candidates"].append({
                    "class": "default_credentials", "surface": "basic_auth",
                    "target": target, "path": path, "realm": realm,
                })
            continue

        if response.status != 200:
            continue

        if target in SENSITIVE_PATHS and response.body:
            result["candidates"].append({
                "class": "exposed_path", "target": target, "path": path, "status": 200,
                "length": len(response.body), "sha256": hashlib.sha256(response.body).hexdigest(),
            })

        if response.content_type in BINARY_TYPES or _is_binary_body(response.body):
            if path.lower().endswith(BINARY_SUFFIXES) or response.content_type in BINARY_TYPES:
                result["binary_links"].append(target)
            continue
        if response.content_type.startswith("text/") and response.content_type not in HTML_TYPES:
            decoded_text = response.body.decode("utf-8", errors="replace")
            _add_hint_text(result, decoded_text)
            _collect_literals(result, decoded_text, path)
            continue
        if response.content_type not in HTML_TYPES:
            continue

        decoded = response.body.decode("utf-8", errors="replace")
        page = _Page()
        page.feed(decoded)
        page.close()
        if page.title and not result["title"]:
            result["title"] = page.title.strip()[:120]
        visible = _TextCollector()
        visible.feed(decoded)
        visible.close()
        _add_hint_text(result, visible.text())
        _collect_literals(result, visible.text(), path)

        for href in page.links:
            link = same_origin_target(href, target, ip, port, scheme)
            if link is None or link in seen or _state_changing(link):
                continue
            if link.split("?", 1)[0].lower().endswith(BINARY_SUFFIXES):
                if link not in result["binary_links"]:
                    result["binary_links"].append(link)
                continue
            queue.append((link, depth + 1))

        for form in page.forms:
            action = same_origin_target(form["action"] or target, target, ip, port, scheme) or target
            is_login = form["method"] == "POST" and any(field["type"] == "password" for field in form["fields"])
            form_record = {
                "page": path, "action": public_path(action), "method": form["method"],
                "fields": [{key: value for key, value in field.items() if key != "value"} for field in form["fields"]],
                "login": is_login,
            }
            result["forms"].append(form_record)
            if not is_login:
                continue
            user_field = next((f["name"] for f in form["fields"]
                               if f["type"] in ("text", "email") and re.search(r"user|login|mail|name|account", f["name"], re.I)),
                              next((f["name"] for f in form["fields"] if f["type"] in ("text", "email")), ""))
            pass_field = next((f["name"] for f in form["fields"] if f["type"] == "password"), "")
            hidden = {f["name"]: f.get("value", "") for f in form["fields"] if f["type"] == "hidden"}
            result["candidates"].append({
                "class": "default_credentials", "surface": "login_form",
                "target": target, "action": action, "path": public_path(action),
                "user_field": user_field, "pass_field": pass_field, "hidden": hidden,
            })

        names = list(dict.fromkeys(name for name, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True)))
        for name in names[:3]:
            if reflection_checks >= 8 or name.lower() in _SECRET_FIELDS:
                break
            marker = f"mitigata-canary-{secrets.token_hex(6)}"
            probe_target = _with_param(target, name, marker)
            if _state_changing(probe_target):
                continue
            reflection_checks += 1
            try:
                probe = request(ip, port, tls=tls, method="GET", target=probe_target, guard=guard, headers=headers,
                                timeout=timeout, purpose="reflection check")
            except (OSError, http.client.HTTPException, ValueError):
                continue
            if probe.status == 200 and probe.content_type in HTML_TYPES and marker.encode() in probe.body:
                result["candidates"].append({
                    "class": "raw_html_reflection", "target": target, "parameter": name, "path": public_path(target),
                })

    for path in SENSITIVE_PATHS[:max(0, max_sensitive_paths)]:
        if path in seen:
            continue
        response = fetch(path, request_timeout=sensitive_timeout)
        if response is None or response.status != 200 or not response.body:
            continue
        result["endpoints"].append({"path": path, "status": 200, "content_type": response.content_type[:60],
                                    "length": len(response.body)})
        result["candidates"].append({
            "class": "exposed_path", "target": path, "path": path, "status": 200,
            "length": len(response.body), "sha256": hashlib.sha256(response.body).hexdigest(),
        })
    return result


#: Paths requested once per origin by the orchestrator, so an index or file-manager entry point is seen without a seed.
ENTRY_PATHS: tuple[str, ...] = ("/index.php", "/index.html", "/share/", "/files/")
#: Header names that edge proxies commonly trust for the client address. Names only; no encoding variants.
KNOWN_FORWARD_HEADERS: tuple[str, ...] = (
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP", "Forwarded", "True-Client-IP", "CF-Connecting-IP",
)
#: Exposure vocabulary for content-named probes. Each word must also appear in the vendored SecLists list.
HINT_WORDS: frozenset[str] = frozenset({
    "vault", "artifact", "artifacts", "backup", "backups", "archive", "archives", "binary", "binaries", "dump",
    "dumps", "download", "downloads", "export", "exports", "files", "handover", "internal", "keys", "keystore",
    "logs", "monitor", "notes", "ops", "private", "secrets", "share", "staging", "store", "tools", "wiki",
})
WORDLIST_PATH = Path(__file__).resolve().parents[1] / "wordlists" / "web-content-common.txt"
HINT_TEXT_LIMIT = 65536
MAX_HINT_PATHS = 8
MAX_HINT_IPS = 8
UNSPECIFIED_ADDRESSES = frozenset({"0.0.0.0", "255.255.255.255"})
_IPV4 = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?!\d|\.\d)")
_PATH_TOKEN = re.compile(r"(?:^|[\s'\"(])(/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?)")
_WORD = re.compile(r"[a-z][a-z0-9_-]{2,31}")
_vocabulary_cache: frozenset[str] | None = None


def vocabulary() -> frozenset[str]:
    """HINT_WORDS that also appear in the vendored SecLists list, so every hint word is a real common path name."""
    global _vocabulary_cache
    if _vocabulary_cache is None:
        listed = {line.strip().lower() for line in WORDLIST_PATH.read_text(encoding="utf-8").splitlines()}
        _vocabulary_cache = frozenset(word for word in HINT_WORDS if word in listed)
    return _vocabulary_cache


def _add_hint_text(result: dict[str, Any], text: str) -> None:
    """Keep a bounded copy of the readable text so the orchestrator can mine it for hints after the crawl."""
    if len(result["hint_text"]) < HINT_TEXT_LIMIT:
        result["hint_text"] = (result["hint_text"] + "\n" + text)[:HINT_TEXT_LIMIT]


def hint_paths(text: str, *, known: set[str], limit: int = MAX_HINT_PATHS) -> list[str]:
    """Origin-relative paths the target names itself: exposure words it mentions and path tokens it prints."""
    vocab = vocabulary()
    candidates = [f"/{word}/" for word in dict.fromkeys(_WORD.findall(text.lower())) if word in vocab]
    candidates += _PATH_TOKEN.findall(text)
    chosen: list[str] = []
    for path in candidates:
        if path in known or path in chosen or len(path) > 160 or ".." in path or _state_changing(path):
            continue
        chosen.append(path)
        if len(chosen) >= limit:
            break
    return chosen


def hint_ipv4(text: str) -> list[str]:
    """Dotted-quad addresses the target prints, minus unspecified, broadcast and multicast values."""
    found: list[str] = []
    for address in _IPV4.findall(text):
        if address in UNSPECIFIED_ADDRESSES or address.startswith("0.") or int(address.split(".")[0]) >= 224:
            continue
        if address not in found:
            found.append(address)
        if len(found) >= MAX_HINT_IPS:
            break
    return found


def hint_header_names(text: str) -> list[str]:
    """Hyphenated forwarded-address header names the target mentions; plain 'forwarded' is ordinary prose."""
    return [name for name in KNOWN_FORWARD_HEADERS if "-" in name
            and re.search(rf"(?<![A-Za-z-]){re.escape(name)}(?![A-Za-z-])", text, re.IGNORECASE)]


def _summary(response: Response) -> dict[str, Any]:
    return {"status": response.status, "length": len(response.body),
            "sha256": hashlib.sha256(response.body).hexdigest()[:16]}


def trusted_header_probe(
    ip: str,
    port: int,
    *,
    tls: bool,
    guard: ScopeGuard | None,
    path: str = "/",
    names: list[str],
    values: list[str],
    control_value: str,
    max_requests: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Differential test of a forwarded-address trust decision: an untrusted control value first, then candidates.

    A candidate counts only when the control gets a non-200 answer and the candidate gets a 200 with a body.
    The probe stops at the first revealing candidate, at the request cap, or on a rate-limit signal (HTTP 429).
    """
    result: dict[str, Any] = {"path": path, "requests": 0, "control": None, "revealed": None, "blocked": False,
                              "tried": [], "errors": []}

    def send(headers: dict[str, str]) -> Response | None:
        result["requests"] += 1
        try:
            return request(ip, port, tls=tls, method="GET", target=path, guard=guard, timeout=timeout,
                           headers=headers, purpose="header trust")
        except (OSError, http.client.HTTPException, ValueError) as exc:
            result["errors"].append(type(exc).__name__)
            return None

    if not names or not values or max_requests < 2:
        return result
    control = send({names[0]: control_value})
    if control is None:
        return result
    result["control"] = _summary(control)
    if control.status == 429:
        result["blocked"] = True
        return result
    for name in names:
        for value in values:
            if result["requests"] >= max_requests:
                return result
            candidate = send({name: value})
            if candidate is None:
                continue
            result["tried"].append({"header": name, "value": value, "status": candidate.status,
                                    "length": len(candidate.body)})
            if candidate.status == 429:
                result["blocked"] = True
                return result
            if control.status != 200 and candidate.status == 200 and candidate.body:
                result["revealed"] = {"header": name, "value": value, **_summary(candidate)}
                return result
    return result


#: Endpoint names for the built-in fuzzer (GET only, no action names). Used when ffuf is not installed.
FUZZ_WORDS: tuple[str, ...] = (
    "admin", "administrator", "login", "signin", "console", "panel", "dashboard", "portal", "api", "api/v1",
    "status", "health", "healthz", "metrics", "debug", "logs", "log", "backup", "backups", "bak", "old", "archive",
    "dump", "db", "database", "config", "config.php", "config.json", "config.yml", "settings", ".env", ".git/HEAD",
    ".gitignore", ".htaccess", "robots.txt", "sitemap.xml", "phpinfo.php", "info.php", "test", "tests", "tmp", "temp",
    "cache", "uploads", "files", "file", "downloads", "download", "dl", "bin", "binaries", "binary", "tool", "tools",
    "tool.bin", "app", "app.bin", "server", "server.bin", "service", "daemon", "agent", "client", "readme.txt",
    "README.md", "notes", "notes.txt", "notes.html", "handover", "handover.txt", "todo.txt", "passwords.txt",
    "creds.txt", "credentials.txt", "secrets.txt", "id_rsa", "backup.zip", "backup.tar.gz", "flag", "flag.txt",
    "index.php", "index.html", "login.php", "admin.php", "auth", "auth.php", "user", "users", "account", "accounts",
    "ops", "operations", "monitor", "monitoring", "edr", "scripts", "script.sh", "cgi-bin", "static", "assets",
    "public", "private", "internal", "staging", "dev", "beta", "docs", "swagger.json", "openapi.json", "graphql",
    "wp-admin", "wp-login.php", "phpmyadmin", "server-status", "web.config", "crossdomain.xml", "security.txt",
    "vault",
)
FUZZ_KEEP = frozenset({200, 204, 301, 302, 307, 308, 401, 403})


def fuzz(
    ip: str,
    port: int,
    *,
    tls: bool = False,
    guard: ScopeGuard | None = None,
    words: tuple[str, ...] = FUZZ_WORDS,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """GET each word once and keep answers that differ from a random control path (catch-all filter)."""
    control: Response | None
    try:
        control = request(ip, port, tls=tls, method="GET", target=f"/mitigata-fuzz-{secrets.token_hex(6)}",
                          guard=guard, timeout=timeout, purpose="fuzz control")
    except (OSError, http.client.HTTPException, ValueError):
        control = None
    found: list[dict[str, Any]] = []
    for word in words:
        target = "/" + word.lstrip("/")
        if _state_changing(target):
            continue
        try:
            response = request(ip, port, tls=tls, method="GET", target=target, guard=guard, timeout=timeout,
                               purpose="fuzz")
        except (OSError, http.client.HTTPException, ValueError):
            continue
        if response.status not in FUZZ_KEEP:
            continue
        if control is not None and (response.status, len(response.body)) == (control.status, len(control.body)):
            continue  # the random path gets the same answer: a catch-all, not an endpoint
        found.append({
            "path": public_path(target), "target": target, "status": response.status,
            "length": len(response.body), "content_type": response.content_type[:60],
            "binary": response.body[:4] == b"\x7fELF" or response.body[:2] == b"MZ"
            or target.lower().endswith(BINARY_SUFFIXES),
            "source": "builtin-fuzz",
        })
    return found


def banner_safe(text: str) -> str:
    """Drop control characters from a pre-authentication banner before storing it."""
    return "".join(ch if ch in "\n\r\t" or 32 <= ord(ch) < 127 else "." for ch in text)[:1024]
