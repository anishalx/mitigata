"""Loopback lab simulator used by the pipeline tests (no root, no external network).

It stands in for the hackathon target so the whole pipeline can be exercised
offline. Each service mirrors one kind of lead the engine must handle:

* a PHP-style web app with a login form, a reflected parameter and a sensitive path;
* an HTTP Basic-auth log monitor whose password is only recoverable from the binary;
* a line protocol that prints a banner, requires ``AUTH <passkey>`` and returns a flag.

The binary is compiled with gcc (when available) and contains the passkey as a
plain string next to the word ``passkey``, which is what static triage looks for.
"""

from __future__ import annotations

import base64
import shutil
import socketserver
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

WEB_PASSWORD = "admin"
BASIC_PASSWORD = "Mon1tor-Pass!"  # only recoverable from the handover notes page, not from the binary
PASSKEY = "Tr4pK3y!x9"  # recoverable from the binary
FLAG = "flag{lab_passkey_captured}"
BANNER = (
    "================================================================\n"
    "        W E L C O M E   T O   T H E   G A M E   Z O N E\n"
    "================================================================\n"
    " Authorized minds get the flag. Everyone else gets this banner.\n\n"
    "   AUTH <passkey>   to begin   (the passkey lives inside a binary\n"
    "                                you had to find and reverse)\n"
    "   HELP             protocol reference\n"
    "   EXIT             disconnect\n\n"
    " note: abusive source addresses are rate limited and blocked.\n"
)
C_SOURCE = """\
#include <stdio.h>
#include <string.h>
static const char passkey_label[] = "passkey";
static const char passkey_value[] = "PASSKEY_PLACEHOLDER";
int main(int argc, char **argv) {
    (void)argv;
    puts(passkey_label);
    return strcmp(argv[0], passkey_value) == 0 ? 0 : (int)strlen(passkey_label) % 7;
}
"""


def build_binary(directory: Path, passkey: str = PASSKEY) -> Path:
    """Compile a small ELF whose rodata carries the passkey; fall back to a hand-made ELF header."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "tool.bin"
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler:
        source = directory / "tool.c"
        source.write_text(C_SOURCE.replace("PASSKEY_PLACEHOLDER", passkey), encoding="utf-8")
        subprocess.run([compiler, "-O0", "-o", str(target), str(source)], check=True, timeout=60)
    else:
        target.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"passkey\x00" + passkey.encode() + b"\x00")
    return target


class _WebHandler(BaseHTTPRequestHandler):
    server_version = "LabWeb/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # noqa: D401 - silence test output
        return

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8",
              headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/":
            self._send(302, b"", headers=(("Location", "/index.php?p="),))
        elif parts.path == "/index.php":
            value = parse_qs(parts.query).get("p", [""])[0]
            body = (
                "<html><head><title>Lab File Manager</title></head><body><h1>Files</h1>"
                f"<div>Path: {value}</div>"
                '<a href="/download/tool.bin">tool</a> <a href="/notes.html">notes</a>'
                '<form method="post" action="/login.php">'
                '<input type="text" name="username"><input type="password" name="password">'
                '<input type="hidden" name="token" value="tok123"><button>Login</button></form>'
                "</body></html>"
            )
            self._send(200, body.encode())
        elif parts.path == "/notes.html":
            body = (
                "<html><head><title>Ops notes</title><script>var hint='password=Zz9!script';</script>"
                "<style>p{color:red}</style></head><body><h1>Ops notes</h1>"
                f"<p>Log monitor login for port 1111: user admin, password: {BASIC_PASSWORD} (rotate after handover)</p>"
                "</body></html>"
            )
            self._send(200, body.encode())
        elif parts.path == "/dashboard.php":
            if "session=ok" in self.headers.get("Cookie", ""):
                self._send(200, b"<html>dashboard <a href='/logout'>logout</a></html>")
            else:
                self._send(302, b"", headers=(("Location", "/index.php?p="),))
        elif parts.path == "/backup":
            self._send(200, b"database backup dump: users table", content_type="text/plain")
        elif parts.path == "/download/tool.bin":
            self._send(200, Path(self.server.binary).read_bytes(), content_type="application/octet-stream")
        else:
            self._send(404, b"not found", content_type="text/plain")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if urlsplit(self.path).path != "/login.php":
            self._send(404, b"not found", content_type="text/plain")
            return
        ok = (form.get("username", [""])[0] == "admin" and form.get("password", [""])[0] == self.server.password
              and form.get("token", [""])[0] == "tok123")
        if ok:
            self._send(302, b"", headers=(("Location", "/dashboard.php"), ("Set-Cookie", "session=ok; Path=/")))
        else:
            self._send(200, b"<html>Invalid credentials<form><input type='password' name='password'></form></html>")


class _BasicHandler(BaseHTTPRequestHandler):
    server_version = "LabLog/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        header = self.headers.get("Authorization", "")
        user = password = ""
        if header.startswith("Basic "):
            user, _, password = base64.b64decode(header[6:]).decode("utf-8", errors="replace").partition(":")
        if (user, password) == ("admin", self.server.password):
            body = b"log monitor: 3 entries"
            self.send_response(200)
        else:
            body = b"authentication required"
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Mitigata Log Monitor"')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class _PasskeyHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(BANNER.encode())
        pid = 4242
        path = "/Desktop/flag"
        crc = f"{(sum(path.encode('ascii')) ^ pid) & 0xFFFFFFFF:x}"
        while True:
            line = self.rfile.readline(256)
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if text.upper().startswith("AUTH "):
                if text[5:] == self.server.passkey:
                    if getattr(self.server, "zone_mode", False):
                        self.wfile.write(
                            f"[+] access granted. welcome to the zone.\n"
                            f"[*] a worker process was spawned for you.  PID: {pid}\n"
                            f"[*] craft a PID request for {path} to capture the flag.\n"
                            f"[*] run HELP for the PIDREQ format.\nzone> ".encode()
                        )
                    else:
                        self.wfile.write(f"AUTHENTICATED. {self.server.flag}\n".encode())
                else:
                    self.wfile.write(b"AUTH denied: invalid passkey\n")
            elif text.upper().startswith("PIDREQ "):
                parts = text.split()
                if getattr(self.server, "zone_mode", False) and parts[1:3] == [str(pid), path] and parts[-1].lower() == crc:
                    self.wfile.write(f"[+] FLAG: {self.server.flag}\nzone> ".encode())
                else:
                    self.wfile.write(b"[-] PIDREQ denied\nzone> ")
            elif text.upper() == "EXIT":
                break
            else:
                self.wfile.write(b"unknown command; try HELP\n")


class _ThreadingTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        # Scanners and banner probes reset connections; that is expected, not a lab fault.
        return


class _QuietHTTP(ThreadingHTTPServer):
    def handle_error(self, request: object, client_address: object) -> None:
        return


class LabSim:
    """Start the three lab services on loopback ephemeral ports; use as a context manager."""

    def __init__(self, workdir: Path, *, zone_mode: bool = False) -> None:
        self.workdir = workdir
        self.binary = build_binary(workdir / "binaries")
        self.web = _QuietHTTP(("127.0.0.1", 0), _WebHandler)
        self.web.binary = str(self.binary)  # type: ignore[attr-defined]
        self.web.password = WEB_PASSWORD  # type: ignore[attr-defined]
        self.basic = _QuietHTTP(("127.0.0.1", 0), _BasicHandler)
        self.basic.password = BASIC_PASSWORD  # type: ignore[attr-defined]
        self.passkey = _ThreadingTCP(("127.0.0.1", 0), _PasskeyHandler)
        self.passkey.passkey = PASSKEY  # type: ignore[attr-defined]
        self.passkey.flag = FLAG  # type: ignore[attr-defined]
        self.passkey.zone_mode = zone_mode  # type: ignore[attr-defined]
        self._threads: list[threading.Thread] = []

    @property
    def ports(self) -> dict[str, int]:
        return {
            "web": self.web.server_address[1],
            "basic": self.basic.server_address[1],
            "passkey": self.passkey.server_address[1],
        }

    def __enter__(self) -> "LabSim":
        for server in (self.web, self.basic, self.passkey):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def __exit__(self, *exc: object) -> None:
        for server in (self.web, self.basic, self.passkey):
            server.shutdown()
            server.server_close()


def write_lab_manifest(
    path: Path,
    *,
    window: str = "2020-01-01T00:00:00Z/2035-01-01T00:00:00Z",
    auth_tests: bool = True,
    max_auth_attempts: int = 8,
    focus_note: str = "",
) -> Path:
    """Write a loopback-only manifest for the simulator (127.0.0.1/32, binaries/ next to the manifest)."""
    path.write_text(f"""# {focus_note or 'loopback lab simulator'}
engagement:
  name: "lab-sim"
  tier: "recon"
  authorised_by: "loopback test harness"
  window: "{window}"
  description: "local simulator"
scope:
  ipv4: ["127.0.0.1/32"]
  binaries: ["binaries/*"]
limits:
  max_auth_attempts_per_account: {max_auth_attempts}
checks:
  auth_tests: {'true' if auth_tests else 'false'}
flags:
  patterns: ['flag\\{{[^}}]+\\}}']
report:
  formats: ["md", "html", "json"]
""", encoding="utf-8")
    return path
