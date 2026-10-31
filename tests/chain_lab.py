"""Loopback simulator for the forwarded-header chain: edge proxy, file share, wiki, vault, computed-check binary.

It mirrors the hackathon writeup without touching any real host: the edge answers 502 unless the request carries the
trusted core-router address in X-Forwarded-For; the handover note in the open file share names that address and the
header; the wiki mentions an unlinked "vault"; the vault lists a binary whose passkey is computed, not stored.
Test values only. The real passkey and flag never appear in this repository.
"""

from __future__ import annotations

import subprocess
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from .lab_sim import FLAG, _PasskeyHandler, _QuietHTTP, _ThreadingTCP

MASK = b"mitigata"
#: Test-only value, 16 bytes like the check in C_TEMPLATE. Not the hackathon passkey.
COMPUTED_PASSKEY = "C0mput3d_K3y_Lab"
CORE_ROUTER = "10.44.0.1"
TRUST_HEADER = "X-Forwarded-For"
UNTRUSTED_VALUE = "203.0.113.7"  # RFC 5737 documentation range; never trusted by the edge
SUCCESS = "access granted"
FAILURE = "access denied"

C_TEMPLATE = """\
#include <stdio.h>
#include <string.h>
static const unsigned char enc[16] = { __ENC__ };
static const char mask[8] = "mitigata";
int main(int argc, char **argv) {
    if (argc < 2 || strlen(argv[1]) != 16) {
        printf("[-] access denied\\n");
        return 1;
    }
    for (int i = 0; i < 16; i++) {
        unsigned char want = enc[i] ^ (unsigned char)(0x0d + 7 * i) ^ (unsigned char)mask[i % 8];
        if ((unsigned char)argv[1][i] != want) {
            printf("[-] access denied\\n");
            return 1;
        }
    }
    printf("[+] access granted\\n");
    return 0;
}
"""

FILE_MANAGER_HTML = (b"<html><body><h1>File share</h1><ul>"
                     b"<li><a href='/share/ops/netops-handover.txt'>ops/netops-handover.txt</a></li>"
                     b"</ul></body></html>")
HANDOVER_TEXT = (b"NetOps handover\n"
                 b"The edge proxy only answers the wiki and the vault for requests that arrive from the core router "
                 + CORE_ROUTER.encode() + b". It checks the " + TRUST_HEADER.encode() + b" header.\n")
WIKI_HTML = (b"<html><head><title>Hidden Wiki</title></head><body><h1>Infra</h1>"
             b"<p>Staged artifacts live in the artifact vault. The vault index is not linked from this page.</p>"
             b"</body></html>")
VAULT_HTML = (b"<html><body><h1>Index of /vault/</h1><ul>"
              b"<li><a href='/vault/keykeeper'>keykeeper</a> (binary, these are real binaries)</li>"
              b"</ul></body></html>")


def _encoded(passkey: str) -> list[int]:
    return [ord(char) ^ ((0x0D + 7 * index) & 0xFF) ^ MASK[index % 8] for index, char in enumerate(passkey)]


def build_computed(directory: Path, passkey: str = COMPUTED_PASSKEY) -> Path:
    """Compile the lab binary: the passkey never appears as text, only as an XOR-encoded table."""
    directory.mkdir(parents=True, exist_ok=True)
    build = directory.parent / "build"  # the C source stays out of the binaries folder that the tool scans
    build.mkdir(parents=True, exist_ok=True)
    source = build / "computed.c"
    binary = directory / "keykeeper"
    values = ", ".join(f"0x{byte:02x}" for byte in _encoded(passkey))
    source.write_text(C_TEMPLATE.replace("__ENC__", values), encoding="utf-8")
    subprocess.run(["gcc", "-O0", "-o", str(binary), str(source)], check=True)
    return binary


class _ChainHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # noqa: D401 - silence test output
        return

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/index.php":
            return self._send(200, FILE_MANAGER_HTML)
        if path == "/share/ops/netops-handover.txt":
            return self._send(200, HANDOVER_TEXT, "text/plain; charset=utf-8")
        trusted = self.headers.get(TRUST_HEADER, "").strip() == CORE_ROUTER
        if not trusted:
            return self._send(502, b"<h1>502 Bad Gateway</h1>")
        if path == "/":
            return self._send(200, WIKI_HTML)
        if path == "/vault/":
            return self._send(200, VAULT_HTML)
        if path == "/vault/keykeeper":
            return self._send(200, self.server.binary_bytes, "application/octet-stream")  # type: ignore[attr-defined]
        return self._send(404, b"not found")


class ChainLab:
    """Edge (HTTP) and computed-check passkey service on loopback ephemeral ports; use as a context manager."""

    def __init__(self, workdir: Path) -> None:
        self.binary = build_computed(workdir / "binaries")
        self.edge = _QuietHTTP(("127.0.0.1", 0), _ChainHandler)
        self.edge.binary_bytes = self.binary.read_bytes()  # type: ignore[attr-defined]
        self.passkey = _ThreadingTCP(("127.0.0.1", 0), _PasskeyHandler)
        self.passkey.passkey = COMPUTED_PASSKEY  # type: ignore[attr-defined]
        self.passkey.flag = FLAG  # type: ignore[attr-defined]
        self.passkey.zone_mode = True  # type: ignore[attr-defined]
        self._threads: list[threading.Thread] = []

    @property
    def ports(self) -> dict[str, int]:
        return {"web": self.edge.server_address[1], "passkey": self.passkey.server_address[1]}

    def __enter__(self) -> "ChainLab":
        for server in (self.edge, self.passkey):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def __exit__(self, *exc: object) -> None:
        for server in (self.edge, self.passkey):
            server.shutdown()
            server.server_close()


def write_chain_manifest(path: Path, *, header_hosts: tuple[str, ...] = ("127.0.0.1",), max_requests: int = 30) -> Path:
    """Loopback-only manifest with the explicit header-trust entry that the hackathon manifest also carries."""
    hosts = ", ".join(f'"{host}"' for host in header_hosts)
    path.write_text(f"""# chain lab: loopback only
engagement:
  name: "chain-lab"
  tier: "breach"
  authorised_by: "loopback test harness"
  window: "2020-01-01T00:00:00Z/2035-01-01T00:00:00Z"
  description: "local forwarded-header chain simulator"
scope:
  ipv4: ["127.0.0.1/32"]
  binaries: ["binaries/*"]
limits:
  max_auth_attempts_per_account: 8
checks:
  auth_tests: true
  header_trust:
    enabled: true
    hosts: [{hosts}]
    max_requests: {max_requests}
flags:
  patterns: ['flag\\{{[^}}]+\\}}']
report:
  formats: ["md", "html", "json"]
""", encoding="utf-8")
    return path
