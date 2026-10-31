"""Trusted egress policy (design §3.2, §6.2).

The ruleset is generated from the compiled scope and installed by a trusted
initializer. Untrusted workers never hold the ability to edit it: workers get a
default-drop policy plus an authenticated control channel, nothing else.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
from typing import Sequence

from .scope import CompiledScope
from .tools.runner import run

DEFAULT_TABLE = "mitigata_egress"
NETWORK_WORKERS = frozenset({"mitigata.surfaces.network", "mitigata.surfaces.web"})


class PolicyError(RuntimeError):
    """Enforcement could not be installed or verified; the run must not proceed."""


def _set(name: str, kind: str, elements: Sequence[str], indent: str = "\t") -> list[str]:
    if not elements:
        return []
    body = ", ".join(elements)
    return [f"{indent}set {name} {{", f"{indent}\ttype {kind}", f"{indent}\tflags interval", f"{indent}\telements = {{ {body} }}", f"{indent}}}"]


def render_nftables(scope: CompiledScope, *, control_ips: Sequence[str] = (), table: str = DEFAULT_TABLE) -> str:
    """Render a default-drop egress ruleset for one worker namespace."""
    v4 = [str(net) for net in scope.allowlist if net.version == 4]
    v6 = [str(net) for net in scope.allowlist if net.version == 6]
    blocked_v4 = [str(net) for net in scope.exclude if net.version == 4]
    blocked_v6 = [str(net) for net in scope.exclude if net.version == 6]

    control_v4: list[str] = []
    control_v6: list[str] = []
    for entry in control_ips:
        address = ipaddress.ip_address(entry)
        (control_v4 if address.version == 4 else control_v6).append(str(address))

    lines = [f"# mitigata compiled scope {scope.scope_hash}", f"table inet {table} {{"]
    lines += _set("allowed_v4", "ipv4_addr", v4)
    lines += _set("allowed_v6", "ipv6_addr", v6)
    lines += _set("blocked_v4", "ipv4_addr", blocked_v4)
    lines += _set("blocked_v6", "ipv6_addr", blocked_v6)
    lines += _set("control_v4", "ipv4_addr", control_v4)
    lines += _set("control_v6", "ipv6_addr", control_v6)
    lines += [
        "\tchain output {",
        "\t\ttype filter hook output priority 0; policy drop;",
    ]
    if blocked_v4:
        lines.append("\t\tip daddr @blocked_v4 drop")
    if blocked_v6:
        lines.append("\t\tip6 daddr @blocked_v6 drop")
    if control_v4:
        lines.append("\t\tip daddr @control_v4 accept")
    if control_v6:
        lines.append("\t\tip6 daddr @control_v6 accept")
    if v4:
        lines.append("\t\tip daddr @allowed_v4 accept")
    if v6 and not scope.block_ipv6:
        lines.append("\t\tip6 daddr @allowed_v6 accept")
    lines += ["\t}", "}"]
    return "\n".join(lines) + "\n"




def namespace_table(scope: CompiledScope) -> str:
    """A per-scope table avoids accepting stale policy from another run."""
    return f"mitigata_{scope.scope_hash[:12]}"


def _namespace_prefix(namespace: str) -> list[str]:
    import re

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", namespace):
        raise PolicyError("a named, isolated network namespace is required")
    if not all(shutil.which(tool) for tool in ("ip", "nft", "setpriv")):
        raise PolicyError("ip, nft and setpriv must be installed for target-facing workers")
    if os.geteuid() != 0:
        raise PolicyError("network namespace policy installation requires a trusted root initializer")
    prefix = ["ip", "netns", "exec", namespace]
    identity = run([*prefix, "readlink", "/proc/self/ns/net"], timeout=5)
    if not identity.ok or identity.stdout.strip() == os.readlink("/proc/self/ns/net"):
        raise PolicyError("worker namespace is absent or is the host network namespace")
    return prefix


def install_in_namespace(
    scope: CompiledScope, namespace: str, *, control_ips: Sequence[str] = ()
) -> str:
    """Replace and verify this scope's policy inside an isolated namespace."""
    prefix = _namespace_prefix(namespace)
    table = namespace_table(scope)
    # A prior interrupted run can leave the fail-closed table behind. Workers
    # have not started yet, so replacing only this scope's table is safe.
    run([*prefix, "nft", "delete", "table", "inet", table], timeout=5)
    rules = render_nftables(scope, control_ips=control_ips, table=table)
    result = run([*prefix, "nft", "-f", "-"], stdin_text=rules, timeout=20)
    if not result.ok:
        raise PolicyError(f"namespace policy install failed: {result.stderr.strip()[:400]}")
    if not run([*prefix, "nft", "list", "table", "inet", table], timeout=5).ok:
        raise PolicyError("namespace egress policy could not be verified")
    return table


def remove_in_namespace(scope: CompiledScope, namespace: str) -> None:
    """Remove this run's table after all network workers have stopped."""
    prefix = _namespace_prefix(namespace)
    table = namespace_table(scope)
    result = run([*prefix, "nft", "delete", "table", "inet", table], timeout=10)
    if not result.ok:
        raise PolicyError(f"namespace policy cleanup failed: {result.stderr.strip()[:400]}")


def worker_command(namespace: str, scope: CompiledScope, module: str, args: Sequence[str]) -> list[str]:
    """Route a trusted worker through the protected namespace without admin capabilities."""
    if module not in NETWORK_WORKERS:
        raise PolicyError(f"unrecognized network worker: {module}")
    prefix = _namespace_prefix(namespace)
    table = namespace_table(scope)
    if not run([*prefix, "nft", "list", "table", "inet", table], timeout=5).ok:
        raise PolicyError("namespace egress policy disappeared; refusing to launch worker")
    import sys

    return [
        *prefix, "setpriv",
        "--reuid=65534", "--regid=65534", "--clear-groups",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
        "--no-new-privs", "--", sys.executable, "-m", module, *args,
    ]
