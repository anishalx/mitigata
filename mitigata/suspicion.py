"""Deterministic exposure heuristics over discovered services.

This is triage, not a vulnerability assessment: it ranks hosts whose open
services are worth a human look (datastores, remote administration, container
APIs, many services). No CVE, banner version or exploit inference is made.
"""

from __future__ import annotations

from typing import Any

# port -> (weight, description)
DIRECT_RULES: dict[int, tuple[int, str]] = {
    3306: (7, "MySQL exposed"),
    5432: (7, "PostgreSQL exposed"),
    6379: (8, "Redis exposed (often unauthenticated)"),
    27017: (7, "MongoDB exposed"),
    9200: (6, "Elasticsearch exposed"),
    11211: (6, "memcached exposed"),
    1433: (7, "MSSQL exposed"),
    1521: (7, "Oracle database exposed"),
    9042: (7, "Cassandra exposed"),
    5984: (6, "CouchDB exposed"),
    2375: (9, "Docker API exposed without TLS"),
    2376: (8, "Docker API exposed over TLS"),
    2379: (8, "etcd client API exposed"),
    6443: (8, "Kubernetes API server exposed"),
    10250: (8, "kubelet API exposed"),
    10255: (6, "kubelet read-only port exposed"),
    3389: (7, "RDP exposed"),
    5900: (7, "VNC exposed"),
    23: (7, "Telnet exposed"),
    21: (5, "FTP exposed"),
    22: (3, "SSH exposed"),
    80: (2, "cleartext HTTP (no TLS)"),
    445: (6, "SMB exposed"),
    139: (4, "NetBIOS/SMB exposed"),
    111: (4, "rpcbind exposed"),
}

ALT_HTTP_PORTS = frozenset({3000, 8000, 8008, 8080, 8443, 8888, 9000, 9090})
MANY_SERVICES_THRESHOLD = 5
LEVELS = ((15, "high"), (8, "medium"), (1, "low"))


def flag_hosts(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return flagged hosts sorted by score, each with its human-readable reasons."""
    flagged: list[dict[str, Any]] = []
    for host in hosts:
        ports = host.get("ports") or []
        if not ports:
            continue
        score = 0
        reasons: list[str] = []
        for service in ports:
            port = service.get("port")
            name = str(service.get("name") or "tcp")
            rule = DIRECT_RULES.get(port)
            if rule is not None:
                weight, description = rule
                score += weight
                reasons.append(f"{port}/{name}: {description}")
            elif port in ALT_HTTP_PORTS:
                score += 2
                reasons.append(f"{port}/{name}: alternate HTTP interface")
        if len(ports) >= MANY_SERVICES_THRESHOLD:
            score += 3
            reasons.append(f"{len(ports)} open services on one host")
        if not score:
            continue
        level = next(label for threshold, label in LEVELS if score >= threshold)
        flagged.append({"ip": host["ip"], "score": score, "level": level, "reasons": reasons})
    return sorted(flagged, key=lambda host: (-host["score"], host["ip"]))
