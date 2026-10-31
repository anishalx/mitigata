from __future__ import annotations

from mitigata.suspicion import flag_hosts


def test_datastore_and_remote_services_raise_the_score():
    hosts = [{
        "ip": "192.168.60.82",
        "state": "tested",
        "ports": [
            {"port": 3306, "name": "mysql"},
            {"port": 445, "name": "smb"},
            {"port": 8080, "name": "http"},
        ],
    }]
    flagged = flag_hosts(hosts)
    assert len(flagged) == 1
    entry = flagged[0]
    assert entry["ip"] == "192.168.60.82"
    assert entry["score"] == 7 + 6 + 2
    assert entry["level"] == "high"
    assert any("MySQL" in reason for reason in entry["reasons"])


def test_cleartext_http_is_low_and_tls_only_is_not_flagged():
    flagged = flag_hosts([{"ip": "10.0.0.5", "state": "tested", "ports": [{"port": 80, "name": "http"}]}])
    assert flagged[0]["level"] == "low"
    assert "cleartext HTTP" in flagged[0]["reasons"][0]
    assert flag_hosts([{"ip": "10.0.0.6", "state": "tested", "ports": [{"port": 443, "name": "https"}]}]) == []


def test_ssh_alone_is_low_and_results_are_sorted():
    hosts = [
        {"ip": "10.0.0.9", "state": "tested", "ports": [{"port": 22, "name": "ssh"}]},
        {"ip": "10.0.0.7", "state": "tested", "ports": [{"port": 2375, "name": "docker"}]},
    ]
    flagged = flag_hosts(hosts)
    assert [entry["ip"] for entry in flagged] == ["10.0.0.7", "10.0.0.9"]
    assert flagged[0]["level"] == "medium"
    assert flagged[1]["level"] == "low"


def test_many_services_add_a_reason():
    ports = [{"port": port, "name": "tcp"} for port in (80, 443, 22, 8000, 9000, 9090)]
    entry = flag_hosts([{"ip": "10.0.0.4", "state": "tested", "ports": ports}])[0]
    assert any("open services" in reason for reason in entry["reasons"])


def test_hosts_without_ports_are_ignored():
    assert flag_hosts([{"ip": "10.0.0.1", "state": "untested", "ports": []}]) == []
