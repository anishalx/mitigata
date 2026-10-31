from __future__ import annotations

import socket
from typing import Any

import pytest

from mitigata import discovery
from mitigata.scope import compile_scope
from mitigata.store import Store

from .conftest import make_manifest


def test_parse_range_forms():
    assert discovery.parse_range("192.168.60.1-3") == ["192.168.60.1", "192.168.60.2", "192.168.60.3"]
    assert discovery.parse_range("192.168.60.253-254") == ["192.168.60.253", "192.168.60.254"]
    assert discovery.parse_range("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_bare_ipv4_expands_to_its_24():
    hosts = discovery.parse_range("192.168.60.139")
    assert len(hosts) == 254
    assert "192.168.60.139" in hosts
    assert hosts[0] == "192.168.60.1" and hosts[-1] == "192.168.60.254"
    assert discovery.parse_range("fd00::1") == ["fd00::1"]
    with pytest.raises(ValueError, match="not an address, CIDR"):
        discovery.parse_range("192.168.60")
    with pytest.raises(ValueError, match="octet range"):
        discovery.parse_range("192.168.60.9-2")


def test_filter_scope_drops_excluded_and_outside_addresses():
    scope = compile_scope(make_manifest(ipv4=["10.10.5.0/29"], exclude=["10.10.5.3"], dns_resolver=None))
    hosts = ["10.10.5.1", "10.10.5.2", "10.10.5.3", "10.10.5.9"]
    assert discovery.filter_scope(scope, hosts) == ["10.10.5.1", "10.10.5.2"]
    assert discovery.in_scope(scope, "10.10.5.3") is False


@pytest.fixture
def store(tmp_path):
    handle = Store(tmp_path / "blackboard.db")
    handle.create_run(
        "run-1", engagement="unit", tier="recon", scope_hash="a" * 64,
        manifest_sha256="b" * 64, enforcement=discovery.MODE,
    )
    yield handle
    handle.close()


def _result(ip: str, ports: list[int], *, reachable: bool = True) -> dict[str, Any]:
    return {
        "ip": ip, "reachable": reachable,
        "services": [{"port": port, "proto": "tcp", "name": "http"} for port in ports],
        "errors": [],
    }


def test_record_result_persists_asset_service_coverage_and_task(store):
    ports = [80, 443]
    info = discovery.record_result(store, "run-1", _result("10.10.5.2", [80]), ports)
    assert info["ip"] == "10.10.5.2" and info["reachable"] is True
    assert info["ports"] == [{"port": 80, "name": "http", "product": None, "version": None, "extrainfo": None}]
    aggregate = store.aggregate("run-1")
    assert aggregate["assets"] == 1 and aggregate["services"] == 1
    row = store.coverage("run-1")[0]
    assert (row["attack_class"], row["state"]) == ("network.tcp_inventory", "tested")
    tasks = store.tasks("run-1")
    assert [task["kind"] for task in tasks] == ["scan_host"]
    assert tasks[0]["state"] == "done"


def test_record_result_is_idempotent_for_repeated_scans(store):
    ports = [80]
    discovery.record_result(store, "run-1", _result("10.10.5.2", [80]), ports)
    discovery.record_result(store, "run-1", _result("10.10.5.2", [80]), ports)
    assert store.aggregate("run-1")["assets"] == 1
    assert store.aggregate("run-1")["services"] == 1
    assert len(store.tasks("run-1")) == 1


def test_host_discovery_stops_after_first_tcp_response_without_service_inventory(store):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        live_port = listener.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed:
            closed.bind(("127.0.0.1", 0))
            closed_port = closed.getsockname()[1]
        result = discovery.probe(
            "127.0.0.1", [live_port, closed_port], timeout_s=0.5,
            liveness_only=True,
        )
    assert result == {"ip": "127.0.0.1", "reachable": True, "services": [], "errors": []}
    info = discovery.record_result(store, "run-1", result, [live_port, closed_port], liveness_only=True)
    assert info["reachable"] is True and info["ports"] == []
    assert store.aggregate("run-1")["services"] == 0
    assert store.coverage("run-1")[0]["attack_class"] == "network.host_discovery"
    assert store.tasks("run-1")[0]["kind"] == "probe_host"


def test_host_discovery_unknown_can_be_retried_without_claiming_a_service(store):
    discovery.record_result(
        store, "run-1", _result("10.10.5.4", [], reachable=False), [80],
        liveness_only=True,
    )
    assert discovery.untested_hosts(store, "run-1") == ["10.10.5.4"]
    discovery.record_result(
        store, "run-1", _result("10.10.5.4", [80]), [80],
        liveness_only=True,
    )
    assert discovery.untested_hosts(store, "run-1") == []
    assert store.aggregate("run-1")["services"] == 0


def test_record_result_marks_silent_host_untested(store):
    discovery.record_result(store, "run-1", _result("10.10.5.4", [], reachable=False), [80])
    rowa = store.coverage("run-1")[0]
    assert rowa["state"] == "untested"


def test_record_result_rejects_unscheduled_ports(store):
    info = discovery.record_result(store, "run-1", _result("10.10.5.2", [8080]), [80])
    assert info["ports"] == []
    assert store.aggregate("run-1")["services"] == 0


def test_open_run_validates_run_id(tmp_path):
    with pytest.raises(ValueError, match="invalid run id"):
        discovery.open_run(tmp_path, "../etc")
    with pytest.raises(ValueError, match="unknown run"):
        discovery.open_run(tmp_path, "run-20200101T000000Z-abcdef")

