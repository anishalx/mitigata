from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mitigata.surfaces import nmap

SAMPLE = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <scaninfo type="connect" protocol="tcp" numservices="65535" services="1-65535"/>
  <host>
    <status state="up"/>
    <address addr="192.168.60.82" addrtype="ipv4"/>
    <ports>
      <extraports state="filtered" count="65532"/>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba" version="4.15.13" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0.36"/>
      </port>
      <port protocol="tcp" portid="139">
        <state state="closed"/>
        <service name="netbios-ssn"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

FAKE = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    f"XML = {SAMPLE!r}\n"
    "args = sys.argv[1:]\n"
    "path = args[args.index('-oX') + 1]\n"
    "open(path, 'w').write(XML)\n"
)


def test_parse_xml_normalizes_open_services():
    parsed = nmap.parse_xml(SAMPLE, "192.168.60.82")
    assert parsed["ip"] == "192.168.60.82"
    assert parsed["reachable"] is True
    assert parsed["closed_ports"] == 1
    assert parsed["filtered_ports"] == 65532
    assert parsed["ports_scanned"] == 65535
    assert [service["port"] for service in parsed["services"]] == [445, 3306]
    assert parsed["services"][0]["product"] == "Samba"
    assert parsed["services"][0]["version"] == "4.15.13"
    assert parsed["services"][1]["name"] == "mysql"


def test_parse_xml_reports_down_host():
    parsed = nmap.parse_xml(
        '<nmaprun><host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/>'
        "<ports/></host></nmaprun>"
    )
    assert parsed["reachable"] is False and parsed["services"] == []


def test_parse_xml_rejects_documents_without_a_host():
    with pytest.raises(ValueError, match="no host element"):
        nmap.parse_xml("<nmaprun/>")


def _fake_nmap(tmp_path: Path) -> Path:
    script = tmp_path / "nmap"
    script.write_text(FAKE)
    script.chmod(0o755)
    return script


def test_scan_nmap_parses_output_from_the_binary(tmp_path: Path):
    result, xml_text = nmap.scan_nmap("192.168.60.82", [139, 445, 3306], binary=str(_fake_nmap(tmp_path)))
    assert result["errors"] == [] and result["scanner"] == "nmap"
    assert [service["port"] for service in result["services"]] == [445, 3306]
    assert nmap.parse_xml(xml_text)["services"][1]["version"] == "8.0.36"

def test_full_tcp_scan_requests_every_port_and_parses_open_services(tmp_path: Path):
    binary = _fake_nmap(tmp_path)
    command = nmap.build_command(str(binary), "192.168.60.82", None, tmp_path / "scan.xml")
    assert command[command.index("-p") + 1] == "1-65535"
    assert command[command.index("--max-rate") + 1] == "1000"
    assert "-sV" in command and "-sT" in command
    result, _ = nmap.scan_nmap("192.168.60.82", binary=str(binary))
    assert result["ports_scanned"] == 65535
    assert result["services"][0]["product"] == "Samba"

def test_incomplete_nmap_scan_is_not_reported_as_success():
    xml = SAMPLE.replace("</nmaprun>", '<runstats><finished exit="error" errormsg="Host timeout"/></runstats></nmaprun>')
    parsed = nmap.parse_xml(xml)
    assert parsed["errors"] == ["Host timeout"]


def test_scan_nmap_reports_a_missing_binary(tmp_path: Path):
    result, xml_text = nmap.scan_nmap("192.168.60.82", [80], binary=str(tmp_path / "absent"))
    assert xml_text == ""
    assert "not found" in result["errors"][0]


def test_scan_nmap_validates_arguments(tmp_path: Path):
    with pytest.raises(ValueError, match="numeric"):
        nmap.scan_nmap("example.com", [80], binary=str(_fake_nmap(tmp_path)))
    with pytest.raises(ValueError, match="ports"):
        nmap.scan_nmap("10.10.5.2", [], binary=str(_fake_nmap(tmp_path)))


def test_module_cli_emits_json(tmp_path: Path):
    completed = subprocess.run(
        [sys.executable, "-m", "mitigata.surfaces.nmap",
         "--ip", "192.168.60.82", "--ports", "445,3306", "--binary", str(_fake_nmap(tmp_path))],
        capture_output=True, text=True, check=False,
    )
    payload = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert payload["xml_bytes"] > 0 and len(payload["services"]) == 2
