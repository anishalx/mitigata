"""Solver parsing always runs; the angr tests run only when angr and gcc are installed."""

from __future__ import annotations

import shutil

import pytest

from mitigata.pipeline import solver

from .chain_lab import COMPUTED_PASSKEY, FAILURE, SUCCESS, build_computed

HAS_ANGR = solver.available()
HAS_GCC = shutil.which("gcc") is not None


def test_argv_length_reads_hex_and_decimal_equality_checks():
    hex_style = "undefined8 main(int argc, char **argv) {\n  size_t sVar1;\n  sVar1 = strlen(argv[1]);\n  if (sVar1 != 0x10) {"
    decimal_style = "int main(void) {\n  n = strlen(argv[1]);\n  if (n == 12) {"
    assert solver.argv_length(hex_style) == 16
    assert solver.argv_length(decimal_style) == 12


def test_argv_length_is_none_without_a_strlen_check_or_with_an_implausible_value():
    assert solver.argv_length("int main(void) { return 0; }") is None
    assert solver.argv_length("n = strlen(argv[1]);\nif (n != 0x1000) {") is None


def test_argv_length_reads_the_comparison_after_a_strlen_call_in_a_listing():
    listing = [
        "|   0x00401071      e8caffffff     call sym.imp.strlen",
        "|   0x00401076      4883f810       cmp rax, 0x10               ; 16",
        "|   0x0040107c      75d9           jne 0x401100",
    ]
    assert solver.argv_length_from_listing(listing) == 16
    assert solver.argv_length_from_listing(["call sym.imp.puts", "cmp rax, 0x10"]) is None


def test_stdout_markers_pick_short_success_and_failure_strings():
    strings = ["hello", "[+] access granted", "x" * 200 + " granted", "[-] access denied"]
    assert solver.stdout_markers(strings) == ("[+] access granted", "[-] access denied")
    assert solver.stdout_markers(["plain text"]) == (None, None)


def test_solve_reports_unavailable_when_angr_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(solver, "available", lambda: False)
    result = solver.solve(tmp_path / "missing", length=16, success=SUCCESS, failure=FAILURE, timeout_s=5)
    assert result["status"] == "unavailable"


@pytest.mark.skipif(not (HAS_ANGR and HAS_GCC), reason="needs angr and gcc in this environment")
def test_concrete_emulation_accepts_the_right_candidate_and_rejects_a_wrong_one(tmp_path):
    binary = build_computed(tmp_path / "bin")
    assert solver.confirm_concrete(binary, COMPUTED_PASSKEY, success=SUCCESS, failure=FAILURE, timeout_s=240)
    assert not solver.confirm_concrete(binary, "A" * 16, success=SUCCESS, failure=FAILURE, timeout_s=240)


@pytest.mark.skipif(not (HAS_ANGR and HAS_GCC), reason="needs angr and gcc in this environment")
def test_angr_recovers_a_computed_passkey_from_the_emulated_check(tmp_path):
    binary = build_computed(tmp_path / "bin")
    result = solver.solve(binary, length=16, success=SUCCESS, failure=FAILURE, timeout_s=300)
    assert result["status"] == "verified", result
    assert result["candidate"] == COMPUTED_PASSKEY
