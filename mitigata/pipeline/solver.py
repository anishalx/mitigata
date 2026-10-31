"""Offline solver for input checks that print a success or failure message.

The target binary is only ever run inside angr's symbolic emulator: no native process starts and no socket opens.
A candidate is returned only after a concrete emulated run with that candidate prints the success marker and not
the failure marker. The live authentication check stays a separate, bounded step owned by the verifier.

angr is an optional dependency. Without it, ``solve`` reports ``unavailable`` and the run records a gap.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

SUCCESS_WORDS = re.compile(r"\b(accepted|granted|welcome|authori[sz]ed|correct|success)\b", re.IGNORECASE)
FAILURE_WORDS = re.compile(r"\b(denied|invalid|wrong|incorrect|rejected|failed)\b", re.IGNORECASE)
_STRLEN_ASSIGNMENT = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*strlen\s*\(")
MIN_ARGV_LENGTH = 1
MAX_ARGV_LENGTH = 128
MAX_MARKER_LENGTH = 120


_available: bool | None = None


def available() -> bool:
    """True when angr and claripy import cleanly; a broken or mismatched install counts as unavailable."""
    global _available
    if _available is None:
        try:
            import angr  # noqa: F401,PLC0415 - optional dependency
            import claripy  # noqa: F401,PLC0415
            _available = True
        except Exception:  # noqa: BLE001 - any import failure means this solver cannot run here
            _available = False
    return _available


def _as_int(text: str) -> int:
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def argv_length(decompiled: str) -> int | None:
    """Length that the decompiler shows for an equality check on strlen(...), e.g. ``n = strlen(argv[1]); if (n != 0x10)``."""
    for assignment in _STRLEN_ASSIGNMENT.finditer(decompiled):
        name = re.escape(assignment.group(1))
        check = re.search(rf"\b{name}\s*(?:!=|==)\s*(0x[0-9a-fA-F]+|\d+)\b", decompiled)
        if check:
            value = _as_int(check.group(1))
            if MIN_ARGV_LENGTH <= value <= MAX_ARGV_LENGTH:
                return value
    return None


_CMP_IMMEDIATE = re.compile(r"\bcmp\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)\b")


def argv_length_from_listing(lines: list[str]) -> int | None:
    """Length from a disassembly listing: the first immediate compared just after a call to strlen."""
    for index, line in enumerate(lines):
        if "strlen" not in line:
            continue
        for follower in lines[index + 1: index + 7]:
            match = _CMP_IMMEDIATE.search(follower)
            if match:
                value = _as_int(match.group(1))
                if MIN_ARGV_LENGTH <= value <= MAX_ARGV_LENGTH:
                    return value
                break
    return None


def stdout_markers(strings: list[str]) -> tuple[str | None, str | None]:
    """First short printable string that reads as success, and first that reads as failure."""
    success = next((text for text in strings if len(text) <= MAX_MARKER_LENGTH and SUCCESS_WORDS.search(text)), None)
    failure = next((text for text in strings if len(text) <= MAX_MARKER_LENGTH and FAILURE_WORDS.search(text)), None)
    return success, failure


def _printable(text: str) -> bool:
    return all(0x20 <= ord(char) <= 0x7E for char in text)


def confirm_concrete(path: Path, candidate: str, *, success: str, failure: str, timeout_s: float) -> bool:
    """Run the emulator once with the concrete candidate; True only if the success marker printed and the failure did not."""
    import angr  # noqa: PLC0415 - optional dependency, imported only when the solver runs

    project = angr.Project(str(path), auto_load_libs=False)
    state = project.factory.full_init_state(args=[str(path), candidate])
    simgr = project.factory.simgr(state)
    started = time.monotonic()
    while simgr.active and time.monotonic() - started < timeout_s:
        simgr.step()
    for done in simgr.stashes.get("deadended", []) + simgr.active:
        output = done.posix.dumps(1)
        if success.encode() in output and failure.encode() not in output:
            return True
    return False


def solve(path: Path, *, length: int, success: str, failure: str, timeout_s: float) -> dict[str, Any]:
    """Find an input of ``length`` printable bytes whose emulated run prints ``success`` and not ``failure``."""
    if not available():
        return {"status": "unavailable", "reason": "angr is not installed", "seconds": 0.0}
    import angr  # noqa: PLC0415
    import claripy  # noqa: PLC0415

    started = time.monotonic()
    project = angr.Project(str(path), auto_load_libs=False)
    symbolic = claripy.BVS("argv1", 8 * length)
    state = project.factory.full_init_state(args=[str(path), symbolic])
    for byte in symbolic.chop(8):
        state.solver.add(byte >= 0x20, byte <= 0x7E)
    success_bytes, failure_bytes = success.encode(), failure.encode()
    simgr = project.factory.simgr(state)
    steps = 0
    while simgr.active and time.monotonic() - started < timeout_s and not simgr.stashes.get("found"):
        simgr.step()
        steps += 1
        simgr.move(from_stash="active", to_stash="found", filter_func=lambda s: success_bytes in s.posix.dumps(1))
        simgr.move(from_stash="active", to_stash="avoided", filter_func=lambda s: failure_bytes in s.posix.dumps(1))
    elapsed = round(time.monotonic() - started, 1)
    found_states = simgr.stashes.get("found", [])
    if not found_states:
        return {"status": "not_found" if not simgr.active else "timeout", "steps": steps, "seconds": elapsed}
    candidate = found_states[0].solver.eval(symbolic, cast_to=bytes).decode("ascii", errors="replace")
    if len(candidate) != length or not _printable(candidate):
        return {"status": "invalid", "steps": steps, "seconds": elapsed}
    remaining = max(5.0, timeout_s - (time.monotonic() - started))
    if not confirm_concrete(path, candidate, success=success, failure=failure, timeout_s=remaining):
        return {"status": "unconfirmed", "steps": steps, "seconds": round(time.monotonic() - started, 1)}
    return {"status": "verified", "candidate": candidate, "steps": steps,
            "seconds": round(time.monotonic() - started, 1)}
