"""argv-only subprocess wrapper (design §11.3).

No shells, no string interpolation, bounded time, and the whole process group
is killed on expiry so a tool cannot leave children sending traffic.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

_ACTIVE: set[subprocess.Popen[str]] = set()
_ACTIVE_LOCK = threading.Lock()


@dataclass(frozen=True)
class Result:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def terminate_active() -> int:
    """Kill every child still running under this process (best effort, process groups).

    Used when a run is interrupted or reaches its deadline: subprocesses are started in
    their own session, so they would otherwise keep scanning after the parent exits.
    """
    with _ACTIVE_LOCK:
        processes = list(_ACTIVE)
    killed = 0
    for process in processes:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            killed += 1
        except (ProcessLookupError, PermissionError, OSError):
            continue
    return killed


def run(
    argv: Sequence[str],
    *,
    timeout: float = 30.0,
    stdin_text: str | None = None,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Result:
    """Execute ``argv`` with a hard timeout and process-group kill."""
    if not argv:
        raise ValueError("argv must not be empty")
    started = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        cwd=str(cwd) if cwd is not None else None,
        env=None if env is None else {**os.environ, **env},
    )
    with _ACTIVE_LOCK:
        _ACTIVE.add(process)
    timed_out = False
    try:
        try:
            stdout, stderr = process.communicate(stdin_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE.discard(process)
    return Result(
        argv=tuple(argv),
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout or "",
        stderr=stderr or "",
        timed_out=timed_out,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
