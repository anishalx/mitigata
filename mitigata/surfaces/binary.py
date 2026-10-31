"""Bounded, static ELF/PE string inspection; no binary is executed or decompiled."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct


MAX_BINARY_SIZE = 64 * 1024 * 1024
MAX_SECRET_CANDIDATES = 256
_PRINTABLE_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
_CREDENTIALS = re.compile(
    rb"(?<![A-Za-z0-9_])(?P<name>password|passwd|pwd|api[_-]?key|"
    rb"access[_-]?token|auth[_-]?token|client[_-]?secret|secret|token)"
    rb"[ \t]{0,8}[:=][ \t]{0,8}['\"]?(?P<value>[^\s'\";,}\]\x00]{3,})",
    re.IGNORECASE,
)
_BEARER = re.compile(rb"(?<![A-Za-z0-9_])Bearer[ \t]+[^\s'\";,}\]\x00]{3,}", re.IGNORECASE)
_UNSAFE_IMPORTS = re.compile(
    rb"(?<![A-Za-z0-9_])(?:__imp_|__isoc99_|_)?"
    rb"(?P<name>gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|fscanf|"
    rb"system|popen|execve|WinExec|ShellExecute[AW]|CreateProcess[AW]|"
    rb"lstrcpy[AW]|lstrcat[AW])(?=$|[^A-Za-z0-9_])",
    re.IGNORECASE,
)
_IMPORT_NAMES = {
    "winexec": "WinExec",
    "shellexecutea": "ShellExecuteA",
    "shellexecutew": "ShellExecuteW",
    "createprocessa": "CreateProcessA",
    "createprocessw": "CreateProcessW",
    "lstrcpya": "lstrcpyA",
    "lstrcpyw": "lstrcpyW",
    "lstrcata": "lstrcatA",
    "lstrcatw": "lstrcatW",
}
_STATIC_LIMITATION = (
    "Static-only analysis: decompiler capability unavailable; unsafe_imports and "
    "secret_candidates are unverified printable-string heuristics, not confirmed "
    "imports or credentials."
)


def _format(data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ") and len(data) >= 64:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 4 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            return "pe"
    return ""


def analyze_binary(path: str) -> dict:
    """Report unverified static string leads; offsets point to indicator bytes.

    Values matching credential indicators are never returned, including in errors.
    Files larger than 64 MiB, non-regular files, and non-ELF/PE files are rejected.
    """
    result = {
        "sha256": "",
        "format": "",
        "size": 0,
        "unsafe_imports": [],
        "secret_candidates": [],
        "errors": [],
    }
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                result["errors"].append("Not a regular file.")
                return result
            result["size"] = info.st_size
            if info.st_size > MAX_BINARY_SIZE:
                result["errors"].append("Binary exceeds the 64 MiB limit.")
                return result
            data = source.read(MAX_BINARY_SIZE + 1)
    except (OSError, TypeError, ValueError) as exc:
        # Exception messages can include the caller's path, which may itself be sensitive.
        result["errors"].append(f"Unable to read binary ({type(exc).__name__}).")
        return result

    result["size"] = len(data)
    if len(data) > MAX_BINARY_SIZE:
        result["errors"].append("Binary exceeds the 64 MiB limit.")
        return result
    result["format"] = _format(data)
    if not result["format"]:
        result["errors"].append("Invalid ELF/PE magic or PE signature; scripts and archives are unsupported.")
        return result

    result["sha256"] = hashlib.sha256(data).hexdigest()
    found_imports: set[str] = set()
    truncated = False
    for printable in _PRINTABLE_STRINGS.finditer(data):
        text = memoryview(data)[printable.start() : printable.end()]
        for match in _UNSAFE_IMPORTS.finditer(text):
            name = match.group("name").decode("ascii").lower()
            found_imports.add(_IMPORT_NAMES.get(name, name))
        if len(result["secret_candidates"]) >= MAX_SECRET_CANDIDATES:
            truncated = True
            continue
        for match in _CREDENTIALS.finditer(text):
            name = match.group("name").decode("ascii").lower().replace("-", "_")
            if name in {"password", "passwd", "pwd"}:
                secret_type = "password"
            elif name in {"api_key", "apikey"}:
                secret_type = "api_key"
            elif name in {"access_token", "accesstoken", "auth_token", "authtoken", "token"}:
                secret_type = "token"
            else:
                secret_type = "secret"
            result["secret_candidates"].append(
                {
                    "offset": printable.start() + match.start(),
                    "secret_type": secret_type,
                    "redacted_context": f"{secret_type}=<redacted>",
                    "status": "unverified static string heuristic",
                }
            )
            if len(result["secret_candidates"]) >= MAX_SECRET_CANDIDATES:
                truncated = True
                break
        if len(result["secret_candidates"]) >= MAX_SECRET_CANDIDATES:
            continue
        for match in _BEARER.finditer(text):
            result["secret_candidates"].append(
                {
                    "offset": printable.start() + match.start(),
                    "secret_type": "bearer_token",
                    "redacted_context": "Bearer <redacted>",
                    "status": "unverified static string heuristic",
                }
            )
            if len(result["secret_candidates"]) >= MAX_SECRET_CANDIDATES:
                truncated = True
                break
    result["unsafe_imports"] = sorted(found_imports)
    result["errors"].append(_STATIC_LIMITATION)
    if truncated:
        result["errors"].append("Secret candidate limit reached; results may be incomplete.")
    return result


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("Invalid arguments; expected --path FILE.")


def main(argv: list[str] | None = None) -> int:
    parser = _JsonArgumentParser(description="Static ELF/PE string inspection", add_help=False)
    parser.add_argument("--path", required=True)
    try:
        args = parser.parse_args(argv)
    except ValueError as exc:
        print(json.dumps({"sha256": "", "format": "", "size": 0, "unsafe_imports": [],
                          "secret_candidates": [], "errors": [str(exc)]}))
        return 2
    result = analyze_binary(args.path)
    print(json.dumps(result))
    return 0 if result["format"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
