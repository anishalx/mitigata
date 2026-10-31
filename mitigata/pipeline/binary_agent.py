"""Binary agent: offline static triage of supplied ELF/PE artifacts. Nothing is executed.

Output separates three things on purpose:

* facts about the file (hash, format, ELF protections);
* unverified leads (unsafe libc imports, credential-like literals);
* the literal values themselves, returned in memory only so the verification
  agent can test them against a live, in-scope service. The orchestrator stores
  values in the run's private secret file and never in events or reports.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from pathlib import Path
from typing import Any

from ..surfaces.binary import MAX_BINARY_SIZE, analyze_binary

PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 1
DT_NULL = 0
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x08000000
ET_DYN = 3

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,128}")
_INLINE = re.compile(
    r"(?i)(passkey|pass_key|passphrase|password|passwd|secret|api[_-]?key|auth[_-]?key|access[_-]?token)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9_!@#$%^&*+\-.~]{4,64})"
)
_KEYWORD = re.compile(r"(?i)passkey|pass_key|passphrase|password|passwd|secret|auth|token|api[_-]?key")
# user:password pairs in an authentication context, e.g. "--basic-auth elastic:changeme" or "credentials: ops:Pass1!"
_PAIR = re.compile(
    r"(?i)(?:--basic-auth|--user|-u|basic[ _-]?auth|credentials?|login)\s*[:=]?\s*['\"]?"
    r"([A-Za-z][A-Za-z0-9_.@-]{1,31}):([^\s'\"<>,;()\[\]{}]{4,64})"
)
_PLACEHOLDER = re.compile(r"[<>{}%]")
# A statically recognisable x86-64 XOR checker: movzx edx,[rax+encoded]; and esi,period-1;
# xor edx,ecx; xor dl,[rsi+mask]; cmp input byte; loop. Only ELF bytes are read.
_X86_XOR_COMPARE_LOOP = re.compile(
    rb"\x0f\xb6\x90(?P<encoded>.{4})"
    rb"\x48\x89\xc6"
    rb"\x83\xe6(?P<period>.)"
    rb"\x31\xca"
    rb"\x32\x96(?P<mask>.{4})"
    rb"(?:\x3a|\x38)\x14\x03\x75."
    rb"\x48\x83\xc0\x01"
    rb"\x83\xc1(?P<step>.)"
    rb"\x48\x83\xf8(?P<count>.)\x75.",
    re.DOTALL,
)
_X86_XOR_SEED = re.compile(rb"\xb9(?P<seed>.{4})\x31\xc0", re.DOTALL)
_STOP = frozenset({
    "password", "passkey", "passphrase", "secret", "authorized", "authorised", "everyone", "protocol",
    "reference", "disconnect", "begin", "note", "token", "error", "usage",
})
MAX_LITERALS = 6
LITERAL_WINDOW = 512


def extract_strings(data: bytes, limit: int = 50_000) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for match in _PRINTABLE.finditer(data):
        found.append((match.start(), match.group().decode("ascii")))
        if len(found) >= limit:
            break
    return found


_FILE_SUFFIXES = frozenset({"zip", "tar", "gz", "txt", "bin", "php", "html", "htm", "json", "xml", "log", "conf",
                            "cfg", "py", "sh", "exe", "elf", "c", "h", "js", "css", "md", "yml", "yaml", "ini"})


def looks_like_pair_secret(value: str) -> bool:
    """A password written after a user name in an auth context: shape checks only, no digit requirement."""
    if not 4 <= len(value) <= 64 or any(ch.isspace() for ch in value):
        return False
    if _PLACEHOLDER.search(value) or any(ch in value for ch in "/\\\"'") or value.lower() in _STOP:
        return False
    return not ("." in value and value.rsplit(".", 1)[-1].lower() in _FILE_SUFFIXES)


def looks_like_secret(value: str) -> bool:
    if not 4 <= len(value) <= 64 or any(ch.isspace() for ch in value):
        return False
    # Quotes and backslashes are excluded so the value survives JSON escaping unchanged.
    if _PLACEHOLDER.search(value) or any(ch in value for ch in "/\\\"'") or value.startswith("-"):
        return False
    if value.lower() in _STOP or value.upper() in {"AUTH", "HELP", "EXIT"}:
        return False
    if "." in value and value.rsplit(".", 1)[-1].lower() in _FILE_SUFFIXES:
        return False  # a file name such as tool.c or backup.zip, not a credential
    has_letter = any(ch.isalpha() for ch in value)
    # A dot or dash alone does not make a credential: it must contain a digit or a strong symbol.
    has_digit_or_symbol = any(ch.isdigit() or ch in "!@#$%^&*+~" for ch in value)
    return has_letter and has_digit_or_symbol


def auth_literals(strings: list[tuple[int, str]], *, max_values: int = MAX_LITERALS) -> list[dict[str, Any]]:
    """Rank credential-like literals: explicit ``key=value`` first, then nearby strings after an auth keyword."""
    best: dict[str, dict[str, Any]] = {}

    def offer(value: str, offset: int, via: str, keyword: str, score: float, user: str | None = None) -> None:
        current = best.get(value)
        if current is None or score > current["score"]:
            best[value] = {"value": value, "offset": offset, "via": via, "keyword": keyword, "score": score,
                           "user": user}

    for offset, text in strings:
        for match in _INLINE.finditer(text):
            value = match.group(2)
            if looks_like_secret(value):
                offer(value, offset + match.start(2), "inline", match.group(1).lower(), 3.0)
        for match in _PAIR.finditer(text):
            value = match.group(2)
            if looks_like_pair_secret(value):
                offer(value, offset + match.start(2), "pair", "basic-auth", 2.5, user=match.group(1))

    for index, (offset, text) in enumerate(strings):
        if len(text) > 64 or len(text.split()) > 2 or not _KEYWORD.search(text):
            continue
        keyword = _KEYWORD.search(text).group(0).lower()  # type: ignore[union-attr]
        for neighbour in range(index + 1, min(index + 4, len(strings))):
            n_offset, n_text = strings[neighbour]
            distance = n_offset - offset
            if distance > LITERAL_WINDOW:
                break
            if looks_like_secret(n_text):
                offer(n_text, n_offset, "adjacent", keyword, 2.0 - distance / (LITERAL_WINDOW * 2))
        if index > 0 and offset - strings[index - 1][0] <= LITERAL_WINDOW and looks_like_secret(strings[index - 1][1]):
            offer(strings[index - 1][1], strings[index - 1][0], "adjacent", keyword, 1.0)

    ranked = sorted(best.values(), key=lambda item: (-item["score"], item["offset"]))
    return ranked[:max_values]


def _elf_load_segments(data: bytes) -> list[tuple[int, int, int]]:
    """Return ``(virtual_address, file_offset, file_size)`` for ELF64 LOAD segments."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return []
    try:
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 54)
    except struct.error:
        return []
    if phentsize < 56:
        return []
    segments: list[tuple[int, int, int]] = []
    for index in range(phnum):
        base = phoff + index * phentsize
        if base + 56 > len(data):
            break
        p_type = struct.unpack_from("<I", data, base)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_offset = struct.unpack_from("<Q", data, base + 8)[0]
        p_vaddr = struct.unpack_from("<Q", data, base + 16)[0]
        p_filesz = struct.unpack_from("<Q", data, base + 32)[0]
        segments.append((p_vaddr, p_offset, p_filesz))
    return segments


def _file_offset_for_va(segments: list[tuple[int, int, int]], va: int, size: int) -> int | None:
    for vaddr, file_offset, file_size in segments:
        if vaddr <= va and va + size <= vaddr + file_size:
            relative = va - vaddr
            if 0 <= relative and relative + size <= file_size:
                return file_offset + relative
    return None


def obfuscated_xor_literals(data: bytes) -> list[dict[str, Any]]:
    """Recover passkeys from one statically-recognisable x86-64 XOR checker.

    The function only reads ELF bytes. It requires an explicit ``passkey``
    context string, file-backed table addresses, a power-of-two mask period,
    and a printable credential-shaped result. Anything else is left as an
    unverified static lead rather than guessed or executed.
    """
    strings = extract_strings(data)
    if not any("passkey" in text.lower() for _offset, text in strings):
        return []
    segments = _elf_load_segments(data)
    if not segments:
        return []
    recovered: dict[str, dict[str, Any]] = {}
    for match in _X86_XOR_COMPARE_LOOP.finditer(data):
        period = match.group("period")[0] + 1
        count = match.group("count")[0]
        step = match.group("step")[0]
        if not (1 <= count <= 64 and 1 <= period <= 32 and period & (period - 1) == 0 and step):
            continue
        prefix = data[max(0, match.start() - 32):match.start()]
        seeds = list(_X86_XOR_SEED.finditer(prefix))
        if not seeds:
            continue
        seed = struct.unpack("<I", seeds[-1].group("seed"))[0] & 0xFF
        encoded_va = struct.unpack("<I", match.group("encoded"))[0]
        mask_va = struct.unpack("<I", match.group("mask"))[0]
        encoded_offset = _file_offset_for_va(segments, encoded_va, count)
        mask_offset = _file_offset_for_va(segments, mask_va, period)
        if encoded_offset is None or mask_offset is None:
            continue
        encoded = data[encoded_offset:encoded_offset + count]
        mask = data[mask_offset:mask_offset + period]
        text = ""
        rolling = seed
        for index in range(count):
            text += chr(encoded[index] ^ rolling ^ mask[index & (period - 1)])
            rolling = (rolling + step) & 0xFF
        if not looks_like_secret(text):
            continue
        recovered.setdefault(text, {
            "value": text,
            "offset": encoded_offset,
            "via": "x86_xor_compare",
            "keyword": "passkey",
            "score": 3.5,
            "user": None,
        })
    return sorted(recovered.values(), key=lambda item: (item["offset"], item["value"]))


def recover_auth_literals(data: bytes, *, max_values: int = MAX_LITERALS) -> list[dict[str, Any]]:
    """Combine plaintext and narrowly decoded static authentication literals."""
    best: dict[str, dict[str, Any]] = {}
    for literal in [*auth_literals(extract_strings(data), max_values=max_values), *obfuscated_xor_literals(data)]:
        current = best.get(literal["value"])
        if current is None or literal["score"] > current["score"]:
            best[literal["value"]] = literal
    return sorted(best.values(), key=lambda item: (-item["score"], item["offset"]))[:max_values]


def elf_protections(data: bytes) -> dict[str, Any]:
    """Read PIE, NX, RELRO and stack-protector facts from ELF headers; no execution."""
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return {}
    if data[5] != 1:
        return {"note": "big-endian ELF is not analysed"}
    word = data[4]
    try:
        if word == 2:
            e_type = struct.unpack_from("<H", data, 16)[0]
            e_phoff = struct.unpack_from("<Q", data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
            ph_fmt, ph_size, dyn_fmt = "<IIQQQQQQ", 56, "<qQ"
        elif word == 1:
            e_type = struct.unpack_from("<H", data, 16)[0]
            e_phoff = struct.unpack_from("<I", data, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
            ph_fmt, ph_size, dyn_fmt = "<IIIIIIII", 32, "<iI"
        else:
            return {"note": "unknown ELF class"}
        pie = e_type == ET_DYN
        nx = True
        relro = False
        bind_now = False
        for index in range(e_phnum):
            base = e_phoff + index * e_phentsize
            if base + ph_size > len(data):
                return {"error": "truncated program header table"}
            if word == 2:
                p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from(ph_fmt, data, base)
            else:
                p_type, p_offset, _vaddr, _paddr, p_filesz, _memsz, p_flags, _align = struct.unpack_from(ph_fmt, data, base)
            if p_type == PT_GNU_STACK:
                nx = not (p_flags & PF_X)
            elif p_type == PT_GNU_RELRO:
                relro = True
            elif p_type == PT_DYNAMIC:
                bind_now = bind_now or _dynamic_bind_now(data, p_offset, p_filesz, dyn_fmt)
        return {
            "class": "ELF64" if word == 2 else "ELF32",
            "pie": pie,
            "nx": nx,
            "relro": "full" if relro and bind_now else ("partial" if relro else "none"),
            "stack_protector_symbol": b"__stack_chk_fail" in data,
        }
    except struct.error:
        return {"error": "truncated ELF headers"}


def _dynamic_bind_now(data: bytes, offset: int, size: int, entry_fmt: str) -> bool:
    entry_size = struct.calcsize(entry_fmt)
    for position in range(offset, min(offset + size, len(data) - entry_size + 1), entry_size):
        tag, value = struct.unpack_from(entry_fmt, data, position)
        if tag == DT_NULL:
            break
        if (tag == DT_FLAGS and value & DF_BIND_NOW) or (tag == DT_FLAGS_1 and value & DF_1_NOW):
            return True
    return False


def triage(path: Path, quarantine_root: Path) -> dict[str, Any]:
    """Static triage of one artifact; copies it read-only into quarantine when it is ELF/PE."""
    result = analyze_binary(str(path))
    summary: dict[str, Any] = {
        "name": path.name,
        "source_path": str(path),
        "sha256": result["sha256"],
        "format": result["format"],
        "size": result["size"],
        "unsafe_imports": list(result["unsafe_imports"]),
        "secret_lead_count": len(result["secret_candidates"]),
        "protections": {},
        "literals": [],
        "artifact": None,
        "errors": [message for message in result["errors"] if not message.startswith("Static-only")],
    }
    if not result["format"]:
        summary["rejected"] = True
        return summary
    if result["size"] > MAX_BINARY_SIZE:
        summary["rejected"] = True
        return summary
    data = path.read_bytes()
    sha = result["sha256"]
    summary["protections"] = elf_protections(data) if result["format"] == "elf" else {"note": "PE protections not analysed"}
    summary["literals"] = recover_auth_literals(data)

    destination = quarantine_root / sha / "artifact"
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name("artifact.tmp")
        digest = hashlib.sha256(data).hexdigest()
        temporary.write_bytes(data)
        if digest != sha:
            temporary.unlink(missing_ok=True)
            summary["rejected"] = True
            summary["errors"].append("artifact changed during quarantine")
            return summary
        os.chmod(temporary, 0o400)
        os.replace(temporary, destination)
    summary["artifact"] = str(destination)
    return summary
