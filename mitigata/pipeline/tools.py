"""External tools the hunt uses, with detection and the fallback used when a tool is missing.

Lookup order: PATH, then the user prefix (``MITIGATA_TOOLS_DIR``, default
``~/.local/share/mitigata-tools``) that holds binaries unpacked without root.
radare2 needs its shared libraries on ``LD_LIBRARY_PATH``; ``runtime_env`` sets that
for the calls this module makes. Every call is argv-only, time-bounded and
rate-limited by the caller.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from urllib.parse import unquote_plus

from ..tools.runner import run

GHIDRA_SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra"
GHIDRA_SCRIPT = "MitigataExport.java"

FFUF_STATUSES = "200,204,301,302,307,308,401,403"
# ``aa`` is fast enough for large host binaries; ``aaa`` can spend minutes on C++ vtables and
# exceed the tool budget. Ghidra remains the preferred decompiler when it is installed.
R2_SCRIPT = (
    "aa; ?e ---STR; izzj; ?e ---IMP; iij; ?e ---FN; aflj; "
    "?e ---MAIN; pdf @ main; ?e ---DEC; pdg @ main"
)


@dataclass(frozen=True)
class ToolSpec:
    key: str
    binary: str
    purpose: str
    fallback: str
    install_hint: str
    wired: bool = True


SPECS = (
    ToolSpec("nmap", "nmap", "host discovery, full port scan, service versions",
             "none: discovery and port scans need nmap", "sudo apt install nmap"),
    ToolSpec("katana", "katana", "web crawl with JavaScript parsing",
             "built-in same-origin crawler", "install the katana release binary or `go install` it"),
    ToolSpec("ffuf", "ffuf", "endpoint fuzzing",
             "built-in wordlist fuzzer with the same rate limit and filters", "sudo apt install ffuf"),
    ToolSpec("radare2", "r2", "disassembly, strings, imports, functions of supplied binaries",
             "strings and ELF headers only, no disassembly", "sudo apt install radare2"),
    ToolSpec("ghidra", "analyzeHeadless", "headless decompilation to C, functions, imports and strings",
             "radare2 disassembly and strings (no decompiled C)",
             "install Ghidra and put analyzeHeadless on PATH or set GHIDRA_INSTALL_DIR"),
)


def _prefix() -> Path | None:
    configured = os.environ.get("MITIGATA_TOOLS_DIR")
    candidate = Path(configured) if configured else Path.home() / ".local/share/mitigata-tools"
    return candidate if candidate.is_dir() else None


def find(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    prefix = _prefix()
    if prefix is not None:
        for directory in (prefix / "bin", prefix / "usr/bin"):
            candidate = directory / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def ghidra_env() -> dict[str, str]:
    """JAVA_HOME for Ghidra's launcher (a JDK in the user prefix) and the JRE library path its javac needs."""
    env: dict[str, str] = {}
    prefix = _prefix()
    if prefix is not None:
        jdk = prefix / "usr/lib/jvm/java-21-openjdk-amd64"
        if (jdk / "bin/javac").is_file():
            env["JAVA_HOME"] = str(jdk)
    java = shutil.which("java")
    if java:
        jre_lib = Path(java).resolve().parents[1] / "lib"
        if jre_lib.is_dir():
            libs = [str(jre_lib / "jli"), str(jre_lib)]
            existing = os.environ.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = ":".join([*libs, existing] if existing else libs)
    return env


def runtime_env() -> dict[str, str]:
    prefix = _prefix()
    if prefix is None:
        return {}
    libraries = [str(prefix / "usr/lib/x86_64-linux-gnu"), str(prefix / "usr/lib")]
    existing = os.environ.get("LD_LIBRARY_PATH", "")
    return {"LD_LIBRARY_PATH": ":".join([*libraries, existing] if existing else libraries)}


def _ghidra() -> str | None:
    found = find("analyzeHeadless")
    if found:
        return found
    home = os.environ.get("GHIDRA_INSTALL_DIR")
    if home and (Path(home) / "support/analyzeHeadless").is_file():
        return str(Path(home) / "support/analyzeHeadless")
    return None


def detect() -> list[dict[str, Any]]:
    """Availability of every tool, for the run record and the dashboard."""
    rows = []
    for spec in SPECS:
        location = _ghidra() if spec.key == "ghidra" else find(spec.binary)
        rows.append({
            "key": spec.key, "installed": location is not None, "path": location or "",
            "purpose": spec.purpose, "fallback": spec.fallback, "install_hint": spec.install_hint,
            "wired": spec.wired,
        })
    return rows


# -- ffuf (endpoint fuzzing) ----------------------------------------------------

def parse_ffuf_json(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text) if text.strip() else {"results": []}
    except ValueError:
        return []
    found = []
    for item in data.get("results", []):
        word = str((item.get("input") or {}).get("FUZZ", ""))
        if not word or "/" in word:
            continue
        found.append({"path": "/" + word, "status": int(item.get("status") or 0),
                      "length": int(item.get("length") or 0), "source": "ffuf"})
    return found


def ffuf_paths(base_url: str, words: list[str], *, rate: int, timeout_s: float = 900.0) -> list[dict[str, Any]]:
    binary = find("ffuf")
    if binary is None:
        raise RuntimeError("ffuf is not installed")
    with tempfile.TemporaryDirectory(prefix="mitigata-ffuf-") as tmp:
        wordlist = Path(tmp) / "words.txt"
        wordlist.write_text("\n".join(words) + "\n", encoding="utf-8")
        output = Path(tmp) / "out.json"
        argv = [binary, "-u", base_url.rstrip("/") + "/FUZZ", "-w", str(wordlist), "-mc", FFUF_STATUSES,
                "-ac", "-rate", str(max(1, rate)), "-t", "2", "-timeout", "5", "-s",
                "-of", "json", "-o", str(output)]
        completed = run(argv, timeout=timeout_s)
        text = output.read_text(encoding="utf-8", errors="replace") if output.is_file() else ""
    if completed.timed_out:
        raise RuntimeError("ffuf timed out")
    if completed.returncode != 0:
        raise RuntimeError(f"ffuf exited with status {completed.returncode}")
    return parse_ffuf_json(text)


# -- katana (crawl) -----------------------------------------------------------------

def parse_katana_jsonl(text: str, origin: str) -> list[str]:
    """Same-origin paths (with query) from katana's JSON lines; anything else is dropped."""
    paths: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        url = ""
        if isinstance(item, dict):
            request = item.get("request") or {}
            url = str(request.get("endpoint") or item.get("endpoint") or item.get("url") or "")
        if not url.startswith(origin + "/") and url != origin:
            continue
        path = url[len(origin):] or "/"
        if path not in paths:
            paths.append(path)
    return paths


def katana_paths(start_url: str, origin: str, *, rate: int, depth: int = 2, timeout_s: float = 600.0) -> list[str]:
    binary = find("katana")
    if binary is None:
        raise RuntimeError("katana is not installed")
    argv = [binary, "-u", start_url, "-d", str(depth), "-jc", "-silent", "-jsonl",
            "-rl", str(max(1, rate)), "-c", "2", "-timeout", "5", "-cs", "^" + re.escape(origin) + "/"]
    completed = run(argv, timeout=timeout_s)
    if completed.timed_out:
        raise RuntimeError("katana timed out")
    if completed.returncode != 0:
        raise RuntimeError(f"katana exited with status {completed.returncode}")
    return parse_katana_jsonl(completed.stdout, origin)


# -- radare2 (strings, imports, functions, disassembly / decompiler) --------------------

def _section_json(lines: list[str]) -> list[Any]:
    text = "\n".join(lines).strip()
    if not text:
        return []
    try:
        value = json.loads(text)
    except ValueError:
        return []
    return value if isinstance(value, list) else []


def parse_r2_output(text: str) -> dict[str, Any]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("---") and line[3:].isupper():
            current = line[3:]
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    strings = [
        {"vaddr": int(item.get("vaddr") or 0), "string": str(item.get("string", "")),
         "section": str(item.get("section", ""))}
        for item in _section_json(sections.get("STR", []))
        if isinstance(item, dict) and len(str(item.get("string", ""))) >= 4
    ]
    imports = [str(item["name"]) for item in _section_json(sections.get("IMP", []))
               if isinstance(item, dict) and item.get("name")]
    functions = [str(item["name"]) for item in _section_json(sections.get("FN", []))
                 if isinstance(item, dict) and item.get("name")]
    listing = [line for line in sections.get("MAIN", []) if line.strip()]
    decompiled = "\n".join(sections.get("DEC", [])).strip()
    if not decompiled or "install the plugin" in decompiled.lower() or "unknown command" in decompiled.lower():
        decompiled = ""
    return {
        "strings": strings, "imports": imports, "functions": functions,
        "main_listing": listing[:120], "decompiled": decompiled[:4000],
        "decompiler": "r2ghidra" if decompiled else "disassembly",
    }


def r2_analyze(path: Path, *, timeout_s: float = 240.0) -> dict[str, Any]:
    binary = find("r2") or find("radare2")
    if binary is None:
        raise RuntimeError("radare2 is not installed")
    argv = [binary, "-q", "-e", "scr.color=0", "-e", "scr.utf8=false", "-c", R2_SCRIPT, str(path)]
    completed = run(argv, timeout=timeout_s, env=runtime_env())
    if completed.timed_out:
        raise RuntimeError("radare2 timed out")
    if not completed.stdout.strip():
        raise RuntimeError(f"radare2 produced no output (exit {completed.returncode})")
    return parse_r2_output(completed.stdout)


# -- Ghidra (headless decompilation) ---------------------------------------------------

def parse_ghidra_output(text: str) -> dict[str, Any]:
    """Split the tagged lines printed by MitigataExport.java; payloads are URL-encoded by the script."""
    result: dict[str, Any] = {"program": "", "functions": [], "imports": [], "decompiled": [], "strings": [],
                              "complete": False}
    for raw in text.splitlines():
        index = raw.find("MITIGATA_")
        if index < 0:
            continue
        # Ghidra's log appends " (GhidraScript)" and spaces to every printed line: neither is part of a value.
        line = re.sub(r"\s*\(GhidraScript\)\s*$", "", raw[index:]).rstrip()
        fields = line.split("|")
        tag = fields[0]
        if tag == "MITIGATA_PROGRAM" and len(fields) >= 2:
            result["program"] = unquote_plus(fields[1])
        elif tag == "MITIGATA_FUNC" and len(fields) >= 4:
            result["functions"].append({"name": unquote_plus(fields[1]), "entry": fields[2], "size": fields[3]})
        elif tag == "MITIGATA_IMP" and len(fields) >= 2:
            result["imports"].append(unquote_plus(fields[1]))
        elif tag == "MITIGATA_DEC" and len(fields) >= 3:
            result["decompiled"].append({"name": unquote_plus(fields[1]), "c": unquote_plus(fields[2])})
        elif tag == "MITIGATA_STR" and len(fields) >= 3:
            value = unquote_plus(fields[2])
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]  # Ghidra reports defined strings as C literals
            result["strings"].append({"address": fields[1], "string": value})
        elif tag == "MITIGATA_END":
            result["complete"] = True
    return result


def ghidra_analyze(path: Path, *, timeout_s: float = 900.0) -> dict[str, Any]:
    """Import the binary into a throw-away Ghidra project, run auto-analysis and the export script."""
    launcher = _ghidra()
    if launcher is None:
        raise RuntimeError("Ghidra (analyzeHeadless) is not installed")
    with tempfile.TemporaryDirectory(prefix="mitigata-ghidra-") as tmp:
        project = Path(tmp) / "project"
        project.mkdir()
        argv = [launcher, str(project), "mitigata", "-import", str(path), "-scriptPath", str(GHIDRA_SCRIPT_DIR),
                "-postScript", GHIDRA_SCRIPT, "-deleteProject"]
        completed = run(argv, timeout=timeout_s, env=ghidra_env())
    if completed.timed_out:
        raise RuntimeError("Ghidra timed out")
    parsed = parse_ghidra_output(completed.stdout + "\n" + completed.stderr)
    if not parsed["complete"]:
        raise RuntimeError(f"Ghidra export did not complete (exit {completed.returncode})")
    return parsed

