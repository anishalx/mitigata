"""Optional LLM planner on the DeepSeek official API (OpenAI-compatible chat completions).

The planner chooses among candidates that the target itself named: paths it printed, forwarded-address header names
and addresses it mentioned. It cannot add paths, headers or addresses, and it cannot confirm a finding. Every
selection still passes the manifest gates and the scope guard. It is off unless the manifest enables it and the
environment variable named by the manifest (DEEPSEEK_API_KEY by default) is set. Excerpts are redacted before they
leave the host, and the key never appears in events, errors or reports.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

from ..models import LLMSection

DEFAULT_TIMEOUT_S = 30.0
MAX_OUTPUT_TOKENS = 600
MAX_WHY_CHARS = 300
MAX_REPLY_BYTES = 262_144
MAX_PROPOSED_ITEMS = 20
SYSTEM_PROMPT = (
    "You help an authorized penetration-test lab choose which of the target's own hints to test next. "
    "Choose only from the candidate lists in the user message. Never invent paths, header names or addresses. "
    "Reply with a single JSON object with the keys \"probe_paths\" (an array of candidate paths, most promising "
    "first), \"trusted_header\" (an object with \"name\" and \"value\" taken from the candidates, or null) and "
    "\"why\" (one short sentence). Reply with the JSON object only."
)
_FLAG = re.compile(r"[A-Za-z0-9_]{2,12}\{[^{}\n]{1,200}\}")
_SECRET = re.compile(
    r"(?i)\b(password|passwd|passkey|secret|token|api[_-]?key|authorization|set-cookie|cookie)\b\s*[:=]\s*\S+")

Transport = Callable[[str, dict[str, str], bytes, float], bytes]


class PlannerError(RuntimeError):
    """A short, key-free reason. The run records it as a gap and continues without the planner."""


def redact(text: str) -> str:
    """Mask flags and credential-looking pairs before any excerpt leaves the host."""
    return _SECRET.sub(lambda match: f"{match.group(1)}: [redacted]", _FLAG.sub("[redacted-flag]", text))


@dataclass(frozen=True)
class Selection:
    probe_paths: tuple[str, ...]
    trusted_header: tuple[str, str] | None
    why: str
    rejected: tuple[str, ...]
    sent_sha256: str
    sent_chars: int


def _urllib_transport(url: str, headers: dict[str, str], payload: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - https endpoint from the manifest
            return response.read(MAX_REPLY_BYTES)
    except urllib.error.HTTPError as exc:
        raise PlannerError(f"the planner endpoint answered HTTP {exc.code}") from None
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        raise PlannerError(f"the planner endpoint was unreachable ({type(exc).__name__})") from None


def _validate(proposal: Any, *, candidate_paths: list[str], candidate_headers: list[str],
              candidate_values: list[str], sent: str) -> Selection:
    rejected: list[str] = []
    accepted: list[str] = []
    raw_paths = proposal.get("probe_paths") if isinstance(proposal, dict) else None
    for item in (raw_paths if isinstance(raw_paths, list) else [])[:MAX_PROPOSED_ITEMS]:
        if isinstance(item, str) and item in candidate_paths and item not in accepted:
            accepted.append(item)
        else:
            rejected.append(f"path {str(item)[:80]!r}")
    header: tuple[str, str] | None = None
    raw_header = proposal.get("trusted_header") if isinstance(proposal, dict) else None
    if isinstance(raw_header, dict):
        name, value = raw_header.get("name"), raw_header.get("value")
        if name in candidate_headers and value in candidate_values:
            header = (str(name), str(value))
        else:
            rejected.append(f"header {str(name)[:40]!r} with value {str(value)[:40]!r}")
    why = str(proposal.get("why", "")) if isinstance(proposal, dict) else ""
    return Selection(
        probe_paths=tuple(accepted), trusted_header=header, why=redact(why)[:MAX_WHY_CHARS],
        rejected=tuple(rejected[:10]), sent_sha256=hashlib.sha256(sent.encode("utf-8")).hexdigest(),
        sent_chars=len(sent),
    )


class DeepSeekPlanner:
    """One chat completion per call: JSON output, thinking disabled, temperature 0, bounded reply size."""

    provider = "deepseek"

    def __init__(self, section: LLMSection, *, api_key: str, transport: Transport | None = None) -> None:
        self.model = section.model
        self.base_url = section.base_url.rstrip("/")
        self.max_excerpt_chars = section.max_excerpt_chars
        self._api_key = api_key
        self._transport: Transport = transport or _urllib_transport

    def request_body(self, context_json: str) -> dict[str, Any]:
        return {
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": context_json}],
            "response_format": {"type": "json_object"},
            "thinking": {"type": "disabled"},
            "temperature": 0,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "stream": False,
        }

    def select(self, context: dict[str, Any], *, candidate_paths: list[str], candidate_headers: list[str],
               candidate_values: list[str]) -> Selection:
        excerpt = redact(str(context.get("text_excerpt", "")))[: self.max_excerpt_chars]
        sent_context = {**context, "text_excerpt": excerpt, "candidate_paths": candidate_paths,
                        "candidate_headers": candidate_headers, "candidate_values": candidate_values}
        context_json = json.dumps(sent_context, sort_keys=True)
        payload = json.dumps(self.request_body(context_json)).encode("utf-8")
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
        raw = self._transport(f"{self.base_url}/chat/completions", headers, payload, DEFAULT_TIMEOUT_S)
        try:
            content = json.loads(raw.decode("utf-8"))["choices"][0]["message"]["content"]
            proposal = json.loads(content)
        except (ValueError, KeyError, IndexError, TypeError):
            raise PlannerError("the planner reply was not the expected JSON") from None
        return _validate(proposal, candidate_paths=candidate_paths, candidate_headers=candidate_headers,
                         candidate_values=candidate_values, sent=context_json)


def build_planner(section: LLMSection, environ: Mapping[str, str] | None = None) -> tuple[DeepSeekPlanner | None, str]:
    """The planner, or None with the reason it is not running. The key is read here and nowhere else."""
    if not section.enabled:
        return None, "disabled in the manifest"
    key = (environ if environ is not None else os.environ).get(section.api_key_env, "").strip()
    if not key:
        return None, f"enabled, but {section.api_key_env} is not set in the environment"
    return DeepSeekPlanner(section, api_key=key), "ready"
