"""Thin wrapper around the OpenAI SDK for triage calls.

Model id comes from config/models.toml and the base URL from config/providers.toml;
nothing is hard-coded. ``triage()`` takes an injected ``client``, so unit tests pass a
fake and no real API is called. ``make_client()`` / ``run_triage()`` are for live use on
the operator's machine only (they read keys from .env and hit the network).
"""

from __future__ import annotations

import json
import os
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from triage.llm.prompts import load_prompt
from triage.llm.schema import InvalidResult, TriageResult, parse_triage

ROOT = Path(__file__).resolve().parents[3]

# Explicit request timeout so a stuck call (e.g. a slow Gemini request) fails cleanly
# with a timeout error instead of hanging on library/OS defaults.
DEFAULT_TIMEOUT_S = 240.0


def _load_toml(name: str) -> dict:
    with open(ROOT / "config" / name, "rb") as fh:
        return tomllib.load(fh)


def get_model(provider: str) -> str:
    return _load_toml("models.toml")[provider]["model"]


def _cap_line(line: str, limit: int) -> str:
    if len(line) <= limit:
        return line
    return line[:limit] + f" [truncated {len(line) - limit} chars]"


def build_messages(
    system_prompt: str, alert: dict, allowed_techniques: list[str], cap_fields: int | None = None
) -> list[dict[str, str]]:
    """System prompt + a user message that separates trusted alert facts from the
    untrusted log evidence (wrapped in markers the prompt tells the model to distrust).

    Defence 3 (input caps): when ``cap_fields`` is set, each evidence line sent to the model is
    truncated to that many characters (marked ``[truncated N chars]``). The alert keeps the full
    raw lines for humans; only the model's copy is capped.
    """
    meta = {k: v for k, v in alert.items() if k != "evidence_lines"}
    ev_lines = alert.get("evidence_lines", [])
    if cap_fields:
        ev_lines = [_cap_line(line, cap_fields) for line in ev_lines]
    evidence = "\n".join(ev_lines)
    user = (
        "ALERT (structured facts, trusted):\n"
        + json.dumps(meta, indent=2, default=str)
        + "\n\nALLOWED TECHNIQUE IDS: "
        + (", ".join(allowed_techniques) or "(none)")
        + "\n\n<<<UNTRUSTED_LOG_DATA\n"
        + evidence
        + "\nUNTRUSTED_LOG_DATA>>>"
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user},
    ]


@dataclass
class CallResult:
    """A triage call plus the metrics needed for the run log (plan Sprint 3)."""

    result: TriageResult | InvalidResult
    raw: str
    tokens_in: int | None
    tokens_out: int | None
    latency_s: float
    attempts: int


def _usage(resp) -> tuple[int | None, int | None]:
    usage = getattr(resp, "usage", None)
    if usage is None:
        return None, None
    return getattr(usage, "prompt_tokens", None), getattr(usage, "completion_tokens", None)


def triage_call(
    alert: dict,
    model: str,
    client,
    system_prompt: str,
    allowed_techniques: list[str],
    temperature: float = 0.0,
    max_retries: int = 1,
    notify: Callable[[str], None] | None = None,
    cap_fields: int | None = None,
) -> CallResult:
    """Call the model, validate, retry once on invalid output, and capture metrics
    (tokens, latency, attempts, raw response). ``client`` must expose
    ``chat.completions.create`` like the OpenAI SDK; tests inject a fake. ``notify``, if
    given, is called with a short status string before each request (so a slow call does
    not look frozen). A request timeout raised by the client propagates unchanged.
    ``cap_fields`` applies Defence 3 (evidence field caps) to the model's copy only.
    """
    messages = build_messages(system_prompt, alert, allowed_techniques, cap_fields=cap_fields)
    raw = ""
    error = ""
    attempts = 0
    tokens_in: int | None = None
    tokens_out: int | None = None
    parsed: TriageResult | None = None
    start = time.perf_counter()
    for _ in range(max_retries + 1):
        attempts += 1
        if notify is not None:
            notify(f"calling model {model} (attempt {attempts})...")
        resp = client.chat.completions.create(
            model=model, messages=messages, temperature=temperature
        )
        raw = resp.choices[0].message.content or ""
        tokens_in, tokens_out = _usage(resp)
        try:
            parsed = parse_triage(raw)
            break
        except (ValidationError, ValueError) as exc:
            error = str(exc)
    latency = time.perf_counter() - start
    result: TriageResult | InvalidResult = (
        parsed if parsed is not None else InvalidResult(raw=raw, error=error, attempts=attempts)
    )
    return CallResult(result, raw, tokens_in, tokens_out, latency, attempts)


def triage(
    alert: dict,
    model: str,
    client,
    system_prompt: str,
    allowed_techniques: list[str],
    temperature: float = 0.0,
    max_retries: int = 1,
) -> TriageResult | InvalidResult:
    """Thin wrapper returning just the validated result (or InvalidResult)."""
    return triage_call(
        alert, model, client, system_prompt, allowed_techniques, temperature, max_retries
    ).result


def make_client(provider: str, timeout: float = DEFAULT_TIMEOUT_S):
    """Build a real OpenAI-SDK client for a provider, with an explicit request timeout.
    Reads the key from .env. Only used for live runs on the operator's machine.
    """
    import openai
    from dotenv import load_dotenv

    providers = _load_toml("providers.toml")[provider]
    load_dotenv(ROOT / ".env")
    key = os.environ.get(providers["api_key_env"])
    if not key:
        raise RuntimeError(f"{providers['api_key_env']} not set in .env")
    return openai.OpenAI(api_key=key, base_url=providers["base_url"], timeout=timeout)


def run_triage(alert: dict, provider: str, allowed_techniques: list[str], version: str = "v1"):
    """Live convenience wrapper (operator machine only): build a real client and triage."""
    return triage(  # pragma: no cover - live use only
        alert,
        get_model(provider),
        make_client(provider),
        load_prompt(version),
        allowed_techniques,
    )
