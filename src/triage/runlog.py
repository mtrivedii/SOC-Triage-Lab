"""Per-call run records (plan Sprint 3 / design principle 6).

Each triage call is logged as one JSON line with: model, prompt version + hash,
temperature, run index, token counts, estimated cost, latency, validity, the parsed
result (or the raw text + error on invalid), and the guardrail report. Cost is an
estimate from config/prices.toml ("as if paid"); free-tier usage is really $0.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_prices(path: str | Path | None = None) -> dict:
    path = Path(path) if path else ROOT / "config" / "prices.toml"
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def runs_path(root: Path | None = None) -> Path:
    return (root or ROOT) / "results" / "runs.jsonl"


def estimate_cost(
    provider: str, model: str, tokens_in: int | None, tokens_out: int | None, prices: dict
) -> float | None:
    """USD estimate, or None if token counts are unknown. 0.0 when prices are unset."""
    if tokens_in is None or tokens_out is None:
        return None
    rate = prices.get(provider, {}).get(model, {})
    cost = (
        tokens_in / 1_000_000 * rate.get("input_per_1m", 0.0)
        + tokens_out / 1_000_000 * rate.get("output_per_1m", 0.0)
    )
    return round(cost, 6)


def build_record(
    call,
    *,
    provider: str,
    model: str,
    prompt_version: str,
    prompt_hash: str,
    temperature: float,
    run_index: int,
    case_id: str,
    alert_id: str,
    prices: dict,
    guardrails=None,
) -> dict:
    """Assemble a JSON-serialisable run record from a client.CallResult."""
    # Imported here to avoid a circular import at module load.
    from triage.llm.schema import TriageResult

    valid = isinstance(call.result, TriageResult)
    return {
        "ts": datetime.now(UTC).isoformat(),
        "case_id": case_id,
        "alert_id": alert_id,
        "provider": provider,
        "model": model,
        "prompt_version": prompt_version,
        "prompt_hash": prompt_hash,
        "temperature": temperature,
        "run_index": run_index,
        "latency_s": round(call.latency_s, 3),
        "tokens_in": call.tokens_in,
        "tokens_out": call.tokens_out,
        "est_cost_usd": estimate_cost(provider, model, call.tokens_in, call.tokens_out, prices),
        "attempts": call.attempts,
        "valid": valid,
        "result": call.result.model_dump(mode="json") if valid else None,
        "raw_response": call.raw,
        "error": None if valid else call.result.error,
        "guardrails": asdict(guardrails) if is_dataclass(guardrails) else None,
    }


def append_record(record: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
