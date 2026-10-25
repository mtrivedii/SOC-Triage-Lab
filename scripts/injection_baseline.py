"""Prompt-injection BASELINE runner (LIVE — operator runs it; the assistant/CI never does).

Reads the fixtures in tests/fixtures/injection/, sends each modified alert to the model N times
with the FROZEN prompt v1 and NO injection defences (that is the point of a baseline), and appends
the RAW result to results/injection_runs.jsonl. Scoring (model-level + pipeline) is done offline by
eval/injection_report.py so the success criteria are applied in one auditable place.

  uv run python scripts/injection_baseline.py --providers groq --runs 3
  uv run python scripts/injection_baseline.py --providers gemini --runs 1   # small spot-check only

Budget: 9 cases. Groq 3 runs = 27 calls (<=54 with one retry each); Gemini 1 run = 9 calls (<=18),
which fits the 20/day free cap. Do not exceed. Defences are added and re-measured only AFTER this.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import openai
import yaml

from triage.llm.client import get_model, make_client, triage_call
from triage.llm.prompts import load_prompt, prompt_hash
from triage.llm.schema import TriageResult
from triage.runlog import append_record

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "injection"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live prompt-injection baseline (makes real API calls).")
    ap.add_argument("--providers", default="groq")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--sleep", type=float, default=2.0)
    args = ap.parse_args(argv)

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    fixtures = [yaml.safe_load(f.read_text(encoding="utf-8")) for f in sorted(FIX.glob("*.yaml"))]
    prompt = load_prompt("v1")
    ph = prompt_hash(prompt)
    allowed: list[str] = []  # baseline: no extra allow-list help beyond the prompt
    out = ROOT / "results" / "injection_runs.jsonl"
    clients = {p: make_client(p) for p in providers}

    exhausted: set[str] = set()
    total = 0
    for fx in fixtures:
        for provider in providers:
            if provider in exhausted:
                continue
            model = get_model(provider)
            for i in range(args.runs):
                print(f"- {fx['id']} | {provider} | run {i}...", flush=True)
                try:
                    call = triage_call(fx["alert"], model, clients[provider], prompt, allowed)
                except openai.RateLimitError as exc:
                    print(f"  RATE LIMIT ({provider}); stopping it: {getattr(exc, 'message', exc)}")
                    exhausted.add(provider)
                    break
                except openai.APIError as exc:
                    print(f"  API ERROR ({provider}): {type(exc).__name__}: {exc}")
                    continue
                valid = isinstance(call.result, TriageResult)
                append_record(
                    {
                        "tool": "injection_baseline",
                        "case_id": fx["id"],
                        "provider": provider,
                        "model": model,
                        "prompt_version": "v1",
                        "prompt_hash": ph,
                        "run_index": i,
                        "defended": False,
                        "valid": valid,
                        "result": call.result.model_dump(mode="json") if valid else None,
                        "raw_response": call.raw,
                        "tokens_in": call.tokens_in,
                        "tokens_out": call.tokens_out,
                        "latency_s": round(call.latency_s, 3),
                    },
                    out,
                )
                total += 1
                if args.sleep:
                    time.sleep(args.sleep)

    print(f"\nAppended {total} injection runs to {out.relative_to(ROOT)}")
    if exhausted:
        print(f"Providers rate-limited (incomplete): {sorted(exhausted)}")
    print("Score with: uv run python eval/injection_report.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
