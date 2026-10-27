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
from datetime import UTC, datetime
from pathlib import Path

import openai

from triage.injection import load_injection_fixtures
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
    ap.add_argument("--cases", default="", help="comma-separated fixture ids; default = all")
    ap.add_argument(
        "--config", choices=["v1", "v2"], default="v1",
        help="v1 = prompt v1, no caps (baseline/control); v2 = prompt v2 + field caps (defended)",
    )
    ap.add_argument("--include-held-out", action="store_true",
                    help="include held_out fixtures (defended v2 or v1 control runs only)")
    ap.add_argument(
        "--retry-wait", type=float, default=0.0,
        help="on a PER-MINUTE 429, wait this many seconds and retry the call once (daily 429 stops)",
    )
    ap.add_argument("--max-tokens", type=int, default=0,
                    help="stop once this run's cumulative in+out tokens reach this (0 = no limit)")
    ap.add_argument("--fixtures-dir", default=str(FIX),
                    help="fixture directory (e.g. tests/fixtures/injection/blind)")
    ap.add_argument("--out", default=str(ROOT / "results" / "injection_runs.jsonl"),
                    help="JSONL file to append run records to")
    args = ap.parse_args(argv)

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    wanted = {c.strip() for c in args.cases.split(",") if c.strip()}
    fixtures = load_injection_fixtures(args.fixtures_dir, include_held_out=args.include_held_out)
    if wanted:
        fixtures = [fx for fx in fixtures if fx["id"] in wanted]

    prompt = load_prompt(args.config)
    ph = prompt_hash(prompt)
    cap_fields = 256 if args.config == "v2" else None
    defended = args.config == "v2"
    allowed: list[str] = []  # no extra allow-list help beyond the prompt
    out = Path(args.out).resolve()
    clients = {p: make_client(p) for p in providers}
    print(f"config={args.config} prompt={args.config} ({ph[:12]}) cap_fields={cap_fields} "
          f"providers={providers} runs={args.runs} held_out={args.include_held_out}")

    exhausted: set[str] = set()
    total = 0
    used_tokens = 0
    stop = False
    for fx in fixtures:
        if stop:
            break
        for provider in providers:
            if stop or provider in exhausted:
                continue
            model = get_model(provider)
            for i in range(args.runs):
                if args.max_tokens and used_tokens >= args.max_tokens:
                    print(f"  token budget reached ({used_tokens} >= {args.max_tokens}); stopping.")
                    stop = True
                    break
                print(f"- {fx['id']} | {provider} | {args.config} | run {i}...", flush=True)
                try:
                    call = triage_call(fx["alert"], model, clients[provider], prompt, allowed,
                                       cap_fields=cap_fields)
                except openai.RateLimitError as exc:
                    msg = str(getattr(exc, "message", exc)).lower()
                    daily = "per day" in msg or "requests per day" in msg or "requestsperday" in msg
                    if not daily and args.retry_wait > 0:
                        print(f"  per-minute RATE LIMIT; waiting {args.retry_wait:.0f}s, retry once...")
                        time.sleep(args.retry_wait)
                        try:
                            call = triage_call(fx["alert"], model, clients[provider], prompt, allowed,
                                               cap_fields=cap_fields)
                        except openai.RateLimitError:
                            print(f"  still rate-limited; skipping {fx['id']} run {i}")
                            if args.sleep:
                                time.sleep(args.sleep)
                            continue
                    else:
                        print(f"  {'daily' if daily else 'per-minute'} RATE LIMIT ({provider}); stopping it")
                        exhausted.add(provider)
                        break
                except openai.APIError as exc:
                    print(f"  API ERROR ({provider}): {type(exc).__name__}: {exc}")
                    continue
                valid = isinstance(call.result, TriageResult)
                used_tokens += (call.tokens_in or 0) + (call.tokens_out or 0)
                append_record(
                    {
                        "ts": datetime.now(UTC).isoformat(),
                        "tool": "injection_baseline",
                        "case_id": fx["id"],
                        "provider": provider,
                        "model": model,
                        "config": args.config,
                        "prompt_version": args.config,
                        "prompt_hash": ph,
                        "cap_fields": cap_fields,
                        "defended": defended,
                        "run_index": i,
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

    print(f"\nAppended {total} injection runs to {out.relative_to(ROOT)}; "
          f"tokens used this run: {used_tokens}")
    if exhausted:
        print(f"Providers rate-limited (incomplete): {sorted(exhausted)}")
    print("Score with: uv run python eval/injection_report.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
