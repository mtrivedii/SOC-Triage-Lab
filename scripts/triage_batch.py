"""Sprint 4 batch eval runner. LIVE: makes many real API calls (>=3 per case per
provider), so run it yourself with keys in .env - CI and the assistant never run it.

  uv run python scripts/triage_batch.py [--providers groq,gemini] [--runs 3]
                                        [--cases c1,c2] [--version v1] [--sleep 2]
                                        [--cap-fields 256]

For every case that raises a deterministic alert, it triages that alert N times per
provider and appends each call to results/runs.jsonl (the raw per-run store, including
raw responses and guardrail reports). Benign cases raise no alert and are skipped - the
detector baseline already handles them. Afterwards, score offline with:

  uv run python eval/triage_eval.py

Notes before running: Gemini calls can take minutes each; Groq has daily token caps. With
5 alerting cases x 2 providers x 3 runs that is ~30 calls - pace with --sleep and watch quotas.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import openai
import yaml

from triage.guardrails import check, load_allowlist
from triage.llm.client import get_model, make_client, triage_call
from triage.llm.prompts import load_prompt, prompt_hash
from triage.llm.schema import TriageResult
from triage.pipeline import alerts_for_case
from triage.runlog import append_record, build_record, load_prices, runs_path

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live batch LLM-triage eval (makes real API calls).")
    ap.add_argument("--providers", default="groq,gemini")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--cases", default="", help="comma-separated case_ids; default = all alerting")
    ap.add_argument("--version", default="v1")
    ap.add_argument("--sleep", type=float, default=2.0, help="seconds between calls (rate limits)")
    ap.add_argument("--cap-fields", type=int, default=0,
                    help="truncate over-long evidence fields to N chars (v2 defence; 0 = off)")
    args = ap.parse_args(argv)

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    wanted = {c.strip() for c in args.cases.split(",") if c.strip()}
    cases = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "cases").glob("*.yaml"))]
    if wanted:
        cases = [c for c in cases if c["case_id"] in wanted]

    allow = load_allowlist()
    prompt = load_prompt(args.version)
    ph = prompt_hash(prompt)
    prices = load_prices()
    out = runs_path(ROOT)
    cap_fields = args.cap_fields or None

    print(f"prompt {args.version} ({ph[:12]}) | providers={providers} | runs={args.runs} "
          f"| cap_fields={cap_fields}")
    clients = {p: make_client(p) for p in providers}  # real network clients

    exhausted: set[str] = set()
    total = 0
    errored = 0
    for case in cases:
        alerts = alerts_for_case(case, ROOT)
        if not alerts:
            print(f"- skip {case['case_id']} (no alert; benign)")
            continue
        alert = alerts[0]
        for provider in providers:
            if provider in exhausted:
                print(f"- skip {case['case_id']} | {provider} (quota exhausted earlier)")
                continue
            model = get_model(provider)
            for i in range(args.runs):
                print(f"- {case['case_id']} | {provider}/{model} | run {i}...", flush=True)
                try:
                    call = triage_call(
                        alert.to_dict(), model, clients[provider], prompt, list(allow),
                        cap_fields=cap_fields,
                    )
                except openai.RateLimitError as exc:
                    print(f"  RATE LIMIT ({provider}): {getattr(exc, 'message', str(exc))}")
                    print(f"  marking {provider} exhausted; skipping its remaining runs/cases.")
                    exhausted.add(provider)
                    break
                except openai.APIError as exc:
                    print(f"  API ERROR ({provider}): {type(exc).__name__}: {exc}")
                    errored += 1
                    if args.sleep:
                        time.sleep(args.sleep)
                    continue

                report = (
                    check(call.result, alert, allow)
                    if isinstance(call.result, TriageResult)
                    else None
                )
                record = build_record(
                    call,
                    provider=provider,
                    model=model,
                    prompt_version=args.version,
                    prompt_hash=ph,
                    temperature=0.0,
                    run_index=i,
                    case_id=case["case_id"],
                    alert_id=alert.alert_id,
                    prices=prices,
                    guardrails=report,
                )
                record["cap_fields"] = cap_fields
                append_record(record, out)
                total += 1
                if args.sleep:
                    time.sleep(args.sleep)

    print(f"\nAppended {total} run records to {out.relative_to(ROOT)}")
    if errored:
        print(f"{errored} call(s) errored and were skipped.")
    if exhausted:
        print(f"Providers hit rate limits (incomplete): {sorted(exhausted)}")
    print("Score with: uv run python eval/triage_eval.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
