"""Run ONE case through the LIVE LLM triage. Operator machine only: this makes a real
API call to the chosen provider, so run it yourself with your keys in .env - CI and the
assistant never run it.

  uv run python scripts/triage_once.py <case_id> <gemini|groq> [--runs N] [--version v1]

It rebuilds the case's deterministic alert (same path as the baseline), sends it to the
model, validates + guardrail-checks the output, prints a summary, and appends one run
record per call to results/runs.jsonl.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from triage.guardrails import check, load_allowlist
from triage.llm.client import get_model, make_client, triage_call
from triage.llm.prompts import load_prompt, prompt_hash
from triage.llm.schema import TriageResult
from triage.pipeline import alerts_for_case
from triage.runlog import append_record, build_record, load_prices, runs_path

ROOT = Path(__file__).resolve().parent.parent


def _print_run(i: int, call, report) -> None:
    r = call.result
    print(
        f"\n--- run {i} | {call.latency_s:.2f}s | "
        f"tokens {call.tokens_in}/{call.tokens_out} | attempts {call.attempts}"
    )
    if not isinstance(r, TriageResult):
        print(f"INVALID after {r.attempts} attempts: {r.error}")
        print("raw:", r.raw[:500])
        return
    print(
        f"verdict={r.verdict.value} attack_type={r.attack_type.value} "
        f"confidence={r.confidence} techniques={r.attack_techniques}"
    )
    print(f"summary: {r.summary}")
    if report is None:
        return
    flags = []
    if report.hallucinated_techniques:
        flags.append(f"hallucinated={report.hallucinated_techniques}")
    if report.unverifiable_evidence:
        flags.append("unverifiable_evidence")
    if report.ungrounded_ips:
        flags.append(f"ungrounded_ips={report.ungrounded_ips}")
    if report.ungrounded_numbers:
        flags.append(f"ungrounded_numbers={report.ungrounded_numbers}")
    if report.model_disagrees_with_rules:
        flags.append("model_disagrees_with_rules")
    status = "PASS" if report.passed else "FLAGS: " + "; ".join(flags)
    print(f"guardrails: {status} | final_severity={report.final_severity}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live single-case LLM triage (makes a real API call).")
    ap.add_argument("case_id")
    ap.add_argument("provider", choices=["gemini", "groq"])
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--version", default="v1")
    ap.add_argument("--temperature", type=float, default=0.0)
    args = ap.parse_args(argv)

    case = yaml.safe_load((ROOT / "cases" / f"{args.case_id}.yaml").read_text())
    alerts = alerts_for_case(case, ROOT)
    if not alerts:
        print(f"No alert for {args.case_id} (benign / no detection) - nothing to triage.")
        return 0
    alert = alerts[0]

    allow = load_allowlist()
    prompt = load_prompt(args.version)
    ph = prompt_hash(prompt)
    model = get_model(args.provider)
    prices = load_prices()
    client = make_client(args.provider)  # real network client; needs the key in .env

    print(
        f"Triaging {args.case_id} via {args.provider}/{model}, "
        f"prompt {args.version} ({ph[:12]}), runs={args.runs}"
    )
    print(f"Alert: {alert.rule_id} src={alert.src_ip} counts={alert.counts}")
    for i in range(args.runs):
        call = triage_call(
            alert.to_dict(), model, client, prompt, list(allow), temperature=args.temperature
        )
        report = check(call.result, alert, allow) if isinstance(call.result, TriageResult) else None
        record = build_record(
            call,
            provider=args.provider,
            model=model,
            prompt_version=args.version,
            prompt_hash=ph,
            temperature=args.temperature,
            run_index=i,
            case_id=args.case_id,
            alert_id=alert.alert_id,
            prices=prices,
            guardrails=report,
        )
        append_record(record, runs_path(ROOT))
        _print_run(i, call, report)

    print(f"\nRun records appended to {runs_path(ROOT).relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
