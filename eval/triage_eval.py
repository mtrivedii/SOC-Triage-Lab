"""Score LLM triage runs against ground truth and emit a markdown summary (Sprint 4).

OFFLINE: reads results/runs.jsonl (produced live by scripts/triage_batch.py), cases/*.yaml
and data/attack_allowlist.json, and writes results/eval_summary.md. It does not call any API.

Metrics per (case, provider): valid/invalid rate, verdict correct (abstentions counted
separately), attack-type correct, technique precision/recall vs the ground-truth IDs,
guardrail-flag rate, mean tokens/cost. Compared against the Sprint 2 detector-only baseline.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from triage.llm.prompts import load_prompt, prompt_hash
from triage.runsets import frozen, out_path

ROOT = Path(__file__).resolve().parent.parent
_GUARDRAIL_KEYS = (
    "hallucinated_techniques",
    "unverifiable_evidence",
    "ungrounded_ips",
    "ungrounded_numbers",
)


def load_cases(root: Path = ROOT) -> dict[str, dict]:
    cases = {}
    for path in sorted((root / "cases").glob("*.yaml")):
        case = yaml.safe_load(path.read_text(encoding="utf-8"))
        cases[case["case_id"]] = case
    return cases


def load_runs(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def filter_by_hash(records: list[dict], wanted_hash: str) -> tuple[list[dict], int]:
    """Keep only runs made with the given prompt hash (so stale/pre-freeze runs in an
    accumulated runs.jsonl do not contaminate the table). Returns (kept, ignored_count).
    """
    kept = [r for r in records if r.get("prompt_hash") == wanted_hash]
    return kept, len(records) - len(kept)


def score_run(record: dict, expected: dict) -> dict:
    """Per-run metrics. ``expected`` is the case's ground-truth ``expected`` block."""
    result = record.get("result") or {}
    valid = bool(record.get("valid"))
    out = {
        "valid": valid,
        "abstained": False,
        "verdict_correct": False,
        "attack_type_correct": False,
        "tech_precision": None,
        "tech_recall": None,
        "tech_found": None,
        "tech_extra": None,
        "tech_expected": len(expected.get("techniques") or []),
        "guardrail_flagged": False,
        "hallucinated": 0,
        "tokens": (record.get("tokens_in") or 0) + (record.get("tokens_out") or 0),
        "cost": record.get("est_cost_usd"),
        "latency": record.get("latency_s"),
    }
    if valid and result:
        verdict = result.get("verdict")
        out["abstained"] = verdict == "needs_human"
        out["verdict_correct"] = verdict == expected.get("verdict")
        out["attack_type_correct"] = result.get("attack_type") == expected.get("attack_type")
        pred = set(result.get("attack_techniques") or [])
        exp = set(expected.get("techniques") or [])
        tp = len(pred & exp)
        out["tech_precision"] = tp / len(pred) if pred else None
        out["tech_recall"] = tp / len(exp) if exp else None
        out["tech_found"] = tp  # expected IDs correctly produced
        out["tech_extra"] = len(pred - exp)  # non-expected IDs produced

    guard = record.get("guardrails") or {}
    out["guardrail_flagged"] = any(guard.get(k) for k in _GUARDRAIL_KEYS)
    out["hallucinated"] = len(guard.get("hallucinated_techniques") or [])
    return out


def _mean(values: list) -> float | None:
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 4) if vals else None


def summarize(records: list[dict], cases: dict[str, dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for rec in records:
        case = cases.get(rec.get("case_id"))
        if case is None:
            continue
        scored = score_run(rec, case["expected"])
        groups.setdefault((rec["case_id"], rec["provider"]), []).append(scored)

    summary = []
    for (case_id, provider), scored in sorted(groups.items()):
        n = len(scored)
        n_valid = sum(s["valid"] for s in scored)
        exp_total = len(cases[case_id]["expected"].get("techniques") or [])
        found = [s["tech_found"] for s in scored if s["tech_found"] is not None]
        extra = [s["tech_extra"] for s in scored if s["tech_extra"] is not None]
        summary.append(
            {
                "case_id": case_id,
                "provider": provider,
                "expected": cases[case_id]["expected"],
                "runs": n,
                "valid": n_valid,
                "invalid_rate": round((n - n_valid) / n, 3) if n else None,
                "verdict_correct": sum(s["verdict_correct"] for s in scored),
                "abstained": sum(s["abstained"] for s in scored),
                "attack_type_correct": sum(s["attack_type_correct"] for s in scored),
                # counts for display (spread across runs); raw decimals kept for JSON
                "tech_expected": exp_total,
                "tech_found_min": min(found) if found else None,
                "tech_found_max": max(found) if found else None,
                "tech_extra_min": min(extra) if extra else None,
                "tech_extra_max": max(extra) if extra else None,
                "tech_precision": _mean([s["tech_precision"] for s in scored]),
                "tech_recall": _mean([s["tech_recall"] for s in scored]),
                "guardrail_flagged": sum(s["guardrail_flagged"] for s in scored),
                "hallucinated_runs": sum(1 for s in scored if s["hallucinated"]),
                "mean_tokens": _mean([s["tokens"] for s in scored]),
                "mean_cost": _mean([s["cost"] for s in scored]),
            }
        )
    return summary


def _range(lo, hi) -> str:
    if lo is None:
        return "-"
    return str(lo) if lo == hi else f"{lo}-{hi}"


def render_markdown(
    summary: list[dict], cases: dict[str, dict], prompt_note: str | None = None
) -> str:
    alerting = {s["case_id"] for s in summary}
    benign_no_alert = sorted(
        c for c, case in cases.items()
        if case["expected"]["verdict"] == "benign" and c not in alerting
    )
    intro = (
        "Generated by `eval/triage_eval.py` from `results/runs.jsonl`. The LLM runs only on "
        "alerts the deterministic detectors raised; benign cases produce no alert, so the AI is "
        "not invoked on them (they are handled by the detector baseline: 0/4 false alarms)."
    )
    header = (
        "| case | expected | provider | runs | valid | verdict ok | abstain | type ok | "
        "tech found | tech extra | guardrail-flagged | mean tok | mean $ |"
    )
    divider = (
        "|------|----------|----------|------|-------|------------|---------|---------|"
        "------------|------------|-------------------|----------|--------|"
    )
    lines = ["# LLM triage eval (vs detector-only baseline)", "", intro]
    if prompt_note:
        lines += ["", prompt_note]
    tech_note = (
        "`tech found` = expected ATT&CK IDs the model produced, out of the ground-truth count "
        "(range across runs). `tech extra` = count of non-expected IDs produced."
    )
    lines += ["", tech_note, "", header, divider]
    for s in summary:
        exp = s["expected"]
        found = f"{_range(s['tech_found_min'], s['tech_found_max'])}/{s['tech_expected']}"
        extra = _range(s["tech_extra_min"], s["tech_extra_max"])
        lines.append(
            f"| {s['case_id']} | {exp['verdict']}/{exp['attack_type']} | {s['provider']} | "
            f"{s['runs']} | {s['valid']} | {s['verdict_correct']}/{s['runs']} | "
            f"{s['abstained']} | {s['attack_type_correct']}/{s['runs']} | "
            f"{found} | {extra} | {s['guardrail_flagged']}/{s['runs']} | "
            f"{s['mean_tokens']} | {s['mean_cost']} |"
        )
    benign_line = (
        f"Benign cases not sent to the LLM (no detector alert): {', '.join(benign_no_alert) or 'none'}."
    )
    flag_note = (
        "**Reading the guardrail-flagged column:** a nonzero rate is expected, not a failure - see the "
        "two accepted sources documented in `docs/lab_journal.md` (non-contiguous evidence quotes and "
        "evidence-only number citations on port-scan cases)."
    )
    baseline_note = (
        "**Detector-only baseline (Sprint 2, `results/detector_baseline.md`):** 5/5 malicious detected "
        "with correct attack type, 0/4 benign false alarms. The LLM layer adds explanation, technique "
        "mapping and checkable guardrails on top; it does not change the detector verdicts."
    )
    lines += ["", benign_line, "", flag_note, "", baseline_note]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Score LLM triage runs (offline).")
    ap.add_argument("--version", default="v1", help="prompt version whose hash to score")
    ap.add_argument("--prompt-hash", default=None, help="score only this exact prompt hash")
    ap.add_argument("--all-hashes", action="store_true", help="score every run, any prompt hash")
    args = ap.parse_args()

    cases = load_cases()
    records = frozen(load_runs(ROOT / "results" / "runs.jsonl"))
    prompt_note = None
    if not args.all_hashes:
        wanted = args.prompt_hash or prompt_hash(load_prompt(args.version))
        records, _ = filter_by_hash(records, wanted)
        prompt_note = (
            f"Scored {len(records)} run(s) at prompt {args.version} ({wanted[:12]}...), "
            "recorded before the results were frozen; runs at other prompt hashes are excluded."
        )

    summary = summarize(records, cases)
    md = render_markdown(summary, cases, prompt_note)
    out = out_path("eval_summary.md")
    out.write_text(md, encoding="utf-8")
    # Raw numbers (incl. decimal precision/recall) kept in a sibling JSON for machine use.
    out_json = out_path("eval_summary.json")
    out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(md)
    if not records:
        print("NOTE: no runs to score - run scripts/triage_batch.py (live) first.")
    print(f"Wrote {out} and {out_json}")


if __name__ == "__main__":
    main()
