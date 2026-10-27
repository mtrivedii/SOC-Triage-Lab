"""v2 regression on the 5 NORMAL alerts (OFFLINE, no API calls).

Scores Groq runs in results/runs.jsonl at prompt v1 (Sprint 4, no caps) and prompt v2 (+ field
caps, made by `scripts/triage_batch.py --version v2 --cap-fields 256`) with the frozen Sprint 4
scorer (eval/triage_eval.py) and the checker-v1 guardrail reports stored on each run. Writes
results/v2_regression.md as counts, v1 vs v2 per case.

Run: uv run python eval/v2_regression.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from triage_eval import filter_by_hash, load_cases, load_runs, summarize

from triage import runsets
from triage.llm.prompts import load_prompt, prompt_hash

PROVIDER = "groq"


def _range(lo, hi) -> str:
    if lo is None:
        return "-"
    return str(lo) if lo == hi else f"{lo}-{hi}"


def _exact(records: list[dict], cases: dict[str, dict]) -> dict[str, int]:
    """Runs whose ATT&CK set equals the ground-truth set exactly, per case."""
    out: dict[str, int] = {}
    for r in records:
        exp = set(cases[r["case_id"]]["expected"].get("techniques") or [])
        pred = set((r.get("result") or {}).get("attack_techniques") or [])
        out[r["case_id"]] = out.get(r["case_id"], 0) + int(bool(r.get("valid")) and pred == exp)
    return out


def main() -> None:
    cases = load_cases(ROOT)
    records = [r for r in runsets.frozen(load_runs(ROOT / "results" / "runs.jsonl"))
               if r.get("provider") == PROVIDER]
    per_cfg = {}
    for version in ("v1", "v2"):
        ph = prompt_hash(load_prompt(version))
        kept, _ = filter_by_hash(records, ph)
        per_cfg[version] = (
            ph,
            {s["case_id"]: s for s in summarize(kept, cases)},
            _exact(kept, cases),
            kept,
        )

    lines = [
        "# Prompt v2 + field caps: regression on the 5 normal alerts (Groq)",
        "",
        ("Scored offline with the frozen Sprint 4 scorer (`eval/triage_eval.py`) and checker v1. "
        f"v1 = prompt v1 ({per_cfg['v1'][0][:12]}...), no caps, Sprint 4 runs. "
        f"v2 = prompt v2 ({per_cfg['v2'][0][:12]}...) + field caps 256. Provider {PROVIDER}, "
        "temperature 0."),
        "",
        ("`tech found` = expected ATT&CK IDs produced / ground-truth count (range across runs); "
        "`tech extra` = non-expected IDs produced (range); `tech exact` = runs whose ID set equals "
        "the ground truth exactly."),
        "",
        ("| case | expected | cfg | runs | valid | verdict ok | abstain | type ok | tech found | "
        "tech extra | tech exact | guardrail-flagged |"),
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    totals = {v: {"runs": 0, "verdict": 0, "type": 0, "exact": 0} for v in per_cfg}
    for cid in sorted({c for v in per_cfg.values() for c in v[1]}):
        exp = cases[cid]["expected"]
        for version, (_, summary, exact, _) in per_cfg.items():
            s = summary.get(cid)
            if s is None:
                lines.append(f"| {cid} | {exp['verdict']}/{exp['attack_type']} | {version} | 0 "
                             "| - | - | - | - | - | - | - | - |")
                continue
            n = s["runs"]
            totals[version]["runs"] += n
            totals[version]["verdict"] += s["verdict_correct"]
            totals[version]["type"] += s["attack_type_correct"]
            totals[version]["exact"] += exact.get(cid, 0)
            lines.append(
                f"| {cid} | {exp['verdict']}/{exp['attack_type']} | {version} | {n} | {s['valid']} | "
                f"{s['verdict_correct']}/{n} | {s['abstained']} | {s['attack_type_correct']}/{n} | "
                f"{_range(s['tech_found_min'], s['tech_found_max'])}/{s['tech_expected']} | "
                f"{_range(s['tech_extra_min'], s['tech_extra_max'])} | {exact.get(cid, 0)}/{n} | "
                f"{s['guardrail_flagged']}/{n} |"
            )
    lines += ["", "| cfg | runs | verdict ok | type ok | tech exact |", "|---|---|---|---|---|"]
    for version, t in totals.items():
        lines.append(f"| {version} | {t['runs']} | {t['verdict']}/{t['runs']} | "
                     f"{t['type']}/{t['runs']} | {t['exact']}/{t['runs']} |")

    out = runsets.out_path("v2_regression.md")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
