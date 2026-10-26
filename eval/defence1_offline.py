"""Defence 1 measured OFFLINE (no API calls).

Runs the log-injection detector over all 12 injection fixtures (incl. held-out) and all 9 real
cases (data/raw), and writes results/defence1_offline.md: per case, flagged yes/no and which
field/rule fired. False positives on the REAL cases are listed explicitly.

Run: uv run python eval/defence1_offline.py
"""

from __future__ import annotations

from pathlib import Path

import yaml

from triage.alert import Alert
from triage.detectors import log_injection
from triage.injection import load_injection_fixtures
from triage.pipeline import alerts_for_case

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "injection"


def _fmt(hits: list[tuple[str, str, list[str]]]) -> str:
    return "; ".join(f"{field}:{','.join(reasons)}" for field, value, reasons in hits) or "-"


def main() -> None:
    cfg = log_injection.load_config()
    lines = [
        "# Defence 1 (log-injection detector) — offline sweep",
        "",
        "Deterministic detector run over every injection fixture and every real case. No API calls.",
        "The held-out fixture texts (`inj_ho_*`) were written BEFORE this detector existed.",
        "",
        "## Injection fixtures (12: 9 baseline + 3 held-out)",
        "",
        "| fixture | held_out | flagged | fields:rules |",
        "|---------|----------|---------|--------------|",
    ]
    for fx in load_injection_fixtures(FIX, include_held_out=True):
        hits = log_injection.suspicious_fields(Alert(**fx["alert"]), cfg)
        lines.append(
            f"| {fx['id']} | {'yes' if fx.get('held_out') else 'no'} | "
            f"{'YES' if hits else 'no'} | {_fmt(hits)} |"
        )

    lines += [
        "",
        "## Real cases (9 from data/raw) — false-positive check",
        "",
        "| case | alert raised | flagged (FALSE POSITIVE) | fields:rules |",
        "|------|--------------|--------------------------|--------------|",
    ]
    false_positives = []
    for p in sorted((ROOT / "cases").glob("*.yaml")):
        case = yaml.safe_load(p.read_text())
        found = alerts_for_case(case, ROOT)
        if not found:
            lines.append(f"| {case['case_id']} | no (benign) | n/a — detector not invoked | - |")
            continue
        hits = log_injection.suspicious_fields(found[0], cfg)
        if hits:
            false_positives.append(case["case_id"])
        lines.append(
            f"| {case['case_id']} | yes | {'YES (FP)' if hits else 'no'} | {_fmt(hits)} |"
        )

    lines += [
        "",
        f"**False positives on real cases:** {', '.join(false_positives) or 'none'}.",
    ]
    out = ROOT / "results" / "defence1_offline.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
