"""Detector v1 vs v2 measured OFFLINE (no API calls).

Runs both log-injection detector versions over the 12 existing injection fixtures (split into the
injected element vs the base alert, as in eval/defences_report.py) and the 9 real cases, and
writes results/detector_v1_vs_v2.md. v1 results elsewhere are untouched.

Run: uv run python eval/detector_v2_offline.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from defences_report import _split_injection

from triage import runsets
from triage.alert import Alert
from triage.detectors import log_injection
from triage.injection import load_injection_fixtures
from triage.pipeline import alerts_for_case

FIX = ROOT / "tests" / "fixtures" / "injection"
CFG = log_injection.load_config()


def _fmt(hits) -> str:
    if not hits:
        return "-"
    return "; ".join(f"{field}:{','.join(reasons)}" for field, _, reasons in hits)


def _fmt_values(hits) -> str:
    if not hits:
        return "-"
    return "; ".join(
        f"{field}={value[:60]!a}:{','.join(reasons)}" for field, value, reasons in hits
    )


def main() -> None:
    lines = [
        "# Log-injection detector v1 vs v2 (offline, deterministic)",
        "",
        "Generated with the fixed auth/nginx parsers (commit 433b088). The pre-fix version cited in `docs/sprint5_findings.md` is in `results/archive_pre_parser_fix/`.",
        "",
        ("**Caveat:** detector v2 was designed after seeing v1's misses; its improvement on these "
         "12 fixtures is expected and not evidence it generalises. It is tested on the blind set."),
        "",
        ("v2 = v1's parsed-field checks + a scan of every full raw evidence line (the text the "
         "model sees), Unicode look-alikes mapped to Latin (curated Cyrillic/Greek subset of "
         "confusables.txt), and keywords that must START a word (no letter/digit before them). "
         "Same keyword list. Strict whole-word matching was not used: it would stop the frozen "
         "stems `authori` and `instruction` matching `authorised`/`instructions`, which would in "
         "effect remove keywords."),
        "",
        "## Injection fixtures: hit on the injected text",
        "",
        ("| case | held_out | inject_field | v1 hit_on_injection | v2 hit_on_injection | "
        "v1 rules (injected) | v2 rules (injected) | v1 base-alert hits | v2 base-alert hits |"),
        "|---|---|---|---|---|---|---|---|---|",
    ]
    tot = {1: 0, 2: 0}
    fixtures = load_injection_fixtures(FIX, include_held_out=True)
    for fx in fixtures:
        injected, base = _split_injection(fx)
        inj = {v: log_injection.suspicious_fields(injected, CFG, v) for v in (1, 2)}
        bas = {v: log_injection.suspicious_fields(base, CFG, v) for v in (1, 2)}
        for v in (1, 2):
            tot[v] += bool(inj[v])
        lines.append(
            f"| {fx['id']} | {'yes' if fx.get('held_out') else 'no'} | {fx['inject_field']} | "
            f"{'yes' if inj[1] else 'no'} | {'yes' if inj[2] else 'no'} | {_fmt(inj[1])} | "
            f"{_fmt(inj[2])} | {_fmt_values(bas[1])} | {_fmt_values(bas[2])} |"
        )
    n = len(fixtures)
    lines += ["", f"**Hit on injected text:** v1 {tot[1]}/{n}, v2 {tot[2]}/{n}."]

    lines += [
        "",
        "## Real cases (9 from data/raw): false positives",
        "",
        "| case | alert raised | v1 flagged | v2 flagged | v1 hits | v2 hits |",
        "|---|---|---|---|---|---|",
    ]
    fps = {1: [], 2: []}
    for p in sorted((ROOT / "cases").glob("*.yaml")):
        case = yaml.safe_load(p.read_text())
        found = alerts_for_case(case, ROOT)
        if not found:
            lines.append(f"| {case['case_id']} | no (benign) | n/a | n/a | - | - |")
            continue
        alert: Alert = found[0]
        hits = {v: log_injection.suspicious_fields(alert, CFG, v) for v in (1, 2)}
        for v in (1, 2):
            if hits[v]:
                fps[v].append(case["case_id"])
        lines.append(
            f"| {case['case_id']} | yes | {'YES (FP)' if hits[1] else 'no'} | "
            f"{'YES (FP)' if hits[2] else 'no'} | {_fmt_values(hits[1])} | {_fmt_values(hits[2])} |"
        )
    lines += [
        "",
        (f"**False positives on real cases:** v1 {len(fps[1])}/5 alerting "
        f"({', '.join(fps[1]) or 'none'}); v2 {len(fps[2])}/5 alerting ({', '.join(fps[2]) or 'none'})."),
    ]
    out = runsets.out_path("detector_v1_vs_v2.md")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
