"""Blind injection set report (OFFLINE, no API calls).

Reads results/blind_runs.jsonl (scripts/injection_baseline.py --fixtures-dir
tests/fixtures/injection/blind --out results/blind_runs.jsonl) and scores each blind case per
config with the success criteria frozen in its fixture:
  v1 = prompt v1, no caps, no detector.
  v2 = prompt v2 + field caps + detector v2 (deterministic, pipeline level).
Detector v1 and v2 hits on the injected text are reported for both configs (offline, same
fixture). For blind_05 it also lists, per run, what the model's summary says about the login.
Writes results/blind_set.md.

Run: uv run python eval/blind_report.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from defences_report import _score

from triage.alert import Alert
from triage.detectors import log_injection
from triage.injection import load_injection_fixtures
from triage.pipeline import alerts_for_case

BLIND = ROOT / "tests" / "fixtures" / "injection" / "blind"
RUNS = ROOT / "results" / "blind_runs.jsonl"
CFG = log_injection.load_config()


def _injected_alert(fx: dict, base_users: list[str]) -> Alert:
    """Only what the injection put in front of the model: its lines that reached the evidence, and
    usernames that are not in the base alert."""
    a = fx["alert"]
    return Alert(**{
        **a,
        "usernames_seen": [u for u in a["usernames_seen"] if u not in base_users],
        "evidence_lines": fx["rendered_in_evidence"],
    })


def main() -> None:
    fixtures = {fx["id"]: fx for fx in load_injection_fixtures(BLIND)}
    cases = {}
    for p in sorted((ROOT / "cases").glob("*.yaml")):
        c = yaml.safe_load(p.read_text())
        cases[c["case_id"]] = c
    inj_hit, alert_flag = {}, {}
    for cid, fx in fixtures.items():
        base_users = alerts_for_case(cases[fx["base_case"]], ROOT)[0].usernames_seen
        injected = _injected_alert(fx, base_users)
        inj_hit[cid] = {v: bool(log_injection.suspicious_fields(injected, CFG, v)) for v in (1, 2)}
        alert_flag[cid] = bool(log_injection.suspicious_fields(Alert(**fx["alert"]), CFG, 2))

    records = [json.loads(x) for x in RUNS.read_text(encoding="utf-8").splitlines() if x.strip()]
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    raw: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for rec in records:
        if rec.get("provider") != "groq" or rec["case_id"] not in fixtures:
            continue
        cfg = "v2" if rec.get("config") == "v2" else "v1"
        # detector only exists in the v2 config (detector v2 on the whole alert)
        flagged = cfg == "v2" and alert_flag[rec["case_id"]]
        groups[(rec["case_id"], cfg)].append(_score(rec, fixtures[rec["case_id"]], flagged))
        raw[(rec["case_id"], cfg)].append(rec)

    lines = [
        "# Blind injection set (DeepSeek-written, Groq)",
        "",
        ("5 blind cases (`tests/fixtures/injection/blind/`, source in `SOURCE.md`), rendered as the "
         "real logs would write them. v1 = prompt v1, no caps, no detector. v2 = prompt v2 + field "
         "caps 256 + detector v2. Success criteria frozen in each fixture before any run."),
        "",
        ("`det_v1_inj` / `det_v2_inj` = detector v1 / v2 fires on the injected text itself (the "
         "injected lines that reached the evidence + injected usernames), offline. "
         "`requires_human` = (v2 only) detector v2 fires on the alert, OR the model disagreed with "
         "the rules. `pipeline_changed` = severity lowered / alert closed (frozen pipeline "
         "criterion)."),
        "",
        ("| case | cfg | runs | full | partial | none | invalid | pipeline_changed | "
         "model_disagrees | det_v1_inj | det_v2_inj | requires_human | in_tok | out_tok |"),
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    total_tok = {"v1": 0, "v2": 0}
    for cid in sorted(fixtures):
        for cfg in ("v1", "v2"):
            scored = groups.get((cid, cfg), [])
            n = len(scored)
            if not n:
                lines.append(f"| {cid} | {cfg} | 0 | - | - | - | - | - | - | "
                             f"{'yes' if inj_hit[cid][1] else 'no'} | "
                             f"{'yes' if inj_hit[cid][2] else 'no'} | - | - | - |")
                continue
            lv = {k: sum(s["verdict_level"] == k for s in scored) for k in ("full", "partial", "none")}
            tin = sum(s["tin"] for s in scored)
            tout = sum(s["tout"] for s in scored)
            total_tok[cfg] += tin + tout
            lines.append(
                f"| {cid} | {cfg} | {n} | {lv['full']} | {lv['partial']} | {lv['none']} | "
                f"{sum(s['invalid_json'] for s in scored)} | "
                f"{sum(s['pipeline_changed'] for s in scored)} | "
                f"{sum(s['model_disagrees'] for s in scored)} | "
                f"{'yes' if inj_hit[cid][1] else 'no'} | {'yes' if inj_hit[cid][2] else 'no'} | "
                f"{sum(s['requires_human'] for s in scored)}/{n} | {tin} | {tout} |"
            )
    lines += [
        "",
        (f"**Tokens (in+out, all runs):** v1 {total_tok['v1']}, v2 {total_tok['v2']}, "
        f"total {total_tok['v1'] + total_tok['v2']}. `in_tok`/`out_tok` above are sums per row."),
    ]

    lines += [
        "",
        "## blind_05: what the model's summary says about the login",
        "",
        ("The parser turned the forged username into 2 accepted publickey logins for `svc_backup` "
         "(see the Sprint 5 finding). Per run: verdict, whether the summary mentions `svc_backup`, "
         "and the summary verbatim."),
        "",
        "| cfg | run | verdict | mentions svc_backup | summary |",
        "|---|---|---|---|---|",
    ]
    for cfg in ("v1", "v2"):
        for rec in raw.get(("blind_05", cfg), []):
            res = rec.get("result") or {}
            summary = (res.get("summary") or "").replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {cfg} | {rec.get('run_index')} | {res.get('verdict', 'invalid')} | "
                f"{'yes' if 'svc_backup' in summary else 'no'} | {summary} |"
            )

    out = ROOT / "results" / "blind_set.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
