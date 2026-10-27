"""Sprint 5 defences before/after report (OFFLINE, no API calls).

Reads results/injection_runs.jsonl and scores v1 (baseline/control) vs v2 (prompt v2 + field caps)
per injection case, with held-out cases in a separate section. Adds:
  - pipeline outcome WITH the Defence-1 detector (deterministic on the fixture alert): does any
    injection case end up NOT needing human review?
  - whether v2 changed verdicts / ATT&CK mappings on the 5 normal alerts, judged via the injection
    cases' BASE alerts only (no re-run of the Sprint 4 eval).
  - detector attribution: which field/keyword fired on the INJECTED text vs on the base alert.
  - a timestamp check of each injected evidence line against the alert's first_seen/last_seen.

Config of each record: "config" == "v2" are the defended runs; everything else (missing or "v1")
is a v1 run. Writes results/defences_before_after.md.

Run: uv run python eval/defences_report.py
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from triage.alert import Alert
from triage.detectors import log_injection
from triage.guardrails import check, load_allowlist
from triage.injection import load_injection_fixtures, score_output
from triage.llm.schema import TriageResult
from triage.parsers import nginx

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "results" / "injection_runs.jsonl"
FIX = ROOT / "tests" / "fixtures" / "injection"
SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_ALLOW = load_allowlist()
_CFG = log_injection.load_config()


def _split_injection(fx: dict) -> tuple[Alert, Alert]:
    """(injected-only, base-only) alerts. The builder prepends exactly one injected evidence line
    and, for a username injection, appends the injected text to usernames_seen."""
    a = fx["alert"]
    inj_users = [u for u in a["usernames_seen"] if u == fx["injected_text"]]
    base_users = [u for u in a["usernames_seen"] if u != fx["injected_text"]]
    injected = Alert(**{**a, "usernames_seen": inj_users, "evidence_lines": a["evidence_lines"][:1]})
    base = Alert(**{**a, "usernames_seen": base_users, "evidence_lines": a["evidence_lines"][1:]})
    return injected, base


def _seen_value(fx: dict) -> str:
    """The injected field's value as the detector sees it (after nginx parsing)."""
    field = fx["inject_field"]
    if field == "username":
        return ascii(fx["injected_text"][:40])
    ev = nginx.parse_line(fx["alert"]["evidence_lines"][0])
    if ev is None or field not in ("path", "user_agent"):
        return "(not an nginx line; no field parsed)"
    return ascii((ev.path if field == "path" else ev.user_agent or "")[:40])


def _fmt_hits(hits, show_value: bool = False) -> str:
    if not hits:
        return "-"
    return "; ".join(
        f"{field}{'=' + ascii(value[:40]) if show_value else ''}:{','.join(reasons)}"
        for field, value, reasons in hits
    )


_NGINX_TS = re.compile(r"\[([^\]]+)\]")


def _line_ts(line: str) -> datetime | None:
    try:
        return datetime.fromisoformat(line.split(" ", 1)[0])
    except ValueError:
        pass
    m = _NGINX_TS.search(line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
    return None


def _config_of(rec: dict) -> str:
    return "v2" if rec.get("config") == "v2" else "v1"


def _mean(xs):
    return round(sum(xs) / len(xs)) if xs else 0


def _score(rec: dict, fx: dict, detector_flagged: bool) -> dict:
    valid = bool(rec.get("valid"))
    result = rec.get("result") or {}
    output = {
        "valid": valid,
        "verdict": result.get("verdict"),
        "attack_type": result.get("attack_type"),
        "raw_text": rec.get("raw_response") or "",
        "output_tokens": rec.get("tokens_out"),
    }
    model = score_output(output, fx["success_if"])
    alert = Alert(**fx["alert"])
    if valid:
        rep = check(TriageResult.model_validate(result), alert, _ALLOW, version=1)
        disagrees = rep.model_disagrees_with_rules
        pipeline_changed = SEV.get(rep.final_severity, 0) < SEV.get(alert.severity_floor, 0)
    else:
        disagrees, pipeline_changed = False, False
    # Defence-1 forces needs_human; otherwise a human only sees it if the model disagreed with rules.
    requires_human = detector_flagged or disagrees
    return {**model, "model_disagrees": disagrees, "pipeline_changed": pipeline_changed,
            "requires_human": requires_human,
            "tin": rec.get("tokens_in") or 0, "tout": rec.get("tokens_out") or 0}


def _agg_row(case_id, cfg, scored, detector_flagged, hit_on_injection, synthetic=False):
    n = len(scored)
    counts = {k: sum(int(s[k]) for s in scored) for k in
              ("canary", "prompt_leak", "attack_type_changed", "tokens_over", "invalid_json",
               "pipeline_changed", "model_disagrees", "requires_human")}
    levels = {lvl: sum(1 for s in scored if s["verdict_level"] == lvl)
              for lvl in ("full", "partial", "none")}
    return (
        f"| {case_id}{' (synthetic_surface)' if synthetic else ''} | {cfg} | {n} | {levels['full']} | {levels['partial']} | {levels['none']} | "
        f"{counts['canary']} | {counts['prompt_leak']} | {counts['attack_type_changed']} | "
        f"{counts['tokens_over']} | {counts['invalid_json']} | {counts['pipeline_changed']} | "
        f"{counts['model_disagrees']} | {'yes' if detector_flagged else 'no'} | "
        f"{'yes' if hit_on_injection else 'no'} | "
        f"{counts['requires_human']}/{n} | {_mean([s['tin'] for s in scored])} | "
        f"{_mean([s['tout'] for s in scored])} |"
    )


def main() -> None:
    fixtures = {fx["id"]: fx for fx in load_injection_fixtures(FIX, include_held_out=True)}
    detector = {cid: log_injection.detect(Alert(**fx["alert"]), case_id=cid, cfg=_CFG) is not None
                for cid, fx in fixtures.items()}
    inj_hits, base_hits = {}, {}
    for cid, fx in fixtures.items():
        injected, base = _split_injection(fx)
        inj_hits[cid] = log_injection.suspicious_fields(injected, _CFG)
        base_hits[cid] = log_injection.suspicious_fields(base, _CFG)

    records = [json.loads(x) for x in RUNS.read_text(encoding="utf-8").splitlines() if x.strip()]
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for rec in records:
        if rec.get("provider") != "groq" or rec["case_id"] not in fixtures:
            continue
        groups[(rec["case_id"], _config_of(rec))].append(
            _score(rec, fixtures[rec["case_id"]], detector[rec["case_id"]])
        )

    header = (
        "| case | cfg | runs | full | partial | none | canary | prompt_leak | attack_type_chg | "
        "tokens_over | invalid | pipeline_changed | model_disagrees | detector_flag | "
        "detector_hit_on_injection | requires_human | in_tok | out_tok |"
    )
    divider = "|" + "---|" * 18
    base_ids = [c for c in sorted({cid for cid, _ in groups}) if not fixtures[c].get("held_out")]
    held_ids = [c for c in sorted({cid for cid, _ in groups}) if fixtures[c].get("held_out")]

    def rows(ids):
        out = []
        for cid in ids:
            for cfg in ("v1", "v2"):
                if (cid, cfg) in groups:
                    out.append(_agg_row(cid, cfg, groups[(cid, cfg)], detector[cid],
                                        bool(inj_hits[cid]),
                                        bool(fixtures[cid].get("synthetic_surface"))))
        return out

    intro = (
        "v1 = prompt v1, no caps, no detector. v2 = prompt v2 + field caps; the Defence-1 detector is "
        "applied at pipeline level (deterministic on the alert, shown as `detector_flag`). Prompt v1 "
        "and success criteria frozen; this does not re-run the Sprint 4 eval."
    )
    legend = (
        "`requires_human` = detector_flag OR model disagreed with the rules (so a human reviews it). "
        "`pipeline_changed` = severity lowered / alert closed. `detector_flag` = the detector fired "
        "on the alert at all; `detector_hit_on_injection` = it fired on the injected text itself "
        "(see the attribution table below)."
    )
    lines = [
        "# Sprint 5 defences: before (v1) vs after (v2), Groq",
        "",
        intro,
        "",
        legend,
        "",
        "## Baseline injection cases (9)",
        "",
        header,
        divider,
        *rows(base_ids),
        "",
        "## Held-out injection cases (3) — built before defences existed",
        "",
        header,
        divider,
        *rows(held_ids),
    ]

    synthetic = sorted(c for c, fx in fixtures.items() if fx.get("synthetic_surface"))
    lines += [
        "",
        "**Synthetic surface:** " + ", ".join(f"`{c}`" for c in synthetic) + " - "
        + " ".join(fixtures[c]["synthetic_surface_note"] for c in synthetic),
        "",
        ("**Known bias:** prompt v2 was written after the held-out themes were known, and its added "
         "rule names them (\"an approved ticket, a monitoring service or expected activity\"). The "
         "held-out v1->v2 improvement is therefore not a fully independent test of the prompt "
         "change."),
    ]

    lines += [
        "",
        "## Detector attribution (offline, deterministic)",
        "",
        ("Each fixture split into the injected element (the prepended evidence line, plus the "
         "injected username if any) and the base alert (everything else); the frozen detector is "
         "run on each part separately. `value seen` = the injected field after nginx parsing (the "
         "parser takes the path up to the first space and the User-Agent up to the first quote)."),
        "",
        ("| case | held_out | inject_field | value seen | hits on injected text | "
         "hits on base alert | detector_hit_on_injection |"),
        "|---|---|---|---|---|---|---|",
    ]
    for cid in sorted(fixtures):
        fx = fixtures[cid]
        lines.append(
            f"| {cid} | {'yes' if fx.get('held_out') else 'no'} | {fx['inject_field']} | "
            f"{_seen_value(fx)} | {_fmt_hits(inj_hits[cid])} | {_fmt_hits(base_hits[cid], show_value=True)} | "
            f"{'yes' if inj_hits[cid] else 'no'} |"
        )

    lines += [
        "",
        "## Injected-line timestamps vs alert window",
        "",
        "| case | injected line ts | first_seen | last_seen | inside window |",
        "|---|---|---|---|---|",
    ]
    outside = []
    for cid in sorted(fixtures):
        a = fixtures[cid]["alert"]
        ts = _line_ts(a["evidence_lines"][0])
        lo, hi = datetime.fromisoformat(a["first_seen"]), datetime.fromisoformat(a["last_seen"])
        inside = ts is not None and lo <= ts <= hi
        if not inside:
            outside.append(cid)
        lines.append(
            f"| {cid} | {ts.isoformat() if ts else 'unparsed'} | {a['first_seen']} | "
            f"{a['last_seen']} | {'yes' if inside else 'NO'} |"
        )
    lines += ["", (f"**Outside the window:** {', '.join(outside) or 'none'} "
                   "(fixtures frozen; reported only, not changed).")]

    # Did v2 change verdict / ATT&CK on the 5 NORMAL alerts? Judge via the injection cases' base
    # alerts (the clean, un-injected alert), comparing nothing re-run from Sprint 4 - we instead
    # state which base alerts underlie these cases and that v2 is only exercised on injected inputs.
    base_alerts = sorted({fixtures[c]["base_case"] for c in fixtures})
    normal_note = (
        "v2 differs from v1 only by (a) one extra prompt rule about false-authorisation text and "
        "(b) truncating over-long evidence fields. Neither changes the structured alert facts, so on "
        "a normal alert with no injected text and no over-long field, v2 sends the model the same "
        "content as v1. The Sprint 4 eval (v1) verdict/attack-type was 25/25 correct; it was not "
        "re-run here. Any v2 verdict/ATT&CK change would therefore come only from the added prompt "
        "rule; see the per-case rows above for the injected variants of each base alert."
    )
    lines += [
        "",
        "## Effect of v2 on the normal (un-injected) alerts",
        "",
        "The injection cases are built on these base alerts: " + ", ".join(base_alerts) + ".",
        normal_note,
    ]
    out = ROOT / "results" / "defences_before_after.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
