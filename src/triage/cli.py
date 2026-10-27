"""`triage` command line: analyst decisions, audit-log verification and triage reports.

  triage approve <alert_id> --decision approve|override|escalate --analyst NAME [--note "..."]
  triage verify-audit [--expect-head HASH]
  triage report <alert_id> [--out PATH]

Offline only: reads saved triage runs (results/runs.jsonl) and rebuilds the alert from its case
with the deterministic pipeline. A decision is bound to one triage run (its timestamp); by
default the latest valid run for the alert, or pick one with --run-ts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from triage import audit, report
from triage.alert import Alert
from triage.detectors import log_injection
from triage.pipeline import alerts_for_case

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUNS = ROOT / "results" / "runs.jsonl"
DEFAULT_AUDIT = ROOT / "audit" / "audit_log.jsonl"


def _find_run(runs_file: Path, alert_id: str, run_ts: str | None) -> dict:
    records = []
    if runs_file.exists():
        lines = runs_file.read_text(encoding="utf-8").splitlines()
        records = [json.loads(x) for x in lines if x.strip()]
    matches = [r for r in records if r.get("alert_id") == alert_id and r.get("valid")]
    if run_ts:
        matches = [r for r in matches if r.get("ts") == run_ts]
    if not matches:
        raise ValueError(f"no valid triage run for alert {alert_id!r}"
                         + (f" at {run_ts}" if run_ts else "") + f" in {runs_file}")
    return max(matches, key=lambda r: r.get("ts") or "")


def _rebuild_alert(record: dict, root: Path) -> Alert:
    case_path = root / "cases" / f"{record['case_id']}.yaml"
    case = yaml.safe_load(case_path.read_text(encoding="utf-8"))
    for alert in alerts_for_case(case, root):
        if alert.alert_id == record["alert_id"]:
            return alert
    raise ValueError(f"case {record['case_id']} no longer produces alert {record['alert_id']}")


def cmd_approve(args) -> int:
    record = _find_run(Path(args.runs_file), args.alert_id, args.run_ts)
    entry = audit.append_entry(
        Path(args.audit_log),
        alert_id=args.alert_id,
        decision=args.decision,
        analyst=args.analyst,
        note=args.note,
        model=record.get("model"),
        prompt_hash=record.get("prompt_hash"),
        run_ts=record.get("ts"),
    )
    print(f"Recorded {entry['decision']} for {entry['alert_id']} by {entry['analyst']} "
          f"(entry {entry['entry_hash'][:12]})")
    return 0


def cmd_verify(args) -> int:
    res = audit.verify(Path(args.audit_log), expect_head=args.expect_head)
    if res.ok:
        print(f"OK: {res.entries} entries, chain intact. Head: {res.head}")
        return 0
    print(f"BROKEN at entry {res.broken_at}: {res.reason}")
    return 1


def cmd_report(args) -> int:
    record = _find_run(Path(args.runs_file), args.alert_id, args.run_ts)
    alert = _rebuild_alert(record, Path(args.root))
    audit_path = Path(args.audit_log)
    audit_ok = audit.verify(audit_path).ok
    decision = audit.latest_decision(audit_path, args.alert_id, record.get("ts")) if audit_ok \
        else None
    hits = log_injection.suspicious_fields(alert, version=2)
    text = report.render(alert, record, decision, audit_ok, hits)
    out = Path(args.out) if args.out else Path(args.root) / "reports" / f"{args.alert_id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", newline="\n")
    print(f"Wrote {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="triage", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, runs=True):
        p.add_argument("--audit-log", default=str(DEFAULT_AUDIT))
        if runs:
            p.add_argument("--runs-file", default=str(DEFAULT_RUNS))
            p.add_argument("--run-ts", default=None, help="pin one triage run by its ts")

    p = sub.add_parser("approve", help="record an analyst decision in the audit log")
    p.add_argument("alert_id")
    p.add_argument("--decision", required=True, choices=audit.DECISIONS)
    p.add_argument("--analyst", required=True)
    p.add_argument("--note", default=None, help="required for override and escalate")
    common(p)
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("verify-audit", help="check the audit log's hash chain")
    p.add_argument("--expect-head", default=None, help="head hash recorded elsewhere")
    common(p, runs=False)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("report", help="write a markdown triage report (DRAFT until decided)")
    p.add_argument("alert_id")
    p.add_argument("--out", default=None, help="default: reports/<alert_id>.md")
    p.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    common(p)
    p.set_defaults(func=cmd_report)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
