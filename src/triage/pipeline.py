"""Turn a ground-truth case into deterministic alerts: parse the listed logs, filter
to the case window, drop the analyst/management IP, and run the matching detector.

Shared by eval/detector_baseline.py (baseline) and scripts/triage_once.py (live AI run)
so both build alerts the exact same way.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from triage.alert import Alert
from triage.detectors import port_scan, ssh_bruteforce, web_scan
from triage.parsers import auth_log, nginx, ufw

DEFAULT_MGMT_IP = "192.168.214.1"

# log filename -> (parser module, detector module)
DISPATCH = {
    "auth.log": (auth_log, ssh_bruteforce),
    "ufw.log": (ufw, port_scan),
    "nginx_access.log": (nginx, web_scan),
}

# rule_id -> attack_type (from the detector modules)
RULE_TO_ATTACK = {detector.RULE_ID: detector.ATTACK_TYPE for _, detector in DISPATCH.values()}


def _in_window(event, start: datetime, end: datetime) -> bool:
    ts = getattr(event, "ts", None)
    return ts is not None and start <= ts <= end


def alerts_for_case(case: dict, root: Path, mgmt_ip: str = DEFAULT_MGMT_IP) -> list[Alert]:
    start = datetime.fromisoformat(case["window"]["start"])
    end = datetime.fromisoformat(case["window"]["end"])
    alerts: list[Alert] = []
    for rel in case["log_files"]:
        name = Path(rel).name
        if name not in DISPATCH:
            continue
        parser, detector = DISPATCH[name]
        events = [e for e in parser.parse_file(root / rel) if _in_window(e, start, end)]
        alerts.extend(detector.detect(events, case_id=case["case_id"], exclude_ips={mgmt_ip}))
    return alerts
