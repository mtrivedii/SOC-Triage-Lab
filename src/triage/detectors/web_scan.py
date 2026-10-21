"""Web directory/wordlist-scan detector.

Flags a client that generates many 404s OR requests many distinct paths in the
window. A known scanner User-Agent is recorded as a weak signal only (attackers
can spoof it), never as the sole basis for the alert. A high-volume monitor that
hits a single existing path (e.g. /health) stays below both thresholds on purpose
- that is the intended false-positive boundary.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from triage.alert import Alert, cap_evidence, iso
from triage.parsers.nginx import NginxEvent

RULE_ID = "web_scan"
ATTACK_TYPE = "web_dir_scan"
DEFAULT_MIN_404 = 15
DEFAULT_MIN_DISTINCT_PATHS = 15

_SCANNER_UA = re.compile(
    r"gobuster|dirb|dirbuster|nikto|sqlmap|nmap|masscan|wpscan|ffuf|feroxbuster|wfuzz|"
    r"gospider|hydra|zgrab|nuclei",
    re.IGNORECASE,
)


def detect(
    events: Iterable[NginxEvent],
    case_id: str | None = None,
    source_log: str = "nginx_access.log",
    target_host: str = "ubuntu-target",
    min_404: int = DEFAULT_MIN_404,
    min_distinct_paths: int = DEFAULT_MIN_DISTINCT_PATHS,
    exclude_ips: set[str] | None = None,
) -> list[Alert]:
    exclude = exclude_ips or set()
    by_ip: dict[str, list[NginxEvent]] = {}
    for ev in events:
        if ev.client_ip is None or ev.client_ip in exclude:
            continue
        by_ip.setdefault(ev.client_ip, []).append(ev)

    alerts: list[Alert] = []
    for ip, reqs in by_ip.items():
        status_404 = sum(1 for e in reqs if e.status == 404)
        distinct_paths = {e.path for e in reqs if e.path}
        if status_404 < min_404 and len(distinct_paths) < min_distinct_paths:
            continue

        scanner_ua = any(e.user_agent and _SCANNER_UA.search(e.user_agent) for e in reqs)
        times = [e.ts for e in reqs if e.ts is not None]
        not_found = [e.raw for e in reqs if e.status == 404]
        evidence, truncated = cap_evidence([e.raw for e in reqs], priority=not_found[:5])
        alerts.append(
            Alert(
                alert_id=f"{RULE_ID}-{case_id}-{ip}",
                case_id=case_id,
                rule_id=RULE_ID,
                rule_name="Web directory/wordlist scan (many 404s or many distinct paths)",
                severity_floor="medium",
                source_log=source_log,
                first_seen=iso(min(times)) if times else None,
                last_seen=iso(max(times)) if times else None,
                src_ip=ip,
                target_host=target_host,
                usernames_seen=[],
                counts={
                    "requests": len(reqs),
                    "status_404": status_404,
                    "distinct_paths": len(distinct_paths),
                    "scanner_ua": scanner_ua,
                },
                evidence_lines=evidence,
                evidence_truncated=truncated,
            )
        )
    return alerts
