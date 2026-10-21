"""Port-scan detector.

Flags a source IP that hits at least ``min_distinct_ports`` distinct destination
ports in ufw BLOCK lines. Only BLOCK is counted (not AUDIT), so the AUDIT/BLOCK
pairing does not double-count. The threshold is far below the full port count on
purpose: the ufw log may be incomplete under fast scans (two data points only, not
a confirmed rule - see docs/lab_journal.md), so we must not assume complete logs.
"""

from __future__ import annotations

from collections.abc import Iterable

from triage.alert import Alert, cap_evidence, iso
from triage.parsers.ufw import UfwEvent

RULE_ID = "port_scan"
ATTACK_TYPE = "port_scan"
DEFAULT_MIN_DISTINCT_PORTS = 50


def detect(
    events: Iterable[UfwEvent],
    case_id: str | None = None,
    source_log: str = "ufw.log",
    target_host: str = "ubuntu-target",
    min_distinct_ports: int = DEFAULT_MIN_DISTINCT_PORTS,
    exclude_ips: set[str] | None = None,
) -> list[Alert]:
    exclude = exclude_ips or set()
    ports_by_ip: dict[str, set[int]] = {}
    lines_by_ip: dict[str, list[str]] = {}
    times_by_ip: dict[str, list] = {}
    packets_by_ip: dict[str, int] = {}

    for ev in events:
        if ev.action != "BLOCK" or ev.src is None or ev.src in exclude or ev.dpt is None:
            continue
        ports_by_ip.setdefault(ev.src, set()).add(ev.dpt)
        lines_by_ip.setdefault(ev.src, []).append(ev.raw)
        packets_by_ip[ev.src] = packets_by_ip.get(ev.src, 0) + 1
        if ev.ts is not None:
            times_by_ip.setdefault(ev.src, []).append(ev.ts)

    alerts: list[Alert] = []
    for ip, ports in ports_by_ip.items():
        if len(ports) < min_distinct_ports:
            continue
        times = times_by_ip.get(ip, [])
        evidence, truncated = cap_evidence(lines_by_ip[ip])
        alerts.append(
            Alert(
                alert_id=f"{RULE_ID}-{case_id}-{ip}",
                case_id=case_id,
                rule_id=RULE_ID,
                rule_name="Port scan (many blocked destination ports from one source)",
                severity_floor="medium",
                source_log=source_log,
                first_seen=iso(min(times)) if times else None,
                last_seen=iso(max(times)) if times else None,
                src_ip=ip,
                target_host=target_host,
                usernames_seen=[],
                counts={"distinct_ports": len(ports), "blocked_packets": packets_by_ip[ip]},
                evidence_lines=evidence,
                evidence_truncated=truncated,
            )
        )
    return alerts
