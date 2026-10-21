"""SSH brute-force detector.

Flags a source IP with at least ``min_failures`` failed SSH logins in the given
events. If the same source also has an accepted login, the alert is escalated to
"followed by success" (but severity floor stays high either way - the model may
raise severity, never lower it; plan 4.2). A few failures followed by a success
(a user fumbling their password) stays below the threshold on purpose.
"""

from __future__ import annotations

from collections.abc import Iterable

from triage.alert import Alert, cap_evidence, iso
from triage.parsers.auth_log import AuthEvent

RULE_ID = "ssh_bruteforce"
ATTACK_TYPE = "ssh_bruteforce"
DEFAULT_MIN_FAILURES = 5


def detect(
    events: Iterable[AuthEvent],
    case_id: str | None = None,
    source_log: str = "auth.log",
    target_host: str = "ubuntu-target",
    min_failures: int = DEFAULT_MIN_FAILURES,
    exclude_ips: set[str] | None = None,
) -> list[Alert]:
    exclude = exclude_ips or set()
    by_ip_failed: dict[str, list[AuthEvent]] = {}
    by_ip_accepted: dict[str, list[AuthEvent]] = {}

    for ev in events:
        if ev.src_ip is None or ev.src_ip in exclude:
            continue
        if ev.event == "failed_password":
            by_ip_failed.setdefault(ev.src_ip, []).append(ev)
        elif ev.event.startswith("accepted_"):
            by_ip_accepted.setdefault(ev.src_ip, []).append(ev)

    alerts: list[Alert] = []
    for ip, failed in by_ip_failed.items():
        if len(failed) < min_failures:
            continue
        accepted = by_ip_accepted.get(ip, [])
        related = [*failed, *accepted]
        related.sort(key=lambda e: (e.ts is None, e.ts))
        users = sorted({e.user for e in related if e.user})
        times = [e.ts for e in related if e.ts is not None]
        success = bool(accepted)

        evidence, truncated = cap_evidence(
            [e.raw for e in related],
            priority=[e.raw for e in accepted],
        )
        alerts.append(
            Alert(
                alert_id=f"{RULE_ID}-{case_id}-{ip}",
                case_id=case_id,
                rule_id=RULE_ID,
                rule_name=(
                    "SSH password guessing followed by a successful login"
                    if success
                    else "SSH password guessing (repeated failed logins)"
                ),
                severity_floor="high",
                source_log=source_log,
                first_seen=iso(min(times)) if times else None,
                last_seen=iso(max(times)) if times else None,
                src_ip=ip,
                target_host=target_host,
                usernames_seen=users,
                counts={"failed": len(failed), "accepted": len(accepted)},
                evidence_lines=evidence,
                evidence_truncated=truncated,
            )
        )
    return alerts
