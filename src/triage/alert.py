"""Alert schema (plan 4.1) emitted by deterministic detectors, and a helper to
cap evidence lines so downstream LLM cost stays bounded.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


@dataclass
class Alert:
    """Deterministic detector output. Field order follows plan 4.1."""

    alert_id: str
    case_id: str | None
    rule_id: str
    rule_name: str
    severity_floor: str  # low | medium | high | critical
    source_log: str
    first_seen: str | None
    last_seen: str | None
    src_ip: str | None
    target_host: str | None
    usernames_seen: list[str] = field(default_factory=list)
    counts: dict[str, int | bool] = field(default_factory=dict)
    evidence_lines: list[str] = field(default_factory=list)
    evidence_truncated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def cap_evidence(
    lines: list[str], priority: list[str] | None = None, cap: int = 30
) -> tuple[list[str], bool]:
    """Keep at most ``cap`` evidence lines, always including any ``priority`` lines
    (e.g. the successful-login line) plus a head and tail of the rest. Returns
    (lines, truncated).
    """
    priority = [p for p in (priority or []) if p in lines]
    if len(lines) <= cap:
        return list(lines), False

    remaining = max(cap - len(priority), 0)
    head_n = remaining // 2
    tail_n = remaining - head_n
    head = lines[:head_n]
    tail = lines[len(lines) - tail_n :] if tail_n else []

    out: list[str] = []
    for line in [*head, *priority, *tail]:
        if line not in out:
            out.append(line)
    return out, True
