"""Guardrails over model output (plan 4.2 / 4.4). All checks are deterministic:

- allow-list: every technique ID must be in data/attack_allowlist.json, else hallucinated.
- verbatim evidence: every key_evidence string must be a substring of some evidence line.
- grounding: every IP and number in the summary must appear somewhere in the alert.
- severity floor: the model can never lower the rule's severity. If the model says benign on a
  high/critical alert, that is not auto-accepted; it is flagged for a human.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from triage.alert import Alert
from triage.llm.schema import TriageResult, Verdict

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# Summary numbers, allowing thousands separators: "65,531" is one token, normalised to "65531".
_SUMMARY_NUM = re.compile(r"\b\d+(?:,\d{3})*\b")
# No word boundary: catches digit runs glued to letters, e.g. the "17" in "...21T17:36".
_DIGITS = re.compile(r"\d+")
# v2 composite tokens whose digit pieces must NOT be checked separately: ISO datetime,
# IPv4, dotted version (3.8.2), clock time. Order matters (datetime before clock).
_COMPOSITE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?"
    r"|\d{1,3}(?:\.\d{1,3}){3}"
    r"|\d+(?:\.\d+){2,}"
    r"|\d{1,2}:\d{2}(?::\d{2})?"
)
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

ROOT = Path(__file__).resolve().parents[2]


def load_allowlist(path: str | Path | None = None) -> dict[str, str]:
    path = Path(path) if path else ROOT / "data" / "attack_allowlist.json"
    return json.loads(Path(path).read_text(encoding="utf-8"))["techniques"]


@dataclass
class GuardrailReport:
    hallucinated_techniques: list[str] = field(default_factory=list)
    unverifiable_evidence: list[str] = field(default_factory=list)
    ungrounded_ips: list[str] = field(default_factory=list)
    ungrounded_numbers: list[str] = field(default_factory=list)
    evidence_only_numbers: list[str] = field(default_factory=list)  # v2 only
    final_severity: str = "low"
    model_disagrees_with_rules: bool = False
    checker_version: int = 1

    @property
    def passed(self) -> bool:
        # evidence_only_numbers is an informational flag (v2), not a hard failure.
        return not (
            self.hallucinated_techniques
            or self.unverifiable_evidence
            or self.ungrounded_ips
            or self.ungrounded_numbers
        )


def _alert_text(alert: Alert) -> str:
    """Blob used for IP containment (evidence included: an IP the model cites should
    appear verbatim in the alert or its evidence)."""
    parts = [alert.src_ip or "", alert.target_host or "", *alert.evidence_lines]
    parts += [str(v) for v in alert.counts.values()]
    parts += list(alert.usernames_seen)
    return " ".join(parts)


def _trusted_numbers(alert: Alert) -> set[str]:
    """Whole-token numbers from the TRUSTED structured fields only. ``evidence_lines`` are
    deliberately excluded: they are untrusted raw log text whose many timestamps and ports
    let almost any 1-3 digit number ground by coincidence (how a wrong count like 27 slipped
    past). ``first_seen``/``last_seen`` ARE trusted alert fields (same tier as src_ip/counts),
    so the window's own timestamp digits count as grounded.
    """
    numbers: set[str] = set()
    for value in alert.counts.values():
        if isinstance(value, bool):  # bool is an int subclass; skip flags like scanner_ua
            continue
        if isinstance(value, int):
            numbers.add(str(value))
    trusted_text = [
        alert.src_ip or "",
        alert.target_host or "",
        alert.first_seen or "",
        alert.last_seen or "",
        *alert.usernames_seen,
    ]
    for text in trusted_text:
        numbers.update(_DIGITS.findall(text))
    return numbers


def _duration_seconds(alert: Alert) -> float | None:
    if not (alert.first_seen and alert.last_seen):
        return None
    try:
        start = datetime.fromisoformat(alert.first_seen)
        end = datetime.fromisoformat(alert.last_seen)
    except ValueError:
        return None
    return (end - start).total_seconds()


def _summary_numbers_v1(summary: str) -> list[str]:
    """Every \\b\\d+\\b token (commas stripped). Pieces of IPs/timestamps/versions are
    included — this is the over-eager behaviour that produced false alarms."""
    return [m.replace(",", "") for m in _SUMMARY_NUM.findall(summary)]


def _summary_numbers_v2(summary: str) -> list[str]:
    """Numbers NOT inside a composite token (IPv4, ISO datetime, dotted version, clock),
    so octets/timestamp pieces/version fragments are never checked separately."""
    spans = [m.span() for m in _COMPOSITE.finditer(summary)]
    out = []
    for m in _SUMMARY_NUM.finditer(summary):
        s, e = m.span()
        if any(cs <= s and e <= ce for cs, ce in spans):
            continue
        out.append(m.group().replace(",", ""))
    return out


def check(
    result: TriageResult, alert: Alert, allowlist: dict[str, str], version: int = 1
) -> GuardrailReport:
    allowed = set(allowlist)
    hallucinated = [t for t in result.attack_techniques if t not in allowed]

    unverifiable = [
        item for item in result.key_evidence if not any(item in line for line in alert.evidence_lines)
    ]

    text = _alert_text(alert)
    ungrounded_ips = sorted({ip for ip in _IP.findall(result.summary) if ip not in text})

    grounded_numbers = _trusted_numbers(alert)
    evidence_only_numbers: list[str] = []
    if version == 1:
        summary_numbers = set(_summary_numbers_v1(result.summary))
        ungrounded_numbers = sorted(n for n in summary_numbers if n not in grounded_numbers)
    else:
        evidence_numbers = set(_DIGITS.findall(" ".join(alert.evidence_lines)))
        duration = _duration_seconds(alert)
        ungrounded: list[str] = []
        evidence_only: list[str] = []
        for n in dict.fromkeys(_summary_numbers_v2(result.summary)):  # unique, ordered
            if n in grounded_numbers:
                continue
            if duration is not None and abs(int(n) - duration) <= 1:
                continue  # a window duration in seconds, grounded by first_seen/last_seen
            if n in evidence_numbers:
                evidence_only.append(n)
            else:
                ungrounded.append(n)
        ungrounded_numbers = sorted(set(ungrounded))
        evidence_only_numbers = sorted(set(evidence_only))

    floor = alert.severity_floor
    disagrees = (
        result.verdict == Verdict.benign
        and _SEVERITY_RANK.get(floor, 0) >= _SEVERITY_RANK["high"]
    )

    return GuardrailReport(
        hallucinated_techniques=hallucinated,
        unverifiable_evidence=unverifiable,
        ungrounded_ips=ungrounded_ips,
        ungrounded_numbers=ungrounded_numbers,
        evidence_only_numbers=evidence_only_numbers,
        final_severity=floor,  # model can raise concern but never lower the rule's floor
        model_disagrees_with_rules=disagrees,
        checker_version=version,
    )
