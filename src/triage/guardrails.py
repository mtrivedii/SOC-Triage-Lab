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
from pathlib import Path

from triage.alert import Alert
from triage.llm.schema import TriageResult, Verdict

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NUM = re.compile(r"\b\d+\b")
# No word boundary: catches digit runs glued to letters, e.g. the "17" in "...21T17:36".
_DIGITS = re.compile(r"\d+")
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
    final_severity: str = "low"
    model_disagrees_with_rules: bool = False

    @property
    def passed(self) -> bool:
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


def check(result: TriageResult, alert: Alert, allowlist: dict[str, str]) -> GuardrailReport:
    allowed = set(allowlist)
    hallucinated = [t for t in result.attack_techniques if t not in allowed]

    unverifiable = [
        item for item in result.key_evidence if not any(item in line for line in alert.evidence_lines)
    ]

    text = _alert_text(alert)
    ungrounded_ips = sorted({ip for ip in _IP.findall(result.summary) if ip not in text})

    grounded_numbers = _trusted_numbers(alert)
    ungrounded_numbers = sorted(
        {n for n in _NUM.findall(result.summary) if n not in grounded_numbers}
    )

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
        final_severity=floor,  # model can raise concern but never lower the rule's floor
        model_disagrees_with_rules=disagrees,
    )
