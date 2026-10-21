"""Pydantic schema for the model's triage output (plan 4.2).

Invalid output is never hand-fixed: it is retried once by the client, then recorded
as InvalidResult. Technique-ID *format* is validated here; membership of the ATT&CK
allow-list is a guardrail check, not a schema check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class Verdict(str, Enum):
    malicious = "malicious"
    benign = "benign"
    needs_human = "needs_human"


class AttackType(str, Enum):
    ssh_bruteforce = "ssh_bruteforce"
    port_scan = "port_scan"
    web_dir_scan = "web_dir_scan"
    web_probe = "web_probe"
    benign_activity = "benign_activity"
    other = "other"


class TriageResult(BaseModel):
    """Validated model output. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    attack_type: AttackType
    confidence: float = Field(ge=0.0, le=1.0)
    attack_techniques: list[str] = Field(default_factory=list)
    summary: str = Field(max_length=600)
    key_evidence: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)

    @field_validator("attack_techniques")
    @classmethod
    def _technique_format(cls, value: list[str]) -> list[str]:
        bad = [t for t in value if not _TECHNIQUE.match(t)]
        if bad:
            raise ValueError(f"malformed technique IDs: {bad}")
        return value


@dataclass
class InvalidResult:
    """Recorded when the model output cannot be validated after the retry."""

    raw: str
    error: str
    attempts: int


def _strip_fences(text: str) -> str:
    s = text.strip()
    if s.startswith("```"):
        s = s[s.find("\n") + 1 :] if "\n" in s else s[3:]
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
    return s.strip()


def parse_triage(text: str) -> TriageResult:
    """Parse model text (tolerating ```json fences) into a TriageResult.

    Raises pydantic.ValidationError or ValueError on bad input; the caller decides
    whether to retry or record InvalidResult.
    """
    return TriageResult.model_validate_json(_strip_fences(text))
