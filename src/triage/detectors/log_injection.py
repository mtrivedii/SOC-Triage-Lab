"""Defence 1: deterministic log-injection detector.

Flags attacker-controlled fields (SSH username, URL path, User-Agent, Referer) that look like
instructions to the model: whitespace in a username, an over-long username, or a configured
keyword (matched case-insensitively after NFKC normalisation + zero-width strip). It emits a
separate `suspected_log_injection` alert (severity_floor medium) and, at pipeline level, forces
the case to `needs_human`. It never lowers a severity or closes anything.

Fields come from the alert: usernames from ``usernames_seen``; path/user-agent/referer are parsed
back out of any nginx evidence lines. Config (keyword list, username cap) is in
config/log_injection.toml and is frozen before the before/after measurement.
"""

from __future__ import annotations

import tomllib
import unicodedata
from pathlib import Path

from triage.alert import Alert, cap_evidence
from triage.parsers import nginx

RULE_ID = "suspected_log_injection"
ROOT = Path(__file__).resolve().parents[3]
# zero-width / invisible joiners stripped before matching (ZWSP, ZWNJ, ZWJ, word-joiner, BOM).
# Built from code points so the source stays ASCII.
_ZERO_WIDTH = dict.fromkeys((0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF), None)


def load_config(path: str | Path | None = None) -> dict:
    path = Path(path) if path else ROOT / "config" / "log_injection.toml"
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def _field_reasons(value: str, is_username: bool, cfg: dict) -> list[str]:
    norm = _normalise(value)
    low = norm.lower()
    reasons: list[str] = []
    if is_username:
        if len(norm) > cfg["username_max_len"]:
            reasons.append("username_too_long")
        if any(ch.isspace() for ch in norm.strip()):
            reasons.append("username_whitespace")
    for kw in cfg["keywords"]:
        if kw in low:
            reasons.append(f"keyword:{kw}")
            break
    return reasons


def suspicious_fields(alert: Alert, cfg: dict | None = None) -> list[tuple[str, str, list[str]]]:
    """Return (field, value, reasons) for each attacker-controlled field that looks injected."""
    cfg = cfg or load_config()
    hits: list[tuple[str, str, list[str]]] = []
    for user in alert.usernames_seen:
        reasons = _field_reasons(user, True, cfg)
        if reasons:
            hits.append(("username", user, reasons))
    for line in alert.evidence_lines:
        ev = nginx.parse_line(line)
        if ev is None:
            continue
        for field_name, value in (("path", ev.path), ("user_agent", ev.user_agent),
                                   ("referer", ev.referer)):
            if not value:
                continue
            reasons = _field_reasons(value, False, cfg)
            if reasons:
                hits.append((field_name, value, reasons))
    return hits


def detect(alert: Alert, case_id: str | None = None, cfg: dict | None = None) -> Alert | None:
    """Return a suspected_log_injection Alert if any attacker-controlled field looks injected,
    else None. A non-None result forces `needs_human` at pipeline level (caller's job)."""
    hits = suspicious_fields(alert, cfg)
    if not hits:
        return None
    evidence = [f"{field}={value[:120]} -> {','.join(reasons)}" for field, value, reasons in hits]
    capped, truncated = cap_evidence(evidence)
    return Alert(
        alert_id=f"{RULE_ID}-{case_id}",
        case_id=case_id,
        rule_id=RULE_ID,
        rule_name="Suspected prompt injection in attacker-controlled log fields",
        severity_floor="medium",
        source_log="(derived from attacker-controlled fields)",
        first_seen=alert.first_seen,
        last_seen=alert.last_seen,
        src_ip=alert.src_ip,
        target_host=alert.target_host,
        usernames_seen=[],
        counts={"suspicious_fields": len(hits)},
        evidence_lines=capped,
        evidence_truncated=truncated,
    )
