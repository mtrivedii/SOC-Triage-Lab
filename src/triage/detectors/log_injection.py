"""Defence 1: deterministic log-injection detector.

Flags attacker-controlled fields (SSH username, URL path, User-Agent, Referer) that look like
instructions to the model: whitespace in a username, an over-long username, or a configured
keyword (matched case-insensitively after NFKC normalisation + zero-width strip). It emits a
separate `suspected_log_injection` alert (severity_floor medium) and, at pipeline level, forces
the case to `needs_human`. It never lowers a severity or closes anything.

Fields come from the alert: usernames from ``usernames_seen``; path/user-agent/referer are parsed
back out of any nginx evidence lines. Config (keyword list, username cap) is in
config/log_injection.toml and is frozen before the before/after measurement.

Two versions, selected with ``version=`` (default 1, frozen):
  v1: parsed fields only; keyword = plain substring after NFKC + zero-width strip.
  v2: v1's field checks PLUS every full raw evidence line (the same text the model sees); Unicode
      look-alikes mapped to Latin (curated Cyrillic/Greek subset of Unicode confusables.txt, no
      extra dependency); keyword must start a word (no letter/digit before it), so ``.cvsignore``
      no longer matches ``ignore`` while stems like ``authori``/``instruction`` still match
      ``authorised``/``instructions``. Same keyword list.
"""

from __future__ import annotations

import re
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


# v2: look-alike letters -> Latin (curated subset of Unicode confusables.txt: Cyrillic and Greek
# letters whose skeleton is a single Latin letter). Code points keep the source ASCII.
_CONFUSABLES = {
    # Cyrillic lowercase
    0x0430: "a", 0x0441: "c", 0x0501: "d", 0x0435: "e", 0x04BB: "h", 0x0456: "i", 0x0458: "j",
    0x04CF: "l", 0x043E: "o", 0x0440: "p", 0x051B: "q", 0x0455: "s", 0x051D: "w", 0x0445: "x",
    0x0443: "y",
    # Cyrillic uppercase
    0x0410: "A", 0x0412: "B", 0x0421: "C", 0x0415: "E", 0x041D: "H", 0x0406: "I", 0x0408: "J",
    0x041A: "K", 0x041C: "M", 0x041E: "O", 0x0420: "P", 0x0405: "S", 0x0422: "T", 0x0425: "X",
    0x04AE: "Y",
    # Greek
    0x03B1: "a", 0x03B9: "i", 0x03BA: "k", 0x03BD: "v", 0x03BF: "o", 0x03C1: "p", 0x03C5: "u",
    0x03F2: "c", 0x03F3: "j",
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H", 0x0399: "I", 0x039A: "K",
    0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
    # Latin script g (U+0261)
    0x0261: "g",
}


def load_config(path: str | Path | None = None) -> dict:
    path = Path(path) if path else ROOT / "config" / "log_injection.toml"
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def _normalise_v2(text: str) -> str:
    return _normalise(text).translate(_CONFUSABLES)


def _keyword_v1(low: str, kw: str) -> bool:
    return kw in low


def _keyword_v2(low: str, kw: str) -> bool:
    # keyword must start a word: no letter/digit immediately before it
    return re.search(rf"(?<![a-z0-9]){re.escape(kw)}", low) is not None


def _field_reasons(value: str, is_username: bool, cfg: dict, version: int = 1) -> list[str]:
    norm = _normalise(value) if version == 1 else _normalise_v2(value)
    low = norm.lower()
    match = _keyword_v1 if version == 1 else _keyword_v2
    reasons: list[str] = []
    if is_username:
        if len(norm) > cfg["username_max_len"]:
            reasons.append("username_too_long")
        if any(ch.isspace() for ch in norm.strip()):
            reasons.append("username_whitespace")
    for kw in cfg["keywords"]:
        if match(low, kw):
            reasons.append(f"keyword:{kw}")
            break
    return reasons


def suspicious_fields(
    alert: Alert, cfg: dict | None = None, version: int = 1
) -> list[tuple[str, str, list[str]]]:
    """Return (field, value, reasons) for each attacker-controlled field that looks injected.
    v2 also returns ("raw_line", line, reasons) for any full evidence line with a keyword."""
    cfg = cfg or load_config()
    hits: list[tuple[str, str, list[str]]] = []
    for user in alert.usernames_seen:
        reasons = _field_reasons(user, True, cfg, version)
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
            reasons = _field_reasons(value, False, cfg, version)
            if reasons:
                hits.append((field_name, value, reasons))
    if version == 2:
        for line in alert.evidence_lines:
            reasons = _field_reasons(line, False, cfg, version)
            if reasons:
                hits.append(("raw_line", line, reasons))
    return hits


def detect(
    alert: Alert, case_id: str | None = None, cfg: dict | None = None, version: int = 1
) -> Alert | None:
    """Return a suspected_log_injection Alert if any attacker-controlled field looks injected,
    else None. A non-None result forces `needs_human` at pipeline level (caller's job)."""
    hits = suspicious_fields(alert, cfg, version)
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
