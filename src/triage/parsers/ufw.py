"""Parse ufw (iptables) kernel log lines into normalised firewall events.

Target format, see docs/lab_journal.md:

    2026-10-21T16:15:38.492690+00:00 ubuntu-target kernel: [UFW BLOCK] IN=ens33 OUT= ...
        SRC=151.101.206.49 DST=192.168.100.131 ... PROTO=TCP SPT=443 DPT=40272 ...

Quirks handled (and left for the detector to use):
- Action is AUDIT, ALLOW or BLOCK. The same packet can appear as an AUDIT line AND an
  ALLOW/BLOCK line, so a detector must not double-count; it should look at BLOCK (and ALLOW).
- Fields are KEY=VALUE in any order, varying by protocol; parse by key, not by position.
- Bare flag tokens (SYN, ACK, PSH, ...) have no '='; they are kept as flags.
Unrecognised lines are skipped; nothing here raises on malformed input.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))\s+"
    r"(?P<host>\S+)\s+kernel:\s+\[UFW (?P<action>[A-Z]+)\]\s+(?P<rest>.*)$"
)


@dataclass
class UfwEvent:
    """One normalised ufw kernel-log line."""

    ts: datetime | None
    host: str | None
    action: str  # AUDIT | ALLOW | BLOCK | ...
    src: str | None
    dst: str | None
    proto: str | None
    spt: int | None
    dpt: int | None
    in_if: str | None
    out_if: str | None
    flags: list[str] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _int(value: str | None) -> int | None:
    return int(value) if value is not None and value.isdigit() else None


def parse_line(line: str) -> UfwEvent | None:
    """Parse one line. Returns None if it is not a recognisable UFW line."""
    raw = line.rstrip("\n")
    m = _LINE.match(raw)
    if not m:
        return None

    kv: dict[str, str] = {}
    flags: list[str] = []
    for token in m.group("rest").split():
        if "=" in token:
            key, _, val = token.partition("=")
            kv[key] = val
        else:
            flags.append(token)

    return UfwEvent(
        ts=_parse_ts(m.group("ts")),
        host=m.group("host"),
        action=m.group("action"),
        src=kv.get("SRC"),
        dst=kv.get("DST"),
        proto=kv.get("PROTO"),
        spt=_int(kv.get("SPT")),
        dpt=_int(kv.get("DPT")),
        in_if=kv.get("IN"),
        out_if=kv.get("OUT"),
        flags=flags,
        fields=kv,
        raw=raw,
    )


def parse_lines(lines: Iterable[str]) -> Iterator[UfwEvent]:
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            yield ev


def parse_file(path: str | Path) -> list[UfwEvent]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return list(parse_lines(fh))
