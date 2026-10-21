"""Parse nginx access logs (combined format) into normalised HTTP events.

Target format, see docs/lab_journal.md:

    ::1 - - [21/Oct/2026:16:15:47 +0000] "GET /health HTTP/1.1" 200 3 "-" "curl/8.18.0"

Quirks handled:
- Client may be IPv6 localhost ``::1`` (local tests) or a real IPv4 (remote clients).
- The request field can be malformed or empty (e.g. ``"-"``); method/path/protocol are then None.
Unrecognised lines are skipped; nothing here raises on malformed input.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

_LINE = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


@dataclass
class NginxEvent:
    """One normalised nginx access-log line."""

    ts: datetime | None
    client_ip: str | None
    method: str | None
    path: str | None
    protocol: str | None
    status: int
    size: int | None
    referer: str | None
    user_agent: str | None
    raw: str


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def parse_line(line: str) -> NginxEvent | None:
    """Parse one line. Returns None if it is not a recognisable access-log line."""
    raw = line.rstrip("\n")
    m = _LINE.match(raw)
    if not m:
        return None

    req = (m.group("req") or "").split()
    method = req[0] if req else None
    path = req[1] if len(req) > 1 else None
    protocol = req[2] if len(req) > 2 else None

    size_raw = m.group("size")
    size = int(size_raw) if size_raw.isdigit() else None

    return NginxEvent(
        ts=_parse_ts(m.group("ts")),
        client_ip=m.group("client"),
        method=method,
        path=path,
        protocol=protocol,
        status=int(m.group("status")),
        size=size,
        referer=m.group("referer"),
        user_agent=m.group("ua"),
        raw=raw,
    )


def parse_lines(lines: Iterable[str]) -> Iterator[NginxEvent]:
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            yield ev


def parse_file(path: str | Path) -> list[NginxEvent]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return list(parse_lines(fh))
