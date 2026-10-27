"""Parse Linux auth.log into normalised SSH authentication events.

Target format (Ubuntu Server 26.04, systemd journal export), see docs/lab_journal.md:

    2026-10-21T17:08:35.658501+00:00 ubuntu-target sshd-session[3169]: Failed password for ...

Key quirks handled:
- ISO-8601 timestamps with microseconds and a UTC offset (not classic syslog style).
- Process is ``sshd-session[PID]`` on this build, but classic ``sshd[PID]`` is also accepted.
- The classic ``Oct 21 16:15:41`` syslog header is tolerated (timestamp left as None, no year).

SSH events are only taken from ``sshd``/``sshd-session`` lines, and each message pattern is
anchored at the START of the message and at the END of the line. The username is everything up
to the LAST `` from <IP> port <N>`` (sshd appends the real source last), so text inside an
attacker-chosen username ("... Accepted publickey for x from <IP> port <N>") can neither change
the event type nor the source IP (log forging, found by blind_05). Other processes (pam_unix,
systemd-logind, sudo) and unrecognised lines become ``other``; blank lines are dropped. Nothing
here raises on malformed input.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

_ISO_HEAD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)
_SYSLOG_HEAD = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_PROC = re.compile(r"^(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

_SSHD = {"sshd", "sshd-session"}
# real source suffix sshd appends; matched at the END so the greedy user takes everything before
# the LAST occurrence
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]+)"
_SRC = rf" from {_IP} port (?P<port>\d+)"
_FAILED = re.compile(rf"^Failed password for (?P<invalid>invalid user )?(?P<user>.*){_SRC} ssh2$")
# publickey lines end with ": <KEYTYPE> SHA256:<fingerprint>"
_ACCEPTED = re.compile(
    rf"^Accepted (?P<method>\S+) for (?P<user>.*){_SRC} ssh2(?:: \S+ SHA256:\S+)?$"
)
_INVALID = re.compile(rf"^Invalid user (?P<user>.*){_SRC}$")


@dataclass
class AuthEvent:
    """One normalised auth.log line."""

    ts: datetime | None
    host: str | None
    process: str | None
    pid: int | None
    event: str  # failed_password | accepted_<method> | invalid_user | other
    user: str | None
    src_ip: str | None
    src_port: int | None
    raw: str


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def parse_line(line: str) -> AuthEvent | None:
    """Parse one line. Returns None for blank lines; never raises."""
    raw = line.rstrip("\n")
    if not raw.strip():
        return None

    ts: datetime | None = None
    host: str | None = None
    rest = raw
    m = _ISO_HEAD.match(raw)
    if m:
        ts = _parse_ts(m.group("ts"))
        host = m.group("host")
        rest = m.group("rest")
    else:
        m = _SYSLOG_HEAD.match(raw)
        if m:
            host = m.group("host")
            rest = m.group("rest")

    process: str | None = None
    pid: int | None = None
    msg = rest
    pm = _PROC.match(rest)
    if pm:
        process = pm.group("proc")
        pid = int(pm.group("pid")) if pm.group("pid") else None
        msg = pm.group("msg")

    event = "other"
    user = src_ip = None
    src_port: int | None = None

    is_sshd = process in _SSHD
    am = _ACCEPTED.match(msg) if is_sshd else None
    fm = _FAILED.match(msg) if is_sshd else None
    im = _INVALID.match(msg) if is_sshd else None
    if am:
        event = "accepted_" + am.group("method").lower()
        user, src_ip = am.group("user"), am.group("ip")
        src_port = int(am.group("port"))
    elif fm:
        event = "failed_password"
        user, src_ip = fm.group("user"), fm.group("ip")
        src_port = int(fm.group("port"))
    elif im:
        event = "invalid_user"
        user, src_ip = im.group("user"), im.group("ip")
        src_port = int(im.group("port")) if im.group("port") else None

    return AuthEvent(ts, host, process, pid, event, user, src_ip, src_port, raw)


def parse_lines(lines: Iterable[str]) -> Iterator[AuthEvent]:
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            yield ev


def parse_file(path: str | Path) -> list[AuthEvent]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return list(parse_lines(fh))
