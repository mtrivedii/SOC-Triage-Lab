"""Unit tests for the log parsers. Fixtures are inline strings, so these tests do
not depend on anything under data/raw/. Edge cases per the plan: empty file,
partial line, unusual usernames, very long lines.
"""

import json
from pathlib import Path

from triage.parsers import auth_log, nginx, ufw

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- auth.log
def test_auth_failed_password_modern_sshd_session():
    line = (
        "2026-10-21T17:07:58.531827+00:00 ubuntu-target "
        "sshd-session[3132]: Failed password for labuser from 192.168.214.130 port 43304 ssh2"
    )
    ev = auth_log.parse_line(line)
    assert ev.event == "failed_password"
    assert ev.process == "sshd-session"
    assert ev.pid == 3132
    assert ev.user == "labuser"
    assert ev.src_ip == "192.168.214.130"
    assert ev.src_port == 43304
    assert ev.ts is not None and ev.ts.utcoffset().total_seconds() == 0


def test_auth_accepted_password_and_publickey():
    pw = (
        "2026-10-21T17:37:13.977340+00:00 ubuntu-target "
        "sshd-session[3848]: Accepted password for victim from 192.168.214.130 port 36580 ssh2"
    )
    pk = (
        "2026-10-21T17:08:35.898806+00:00 ubuntu-target "
        "sshd-session[3194]: Accepted publickey for labuser from 192.168.214.1 port 61702 ssh2: "
        "ED25519 SHA256:abc"
    )
    assert auth_log.parse_line(pw).event == "accepted_password"
    epk = auth_log.parse_line(pk)
    assert epk.event == "accepted_publickey"
    assert epk.user == "labuser"
    assert epk.src_ip == "192.168.214.1"


def test_auth_failed_invalid_user_and_invalid_user_line():
    failed = (
        "2026-10-21T17:00:00.0+00:00 ubuntu-target sshd-session[1]: "
        "Failed password for invalid user admin from 10.0.0.9 port 2222 ssh2"
    )
    invalid = (
        "2026-10-21T17:00:00.0+00:00 ubuntu-target sshd-session[1]: "
        "Invalid user admin from 10.0.0.9 port 2222"
    )
    ef = auth_log.parse_line(failed)
    assert ef.event == "failed_password" and ef.user == "admin" and ef.src_ip == "10.0.0.9"
    ei = auth_log.parse_line(invalid)
    assert ei.event == "invalid_user" and ei.user == "admin"


def test_auth_classic_syslog_is_tolerated():
    line = "Oct 21 16:15:41 host sshd[999]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ev = auth_log.parse_line(line)
    assert ev.event == "failed_password"
    assert ev.process == "sshd" and ev.pid == 999
    assert ev.user == "root" and ev.src_ip == "1.2.3.4"
    assert ev.ts is None  # classic syslog has no year; left unparsed on purpose


def test_auth_pam_line_is_other_not_crash():
    line = (
        "2026-10-21T17:00:00.0+00:00 ubuntu-target "
        "sshd-session[1]: pam_unix(sshd:session): session opened for user victim(uid=1001)"
    )
    ev = auth_log.parse_line(line)
    assert ev is not None and ev.event == "other"


def test_auth_blank_lines_return_none():
    assert auth_log.parse_line("") is None
    assert auth_log.parse_line("   \n") is None


def test_auth_partial_line_does_not_crash():
    ev = auth_log.parse_line("2026-10-21T17:00:00.0+00:00 ubuntu-target sshd-sessi")
    assert ev is not None and ev.event == "other"


def test_auth_unusual_username():
    line = (
        "2026-10-21T17:00:00.0+00:00 ubuntu-target sshd-session[1]: "
        "Failed password for admin'; DROP TABLE-- from 9.9.9.9 port 22 ssh2"
    )
    ev = auth_log.parse_line(line)
    assert ev.event == "failed_password"
    assert ev.user == "admin'; DROP TABLE--"
    assert ev.src_ip == "9.9.9.9"


def test_auth_very_long_line():
    junk = "A" * 20000
    line = (
        f"2026-10-21T17:00:00.0+00:00 ubuntu-target sshd-session[1]: "
        f"Failed password for {junk} from 9.9.9.9 port 22 ssh2"
    )
    ev = auth_log.parse_line(line)
    assert ev.event == "failed_password" and ev.src_ip == "9.9.9.9"


def test_auth_parse_lines_skips_blanks():
    text = [
        "",
        "2026-10-21T17:00:00.0+00:00 h sshd-session[1]: Failed password for a from 1.1.1.1 port 1 ssh2",
        "   ",
    ]
    assert len(list(auth_log.parse_lines(text))) == 1


# --------------------------------------------------------------------------- nginx
def test_nginx_ipv6_localhost_client():
    line = '::1 - - [21/Oct/2026:16:15:47 +0000] "GET /health HTTP/1.1" 200 3 "-" "curl/8.18.0"'
    ev = nginx.parse_line(line)
    assert ev.client_ip == "::1"
    assert ev.method == "GET" and ev.path == "/health" and ev.protocol == "HTTP/1.1"
    assert ev.status == 200 and ev.size == 3
    assert ev.user_agent == "curl/8.18.0"
    assert ev.ts is not None


def test_nginx_real_ipv4_404_with_scanner_ua():
    line = (
        '192.168.214.130 - - [21/Oct/2026:17:49:02 +0000] '
        '"GET /admin HTTP/1.1" 404 153 "-" "gobuster/3.8.2"'
    )
    ev = nginx.parse_line(line)
    assert ev.client_ip == "192.168.214.130"
    assert ev.status == 404 and ev.path == "/admin"
    assert ev.user_agent == "gobuster/3.8.2"


def test_nginx_malformed_request_field():
    line = '192.168.214.130 - - [21/Oct/2026:17:49:02 +0000] "-" 400 0 "-" "-"'
    ev = nginx.parse_line(line)
    assert ev.method == "-" and ev.path is None and ev.protocol is None
    assert ev.status == 400


def test_nginx_without_referer_and_ua():
    line = '10.0.0.5 - - [21/Oct/2026:17:49:02 +0000] "GET / HTTP/1.1" 200 12'
    ev = nginx.parse_line(line)
    assert ev is not None and ev.status == 200
    assert ev.referer is None and ev.user_agent is None


def test_nginx_blank_and_garbage_return_none():
    assert nginx.parse_line("") is None
    assert nginx.parse_line("not an access log line") is None


def test_nginx_very_long_user_agent():
    ua = "M" * 20000
    line = f'1.2.3.4 - - [21/Oct/2026:17:49:02 +0000] "GET / HTTP/1.1" 200 1 "-" "{ua}"'
    ev = nginx.parse_line(line)
    assert ev is not None and ev.status == 200 and ev.user_agent == ua


# --------------------------------------------------------------------------- ufw
def test_ufw_block_tcp_fields_by_key():
    line = (
        "2026-10-21T16:15:38.492690+00:00 ubuntu-target kernel: [UFW BLOCK] "
        "IN=ens33 OUT= MAC=aa:bb SRC=192.168.214.130 DST=192.168.214.129 LEN=60 "
        "PROTO=TCP SPT=40000 DPT=4444 WINDOW=64240 SYN"
    )
    ev = ufw.parse_line(line)
    assert ev.action == "BLOCK"
    assert ev.src == "192.168.214.130" and ev.dst == "192.168.214.129"
    assert ev.proto == "TCP" and ev.spt == 40000 and ev.dpt == 4444
    assert ev.in_if == "ens33" and ev.out_if == ""
    assert "SYN" in ev.flags
    assert ev.ts is not None


def test_ufw_audit_and_allow_actions():
    audit = (
        "2026-10-21T16:15:30.754157+00:00 ubuntu-target kernel: [UFW AUDIT] "
        "IN= OUT=ens33 SRC=192.168.214.129 DST=1.1.1.1 PROTO=UDP SPT=52704 DPT=123"
    )
    allow = (
        "2026-10-21T16:15:30.754196+00:00 ubuntu-target kernel: [UFW ALLOW] "
        "IN= OUT=ens33 SRC=192.168.214.129 DST=1.1.1.1 PROTO=UDP SPT=52704 DPT=123"
    )
    assert ufw.parse_line(audit).action == "AUDIT"
    assert ufw.parse_line(allow).action == "ALLOW"


def test_ufw_ipv6_full_form_src():
    line = (
        "2026-10-21T16:15:47.413560+00:00 ubuntu-target kernel: [UFW AUDIT] "
        "IN= OUT=lo SRC=0000:0000:0000:0000:0000:0000:0000:0001 "
        "DST=0000:0000:0000:0000:0000:0000:0000:0001 PROTO=TCP SPT=37416 DPT=80 SYN"
    )
    ev = ufw.parse_line(line)
    assert ev.src == "0000:0000:0000:0000:0000:0000:0000:0001"
    assert ev.dpt == 80


def test_ufw_distinct_dpt_across_block_lines():
    base = "2026-10-21T16:15:38.4+00:00 h kernel: [UFW BLOCK] SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT="
    lines = [base + str(p) for p in (22, 80, 443, 22)]
    blocks = [e for e in ufw.parse_lines(lines) if e.action == "BLOCK"]
    assert len({e.dpt for e in blocks}) == 3


def test_ufw_blank_and_non_ufw_return_none():
    assert ufw.parse_line("") is None
    assert ufw.parse_line("2026-10-21T16:15:38+00:00 h sshd[1]: something") is None


# --------------------------------------------------------------------------- allow-list
def test_attack_allowlist_valid_and_has_used_ids():
    data = json.loads((ROOT / "data" / "attack_allowlist.json").read_text())
    techniques = data["techniques"]
    for tid in ("T1110", "T1110.001", "T1078", "T1021.004", "T1046", "T1595.003"):
        assert techniques.get(tid)
