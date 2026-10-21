"""Unit tests for the deterministic detectors. Fixtures are built by feeding small
inline log strings through the real parsers, so these do not touch data/raw/.
"""

from triage.detectors import port_scan, ssh_bruteforce, web_scan
from triage.parsers import auth_log, nginx, ufw

MGMT = "192.168.214.1"
KALI = "192.168.214.130"


def _auth_fail(i, ip=KALI, user="labuser"):
    return (
        f"2026-10-21T17:00:{i % 60:02d}.0+00:00 ubuntu-target "
        f"sshd-session[{1000 + i}]: Failed password for {user} from {ip} port {40000 + i} ssh2"
    )


def _auth_accept(ip=KALI, user="victim", method="password"):
    return (
        "2026-10-21T17:01:00.0+00:00 ubuntu-target "
        f"sshd-session[2000]: Accepted {method} for {user} from {ip} port 50000 ssh2"
    )


def _events_auth(lines):
    return list(auth_log.parse_lines(lines))


# ------------------------------------------------------------------- ssh brute force
def test_ssh_bruteforce_failures_only_fires():
    alerts = ssh_bruteforce.detect(_events_auth([_auth_fail(i) for i in range(10)]), case_id="t")
    assert len(alerts) == 1
    a = alerts[0]
    assert a.src_ip == KALI
    assert a.counts == {"failed": 10, "accepted": 0}
    assert "failed logins" in a.rule_name
    assert a.severity_floor == "high"


def test_ssh_bruteforce_with_success_escalates():
    lines = [_auth_fail(i) for i in range(10)] + [_auth_accept()]
    alerts = ssh_bruteforce.detect(_events_auth(lines), case_id="t")
    assert len(alerts) == 1
    a = alerts[0]
    assert a.counts["accepted"] == 1
    assert "successful login" in a.rule_name
    assert any("Accepted password" in line for line in a.evidence_lines)


def test_ssh_mistype_then_success_below_threshold_no_alert():
    lines = [_auth_fail(i) for i in range(3)] + [_auth_accept()]
    assert ssh_bruteforce.detect(_events_auth(lines), case_id="t") == []


def test_ssh_single_login_no_alert():
    assert ssh_bruteforce.detect(_events_auth([_auth_accept()]), case_id="t") == []


def test_ssh_excludes_management_ip():
    lines = [_auth_fail(i, ip=MGMT) for i in range(10)]
    alerts = ssh_bruteforce.detect(_events_auth(lines), case_id="t", exclude_ips={MGMT})
    assert alerts == []


def test_ssh_evidence_capped():
    lines = [_auth_fail(i) for i in range(40)] + [_auth_accept()]
    a = ssh_bruteforce.detect(_events_auth(lines), case_id="t")[0]
    assert a.evidence_truncated is True
    assert len(a.evidence_lines) <= 30
    assert any("Accepted password" in line for line in a.evidence_lines)


# ------------------------------------------------------------------- port scan
def _ufw_block(dpt, src=KALI):
    return (
        "2026-10-21T17:00:00.0+00:00 ubuntu-target kernel: [UFW BLOCK] "
        f"IN=ens33 OUT= SRC={src} DST=192.168.214.129 PROTO=TCP SPT=40000 DPT={dpt} SYN"
    )


def _ufw_audit(dpt, src=KALI):
    return (
        "2026-10-21T17:00:00.0+00:00 ubuntu-target kernel: [UFW AUDIT] "
        f"IN=ens33 OUT= SRC={src} DST=192.168.214.129 PROTO=TCP SPT=40000 DPT={dpt} SYN"
    )


def test_port_scan_fires_on_many_distinct_ports():
    events = list(ufw.parse_lines([_ufw_block(p) for p in range(1, 101)]))
    alerts = port_scan.detect(events, case_id="t")
    assert len(alerts) == 1
    assert alerts[0].counts["distinct_ports"] == 100
    assert alerts[0].src_ip == KALI


def test_port_scan_ignores_audit_lines():
    # 100 AUDIT + only 10 BLOCK -> below threshold, no alert
    events = list(ufw.parse_lines([_ufw_audit(p) for p in range(1, 101)]
                                  + [_ufw_block(p) for p in range(1, 11)]))
    assert port_scan.detect(events, case_id="t") == []


def test_port_scan_below_threshold_no_alert():
    events = list(ufw.parse_lines([_ufw_block(p) for p in range(1, 11)]))
    assert port_scan.detect(events, case_id="t") == []


def test_port_scan_excludes_management_ip():
    events = list(ufw.parse_lines([_ufw_block(p, src=MGMT) for p in range(1, 101)]))
    assert port_scan.detect(events, case_id="t", exclude_ips={MGMT}) == []


# ------------------------------------------------------------------- web scan
def _nginx(path, status=404, ua="gobuster/3.8.2", ip=KALI):
    return f'{ip} - - [21/Oct/2026:17:49:02 +0000] "GET {path} HTTP/1.1" {status} 100 "-" "{ua}"'


def test_web_scan_fires_on_many_404s_with_scanner_ua():
    events = list(nginx.parse_lines([_nginx(f"/p{i}") for i in range(30)]))
    alerts = web_scan.detect(events, case_id="t")
    assert len(alerts) == 1
    a = alerts[0]
    assert a.counts["status_404"] == 30
    assert a.counts["scanner_ua"] is True


def test_web_scan_fires_on_many_distinct_paths_even_if_200():
    events = list(nginx.parse_lines([_nginx(f"/p{i}", status=200, ua="x") for i in range(20)]))
    alerts = web_scan.detect(events, case_id="t")
    assert len(alerts) == 1
    assert alerts[0].counts["scanner_ua"] is False


def test_web_health_monitor_single_path_no_alert():
    events = list(nginx.parse_lines(
        [_nginx("/health", status=200, ua="HealthMonitor/1.0") for _ in range(20)]
    ))
    assert web_scan.detect(events, case_id="t") == []


def test_web_normal_browsing_no_alert():
    events = list(nginx.parse_lines([
        _nginx("/", status=200, ua="Mozilla/5.0"),
        _nginx("/health", status=200, ua="Mozilla/5.0"),
    ]))
    assert web_scan.detect(events, case_id="t") == []
