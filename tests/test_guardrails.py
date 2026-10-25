"""Tests for guardrails on model output (no network)."""

from triage import guardrails
from triage.alert import Alert
from triage.llm.schema import TriageResult

ALLOWLIST = {"T1110": "Brute Force", "T1110.001": "Brute Force: Password Guessing"}


def _alert(**over):
    base = {
        "alert_id": "a",
        "case_id": "c",
        "rule_id": "ssh_bruteforce",
        "rule_name": "SSH password guessing",
        "severity_floor": "high",
        "source_log": "auth.log",
        "first_seen": None,
        "last_seen": None,
        "src_ip": "192.168.214.130",
        "target_host": "ubuntu-target",
        "usernames_seen": ["labuser"],
        "counts": {"failed": 48, "accepted": 0},
        "evidence_lines": ["Failed password for labuser from 192.168.214.130 port 43304 ssh2"],
        "evidence_truncated": False,
    }
    base.update(over)
    return Alert(**base)


def _result(**over):
    base = {
        "verdict": "malicious",
        "attack_type": "ssh_bruteforce",
        "confidence": 0.9,
        "attack_techniques": ["T1110"],
        "summary": "48 failed SSH logins from 192.168.214.130 against labuser.",
        "key_evidence": ["Failed password for labuser from 192.168.214.130"],
        "recommended_next_steps": ["Block the source IP"],
    }
    base.update(over)
    return TriageResult.model_validate(base)


def test_clean_result_passes():
    rep = guardrails.check(_result(), _alert(), ALLOWLIST)
    assert rep.passed
    assert rep.final_severity == "high"
    assert rep.model_disagrees_with_rules is False


def test_hallucinated_technique_flagged():
    rep = guardrails.check(_result(attack_techniques=["T1110", "T9999"]), _alert(), ALLOWLIST)
    assert rep.hallucinated_techniques == ["T9999"]
    assert not rep.passed


def test_unverifiable_evidence_flagged():
    rep = guardrails.check(_result(key_evidence=["totally made up line"]), _alert(), ALLOWLIST)
    assert rep.unverifiable_evidence == ["totally made up line"]
    assert not rep.passed


def test_ungrounded_ip_flagged():
    rep = guardrails.check(
        _result(summary="Traffic seen from 10.9.9.9 hitting the host."), _alert(), ALLOWLIST
    )
    assert rep.ungrounded_ips == ["10.9.9.9"]
    assert not rep.passed


def test_model_benign_on_high_floor_flags_disagreement():
    rep = guardrails.check(
        _result(verdict="benign", summary="Looks like normal activity."), _alert(), ALLOWLIST
    )
    assert rep.model_disagrees_with_rules is True
    assert rep.final_severity == "high"  # model cannot lower the floor


def test_wrong_count_in_summary_is_ungrounded_regression():
    # Real Gemini output on ssh_bruteforce_success_01: it wrote "27 failed" but the alert's
    # true count is 28. The old substring grounding matched "27" inside an evidence port
    # (e.g. 32271) and wrongly PASSed. Numbers now ground against trusted fields only.
    alert = _alert(
        counts={"failed": 28, "accepted": 1},
        usernames_seen=["victim"],
        evidence_lines=[
            (
                "2026-10-21T17:36:49.111111+00:00 ubuntu-target sshd-session[3800]: "
                "Failed password for victim from 192.168.214.130 port 32271 ssh2"
            ),
            (
                "2026-10-21T17:37:13.977340+00:00 ubuntu-target sshd-session[3848]: "
                "Accepted password for victim from 192.168.214.130 port 36580 ssh2"
            ),
        ],
    )
    result = _result(
        summary="There were 27 failed login attempts from 192.168.214.130 before a success.",
        key_evidence=["Accepted password for victim from 192.168.214.130"],
    )
    rep = guardrails.check(result, alert, ALLOWLIST)
    assert "27" in rep.ungrounded_numbers
    assert not rep.passed


def test_window_timestamps_are_grounded_only_wrong_count_flagged():
    # Summary correctly quotes the window (from trusted first_seen/last_seen) but gets the
    # count wrong. Only "27" should be ungrounded, not the timestamp digits.
    alert = _alert(
        counts={"failed": 28, "accepted": 1},
        first_seen="2026-10-21T17:36:52+00:00",
        last_seen="2026-10-21T17:37:15+00:00",
    )
    result = _result(
        summary=(
            "Between 17:36:52 and 17:37:15 UTC there were 27 failed SSH logins "
            "from 192.168.214.130 before a successful login."
        ),
    )
    rep = guardrails.check(result, alert, ALLOWLIST)
    assert rep.ungrounded_numbers == ["27"]
    assert not rep.passed


def test_thousands_separator_count_is_grounded():
    # Real Gemini output on port_scan_01: "65,531 distinct" is the exact trusted count
    # (counts.distinct_ports == 65531) written with a thousands separator. It must not be
    # split into 65 and 531 and flagged.
    alert = _alert(counts={"distinct_ports": 65531}, rule_id="port_scan")
    result = _result(
        attack_type="port_scan",
        attack_techniques=["T1046"],
        summary="The scan touched 65,531 distinct ports on 192.168.214.130.",
    )
    rep = guardrails.check(result, alert, {**ALLOWLIST, "T1046": "Network Service Discovery"})
    assert "65531" not in rep.ungrounded_numbers
    assert rep.ungrounded_numbers == []


def test_correct_count_in_summary_is_grounded():
    # The matching positive: the true count 28 grounds cleanly.
    alert = _alert(counts={"failed": 28, "accepted": 1}, usernames_seen=["victim"])
    result = _result(
        summary="There were 28 failed login attempts from 192.168.214.130 before a success.",
        key_evidence=["Failed password for labuser from 192.168.214.130"],
    )
    rep = guardrails.check(result, alert, ALLOWLIST)
    assert rep.ungrounded_numbers == []


def test_v2_ipv4_version_timestamp_pieces_not_flagged():
    alert = _alert(first_seen="2026-10-21T17:36:52+00:00", last_seen="2026-10-21T17:37:15+00:00")
    result = _result(
        summary="From 192.168.214.130 at 17:37:13 via gobuster/3.8.2; 48 failed logins.",
        key_evidence=["Failed password for labuser from 192.168.214.130"],
    )
    rep = guardrails.check(result, alert, ALLOWLIST, version=2)
    assert rep.ungrounded_numbers == []  # octets, clock pieces, version fragments all tokenised
    assert rep.evidence_only_numbers == []
    assert rep.checker_version == 2


def test_v2_evidence_only_number_gets_soft_flag_not_hard():
    alert = _alert(
        evidence_lines=["2026-10-21 kernel: [UFW BLOCK] SRC=192.168.214.130 PROTO=TCP DPT=143 SYN"],
    )
    result = _result(summary="The scan hit port 143 among others.", key_evidence=["DPT=143"])
    rep = guardrails.check(result, alert, ALLOWLIST, version=2)
    assert rep.evidence_only_numbers == ["143"]
    assert rep.ungrounded_numbers == []
    assert rep.passed  # evidence_only is informational, not a hard failure


def test_v2_duration_within_one_second_is_grounded():
    alert = _alert(first_seen="2026-10-21T18:36:10+00:00", last_seen="2026-10-21T18:36:45+00:00")
    result = _result(
        summary="48 failed logins within a 35-second window.",
        key_evidence=["Failed password for labuser from 192.168.214.130"],
    )
    rep = guardrails.check(result, alert, ALLOWLIST, version=2)
    assert "35" not in rep.ungrounded_numbers
    assert "35" not in rep.evidence_only_numbers


def test_v2_invented_number_still_flagged():
    alert = _alert(first_seen="2026-10-21T18:36:10+00:00", last_seen="2026-10-21T18:36:45+00:00")
    result = _result(
        summary="There were 9999 failed logins.",
        key_evidence=["Failed password for labuser from 192.168.214.130"],
    )
    rep = guardrails.check(result, alert, ALLOWLIST, version=2)
    assert rep.ungrounded_numbers == ["9999"]
    assert not rep.passed


def test_load_allowlist_from_repo():
    allow = guardrails.load_allowlist()
    assert "T1110" in allow and "T1046" in allow
