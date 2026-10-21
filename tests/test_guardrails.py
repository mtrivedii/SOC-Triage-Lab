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


def test_load_allowlist_from_repo():
    allow = guardrails.load_allowlist()
    assert "T1110" in allow and "T1046" in allow
