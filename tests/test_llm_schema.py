"""Tests for the triage output schema (no network)."""

import json

import pytest
from pydantic import ValidationError

from triage.llm.schema import TriageResult, parse_triage

VALID = {
    "verdict": "malicious",
    "attack_type": "ssh_bruteforce",
    "confidence": 0.9,
    "attack_techniques": ["T1110", "T1110.001"],
    "summary": "48 failed SSH logins from 192.168.214.130 against labuser.",
    "key_evidence": ["Failed password for labuser from 192.168.214.130"],
    "recommended_next_steps": ["Block the source IP", "Review the account"],
}


def test_valid_result_parses():
    r = parse_triage(json.dumps(VALID))
    assert r.verdict.value == "malicious"
    assert r.attack_techniques == ["T1110", "T1110.001"]


def test_parse_strips_code_fences():
    r = parse_triage("```json\n" + json.dumps(VALID) + "\n```")
    assert r.attack_type.value == "ssh_bruteforce"


def test_confidence_out_of_range_rejected():
    bad = {**VALID, "confidence": 1.5}
    with pytest.raises(ValidationError):
        TriageResult.model_validate(bad)


def test_extra_field_rejected():
    with pytest.raises(ValidationError):
        TriageResult.model_validate({**VALID, "note": "surprise"})


def test_bad_technique_format_rejected():
    with pytest.raises(ValidationError):
        TriageResult.model_validate({**VALID, "attack_techniques": ["T1110", "not-an-id"]})


def test_summary_too_long_rejected():
    with pytest.raises(ValidationError):
        TriageResult.model_validate({**VALID, "summary": "x" * 601})


def test_invalid_verdict_rejected():
    with pytest.raises(ValidationError):
        TriageResult.model_validate({**VALID, "verdict": "probably-bad"})


def test_parse_invalid_json_raises():
    with pytest.raises(ValidationError):
        parse_triage("{not json")
