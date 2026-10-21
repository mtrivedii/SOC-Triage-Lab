"""Tests for the client wrapper using a fake OpenAI-style client (no network)."""

import json
import types

from triage.llm.client import build_messages, triage
from triage.llm.schema import InvalidResult, TriageResult

VALID = json.dumps({
    "verdict": "malicious",
    "attack_type": "ssh_bruteforce",
    "confidence": 0.9,
    "attack_techniques": ["T1110"],
    "summary": "48 failed logins from 192.168.214.130.",
    "key_evidence": ["Failed password for labuser from 192.168.214.130"],
    "recommended_next_steps": ["Block the IP"],
})

ALERT = {
    "alert_id": "a",
    "rule_id": "ssh_bruteforce",
    "src_ip": "192.168.214.130",
    "counts": {"failed": 48, "accepted": 0},
    "evidence_lines": ["Failed password for labuser from 192.168.214.130 port 43304 ssh2"],
}


def fake_client(responses):
    responses = list(responses)
    state = {"calls": 0}

    def create(**kwargs):
        content = responses[min(state["calls"], len(responses) - 1)]
        state["calls"] += 1
        msg = types.SimpleNamespace(content=content)
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])

    client = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create)),
        state=state,
    )
    return client


def _triage(client):
    return triage(ALERT, "test-model", client, "system prompt", ["T1110"])


def test_valid_response_parses_in_one_call():
    client = fake_client([VALID])
    result = _triage(client)
    assert isinstance(result, TriageResult)
    assert client.state["calls"] == 1


def test_invalid_then_valid_retries_once():
    client = fake_client(["{garbage", VALID])
    result = _triage(client)
    assert isinstance(result, TriageResult)
    assert client.state["calls"] == 2


def test_invalid_twice_returns_invalid_result():
    client = fake_client(["{garbage", "{still bad"])
    result = _triage(client)
    assert isinstance(result, InvalidResult)
    assert result.attempts == 2
    assert result.raw == "{still bad"


def test_build_messages_wraps_evidence_and_keeps_facts_trusted():
    msgs = build_messages("SYS", ALERT, ["T1110"])
    assert msgs[0]["role"] == "system" and msgs[0]["content"] == "SYS"
    user = msgs[1]["content"]
    assert "<<<UNTRUSTED_LOG_DATA" in user and "UNTRUSTED_LOG_DATA>>>" in user
    assert "Failed password for labuser" in user
    # evidence lines must NOT be duplicated into the trusted structured-facts JSON
    facts = user.split("<<<UNTRUSTED_LOG_DATA")[0]
    assert "evidence_lines" not in facts
    assert "ALLOWED TECHNIQUE IDS: T1110" in user
