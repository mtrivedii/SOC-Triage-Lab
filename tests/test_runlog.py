"""Tests for run-record building and cost estimation (no network)."""

from triage.guardrails import GuardrailReport
from triage.llm.client import CallResult
from triage.llm.schema import InvalidResult, TriageResult
from triage.runlog import build_record, estimate_cost

PRICES = {"groq": {"openai/gpt-oss-120b": {"input_per_1m": 1.0, "output_per_1m": 2.0}}}

RESULT = TriageResult.model_validate({
    "verdict": "malicious",
    "attack_type": "ssh_bruteforce",
    "confidence": 0.9,
    "attack_techniques": ["T1110"],
    "summary": "48 failed logins from 192.168.214.130.",
    "key_evidence": ["Failed password for labuser from 192.168.214.130"],
    "recommended_next_steps": ["Block the IP"],
})


def test_estimate_cost_math():
    cost = estimate_cost("groq", "openai/gpt-oss-120b", 1_000_000, 500_000, PRICES)
    assert cost == 2.0  # 1.0 in + 0.5 * 2.0 out


def test_estimate_cost_unknown_tokens_is_none():
    assert estimate_cost("groq", "openai/gpt-oss-120b", None, 10, PRICES) is None


def test_estimate_cost_unset_prices_is_zero():
    assert estimate_cost("gemini", "gemini-3.8-flash", 100, 100, {}) == 0.0


def test_build_record_valid_result():
    call = CallResult(result=RESULT, raw="{...}", tokens_in=100, tokens_out=50,
                      latency_s=1.234, attempts=1)
    report = GuardrailReport(final_severity="high")
    rec = build_record(
        call, provider="groq", model="openai/gpt-oss-120b", prompt_version="v1",
        prompt_hash="abc123", temperature=0.0, run_index=0, case_id="c", alert_id="a",
        prices=PRICES, guardrails=report,
    )
    assert rec["valid"] is True
    assert rec["result"]["verdict"] == "malicious"
    assert rec["tokens_in"] == 100 and rec["tokens_out"] == 50
    assert rec["est_cost_usd"] == round(100 / 1e6 * 1.0 + 50 / 1e6 * 2.0, 6)
    assert rec["guardrails"]["final_severity"] == "high"
    assert rec["error"] is None


def test_build_record_invalid_result():
    call = CallResult(
        result=InvalidResult(raw="{bad", error="boom", attempts=2),
        raw="{bad", tokens_in=None, tokens_out=None, latency_s=0.1, attempts=2,
    )
    rec = build_record(
        call, provider="groq", model="openai/gpt-oss-120b", prompt_version="v1",
        prompt_hash="abc123", temperature=0.0, run_index=1, case_id="c", alert_id="a",
        prices=PRICES, guardrails=None,
    )
    assert rec["valid"] is False
    assert rec["result"] is None
    assert rec["error"] == "boom"
    assert rec["est_cost_usd"] is None
    assert rec["guardrails"] is None
