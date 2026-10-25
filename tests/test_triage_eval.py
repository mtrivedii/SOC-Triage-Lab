"""Offline tests for the Sprint 4 scorer (synthetic run records, no file or network)."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("triage_eval", ROOT / "eval" / "triage_eval.py")
triage_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(triage_eval)

EXPECTED = {"verdict": "malicious", "attack_type": "ssh_bruteforce", "techniques": ["T1110", "T1078"]}


def _rec(result=None, valid=True, guardrails=None, tin=100, tout=50, cost=0.0):
    return {
        "case_id": "ssh_bruteforce_success_01",
        "provider": "groq",
        "valid": valid,
        "result": result,
        "guardrails": guardrails or {},
        "tokens_in": tin,
        "tokens_out": tout,
        "est_cost_usd": cost,
        "latency_s": 1.0,
    }


def test_score_run_correct():
    result = {"verdict": "malicious", "attack_type": "ssh_bruteforce", "attack_techniques": ["T1110"]}
    s = triage_eval.score_run(_rec(result), EXPECTED)
    assert s["verdict_correct"] is True
    assert s["attack_type_correct"] is True
    assert s["tech_precision"] == 1.0
    assert s["tech_recall"] == 0.5  # 1 of 2 expected
    assert s["abstained"] is False
    assert s["guardrail_flagged"] is False


def test_score_run_abstention():
    result = {"verdict": "needs_human", "attack_type": "other", "attack_techniques": []}
    s = triage_eval.score_run(_rec(result), EXPECTED)
    assert s["abstained"] is True
    assert s["verdict_correct"] is False


def test_score_run_invalid():
    s = triage_eval.score_run(_rec(result=None, valid=False), EXPECTED)
    assert s["valid"] is False
    assert s["verdict_correct"] is False
    assert s["tech_precision"] is None


def test_score_run_guardrail_flag():
    result = {"verdict": "malicious", "attack_type": "ssh_bruteforce", "attack_techniques": ["T1110"]}
    s = triage_eval.score_run(_rec(result, guardrails={"unverifiable_evidence": ["x"]}), EXPECTED)
    assert s["guardrail_flagged"] is True


def test_technique_counts_and_render_shows_counts():
    cases = {"ssh_bruteforce_success_01": {"expected": EXPECTED}}  # expected techniques T1110, T1078
    res = {"verdict": "malicious", "attack_type": "ssh_bruteforce",
           "attack_techniques": ["T1110", "T9999"]}  # 1 of 2 expected + 1 extra
    s = triage_eval.score_run(_rec(res), EXPECTED)
    assert s["tech_found"] == 1 and s["tech_expected"] == 2 and s["tech_extra"] == 1
    # raw decimals still present for the JSON output
    assert s["tech_precision"] == 0.5 and s["tech_recall"] == 0.5

    md = triage_eval.render_markdown(triage_eval.summarize([_rec(res)], cases), cases)
    assert "tech found" in md and "tech extra" in md
    assert "| 1/2 |" in md  # found/expected as counts, not a decimal


def test_filter_by_hash():
    recs = [
        {"prompt_hash": "aaa", "case_id": "x"},
        {"prompt_hash": "bbb", "case_id": "x"},
        {"prompt_hash": "aaa", "case_id": "y"},
    ]
    kept, ignored = triage_eval.filter_by_hash(recs, "aaa")
    assert len(kept) == 2 and ignored == 1


def test_summarize_and_render():
    cases = {
        "ssh_bruteforce_success_01": {"expected": EXPECTED},
        "benign_browsing_01": {
            "expected": {"verdict": "benign", "attack_type": "benign_activity", "techniques": []}
        },
    }
    good = {"verdict": "malicious", "attack_type": "ssh_bruteforce", "attack_techniques": ["T1110"]}
    records = [_rec(good), _rec(good), _rec(result=None, valid=False)]
    summary = triage_eval.summarize(records, cases)
    assert len(summary) == 1
    row = summary[0]
    assert row["runs"] == 3 and row["valid"] == 2
    assert row["verdict_correct"] == 2
    assert row["invalid_rate"] == round(1 / 3, 3)

    md = triage_eval.render_markdown(summary, cases)
    assert "ssh_bruteforce_success_01" in md
    assert "benign_browsing_01" in md  # listed as not sent to the LLM
    assert "detector-only baseline" in md.lower()
