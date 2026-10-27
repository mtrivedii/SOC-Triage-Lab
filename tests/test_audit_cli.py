"""Human-in-the-loop: approve command, hash-chained audit log, DRAFT reports (no network)."""

import json
from pathlib import Path

import pytest
import yaml

from triage import audit, cli
from triage.pipeline import alerts_for_case

ROOT = Path(__file__).resolve().parent.parent
CASE = "ssh_bruteforce_fail_01"


@pytest.fixture
def env(tmp_path):
    """A saved triage run for a real lab alert (fake model output, no API call)."""
    case = yaml.safe_load((ROOT / "cases" / f"{CASE}.yaml").read_text(encoding="utf-8"))
    alert = alerts_for_case(case, ROOT)[0]
    record = {
        "ts": "2026-10-27T12:00:00+00:00", "case_id": CASE, "alert_id": alert.alert_id,
        "provider": "groq", "model": "openai/gpt-oss-120b", "prompt_version": "v1",
        "prompt_hash": "ec891d09" + "0" * 56, "valid": True,
        "result": {"verdict": "malicious", "attack_type": "ssh_bruteforce", "confidence": 0.9,
                   "attack_techniques": ["T1110.001"], "summary": "48 failed SSH logins.",
                   "key_evidence": [], "recommended_next_steps": ["Block the source IP."]},
        "guardrails": {"hallucinated_techniques": [], "unverifiable_evidence": [],
                       "ungrounded_ips": [], "ungrounded_numbers": ["7"],
                       "model_disagrees_with_rules": True, "final_severity": "high"},
    }
    runs = tmp_path / "runs.jsonl"
    runs.write_text(json.dumps(record) + "\n", encoding="utf-8")
    log = tmp_path / "audit.jsonl"
    return {"alert_id": alert.alert_id, "runs": str(runs), "log": log, "tmp": tmp_path}


def _approve(env, decision, note=None, analyst="lab-analyst"):
    argv = ["approve", env["alert_id"], "--decision", decision, "--analyst", analyst,
            "--runs-file", env["runs"], "--audit-log", str(env["log"])]
    if note is not None:
        argv += ["--note", note]
    return cli.main(argv)


def _report(env) -> str:
    out = env["tmp"] / "report.md"
    assert cli.main(["report", env["alert_id"], "--runs-file", env["runs"],
                     "--audit-log", str(env["log"]), "--out", str(out)]) == 0
    return out.read_text(encoding="utf-8")


def test_decisions_recorded_with_model_and_prompt_hash(env):
    assert _approve(env, "approve") == 0
    assert _approve(env, "escalate", note="credential reuse suspected") == 0
    entries = audit.read_entries(env["log"])
    assert [e["decision"] for e in entries] == ["approve", "escalate"]
    assert entries[0]["model"] == "openai/gpt-oss-120b"
    assert entries[0]["prompt_hash"].startswith("ec891d09")
    assert entries[0]["prev_hash"] == audit.GENESIS
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]


@pytest.mark.parametrize("decision", ["override", "escalate"])
def test_note_required_for_override_and_escalate(env, decision):
    assert _approve(env, decision) == 2
    assert _approve(env, decision, note="   ") == 2
    assert not env["log"].exists()


def test_unknown_alert_rejected(env):
    env = {**env, "alert_id": "no-such-alert"}
    assert _approve(env, "approve") == 2
    assert not env["log"].exists()


def test_report_draft_then_decision_with_flags_on_top(env):
    text = _report(env)
    assert "**Status: DRAFT.**" in text
    top = text.split("## AI triage")[0]
    assert "numbers not in the alert: ['7']" in top
    assert "Model disagrees with the rules: YES" in top
    assert "Log-injection detector (v2): not flagged" in top

    _approve(env, "override", note="benign: scheduled password audit", analyst="alice")
    text = _report(env)
    assert "DRAFT" not in text
    assert "**Status: OVERRIDDEN** by alice" in text
    assert "benign: scheduled password audit" in text


def test_report_stays_draft_when_audit_log_is_tampered(env):
    _approve(env, "approve")
    lines = env["log"].read_text(encoding="utf-8").splitlines()
    env["log"].write_text(lines[0].replace("lab-analyst", "mallory") + "\n", encoding="utf-8")
    assert "**Status: DRAFT.** The audit log failed verification" in _report(env)


def _three_entries(env) -> list[str]:
    _approve(env, "approve")
    _approve(env, "escalate", note="second look")
    _approve(env, "override", note="false positive")
    return env["log"].read_text(encoding="utf-8").splitlines()


def _verify(env, *extra) -> int:
    return cli.main(["verify-audit", "--audit-log", str(env["log"]), *extra])


def test_verify_passes_on_clean_log(env):
    _three_entries(env)
    res = audit.verify(env["log"])
    assert res.ok and res.entries == 3
    assert _verify(env) == 0
    assert _verify(env, "--expect-head", res.head) == 0


def test_verify_detects_edited_entry(env):
    lines = _three_entries(env)
    lines[1] = lines[1].replace("second look", "nothing to see")
    env["log"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = audit.verify(env["log"])
    assert not res.ok and res.broken_at == 2 and "edited" in res.reason
    assert _verify(env) == 1


def test_verify_detects_deleted_entry(env):
    lines = _three_entries(env)
    env["log"].write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    res = audit.verify(env["log"])
    assert not res.ok and res.broken_at == 2


def test_verify_detects_reordered_entries(env):
    lines = _three_entries(env)
    env["log"].write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n", encoding="utf-8")
    res = audit.verify(env["log"])
    assert not res.ok and res.broken_at == 1


def test_verify_detects_tail_deletion_only_with_expected_head(env):
    _three_entries(env)
    head = audit.verify(env["log"]).head
    lines = env["log"].read_text(encoding="utf-8").splitlines()
    env["log"].write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    assert audit.verify(env["log"]).ok  # the file alone cannot show a removed tail
    assert not audit.verify(env["log"], expect_head=head).ok
    assert _verify(env, "--expect-head", head) == 1


def test_example_audit_log_verifies():
    assert audit.verify(ROOT / "audit" / "audit_log.example.jsonl").ok


def test_ai_path_never_imports_the_audit_log():
    for path in (ROOT / "src" / "triage").rglob("*.py"):
        if path.name in {"audit.py", "cli.py"}:
            continue
        text = path.read_text(encoding="utf-8")
        assert "triage.audit" not in text and "import audit" not in text, path
