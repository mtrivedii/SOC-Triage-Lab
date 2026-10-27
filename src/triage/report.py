"""Markdown triage report for one alert: deterministic alert facts + one saved triage run.

The report is stamped DRAFT until the audit log holds an analyst decision for this alert and
this run (and the audit log verifies). Anything a reviewer must not miss (guardrail flags,
model/rule disagreement, the log-injection detector) is at the top. Guardrail flags come from a
fresh run of the grounding checker (CHECKER_VERSION, the final version) on the full alert, not
from the report stored with the run (Sprint 4 runs stored checker v1).
"""

from __future__ import annotations

from triage.alert import Alert
from triage.guardrails import GuardrailReport

CHECKER_VERSION = 2
# hard flags: the output cites something the alert does not support
_GUARD_KEYS = (
    ("hallucinated_techniques", "hallucinated ATT&CK IDs"),
    ("unverifiable_evidence", "evidence quotes not found in the logs"),
    ("ungrounded_ips", "IPs not in the alert"),
    ("ungrounded_numbers", "numbers not in the alert"),
)
_STAMP = {"approve": "APPROVED", "override": "OVERRIDDEN", "escalate": "ESCALATED"}


def _status(decision: dict | None, audit_ok: bool) -> list[str]:
    if not audit_ok:
        return ["**Status: DRAFT.** The audit log failed verification, so no decision is trusted."]
    if decision is None:
        return ["**Status: DRAFT.** Not reviewed by an analyst. The AI output below is a suggestion."]
    out = [(f"**Status: {_STAMP[decision['decision']]}** by {decision['analyst']} "
           f"at {decision['ts']}.")]
    if decision.get("note"):
        out.append(f"Analyst note: {decision['note']}")
    return out


def render(alert: Alert, record: dict, guard: GuardrailReport | None, decision: dict | None,
           audit_ok: bool, injection_hits: list) -> str:
    """``guard`` is the checker-v2 report for this run (None if the model output was invalid)."""
    result = record.get("result") or {}
    flags = [f"{label}: {getattr(guard, key)}" for key, label in _GUARD_KEYS
             if guard and getattr(guard, key)]
    evidence_only = guard.evidence_only_numbers if guard else []
    disagrees = bool(guard and guard.model_disagrees_with_rules)
    version = guard.checker_version if guard else CHECKER_VERSION

    lines = [f"# Triage report: {alert.alert_id}", "", *_status(decision, audit_ok), ""]
    lines += [
        "## Needs attention",
        "",
        f"- Guardrail flags (checker v{version}): {'; '.join(flags) if flags else 'none'}",
        ("- Lower severity (checker v{v}, informational): numbers found only in the untrusted "
         "evidence lines, not in the trusted alert facts: {n}").format(
            v=version, n=evidence_only or "none"),
        f"- Model disagrees with the rules: {'YES' if disagrees else 'no'}",
        "- Log-injection detector (v2): "
        + (f"FLAGGED ({len(injection_hits)} suspicious field(s): "
           + "; ".join(f"{f} -> {','.join(r)}" for f, _, r in injection_hits) + ")"
           if injection_hits else "not flagged"),
        (f"- Final severity (never below the rule's floor): "
        f"{guard.final_severity if guard else alert.severity_floor} "
        f"(rule floor: {alert.severity_floor})"),
        "",
        "## AI triage (model output)",
        "",
    ]
    if not record.get("valid"):
        lines += ["The model output was invalid; no AI triage is available.", ""]
    else:
        lines += [
            f"- Verdict: {result.get('verdict')}",
            f"- Attack type: {result.get('attack_type')}",
            f"- Confidence: {result.get('confidence')}",
            f"- ATT&CK techniques: {', '.join(result.get('attack_techniques') or []) or 'none'}",
            "",
            f"Summary: {result.get('summary')}",
            "",
            "Key evidence (as quoted by the model):",
            *[f"- `{e}`" for e in result.get("key_evidence") or []],
            "",
            "Recommended next steps:",
            *[f"- {s}" for s in result.get("recommended_next_steps") or []],
            "",
        ]
    lines += [
        "## Alert facts (deterministic detector)",
        "",
        f"- Rule: {alert.rule_id} ({alert.rule_name})",
        f"- Source IP: {alert.src_ip} -> target: {alert.target_host}",
        f"- First / last seen: {alert.first_seen} / {alert.last_seen}",
        f"- Usernames seen: {', '.join(alert.usernames_seen) or 'none'}",
        f"- Counts: {alert.counts}",
        f"- Evidence lines: {len(alert.evidence_lines)}"
        + (" (truncated)" if alert.evidence_truncated else ""),
        "",
        "## Provenance",
        "",
        f"- Model: {record.get('provider')}/{record.get('model')}",
        f"- Prompt: {record.get('prompt_version')} ({record.get('prompt_hash')})",
        f"- Triage run: {record.get('ts')}",
        "",
    ]
    return "\n".join(lines)
