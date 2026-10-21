"""LLM triage layer: schema, prompt loading, client wrapper.

The model only ever *explains and maps*; deterministic detectors decide. Output is
validated against a Pydantic schema and then checked by triage.guardrails. No module
here makes a network call at import time, and the unit tests inject a fake client, so
CI never touches a real API (plan Sprint 3).
"""
