"""Deterministic detectors: normalised events -> Alert list (plan 4.1).

Each module exposes ``RULE_ID``, ``ATTACK_TYPE`` and ``detect(...)``. Detectors are
pure functions over already-parsed events; the caller filters events to the case
window and drops the analyst/management IP first (see eval/detector_baseline.py).
The LLM never runs here: detection is ordinary thresholded code.
"""
