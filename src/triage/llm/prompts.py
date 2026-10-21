"""Load and hash versioned prompts. The hash goes into every run record so results
are reproducible and tied to the exact prompt text (plan 4 design principle 6).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parents[3] / "prompts"


def load_prompt(version: str = "v1") -> str:
    return (PROMPTS_DIR / f"{version}.txt").read_text(encoding="utf-8")


def prompt_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
