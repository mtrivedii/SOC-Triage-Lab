# soc-triage-lab

Work in progress. A small pipeline that detects suspicious activity in security logs with ordinary rules, then uses an LLM only to summarise and map findings to MITRE ATT&CK. A human reviews everything, and the pipeline is measured against cases where the right answer is known.

Status: Sprint 0 (setup). See `PROJECT_PLAN.md`. This README will be rewritten at the end with real results and limitations.

## Quick start

```
uv sync
uv run pytest
```

Copy `.env.example` to `.env` and add API keys (never commit `.env`).
