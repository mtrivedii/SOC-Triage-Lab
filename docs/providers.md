# Free-tier provider notes

Checked 2026-10-21 against official docs. Limits and model names change; re-check before the real evaluation and record the exact model and date in every results file.

## Candidates

| Provider | Free tier | Endpoint / structured output | Notes |
|----------|-----------|------------------------------|-------|
| Google AI Studio (Gemini) | Yes, needs a project, no card | OpenAI-compatible base URL `https://generativelanguage.googleapis.com/v1beta/openai/`. Structured output via Pydantic `response_format` (`client.beta.chat.completions.parse`). | Per-model limits are NOT on the docs page; they show in AI Studio after login. Limits are per project, daily quota resets at midnight Pacific. OpenAI-library support is still labelled beta. Reasoning cannot be turned off on Gemini 3 / 2.5 Pro models. |
| Groq | Yes, no card | OpenAI-compatible base URL `https://api.groq.com/openai/v1` (confirmed in Groq docs). Temperature 0 is silently converted to 1e-8; `n` must be 1. | Docs table (plan label ambiguous) for `openai/gpt-oss-120b`: 30 RPM, 1K requests/day, 8K tokens/min, 200K tokens/day. The token caps are the real constraint: roughly 70-100 alert-sized calls per day. |
| Mistral | Experiment plan, no card but verified phone number needed | Not checked. | Mistral's help page says Experiment-plan API requests may be used to train their models. No limits listed. Backup option only. |

## Decision
User has no model preference, so the assistant chose Gemini + Groq `openai/gpt-oss-120b` (two different model families, both free, no card). Mistral stays as backup.

## Fallback
Claude API, last resort only (paid, not free). Needs a Console account and prepaid credit: the user's Claude Pro plan does not include API usage (https://support.claude.com/en/articles/9876003-i-subscribe-to-claude-pro-why-do-i-have-to-pay-separately-for-api-usage-on-console). No key exists yet. Not configured. Check Anthropic's docs before adding it.

## Models (confirmed 2026-10-21)
Pinned in `config/models.toml`. Both IDs appeared in `client.models.list()` and answered a `scripts/hello.py` test call ("ok").

| Provider | Model ID | Why this one | Test call notes |
|----------|----------|--------------|-----------------|
| Gemini | `gemini-3.8-flash` | Newest Flash-class ID with no `preview`/`exp`/`latest` tag. `gemini-flash-latest` skipped: it is an alias, not a pin. | Took over 2 minutes to answer; usage reported `completion_tokens=0`, `total_tokens=102` (thinking tokens not itemised). Sprint 3 needs an explicit client timeout and latency logging. |
| Groq | `openai/gpt-oss-120b` | Planned choice, present in the list. | Answered in about 0.1 s of model time; usage 78 in / 32 out (22 reasoning). |

## Free-tier rate limits
- **Gemini `gemini-3.8-flash` (observed 2026-10-22):** free tier = **20 `generate_content` requests/day** per project per model (quota id `GenerateRequestsPerDayPerProjectPerModel-FreeTier`). Observed directly via an HTTP 429 `RESOURCE_EXHAUSTED` during the Sprint 4 batch; resets ~daily (retry window ~8h reported). This caps Gemini at ~2 runs/case for the 5 alerting cases per day.
- **Groq `openai/gpt-oss-120b`:** not yet observed live; docs table (to confirm in the console) is 30 RPM, 1K req/day, 8K tokens/min, 200K tokens/day — token caps are the real constraint. Prefer Groq for the full 3x matrix.

## Secrets check (manual, 2026-10-21)
Done instead of a gitleaks hook (Sprint 0 cut list). Re-run in Sprint 7 before going public.
- `git log --all --full-history -- .env`: no commits. `.env` was never committed; `git check-ignore -v .env` shows it ignored by `.gitignore:2`.
- Every commit's patch (`git show` over `git rev-list --all`, 5 commits at the time) grepped for `AIza…`, `gsk_…` and `sk-ant-…` key patterns: no hits. Plain `AIza`/`gsk_` in `git log -p --all`: 0 matches.
- Tracked and untracked working-tree files (excluding `.env`) grepped for the same patterns: no hits.
- `.env.example` values are empty (also enforced by `tests/test_config.py`).

## Sources
- https://ai.google.dev/gemini-api/docs/rate-limits
- https://ai.google.dev/gemini-api/docs/openai
- https://console.groq.com/docs/rate-limits
- https://help.mistral.ai/en/articles/455206-how-can-i-try-the-api-for-free-with-the-experiment-plan

## Rate limits (recorded 2026-10-21)
- Groq `openai/gpt-oss-120b`: 30 RPM, 1,000 RPD, 8K TPM, 200K TPD. Source: Groq docs table (https://console.groq.com/docs/rate-limits), which does not clearly say which plan it describes. A third-party summary gave the same numbers.
- Gemini `gemini-3.8-flash`: NOT CONFIRMED. A community tracker (via a third-party summary) suggests roughly 10 RPM and 1,500 RPD, but Google's docs say real limits are per project and shown only at https://aistudio.google.com/rate-limit. TODO: record the real numbers from there.
- Google reserves the right to use free-tier prompts to train its products. Lab-only data, so acceptable.
