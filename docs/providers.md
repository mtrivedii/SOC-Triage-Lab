# Free-tier provider notes

Checked 2026-10-21 against official docs. Limits and model names change; re-check before the real evaluation and record the exact model and date in every results file.

## Candidates

| Provider | Free tier | Endpoint / structured output | Notes |
|----------|-----------|------------------------------|-------|
| Google AI Studio (Gemini) | Yes, needs a project, no card | OpenAI-compatible base URL `https://generativelanguage.googleapis.com/v1beta/openai/`. Structured output via Pydantic `response_format` (`client.beta.chat.completions.parse`). | Per-model limits are NOT on the docs page; they show in AI Studio after login. Limits are per project, daily quota resets at midnight Pacific. OpenAI-library support is still labelled beta. Reasoning cannot be turned off on Gemini 3 / 2.5 Pro models. |
| Groq | Yes, no card | Base URL not yet verified (check docs when creating the key). | Docs table (plan label ambiguous) for `openai/gpt-oss-120b`: 30 RPM, 1K requests/day, 8K tokens/min, 200K tokens/day. The token caps are the real constraint: roughly 70-100 alert-sized calls per day. |
| Mistral | Experiment plan, no card but verified phone number needed | Not checked. | Mistral's help page says Experiment-plan API requests may be used to train their models. No limits listed. Backup option only. |

## Status
- Nothing here has been tested with a real key yet. Model IDs below the "Models" heading must be confirmed with `client.models.list()` once keys exist; do not hard-code from this file.
- Models seen in docs (unconfirmed): Gemini `gemini-3.8-flash` (docs example), Groq `openai/gpt-oss-120b`.

## Sources
- https://ai.google.dev/gemini-api/docs/rate-limits
- https://ai.google.dev/gemini-api/docs/openai
- https://console.groq.com/docs/rate-limits
- https://help.mistral.ai/en/articles/455206-how-can-i-try-the-api-for-free-with-the-experiment-plan
