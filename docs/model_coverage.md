# Model coverage

## Decision
The planned multi-model comparison (Sprint 6) was not carried out. All main results use one model: Groq `openai/gpt-oss-120b`.

## Reason
The second model, Google `gemini-3.8-flash` on the free tier, was not reliable enough for repeated measurement:
- The free tier allows 20 requests per day per project per model.
- Gemini calls in Sprint 4 had a median latency of about 2.5 minutes (range: about 15 seconds to 3.5 minutes, 10 runs). Groq calls had a median latency of about 2 seconds (range: about 1.3 to 51 seconds, 149 runs across Sprints 4 and 5).
- On 2026-10-26, all 7 attempted injection-test calls failed: 5 with HTTP 503, 1 with a timeout, then 1 with the daily limit. The remaining 2 test cases were not attempted.

## What exists for Gemini
- Sprint 4 evaluation: 10 runs on the 5 normal alerts (1 to 3 runs per alert). Results are in results/eval_summary.md.
- Sprint 5 injection testing: no runs.

## Effect on the results
The findings describe one model. They do not show whether other models resist the same injection techniques better or worse. The deterministic parts of the pipeline (parsers, detectors, guardrails, severity floor) do not depend on the model.
