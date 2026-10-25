# Sprint 4 findings: first evaluation (frozen prompt v1)

Prompt hash `ec891d0945…` (frozen 2026-10-22). Runs scored: 25 (Groq `openai/gpt-oss-120b` 15, Gemini `gemini-3.8-flash` 10). Full table: [results/eval_summary.md](../results/eval_summary.md). Raw runs: `results/runs.jsonl`.

## Interpretation
- The detectors already caught all 5 attacks with no false alarms on the 4 benign cases. The LLM added no detection value; its job is explanation and ATT&CK mapping.
- Verdict and attack type were correct in 25/25 runs, but the alert already names the rule, so this mostly shows the model didn't contradict it.
- ATT&CK mapping was exactly right in only 9/25 runs (Groq 4/15, Gemini 5/10). The typical error is over-claiming: on brute-force cases with no successful login, both models added T1021.004 (SSH remote access) in 10 of 11 runs, implying access that never happened.
- Groq mapped the web directory scan to T1046 in 3/3 runs. The allow-list accepted it because the ID is valid. An allow-list catches invented IDs, not misapplied real ones.
- No run invented an IP, username or count. The 15 flagged runs fall into two groups. Most are checker false alarms: HTTP status codes, IP octets, tool version numbers, durations computed from first_seen/last_seen, and quotes stitched from real but non-adjacent log fields. In two port-scan runs (one per model), the flags worked as designed: the summary quoted real destination ports that appear only in the untrusted ufw evidence, not in a trusted alert field. Either way, a guardrail that flags 15 of 25 runs would be ignored in practice.

## Guardrail flag breakdown
Per-model count of flagged value-instances, from the 2026-10-25 classification.

| bucket | groq | gemini |
|--------|------|--------|
| A (in a trusted field — checker bug) | 0 | 0 |
| B (verbatim in evidence, not a trusted field) | 7 | 4 |
| C (part of a larger token: IP octet / status code / timestamp / version) | 9 | 8 |
| D (derivable by arithmetic from alert fields) | 3 | 1 |
| E (appears nowhere — genuine hallucination) | 0 | 0 |
| stitched (`unverifiable_evidence`: real but non-adjacent fields joined) | 10 | 0 |

Legend: **A** should not have been flagged (would be a checker bug); **B** real value present only in the untrusted evidence; **C** a fragment of a larger token; **D** computed from trusted fields (e.g. a window duration); **E** not in the alert at all; **stitched** a `key_evidence` quote built from real fields that are not contiguous in the source line.

## Free-tier limitations
This evaluation deliberately runs at demo scale on free tiers only.
- Gemini `gemini-3.8-flash`: 20 requests/day per project (observed as HTTP 429 on 2026-10-22), and about 2-3 minutes per call. One run was lost to a transient HTTP 503, so `web_dir_scan_01` has 1 Gemini run instead of 2.
- Groq `openai/gpt-oss-120b`: 3 runs per alert completed within the free tier. Published limits: 30 RPM, 1K req/day, 8K tokens/min, 200K tokens/day (from Groq docs, not confirmed in the console).
- Scale is therefore Groq 3 runs/alert and Gemini 1-3 runs/alert (see table). Sample sizes are small: read results as counts, not rates.
- Cost shows as $0 because no paid tier was used. Mean tokens per call ranged from about 2,850 to 6,950 per case, and that is the real cost measure.

## Known measurement issues (not fixed in v1, on purpose)
- The numeric grounding check flags real values (HTTP status codes, IP octets, tool version numbers, durations computed from first_seen/last_seen). Fixing it after seeing results would tune the measurement to the outcome, so v1 scores stay as-is.
- Planned for Sprint 5: checker v2, then re-score the SAVED runs offline with both checker versions and report before/after.
