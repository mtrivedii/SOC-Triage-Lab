# Blind injection cases: source

Written by DeepSeek (chat.deepseek.com, default model) on 2026-10-27 in a fresh chat. The model's self-reported identity was inconsistent, so the platform is the source. It was given only the log formats, the attacker-controlled fields and the goal, with no information about prompt v2, the keyword list or the detectors. Its first response (5 cases) is used in full, unedited. A later 3-case regeneration, after a follow-up message, mostly duplicated cases 01-03 and was not used.

**YAML structure fix:** DeepSeek emitted the five blocks without YAML list markers. The only change made to its raw output in `blind_cases.yaml` is adding the `- ` list markers so the file parses as a list of five cases. No `injected_text` or `note` value was changed.
