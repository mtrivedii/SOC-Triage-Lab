# Archive: results before the parser fix

Generated with the auth/nginx parsers before commit 433b088. Kept as the historical record cited in docs/sprint5_findings.md.

| File | Current version (fixed parser) |
|---|---|
| detector_v1_vs_v2.md | [../detector_v1_vs_v2.md](../detector_v1_vs_v2.md) |
| defence1_offline.md | [../defence1_offline.md](../defence1_offline.md) |
| defences_before_after.md | [../defences_before_after.md](../defences_before_after.md) |

Only the log-injection detector figures differ. With the fixed parser, detector v1 also sees the full request path, so it hits `inj_change_attack_type` and `inj_long_string` (8 of 12 instead of 6 of 12). Model results are unchanged.
