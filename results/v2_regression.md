# Prompt v2 + field caps: regression on the 5 normal alerts (Groq)

Scored offline with the frozen Sprint 4 scorer (`eval/triage_eval.py`) and checker v1. v1 = prompt v1 (ec891d09445e...), no caps, Sprint 4 runs. v2 = prompt v2 (c07d79f4a26f...) + field caps 256. Provider groq, temperature 0.

`tech found` = expected ATT&CK IDs produced / ground-truth count (range across runs); `tech extra` = non-expected IDs produced (range); `tech exact` = runs whose ID set equals the ground truth exactly.

| case | expected | cfg | runs | valid | verdict ok | abstain | type ok | tech found | tech extra | tech exact | guardrail-flagged |
|---|---|---|---|---|---|---|---|---|---|---|---|
| mixed_bruteforce_and_browsing_01 | malicious/ssh_bruteforce | v1 | 3 | 3 | 3/3 | 0 | 3/3 | 2/2 | 1 | 0/3 | 3/3 |
| mixed_bruteforce_and_browsing_01 | malicious/ssh_bruteforce | v2 | 3 | 3 | 3/3 | 0 | 3/3 | 2/2 | 1 | 0/3 | 0/3 |
| port_scan_01 | malicious/port_scan | v1 | 3 | 3 | 3/3 | 0 | 3/3 | 1/1 | 1 | 0/3 | 3/3 |
| port_scan_01 | malicious/port_scan | v2 | 3 | 3 | 3/3 | 0 | 3/3 | 1/1 | 0-1 | 1/3 | 3/3 |
| ssh_bruteforce_fail_01 | malicious/ssh_bruteforce | v1 | 3 | 3 | 3/3 | 0 | 3/3 | 2/2 | 0-1 | 1/3 | 0/3 |
| ssh_bruteforce_fail_01 | malicious/ssh_bruteforce | v2 | 3 | 3 | 3/3 | 0 | 3/3 | 2/2 | 1 | 0/3 | 0/3 |
| ssh_bruteforce_success_01 | malicious/ssh_bruteforce | v1 | 3 | 3 | 3/3 | 0 | 3/3 | 4/4 | 0 | 3/3 | 0/3 |
| ssh_bruteforce_success_01 | malicious/ssh_bruteforce | v2 | 3 | 3 | 3/3 | 0 | 3/3 | 3-4/4 | 0 | 1/3 | 1/3 |
| web_dir_scan_01 | malicious/web_dir_scan | v1 | 3 | 3 | 3/3 | 0 | 3/3 | 0/1 | 1 | 0/3 | 3/3 |
| web_dir_scan_01 | malicious/web_dir_scan | v2 | 3 | 3 | 3/3 | 0 | 3/3 | 0-1/1 | 1 | 0/3 | 3/3 |

| cfg | runs | verdict ok | type ok | tech exact |
|---|---|---|---|---|
| v1 | 15 | 15/15 | 15/15 | 4/15 |
| v2 | 15 | 15/15 | 15/15 | 2/15 |
