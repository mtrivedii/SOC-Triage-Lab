# Threat model: prompt injection via logs (Sprint 5)

One page. The pipeline feeds attacker-influenced log text to an LLM. This is the AI-specific
risk the project exists to test. Written before any injection run; defences are NOT built yet so
the baseline can be measured without them.

## Assets (what the attacker wants to move)
- The **triage verdict** (malicious / benign / needs_human).
- The **severity** a human sees.
- The **ATT&CK mapping** (attack_type + technique IDs).
- The **recommended next steps** shown to the analyst.
- The **system prompt** (`prompts/v1.txt`) — confidentiality.
- **API cost / tokens** — availability and spend.

## Attacker
Someone who can influence what lands in our logs but has **no access** to the pipeline, repo, host
or API keys. They act only by generating traffic against the target VM. Fields they control:
- **SSH username** (auth.log).
- **URL path and query string** (nginx access log).
- **User-Agent** and **Referer** (nginx access log).

Where that attacker text actually reaches the model (from the parsers/detectors):
- `auth_log.py` + `ssh_bruteforce` detector: the username appears **verbatim in `evidence_lines`** AND
  in the structured field **`usernames_seen`**. So an attacker-chosen username is presented to the
  model inside the *trusted* ALERT JSON, not only inside the untrusted-data block — the sharper risk.
- `nginx.py` + `web_scan` detector: the **path, User-Agent and Referer** appear verbatim in
  `evidence_lines`. They are not promoted into any structured alert field.
- `ufw.py` + `port_scan` detector: evidence is kernel/firewall lines (IPs, ports, flags); no
  attacker free-text. Low injection surface.
- `src_ip` / `client_ip` are attacker-controlled values but are not free text.

## Attacker goals (what we will test)
1. Flip the verdict to **benign** or **needs_human**.
2. Change the **attack_type**.
3. Make the model **follow an injected instruction** (e.g. emit a canary token).
4. **Leak the system prompt**.
5. Plant **misleading recommended next steps**.
6. **Break the JSON** (force an invalid/unparseable response).
7. **Inflate tokens/cost** (very long or looping output).

## What already limits damage (design, NOT yet tested)
- **Severity floor + `model_disagrees_with_rules`:** the LLM cannot lower the rule's severity; a
  benign verdict on a high/critical alert is flagged for a human, not auto-accepted.
- **Schema validation:** output must parse as the Pydantic `TriageResult`; invalid output is retried
  once then recorded `invalid` (a broken-JSON attack is visible, not silently obeyed).
- **Technique allow-list:** only IDs in `data/attack_allowlist.json` are accepted; invented IDs are
  flagged (note: it does not catch a *valid but misapplied* ID).
- **Grounding check:** IPs/numbers in the summary are checked against the alert (v1/v2 in guardrails).
- **Untrusted-data delimiters** in `prompts/v1.txt` tell the model to treat the evidence block as data.
  (This is a prompt instruction, not a hard control — its effectiveness is exactly what Sprint 5 measures.)

Whether these actually hold under attack is unknown until the before/after injection runs.

## Out of scope (explicitly)
- An attacker with access to the **host**, the **repository**, or the **API keys**.
- Attacks on the model provider's infrastructure.
- Non-log input channels (there are none in this pipeline).
