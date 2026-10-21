# Rules for the assistant

Read `PROJECT_PLAN.md` first. Work on the current sprint only (see its Progress Log).

- Be honest and pragmatic. Push back on weak ideas and scope creep.
- Explain in plain English, briefly.
- Never invent results. Every number must come from a run stored in `results/`.
- Lab autonomy (updated 2026-10-21): the assistant MAY run the Sprint 1 lab scenarios itself, but ONLY within these limits:
  - SSH only to `labuser@192.168.214.129` (ubuntu-target) and `kali@192.168.214.130` (lab Kali) with the key `~/.ssh/lab_ed25519`.
  - Attacks run ONLY from the lab Kali (192.168.214.130) against 192.168.214.129, and every attack command must check the target IP first. Never any other IP, host or network.
  - Never print or store passwords or private keys. Never touch the original HTB Kali VM.
  - Stop and ask before doing anything outside the plan's Sprint 1 scenario list.
  - Anything bigger (new scenarios, VM config changes beyond snapshot revert, new tools) still goes to me first.
- Attacks only against my own Ubuntu target VM on an isolated host-only network.
- Never commit secrets, real company data, or third-party data with an unchecked licence. HTB files stay in git-ignored `data/private/`.
- Do NOT use LiteLLM. Use the official `openai` SDK. Pin model names in config.
- Git commits must NOT include a Co-Authored-By line or any Claude/session attribution trailer.
- Commit small and often with clear messages. CI and tests must never call a real API.
- Time-box each sprint; at 1.5x budget, use the sprint's cut list.
- After each sprint: update the Progress Log, list what was cut, say what the next sprint needs.
