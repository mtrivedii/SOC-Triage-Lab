# Rules for the assistant

Read `PROJECT_PLAN.md` first. Work on the current sprint only (see its Progress Log).

- Be honest and pragmatic. Push back on weak ideas and scope creep.
- Explain in plain English, briefly.
- Never invent results. Every number must come from a run stored in `results/`.
- I run anything that touches the lab (Kali attacks, VM changes). Give me the commands; I paste back the output.
- Attacks only against my own Ubuntu target VM on an isolated host-only network.
- Never commit secrets, real company data, or third-party data with an unchecked licence. HTB files stay in git-ignored `data/private/`.
- Do NOT use LiteLLM. Use the official `openai` SDK. Pin model names in config.
- Git commits must NOT include a Co-Authored-By line or any Claude/session attribution trailer.
- Commit small and often with clear messages. CI and tests must never call a real API.
- Time-box each sprint; at 1.5x budget, use the sprint's cut list.
- After each sprint: update the Progress Log, list what was cut, say what the next sprint needs.
