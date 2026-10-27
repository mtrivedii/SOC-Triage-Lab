# Pre-publication review (2026-10-27)

Read-only review of the full git history before making the repo public. Nothing was changed.
No secret values appear in this document: findings give the file, commit and pattern only.

Scope: 81 commits, 1 branch (`main`, same as `origin/main`), 154 paths ever committed. No file
has ever been deleted from history, so every path ever committed is still in the current tree.

## Result

| # | Check | Result |
|---|---|---|
| 1a | API keys / tokens / private keys in full history | PASS |
| 1b | Lab password for `victim` in history | **FIX**: present in a tracked file |
| 1c | `.env` ever committed | PASS |
| 2 | data/private, attack_output.txt, HTB/Sherlock files, SSH keys | PASS |
| 3 | Personal data | **FIX**: one personal Windows path; INFO: job-search context in the plan |
| 4 | Repo size | PASS (one expected large file) |
| 5 | Third-party content | INFO: attribution/licence notes needed |
| 6 | LICENSE file | **FIX**: none |
| 7 | Indirect credential disclosure | INFO: password derivable from public wordlist reference |

## 1. Secrets

**Method.** gitleaks/trufflehog are not installed. `git log -p --all --text` was scanned for
`AIza`, `gsk_`, `sk-`, `ghp_`, `github_pat_`, `BEGIN ... PRIVATE KEY`, `api_key=`, `password=`,
`token=` (added and removed lines, all commits). Matches were printed with values masked.

| Pattern | Hits | Assessment |
|---|---|---|
| `AIza`, `gsk_`, `sk-` (as prefixes) | 1 line each, `docs/providers.md` (c1d3022) | Prose naming the prefixes that were searched for. Key-shaped matches (`AIza` + 20 chars, `gsk_` + 10, `sk-` + 16): 0. |
| `ghp_`, `github_pat_`, `PRIVATE KEY`, `token=` | 0 | - |
| `api_key=` | 9 lines | Code passing a variable or a test dummy (`scripts/hello.py`, `src/triage/llm/client.py`, `tests/test_network_block.py`) and `.env.example`, where all three keys are empty. |
| `password=` | 2 lines | `PROJECT_PLAN.md` (history, removed in ff7cec5): refers to a wordlist line, not the password itself (see 7). |

**Lab password (`victim`).** Checked without printing it: the value was read from the git-ignored
`data/raw/ssh_bruteforce_success_01/attack_output.txt` into a shell variable and searched for
literally in the full history and the working tree.

- **Found:** `docs/audit_2026-10-25.md`, lines 82 and 84, 2 occurrences, added in commit
  `ff7cec5` (2026-10-25) and still in the current tree. The audit names the password in the
  sentence that states it was not committed.
- Not found in any other file or commit.
- Fixing it needs both an edit to the file and a history rewrite (e.g. `git filter-repo
  --replace-text`) before the repo is made public, because the old commits keep the value. See 7:
  the password is also derivable from a public wordlist reference, so a rewrite alone does not
  make it secret.
- The `labuser` password was not checked by the assistant (no local copy to compare against).
  The owner checked it against the full history: 0 matches (see Resolution).

**`.env`.** Never committed in any commit; only `.env.example` (empty values).

## 2. Data that must not be public

None of these paths was ever committed in any commit: `data/private/`, any
`attack_output.txt`, HTB/Sherlock/Brutus files, `.evtx`/`.pcap`, archives, wordlist files,
`id_*`, `*_ed25519`, `*.pem`, `*.key`, `known_hosts`, `authorized_keys`. The lab key is only
referred to by its path (`~/.ssh/lab_ed25519`). The lab logs contain 128 `Accepted publickey`
lines with the lab key's SHA256 fingerprint (a public-key fingerprint, not a secret).

## 3. Personal data

- **Authors/committers:** one identity in all 81 commits: `mtrivedii <mtrivedii@users.noreply.github.com>` (GitHub no-reply address).
- **Personal path (FIX):** `scripts/run_scenario.ps1` line 40 holds a local VM path containing
  the Windows user name and a school OneDrive folder name. Added in commit `9b484bf`; the only
  occurrence in history.
- **Commit messages:** no personal paths, e-mail addresses or secrets.
- **Lab data:** `/home/labuser`, `/home/victim`, `192.168.214.x` (host-only lab), `192.168.100.x`
  (VMware NAT) and public Ubuntu/CDN IPs from the VM's own traffic. No personal data.
- **Context (INFO):** `PROJECT_PLAN.md` describes the project as a portfolio piece for junior
  SOC/DevSecOps roles and mentions interview preparation. Not sensitive, but it will be public.
  `CLAUDE.md` and `PROJECT_PLAN.md` also describe the lab layout (IPs, account names, key path).

## 4. Repository size

Local `.git`: 5.9 MB (packed). GitHub reports 2,431 KB. Largest blobs in history (uncompressed):

| Size | File |
|---|---|
| 34.23 MB | data/raw/port_scan_01/ufw.log (expected) |
| 0.45 MB | data/raw/web_dir_scan_01/nginx_access.log |
| 0.27 MB | data/raw/benign_health_monitor_01/ufw.log |
| 0.27 MB | data/raw/mixed_bruteforce_and_browsing_01/ufw.log |
| 0.26 MB | data/raw/ssh_bruteforce_success_01/ufw.log |
| 0.26 MB | data/raw/benign_ssh_mistype_then_success_01/ufw.log |
| 0.26 MB | data/raw/benign_browsing_01/ufw.log |
| 0.26 MB | data/raw/web_dir_scan_01/ufw.log |
| 0.26 MB | data/raw/benign_ssh_login_01/ufw.log |
| 0.20 MB | data/raw/ssh_bruteforce_fail_01/ufw.log |

Nothing else is large. The port-scan log is under GitHub's 50 MB warning and 100 MB limit.

## 5. Third-party content

| File(s) | Origin | Licence status |
|---|---|---|
| `data/attack_allowlist.json` | MITRE ATT&CK technique IDs and names | ATT&CK Terms of Use permit reuse with MITRE's copyright notice. Add an attribution line (e.g. in the README). |
| `data/raw/web_dir_scan_01/nginx_access.log` | Lab log; its ~4,600 request paths are the entries of `dirb/common.txt` sent by gobuster | The wordlist file is not included, but its entries appear as requested paths. dirb is distributed under GPL-2.0 (confirm). Low risk: log data of a scan, not the file. A README note is enough. |
| `tests/fixtures/injection/blind/blind_cases.yaml` | Generated by DeepSeek (chat.deepseek.com) | AI output; provenance recorded in `SOURCE.md`. Check DeepSeek's terms on output use (generally assigned to the user). |
| `results/*.jsonl`, `results/*.md` | Model outputs (Groq `openai/gpt-oss-120b`, Google `gemini-3.8-flash`) on lab data | Provider terms generally leave outputs to the user; gpt-oss is Apache-2.0. No third-party data in the inputs. |
| `uv.lock` | Package names, versions, hashes, URLs | Standard lockfile metadata; no package code is vendored. |
| Lab logs (`data/raw/`) | Own lab VMs | Own data. |

No HTB, Sherlock or other third-party dataset files are tracked. `rockyou.txt` is only named;
no part of it is committed.

## 6. Licence

No `LICENSE` file. Without one, the public repo is "all rights reserved" by default. Pick a
licence before publishing (e.g. MIT or Apache-2.0 for the code) and decide whether the lab data
and results fall under it.

## 7. Indirect credential disclosure

- `docs/lab_journal.md` (lines 83-84) and older `PROJECT_PLAN.md` versions (history, before
  ff7cec5) state that the `victim` password is **rockyou.txt line 1384** and give the `sed` command
  that extracts it. rockyou is public, so anyone can recover the password from the repo, even
  after the literal in `docs/audit_2026-10-25.md` is removed.
- `docs/lab_journal.md` also states that the `labuser` password is NOT in the rockyou top 50; that
  reveals nothing usable.
- **Does it matter?** Little, if `victim` is a throwaway account on a host-only VM, the password is
  not reused anywhere, and the VM is never exposed to a network. It would matter if the password
  is reused elsewhere, or if the VM image or snapshot is ever shared or bridged. Owner to confirm
  no reuse. Optional: delete or re-password the `victim` account after the project, and/or reword
  the journal to "a password present in a public wordlist" without the line number.

## FIX list (as found)

1. Remove the literal lab password from `docs/audit_2026-10-25.md` and rewrite history to remove
   it from commit `ff7cec5` onwards, or accept it as a throwaway lab password (see 7).
2. Replace the personal path in `scripts/run_scenario.ps1` (e.g. a parameter or environment
   variable); it is also in history at `9b484bf`.
3. Add a `LICENSE`.
4. Add attribution in the README: MITRE ATT&CK notice; dirb wordlist source for the scan log;
   DeepSeek for the blind cases.
5. Confirm the `victim` password is not reused anywhere.

## Resolution (2026-10-27)

Git history was **not** rewritten: commit hashes are cited in the docs, and the commit order
shows that labels and fixtures were written before the results.

1. **Lab password.** Replaced with `[lab password removed]` in `docs/audit_2026-10-25.md`
   (2 occurrences). A masked literal search of the tracked working tree now finds 0 matches.
   The value **remains in history at `ff7cec5`** and later commits that contain the old file.
   Accepted: it is a deliberately weak rockyou password on a throwaway `victim` account on an
   isolated host-only VM, it is not reused anywhere (confirmed by the owner), and it is already
   recoverable from the documented rockyou line (see 7).
2. **Personal path.** `scripts/run_scenario.ps1` now takes the VM path as `-TargetVmx` or from
   `$env:LAB_TARGET_VMX` and stops with a clear error if neither is set. The old path **remains in
   history at `9b484bf`**. Accepted: a local folder name, not sensitive.
3. **Licence.** `LICENSE` added: MIT, copyright 2026 mtrivedii.
4. **Attribution.** To be added in the README (MITRE ATT&CK, dirb wordlist, DeepSeek).
5. **`labuser` password.** Checked by the owner against the full history: 0 matches.
