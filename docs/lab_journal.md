# Lab journal

One entry per scenario: start/end time, exact command, what I expected.

## Setup
- 2026-10-21: VMware Workstation Pro. Lab Kali = clone of original (updated and upgraded). Original Kali kept for HTB.
- Target OS: Ubuntu Server 26.04.1 LTS live-server amd64 (ISO not yet downloaded/verified).

## Phase A checklist (target, adapter on NAT) - not yet run
1. `sudo apt update && sudo apt full-upgrade -y`
2. `sudo apt install -y nginx ufw rsyslog` then `sudo systemctl enable --now ssh nginx rsyslog`
3. Firewall (allow SSH BEFORE enabling): `sudo ufw default deny incoming`, `sudo ufw default allow outgoing`, `sudo ufw allow 22/tcp`, `sudo ufw allow 80/tcp`, `sudo ufw logging medium` (confirm level meaning with `man ufw`; watch for log rate limiting during scans), `sudo ufw enable`, `sudo ufw status verbose`
4. Health page for the false-positive trap: `echo ok | sudo tee /var/www/html/health`
5. Check logs and clock: `cat /etc/os-release | head -3`, `timedatectl | head -4`, `ls -l /var/log/auth.log /var/log/ufw.log /var/log/nginx/access.log` (ufw.log may not exist until something is blocked), `curl -s localhost/health`, `sudo tail -n 5 /var/log/auth.log`, `sudo tail -n 3 /var/log/nginx/access.log`
6. Compare the target's timezone with Kali's; both should match for case windows.

Then Phase B: both VMs to host-only, verify target cannot reach the internet or the home network, snapshot `clean-base`.

## Log formats observed on the target (2026-10-21, Ubuntu Server 26.04.1 LTS)
Checked after Phase A (ufw, nginx, rsyslog installed). Target clock and timezone: UTC (`Etc/UTC`, NTP not yet compared with Kali).

**auth.log** (`/var/log/auth.log`, owner syslog:adm, mode 640, readable only via sudo). Timestamps are ISO 8601 with microseconds and a UTC offset, NOT the classic `Oct 21 16:15:41` syslog style:
```
2026-10-21T16:15:41.138028+00:00 ubuntu-target sudo: labuser : TTY=/dev/pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/tee /var/www/html/health
```
Parser must handle this format (and ideally tolerate the classic one, in case other sources differ). The file also contains our own sudo activity, so each case log slice must be cut by time window.

**nginx access.log** (`/var/log/nginx/access.log`, owner www-data:adm, mode 640). Combined log format, timestamp `[21/Oct/2026:16:15:47 +0000]`:
```
::1 - - [21/Oct/2026:16:15:47 +0000] "GET /health HTTP/1.1" 200 3 "-" "curl/8.18.0"
```
Note IPv6 localhost (`::1`) appears as the client when testing locally.

**ufw.log** (`/var/log/ufw.log`): exists already and was about 10.5 KB within minutes of enabling ufw. Same ISO timestamps as auth.log, then `kernel: [UFW <ACTION>] key=value ...`. Samples (lab traffic only):
```
2026-10-21T16:15:30.754157+00:00 ubuntu-target kernel: [UFW AUDIT] IN= OUT=ens33 SRC=192.168.100.131 DST=185.125.190.122 LEN=216 ... PROTO=UDP SPT=52704 DPT=123 LEN=196
2026-10-21T16:15:30.754196+00:00 ubuntu-target kernel: [UFW ALLOW] IN= OUT=ens33 SRC=192.168.100.131 DST=185.125.190.122 LEN=216 ... PROTO=UDP SPT=52704 DPT=123 LEN=196
2026-10-21T16:15:38.492690+00:00 ubuntu-target kernel: [UFW BLOCK] IN=ens33 OUT= MAC=... SRC=151.101.206.49 DST=192.168.100.131 LEN=682 ... PROTO=TCP SPT=443 DPT=40272 WINDOW=64240 RES=0x00 ACK PSH URGP=0
2026-10-21T16:15:47.413560+00:00 ubuntu-target kernel: [UFW AUDIT] IN= OUT=lo SRC=0000:0000:0000:0000:0000:0000:0000:0001 DST=0000:0000:0000:0000:0000:0000:0000:0001 ... PROTO=TCP SPT=37416 DPT=80 ... SYN URGP=0
```
Observations that affect the parser and detectors:
- Each logged packet can appear twice: a `[UFW AUDIT]` line plus an `[UFW ALLOW]` or `[UFW BLOCK]` line with the same packet fields. Detectors must count only BLOCK (and ALLOW if needed) and must not count AUDIT, or counts double.
- Outbound traffic (`OUT=ens33`, e.g. NTP to port 123), loopback (`lo`) and IPv6 appear. IPv6 addresses are zero-padded in full form. Detectors should look at inbound (`IN=` set) lines from external sources.
- Background noise exists: e.g. a BLOCK of an inbound TCP ACK/PSH from a web server with source port 443 (a stray reply to a connection that predates the firewall). Not a scan.
- Key=value fields vary by protocol (TCP has WINDOW and flags, UDP has LEN, IPv6 has TC/HOPLIMIT/FLOWLBL). Parse by key, not by position.

**ufw log levels** (from `man ufw` on this system): `low` = blocked packets not matching policy, with rate limiting; `medium` = low plus allowed packets not matching policy, INVALID packets and new connections, all with rate limiting; `high` = medium WITHOUT rate limiting, plus all packets with rate limiting; `full` = high without rate limiting. Risk: at `medium` a `nmap -p-` scan will likely be rate limited, so ufw.log would contain only a small fraction of the scan packets and the port-scan detector would see few distinct ports. Plan: switch to `high` and test with a scan before collecting cases; record how many lines a scan produces.

**Open items:** compare Kali clock and timezone with the target; record ufw.log line samples; record real sshd failed/accepted lines once Kali has connected; confirm what ufw `medium` logging does (docs: `man ufw`).

## Clock check (2026-10-21)
- Target: `Etc/UTC`. Kali clone: `America/New_York` (EDT, -0400) at first check. UTC time was identical on both (16:17:04 UTC on Kali vs target log times around 16:15 UTC), so the clocks are in sync and only the display timezone differed.
- Decision: set Kali to UTC (`sudo timedatectl set-timezone UTC`). All journal times and case windows are written in UTC.
- Open: host-only network has no NTP. Re-compare clocks (`date -u` on both) at the start of each scenario session, since case windows depend on them.

## Phase B: host-only network and isolation check (2026-10-21, ~16:20 UTC)
- Both VMs moved to VMware host-only. Subnet 192.168.214.0/24. Target `ubuntu-target` = 192.168.214.129, lab Kali clone = 192.168.214.130, host adapter = 192.168.214.1. IPs come from DHCP and may change after a restart; re-check with `ip -br a`.
- Target isolation verified: `ip route` shows no default route; `ping 1.1.1.1` -> "Network is unreachable"; `curl -m 5 -sI https://example.com` returned nothing (failed).
- Kali -> target ping works (2/2, ~1 ms).
- ufw logging level set to `high` (to avoid rate limiting of blocked packets). Not yet confirmed with `ufw status verbose`.
- Next: take `clean-base` snapshots (target and Kali clone), then run a calibration scan to measure how many ufw log lines a scan produces.

## Calibration scan: how much of a port scan reaches ufw.log (2026-10-21, ~16:25 UTC) - NOT a case
- Command (Kali -> target): `sudo nmap -sS -p 1-5000 -T4 192.168.214.129`. nmap: 4998 filtered (no response), ports 22 and 80 open, finished in 18.56 s.
- Target ufw logging level `high`. `UFW BLOCK` lines in ufw.log: 29 before, 3911 after (+3882). Distinct `DPT=` values among all BLOCK lines: 1985 (includes ~29 earlier noise lines).
- Interpretation: the log holds only a fraction of the scanned ports (about 40% distinct), so some packets are not logged even at `high`. Cause not confirmed (possible kernel or rsyslog rate limiting). Retransmissions at -T4 may also mean several lines per port.
- Consequence: port-scan detector should key on many distinct destination ports from one source in a short window (thresholds far below 1985); do not rely on complete logs. Limitation to state in the README: ufw log is incomplete under heavy scans.
- Optional check not yet done: `sudo dmesg | grep -i suppress` or `journalctl -k | grep -i suppress` for "callbacks suppressed" messages.

## ssh_bruteforce_fail_01 (2026-10-21T17:07:55Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T17:07:55Z end=2026-10-21T17:08:36Z
- Clock check: target=2026-10-21T17:07:54Z kali=2026-10-21T17:07:54Z
- Attack (from Kali): `head -n 50 /usr/share/wordlists/rockyou.txt > /tmp/wl50.txt; hydra -l labuser -P /tmp/wl50.txt -t 4 -I -o /tmp/hydra_out.txt ssh://192.168.214.129`
- Expected: SSH brute force, failures only - correct password NOT in the 50-word list, so all attempts fail
- Attack exit code: 255. auth.log lines in window (approx): 176
- Logs copied to: data/raw/ssh_bruteforce_fail_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## ssh_bruteforce_success_01 (2026-10-21T17:36:47Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T17:36:47Z end=2026-10-21T17:37:17Z
- Clock check: target=2026-10-21T17:36:46Z kali=2026-10-21T17:36:46Z
- Attack (from Kali): `sed -n "1360,1384p" /usr/share/wordlists/rockyou.txt > /tmp/wl.txt; hydra -l victim -P /tmp/wl.txt -t 4 -I -o /tmp/hydra_out.txt ssh://192.168.214.129`
- Expected: SSH brute force against victim; correct password IS present in the wordlist (rockyou line 1384), so it ends in a successful login. Wordlist sliced to ~25 lines ending at 1384 because OpenSSH 10.2p1 PerSourcePenalties blocks the source IP after a few dozen failures (see scenario 1), making a full walk to line 1384 unreachable.
- Attack exit code: 0. auth.log lines in window (approx): 118
- Logs copied to: data/raw/ssh_bruteforce_success_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## port_scan_01 (2026-10-21T17:45:28Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T17:45:28Z end=2026-10-21T17:47:20Z
- Clock check: target=2026-10-21T17:45:27Z kali=2026-10-21T17:45:27Z
- Attack (from Kali): `sudo -n nmap -sS -p- 192.168.214.129`
- Expected: Full TCP SYN port scan (nmap -sS -p-, all 65535 ports) from Kali against the target. Expect ufw.log to show many distinct blocked destination ports from one source (192.168.214.130); per the earlier calibration, ufw logs only a fraction of scanned ports, so the distinct-port count is reported from this run, not assumed.
- Attack exit code: 0. auth.log lines in window (approx): 16
- Logs copied to: data/raw/port_scan_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## web_dir_scan_01 (2026-10-21T17:49:01Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T17:49:01Z end=2026-10-21T17:49:04Z
- Clock check: target=2026-10-21T17:49:00Z kali=2026-10-21T17:49:00Z
- Attack (from Kali): `gobuster dir -u http://192.168.214.129 -w /usr/share/wordlists/dirb/common.txt -t 20`
- Expected: Web directory/wordlist scan with gobuster (dirb common.txt, 20 threads) from Kali against nginx on the target. Expect many HTTP requests from 192.168.214.130 in nginx access.log, mostly 404s, with a few hits for whatever nginx actually serves (e.g. / and /health). Maps to T1595.003 (Wordlist Scanning).
- Attack exit code: 0. auth.log lines in window (approx): 24
- Logs copied to: data/raw/web_dir_scan_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## Known issues
- **Early commit-message mismatches (data is correct and verified, history left as-is):** `5b4106e` is titled "Refactor code structure..." but contains `ssh_bruteforce_fail_01`'s data; `31656c0` is titled "Add ssh_bruteforce_fail_01 case logs" but its diff contains `ssh_bruteforce_success_01`'s files. Not rewritten (avoiding repeated force-pushes). The case logs themselves are verified correct.
- **Large raw ufw.log for full-range scans:** `port_scan_01/ufw.log` is ~35 MB / 132k lines. Trimming to the case window removes only ~0.9% (1,231 of 132,373 lines) because the scan traffic is itself in-window. Real size reduction needs a different lever (git-LFS, a capped port range, or dedup-by-destination-port) — under discussion before more scan cases.

## benign_ssh_login_01 (2026-10-21T18:28:53Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T18:28:53Z end=2026-10-21T18:28:56Z
- Clock check: target=2026-10-21T18:28:53Z kali=2026-10-21T18:28:53Z
- Attack (from Kali): `SSH_ASKPASS=/tmp/askpass SSH_ASKPASS_REQUIRE=force setsid -w ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no victim@192.168.214.129 "echo hi; exit" </dev/null`
- Expected: BENIGN: a single normal SSH login as victim from Kali (192.168.214.130) using the correct password (password auth). Expect exactly one 'Accepted password for victim from 192.168.214.130' and no failed-password lines. False-positive check for the SSH brute-force detector.
- Attack exit code: 0. auth.log lines in window (approx): 47
- Logs copied to: data/raw/benign_ssh_login_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## benign_ssh_mistype_then_success_01 (2026-10-21T18:31:05Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T18:31:05Z end=2026-10-21T18:31:17Z
- Clock check: target=2026-10-21T18:31:05Z kali=2026-10-21T18:31:05Z
- Attack (from Kali): `for i in 1 2 3; do SSH_ASKPASS=/tmp/awrong SSH_ASKPASS_REQUIRE=force setsid -w ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 victim@192.168.214.129 true </dev/null; done; SSH_ASKPASS=/tmp/askpass SSH_ASKPASS_REQUIRE=force setsid -w ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no victim@192.168.214.129 "echo hi" </dev/null`
- Expected: BENIGN: a user fumbles the password 3 times then logs in, all from Kali (192.168.214.130). Expect exactly 3 'Failed password for victim' then 1 'Accepted password for victim', same source. Tests the SSH brute-force detector's threshold: a small number of failures followed by success must NOT be flagged as an attack.
- Attack exit code: 0. auth.log lines in window (approx): 43
- Logs copied to: data/raw/benign_ssh_mistype_then_success_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## benign_browsing_01 (2026-10-21T18:32:41Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T18:32:41Z end=2026-10-21T18:32:47Z
- Clock check: target=2026-10-21T18:32:40Z kali=2026-10-21T18:32:40Z
- Attack (from Kali): `for i in 1 2 3 4 5; do curl -s -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36" http://192.168.214.129/; sleep 1; done; curl -s -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://192.168.214.129/health`
- Expected: BENIGN: normal web browsing from Kali (192.168.214.130): a few GETs to / and /health with a real browser User-Agent, all expected 200/304, no 404 sweep. Tests the web-scan detector: low request count, served paths only, non-scanner UA must NOT be flagged as a directory scan.
- Attack exit code: 0. auth.log lines in window (approx): 17
- Logs copied to: data/raw/benign_browsing_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## benign_health_monitor_01 (2026-10-21T18:33:51Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T18:33:51Z end=2026-10-21T18:34:53Z
- Clock check: target=2026-10-21T18:33:50Z kali=2026-10-21T18:33:51Z
- Attack (from Kali): `for i in $(seq 1 20); do curl -s -o /dev/null -A "HealthMonitor/1.0" http://192.168.214.129/health; sleep 3; done`
- Expected: BENIGN false-positive TRAP: a monitoring loop polling /health from Kali (192.168.214.130) ~20 times, 3s apart, UA 'HealthMonitor/1.0'. Expect ~20 GETs to /health, all 200, one repeated path. Web-scan detector keys on many DISTINCT paths / 404s, so this must NOT alarm - but a naive volume-only rule would false-positive here. This case defines that boundary.
- Attack exit code: 0. auth.log lines in window (approx): 32
- Logs copied to: data/raw/benign_health_monitor_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## mixed_bruteforce_and_browsing_01 (2026-10-21T18:36:01Z UTC)
- Target: ubuntu-target @ 192.168.214.129 (verified). Kali: kali@192.168.214.130. Logs via adm-group read (no password).
- Window (target clock, UTC): start=2026-10-21T18:36:01Z end=2026-10-21T18:36:46Z
- Clock check: target=2026-10-21T18:36:01Z kali=2026-10-21T18:36:01Z
- Attack (from Kali): `( for i in $(seq 1 10); do curl -s -o /dev/null -A "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0" http://192.168.214.129/; sleep 2; done ) & head -n 50 /usr/share/wordlists/rockyou.txt > /tmp/wl50.txt; hydra -l labuser -P /tmp/wl50.txt -t 4 -I -o /tmp/hydra_mixed.txt ssh://192.168.214.129; wait`
- Expected: MIXED window (ground truth = malicious): an SSH brute force against labuser (rockyou top-50, correct password NOT in list, failures only) running CONCURRENTLY with benign browser GETs to /, all from Kali (192.168.214.130). auth.log should show many Failed password for labuser; nginx should show a handful of benign 200s. The detector must flag the SSH brute force while the web browsing is benign noise in the same window.
- Attack exit code: 0. auth.log lines in window (approx): 183
- Logs copied to: data/raw/mixed_bruteforce_and_browsing_01/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)

## ufw logging completeness — caveat (not a confirmed rule)
We have only two data points on how much of a scan reaches ufw.log: the `-T4` calibration (~40% of
scanned ports logged) and `port_scan_01` at default `-T3` (~100%). That is an observation, not a
confirmed rule, and the cause (kernel/rsyslog rate limiting at higher speed) is unverified. The
port-scan detector must therefore NOT assume logs are either complete or incomplete: key on "many
distinct destination ports from one source in a short window" with thresholds well below the full port
count, and treat the log as possibly partial.
