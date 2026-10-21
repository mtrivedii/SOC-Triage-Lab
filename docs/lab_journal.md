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
