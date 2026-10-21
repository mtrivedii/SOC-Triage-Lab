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

**ufw.log** (`/var/log/ufw.log`): exists already and was about 10.5 KB within minutes of enabling ufw, so the lab network produces background noise that the port-scan detector must tolerate. Line format still to be recorded (sample needed).

**Open items:** compare Kali clock and timezone with the target; record ufw.log line samples; record real sshd failed/accepted lines once Kali has connected; confirm what ufw `medium` logging does (docs: `man ufw`).
