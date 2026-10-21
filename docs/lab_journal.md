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
