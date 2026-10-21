<#
run_scenario.ps1 - run one Sprint 1 lab scenario with a fixed, auditable routine.

Routine (same for every scenario):
  1. Safety-check the attack command (only the target IP may appear in it).
  2. Revert the TARGET to the clean-base snapshot and power it on.
  3. Wait for key-based SSH; confirm hostname = ubuntu-target and IP = target IP (abort otherwise).
  4. Compare TARGET and KALI clocks (both should be UTC).
  5. Record START from the TARGET's own clock (UTC).
  6. Run the attack FROM the lab Kali against the target.
  7. Record END from the TARGET's own clock (UTC).
  8. Copy auth.log, ufw.log and nginx access.log to data/raw/<case_id>/.
  9. Append a UTC journal entry to docs/lab_journal.md.

Hard limits (see CLAUDE.md): SSH only to the two lab VMs with the lab key; attacks only
from the lab Kali (192.168.214.130) against the target (192.168.214.129). No other host, ever.
Never prints or stores passwords or private keys.

Usage:
  pwsh scripts/run_scenario.ps1 -CaseId ssh_bruteforce_fail_01 `
      -Expect "SSH brute force, failures only (correct password not in the list)" `
      -Attack 'head -n 50 /usr/share/wordlists/rockyou.txt > /tmp/wl.txt; hydra -l labuser -P /tmp/wl.txt -t 4 -I ssh://192.168.214.129'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CaseId,
    [Parameter(Mandatory = $true)][string]$Attack,
    [string]$Expect = ""
)

$ErrorActionPreference = "Stop"

# --- Fixed lab constants (do not parameterise the targets) ---------------------
$TargetIp   = "192.168.214.129"
$KaliIp     = "192.168.214.130"
$TargetUser = "labuser"
$KaliUser   = "kali"
$Key        = Join-Path $env:USERPROFILE ".ssh\lab_ed25519"
$Vmrun      = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
$TargetVmx  = "C:\Users\maani\OneDrive - FHICT\Documenten\Virtual Machines\Ubuntu-Server-SOC\Ubuntu-Server-SOC.vmx"
$Snapshot   = "clean-base"

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$RawDir     = Join-Path $RepoRoot "data\raw\$CaseId"
$Journal    = Join-Path $RepoRoot "docs\lab_journal.md"

function SshTarget([string]$cmd) {
    ssh -i $Key -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new "$TargetUser@$TargetIp" $cmd
}
function SshKali([string]$cmd) {
    ssh -i $Key -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new "$KaliUser@$KaliIp" $cmd
}

# --- 1. Safety: every IPv4 literal in the attack must be the target IP ----------
$ips = [regex]::Matches($Attack, '\b\d{1,3}(\.\d{1,3}){3}\b') | ForEach-Object { $_.Value } | Sort-Object -Unique
if ($ips -notcontains $TargetIp) {
    throw "SAFETY: attack command does not reference the target IP $TargetIp. Aborting."
}
$bad = $ips | Where-Object { $_ -ne $TargetIp }
if ($bad) {
    throw "SAFETY: attack command references non-target IP(s): $($bad -join ', '). Aborting."
}
Write-Host "[safety] attack targets only $TargetIp" -ForegroundColor Green

# --- 2. Revert target to clean-base and power on --------------------------------
Write-Host "[vm] reverting target to $Snapshot ..."
& $Vmrun revertToSnapshot $TargetVmx $Snapshot
& $Vmrun start $TargetVmx nogui 2>&1 | Out-Null

# --- 3. Wait for SSH, confirm identity and IP -----------------------------------
Write-Host "[vm] waiting for key-based SSH ..."
$up = $false
foreach ($i in 1..30) {
    $host_ = SshTarget "hostname"
    if ($LASTEXITCODE -eq 0) { $up = $true; break }
    Start-Sleep -Seconds 5
}
if (-not $up) { throw "Target SSH did not come up after revert." }

$hn = (SshTarget "hostname").Trim()
$ip = (SshTarget "ip -4 -o addr show ens33 | awk '{print `$4}' | cut -d/ -f1").Trim()
if ($hn -ne "ubuntu-target") { throw "Unexpected target hostname '$hn'. Aborting." }
if ($ip -ne $TargetIp)       { throw "Target IP is '$ip', expected $TargetIp. Aborting." }
Write-Host "[vm] target confirmed: $hn @ $ip" -ForegroundColor Green

# --- 4. Clock check -------------------------------------------------------------
$tClock = (SshTarget "date -u +%Y-%m-%dT%H:%M:%SZ").Trim()
$kClock = (SshKali   "date -u +%Y-%m-%dT%H:%M:%SZ").Trim()
Write-Host "[clock] target(UTC)=$tClock  kali(UTC)=$kClock"

# --- 5. Start time (from the TARGET clock) --------------------------------------
$start = (SshTarget "date -u +%Y-%m-%dT%H:%M:%SZ").Trim()
Write-Host "[run] start=$start"

# --- 6. Run the attack from the lab Kali ----------------------------------------
Write-Host "[attack] (from kali $KaliIp): $Attack"
New-Item -ItemType Directory -Force -Path $RawDir | Out-Null
$attackOut = SshKali $Attack 2>&1
$attackExit = $LASTEXITCODE
$attackOut | Out-File -FilePath (Join-Path $RawDir "attack_output.txt") -Encoding utf8
Write-Host "[attack] exit=$attackExit (output saved to attack_output.txt)"

# --- 7. End time (from the TARGET clock) ----------------------------------------
$end = (SshTarget "date -u +%Y-%m-%dT%H:%M:%SZ").Trim()
Write-Host "[run] end=$end"

# --- 8. Copy logs out -----------------------------------------------------------
Write-Host "[logs] copying auth.log, ufw.log, nginx access.log ..."
$files = @{
    "auth.log"        = "/var/log/auth.log"
    "ufw.log"         = "/var/log/ufw.log"
    "nginx_access.log" = "/var/log/nginx/access.log"
}
foreach ($name in $files.Keys) {
    scp -i $Key -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TargetUser@${TargetIp}:$($files[$name])" (Join-Path $RawDir $name) 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "scp failed for $name" }
}
$authLines = (SshTarget "awk -v s='$start' -v e='$end' 'substr(`$0,1,20) >= substr(s,1,19) && substr(`$0,1,19) <= e' /var/log/auth.log | wc -l").Trim()

# --- 9. Journal entry -----------------------------------------------------------
$entry = @"

## $CaseId ($start UTC)
- Target: $hn @ $ip (verified). Kali: $KaliUser@$KaliIp. Logs via adm-group read (no password).
- Window (target clock, UTC): start=$start end=$end
- Clock check: target=$tClock kali=$kClock
- Attack (from Kali): ``$Attack``
- Expected: $Expect
- Attack exit code: $attackExit. auth.log lines in window (approx): $authLines
- Logs copied to: data/raw/$CaseId/ (auth.log, ufw.log, nginx_access.log, attack_output.txt)
"@
Add-Content -Path $Journal -Value $entry -Encoding utf8
Write-Host "[journal] appended entry for $CaseId" -ForegroundColor Green
Write-Host "[done] $CaseId" -ForegroundColor Green
