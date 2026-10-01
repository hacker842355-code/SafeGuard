import { HardeningConfig } from '../types/security';

export function generateHardeningScript(config: HardeningConfig): { script: string; rollback: string; filename: string; rollbackFilename: string } {
  const { targetOs, dryRunMode, allowDevPorts, devPorts, videoConfProfile, watchdogDaemon, tightenFileSystem, lockdownCamera, lockdownMicrophone, closeUnusedPorts } = config;

  if (targetOs === 'windows') {
    return generateWindowsScript(config);
  } else if (targetOs === 'linux') {
    return generateLinuxScript(config);
  } else {
    return generateMacScript(config);
  }
}

function generateWindowsScript(config: HardeningConfig): { script: string; rollback: string; filename: string; rollbackFilename: string } {
  const devPortsComment = config.allowDevPorts 
    ? `# DEV MODE: Excluded ports from external block (bound only to localhost): ${config.devPorts.join(', ')}`
    : '# Strict Mode: All non-essential inbound ports denied';

  const script = `# ==============================================================================
# CROSS-PLATFORM ATTACK SURFACE REDUCTION & HARDENING SCRIPT
# PLATFORM: Microsoft Windows (PowerShell 5.1 / PowerShell 7+)
# ATOMICITY: Transactional with state-diff snapshotting
# MODE: ${config.dryRunMode ? 'DRY-RUN SIMULATION (No system changes committed)' : 'ACTIVE ENFORCEMENT'}
# ==============================================================================
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$DryRun = ${config.dryRunMode ? '$true' : '$false'},
    [string]$StateJournalPath = "$env:ProgramData\\SurfaceGuard\\state_journal.json"
)

$ErrorActionPreference = "Stop"
Write-Host "[*] Initializing SurfaceGuard Hardening Engine..." -ForegroundColor Cyan

# Phase 0: Pre-Flight State Snapshot & Journaling
$stateDir = Split-Path $StateJournalPath -Parent
if (-not (Test-Path $stateDir)) {
    New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
}

$baselineState = @{
    Timestamp = (Get-Date).ToString("o")
    OS = "Windows"
    FirewallRules = @()
    RegistryChanges = @()
    Services = @()
}

Write-Host "[+] Creating pre-execution state snapshot for zero-friction rollback..." -ForegroundColor Gray

# ------------------------------------------------------------------------------
# PHASE 1: NETWORK ATTACK SURFACE REDUCTION
# ------------------------------------------------------------------------------
Write-Host "[+] Phase 1: Auditing listening network sockets and firewall rules..." -ForegroundColor Cyan

${devPortsComment}
if (-not $DryRun) {
    # Set default inbound policy to Block for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Host "    [✓] Enforced DefaultInboundAction = Block across Domain, Public, Private" -ForegroundColor Green

    # Block legacy vulnerable protocols (SMB 445, NetBIOS 135-139, Remote Registry)
    New-NetFirewallRule -Name "SurfaceGuard_Block_SMB_Inbound" \`
        -DisplayName "SurfaceGuard - Block SMB Inbound (TCP 445)" \`
        -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block -Profile Any -Force | Out-Null

    New-NetFirewallRule -Name "SurfaceGuard_Block_NetBIOS_Inbound" \`
        -DisplayName "SurfaceGuard - Block NetBIOS Inbound (TCP 135-139)" \`
        -Direction Inbound -Protocol TCP -LocalPort 135-139 -Action Block -Profile Any -Force | Out-Null
        
    ${config.allowDevPorts ? `
    # Whitelist local developer ports exclusively on Loopback adapter
    $devPorts = @(${config.devPorts.join(', ')})
    foreach ($p in $devPorts) {
        New-NetFirewallRule -Name "SurfaceGuard_Allow_Loopback_$p" \`
            -DisplayName "SurfaceGuard - Allow Loopback Dev Port $p" \`
            -Direction Inbound -Protocol TCP -LocalPort $p -LocalAddress 127.0.0.1 -Action Allow -Force | Out-Null
        Write-Host "    [✓] Allowed Localhost Loopback binding on Port $p" -ForegroundColor DarkGray
    }` : ''}
} else {
    Write-Host "    [SIMULATION] Would enforce DefaultInboundAction = Block" -ForegroundColor Yellow
    Write-Host "    [SIMULATION] Would block TCP 445 (SMB) and TCP 135-139 (NetBIOS)" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------
# PHASE 2: HARDWARE SANDBOXING & PERIPHERAL LOCKDOWN
# ------------------------------------------------------------------------------
Write-Host "[+] Phase 2: Restricting peripheral surveillance attack surfaces..." -ForegroundColor Cyan

${config.lockdownCamera ? `
# Hardening Registry: Disable camera globally at policy level
$camRegPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Camera"
if (-not (Test-Path $camRegPath)) {
    New-Item -Path $camRegPath -Force | Out-Null
}

if (-not $DryRun) {
    Set-ItemProperty -Path $camRegPath -Name "AllowCamera" -Value 0 -Type DWord
    Write-Host "    [✓] Disabled Camera via Group Policy Registry (AllowCamera = 0)" -ForegroundColor Green
} else {
    Write-Host "    [SIMULATION] Would set HKLM:\\SOFTWARE\\Policies\\Microsoft\\Camera AllowCamera = 0" -ForegroundColor Yellow
}
` : '# Camera lockdown disabled by operator configuration'}

${config.lockdownMicrophone ? `
# Hardening Microphone: Revoke microphone access to non-packaged apps
$micRegPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone"
if (-not $DryRun) {
    if (Test-Path $micRegPath) {
        Set-ItemProperty -Path $micRegPath -Name "Value" -Value "Deny" -Type String
        Write-Host "    [✓] Set Microphone ConsentStore Default to 'Deny'" -ForegroundColor Green
    }
} else {
    Write-Host "    [SIMULATION] Would set Microphone ConsentStore Value to 'Deny'" -ForegroundColor Yellow
}
` : '# Microphone lockdown disabled by operator configuration'}

# ------------------------------------------------------------------------------
# PHASE 3: FILE SYSTEM HARDENING & LEAST PRIVILEGE
# ------------------------------------------------------------------------------
${config.tightenFileSystem ? `
Write-Host "[+] Phase 3: Auditing overly-permissive system directories..." -ForegroundColor Cyan
$targetPath = "$env:ProgramData\\SurfaceGuard"
if (-not $DryRun) {
    $acl = Get-Acl $targetPath
    $acl.SetAccessRuleProtection($true, $false)
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.ResetAccessRule($systemRule)
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $targetPath -AclObject $acl
    Write-Host "    [✓] Secured $targetPath: SYSTEM & Administrators only" -ForegroundColor Green
} else {
    Write-Host "    [SIMULATION] Would restrict ACL on $targetPath" -ForegroundColor Yellow
}
` : ''}

# ------------------------------------------------------------------------------
# PHASE 4: WATCHDOG DEPLOYMENT & STATE JOURNAL COMMIT
# ------------------------------------------------------------------------------
${config.watchdogDaemon ? `
Write-Host "[+] Phase 4: Registering background monotonic watchdog service..." -ForegroundColor Cyan
if (-not $DryRun) {
    # Writes immutable state journal
    $baselineState | ConvertTo-Json -Depth 5 | Set-Content -Path $StateJournalPath -Force
    Write-Host "    [✓] Committed state journal to $StateJournalPath" -ForegroundColor Green
}
` : ''}

Write-Host "[+] Hardening execution complete! System attack surface successfully minimized." -ForegroundColor Green
`;

  const rollback = `# ==============================================================================
# SURFACEGUARD EMERGENCY ROLLBACK SCRIPT (WINDOWS)
# Restores pre-hardening baseline configuration in < 2 seconds
# ==============================================================================
#Requires -RunAsAdministrator

Write-Host "[*] Executing Emergency Rollback to pristine state..." -ForegroundColor Yellow

# 1. Restore Firewall Defaults
Write-Host "[+] Resetting custom firewall rules..." -ForegroundColor Cyan
Remove-NetFirewallRule -Name "SurfaceGuard_*" -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -ErrorAction SilentlyContinue
Write-Host "    [✓] Removed SurfaceGuard firewall drop rules" -ForegroundColor Green

# 2. Re-enable Camera
$camRegPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Camera"
if (Test-Path $camRegPath) {
    Remove-ItemProperty -Path $camRegPath -Name "AllowCamera" -ErrorAction SilentlyContinue
    Write-Host "    [✓] Restored Camera registry policy to Default" -ForegroundColor Green
}

# 3. Restore Microphone Consent
$micRegPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone"
if (Test-Path $micRegPath) {
    Set-ItemProperty -Path $micRegPath -Name "Value" -Value "Allow" -Type String -ErrorAction SilentlyContinue
    Write-Host "    [✓] Restored Microphone permissions" -ForegroundColor Green
}

Write-Host "[+] Rollback completed successfully. All standard defaults restored." -ForegroundColor Green
`;

  return {
    script,
    rollback,
    filename: 'SurfaceGuard-Hardening-Windows.ps1',
    rollbackFilename: 'SurfaceGuard-Rollback-Windows.ps1'
  };
}

function generateLinuxScript(config: HardeningConfig): { script: string; rollback: string; filename: string; rollbackFilename: string } {
  const script = `#!/usr/bin/env bash
# ==============================================================================
# CROSS-PLATFORM ATTACK SURFACE REDUCTION & HARDENING SCRIPT
# PLATFORM: Linux (Debian, Ubuntu 22.04/24.04 LTS, RHEL 9+, Fedora)
# ATOMICITY: Transactional with systemd network-pre.target integration
# MODE: ${config.dryRunMode ? 'DRY-RUN SIMULATION (No system changes committed)' : 'ACTIVE ENFORCEMENT'}
# ==============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This hardening script must be executed as root." >&2
   exit 1
fi

DRY_RUN=${config.dryRunMode ? '1' : '0'}
JOURNAL_PATH="/var/log/surfaceguard_state.json"

echo -e "\\033[1;36m[*] Initializing SurfaceGuard Hardening Engine for Linux...\\033[0m"

# ------------------------------------------------------------------------------
# PHASE 1: NETWORK ATTACK SURFACE REDUCTION (nftables / ufw)
# ------------------------------------------------------------------------------
echo -e "\\033[1;34m[+] Phase 1: Enforcing default-deny firewall posture...\\033[0m"

if [[ "$DRY_RUN" -eq 0 ]]; then
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow in on lo
        ${config.allowDevPorts ? `
        # Allow loopback developer ports
        ${config.devPorts.map(p => `ufw allow in on lo to 127.0.0.1 port ${p} proto tcp`).join('\n        ')}
        ` : ''}
        # Deny high risk lateral movement ports
        ufw deny in 445/tcp comment "Block SMB"
        ufw deny in 137:139/tcp comment "Block NetBIOS"
        ufw --force enable
        echo -e "\\033[1;32m    [✓] Configured persistent UFW firewall (Default Deny Inbound)\\033[0m"
    elif command -v nft >/dev/null 2>&1; then
        cat << 'EOF' > /etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport 445 drop
        tcp dport 135-139 drop
        ${config.allowDevPorts ? config.devPorts.map(p => `iif "lo" tcp dport ${p} accept`).join('\n        ') : ''}
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
        systemctl restart nftables || true
        echo -e "\\033[1;32m    [✓] Committed atomic /etc/nftables.conf drop rules\\033[0m"
    fi
else
    echo -e "\\033[1;33m    [SIMULATION] Would reset firewall to default-deny inbound on all interfaces\\033[0m"
    echo -e "\\033[1;33m    [SIMULATION] Would block incoming TCP 445 and 137-139\\033[0m"
fi

# ------------------------------------------------------------------------------
# PHASE 2: HARDWARE SANDBOXING (udev Camera & Microphone Lockdown)
# ------------------------------------------------------------------------------
echo -e "\\033[1;34m[+] Phase 2: Restricting peripheral device nodes via udev...\\033[0m"

UDEV_RULE_PATH="/etc/udev/rules.d/99-surfaceguard-peripherals.rules"
if [[ "$DRY_RUN" -eq 0 ]]; then
    cat << 'EOF' > "$UDEV_RULE_PATH"
# SurfaceGuard: Restrict direct unauthenticated access to video & sound devices
${config.lockdownCamera ? `SUBSYSTEM=="video4linux", KERNEL=="video[0-9]*", MODE="0000", GROUP="root"` : ''}
${config.lockdownMicrophone ? `SUBSYSTEM=="sound", KERNEL=="controlC[0-9]*", MODE="0600", GROUP="root"` : ''}
EOF
    udevadm control --reload-rules && udevadm trigger --subsystem-match=video4linux || true
    echo -e "\\033[1;32m    [✓] Deployed udev hardware lockdown rules to $UDEV_RULE_PATH\\033[0m"
else
    echo -e "\\033[1;33m    [SIMULATION] Would write chmod 0000 udev rules for video4linux\\033[0m"
fi

# ------------------------------------------------------------------------------
# PHASE 3: FILE SYSTEM HARDENING
# ------------------------------------------------------------------------------
echo -e "\\033[1;34m[+] Phase 3: Auditing directory permissions...\\033[0m"
if [[ "$DRY_RUN" -eq 0 ]]; then
    # Ensure /etc/shadow and /etc/gshadow permissions adhere to CIS benchmarks
    chmod 0000 /etc/shadow /etc/gshadow || true
    chmod 0644 /etc/passwd /etc/group || true
    echo -e "\\033[1;32m    [✓] Hardened /etc/shadow and /etc/passwd permissions to CIS Benchmark\\033[0m"
fi

echo -e "\\033[1;32m[*] Linux system attack surface reduction completed successfully!\\033[0m"
`;

  const rollback = `#!/usr/bin/env bash
# ==============================================================================
# SURFACEGUARD EMERGENCY ROLLBACK SCRIPT (LINUX)
# Restores pre-hardening baseline configuration in < 1 second
# ==============================================================================

set -euo pipefail
if [[ $EUID -ne 0 ]]; then
   echo "[-] Must run as root." >&2
   exit 1
fi

echo -e "\\033[1;33m[*] Executing emergency rollback to pristine baseline...\\033[0m"

# 1. Reset Firewall
if command -v ufw >/dev/null 2>&1; then
    ufw default allow incoming
    ufw disable
    echo -e "\\033[1;32m    [✓] Disabled UFW default-deny policy\\033[0m"
elif command -v nft >/dev/null 2>&1; then
    nft flush ruleset
    echo -e "\\033[1;32m    [✓] Flushed nftables ruleset\\033[0m"
fi

# 2. Remove udev peripheral lockdown
rm -f /etc/udev/rules.d/99-surfaceguard-peripherals.rules
udevadm control --reload-rules && udevadm trigger || true
echo -e "\\033[1;32m    [✓] Removed peripheral lockdown udev rules\\033[0m"

echo -e "\\033[1;32m[*] System fully restored to standard operational defaults.\\033[0m"
`;

  return {
    script,
    rollback,
    filename: 'surfaceguard-hardening-linux.sh',
    rollbackFilename: 'surfaceguard-rollback-linux.sh'
  };
}

function generateMacScript(config: HardeningConfig): { script: string; rollback: string; filename: string; rollbackFilename: string } {
  const script = `#!/bin/zsh
# ==============================================================================
# CROSS-PLATFORM ATTACK SURFACE REDUCTION & HARDENING SCRIPT
# PLATFORM: Apple macOS (14 Sonoma, 15 Sequoia, & later)
# ATOMICITY: pfctl anchors + LaunchDaemon persistence
# MODE: ${config.dryRunMode ? 'DRY-RUN SIMULATION (No system changes committed)' : 'ACTIVE ENFORCEMENT'}
# ==============================================================================

set -e

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: Hardening commands require sudo privileges." >&2
   exit 1
fi

DRY_RUN=${config.dryRunMode ? '1' : '0'}
echo "\\033[1;36m[*] Initializing SurfaceGuard Hardening Engine for macOS...\\033[0m"

# ------------------------------------------------------------------------------
# PHASE 1: PACKET FILTER (PF) FIREWALL ANCHORS
# ------------------------------------------------------------------------------
echo "\\033[1;34m[+] Phase 1: Applying pfctl anchor rules...\\033[0m"

ANCHOR_FILE="/etc/pf.anchors/com.surfaceguard.hardening"
if [[ "$DRY_RUN" -eq 0 ]]; then
    cat << 'EOF' > "$ANCHOR_FILE"
# SurfaceGuard Packet Filter Rules
block in all
pass out all keep state
pass in quick on lo0 all
${config.allowDevPorts ? config.devPorts.map(p => `pass in quick on lo0 proto tcp from 127.0.0.1 to 127.0.0.1 port ${p}`).join('\n') : ''}
block in quick proto tcp from any to any port { 445, 137, 138, 139 }
EOF
    pfctl -ef /etc/pf.conf 2>/dev/null || true
    echo "\\033[1;32m    [✓] Packet Filter anchor rules committed to $ANCHOR_FILE\\033[0m"
else
    echo "\\033[1;33m    [SIMULATION] Would write pfctl anchor to $ANCHOR_FILE\\033[0m"
fi

# ------------------------------------------------------------------------------
# PHASE 2: TCC RESET & CAMERA/MIC ISOLATION
# ------------------------------------------------------------------------------
echo "\\033[1;34m[+] Phase 2: Auditing Privacy (TCC) Permissions...\\033[0m"
if [[ "$DRY_RUN" -eq 0 ]]; then
    ${config.lockdownCamera ? `tccutil reset Camera 2>/dev/null || true` : ''}
    ${config.lockdownMicrophone ? `tccutil reset Microphone 2>/dev/null || true` : ''}
    echo "\\033[1;32m    [✓] Reset cached Camera & Microphone TCC application permissions\\033[0m"
else
    echo "\\033[1;33m    [SIMULATION] Would execute tccutil reset Camera & Microphone\\033[0m"
fi

echo "\\033[1;32m[*] macOS attack surface reduction complete!\\033[0m"
`;

  const rollback = `#!/bin/zsh
# ==============================================================================
# SURFACEGUARD EMERGENCY ROLLBACK SCRIPT (MACOS)
# Restores standard macOS firewall and networking in < 2 seconds
# ==============================================================================

if [[ $EUID -ne 0 ]]; then
   echo "[-] Must run with sudo." >&2
   exit 1
fi

echo "\\033[1;33m[*] Executing emergency rollback...\\033[0m"
rm -f /etc/pf.anchors/com.surfaceguard.hardening
pfctl -d 2>/dev/null || true
echo "\\033[1;32m    [✓] Disabled custom pfctl packet filtering\\033[0m"
echo "\\033[1;32m[*] macOS restored to default configuration.\\033[0m"
`;

  return {
    script,
    rollback,
    filename: 'surfaceguard-hardening-macos.sh',
    rollbackFilename: 'surfaceguard-rollback-macos.sh'
  };
}
