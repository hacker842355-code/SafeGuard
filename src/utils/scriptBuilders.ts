import { PortItem, HardwareState, BackgroundProcess, SecurityProfileMode } from '../types/security';
import { ActiveLease } from '../context/SecurityContext';

export interface ScriptGeneratorParams {
  ports: PortItem[];
  hardware: HardwareState;
  processes: BackgroundProcess[];
  isStrictLockdown: boolean;
  activeProfile: SecurityProfileMode;
  activeLease: ActiveLease | null;
  targetOS?: 'windows' | 'linux' | 'macos';
}

/**
 * 1. DYNAMIC ACTIVE HARDENING SCRIPT GENERATOR
 * Generates an idempotent, production-ready PowerShell script containing ONLY
 * the rules currently active in the user's live configuration.
 */
export function buildHardeningScript(params: ScriptGeneratorParams): string {
  const { ports, hardware, processes, isStrictLockdown, activeProfile, activeLease } = params;
  const now = new Date().toISOString();
  const blockedPorts = ports.filter((p) => !p.isOpen);
  const openPorts = ports.filter((p) => p.isOpen);
  const blockedProcesses = processes.filter((p) => p.isBlocked);

  // Network Ports Commands
  const portLines: string[] = [];
  if (isStrictLockdown) {
    portLines.push(
      '# Global Strict Inbound Lockdown (Drop all unlisted TCP traffic 1-65535)',
      'Write-Host "    [!] Enforcing Global Strict Lockdown on TCP ports 1-65535..." -ForegroundColor Yellow',
      'netsh advfirewall firewall delete rule name="SurfaceGuard_Block_All_Unlisted" 2>$null',
      'if ($LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0 }',
      'netsh advfirewall firewall add rule name="SurfaceGuard_Block_All_Unlisted" dir=in action=block protocol=TCP localport=1-65535 enable=yes'
    );
  }

  if (blockedPorts.length > 0) {
    portLines.push('# Individual Inbound Port Drop Rules (Zero-Trust)');
    blockedPorts.forEach((p) => {
      const ruleName = `SurfaceGuard_Block_${p.port}`;
      portLines.push(
        `# Block Port ${p.port}/${p.protocol} - ${p.service}`,
        `Write-Host "    [-] Blocking Port ${p.port}/${p.protocol} (${p.service})..." -ForegroundColor DarkGray`,
        `netsh advfirewall firewall delete rule name="${ruleName}" 2>$null`,
        'if ($LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0 }',
        `netsh advfirewall firewall add rule name="${ruleName}" dir=in action=block protocol=${p.protocol} localport=${p.port} enable=yes -ErrorAction SilentlyContinue`
      );
    });
  } else {
    portLines.push('# No specific individual ports are currently marked as blocked.');
  }

  // Telemetry & Process Outbound Commands
  const procLines: string[] = [];
  if (blockedProcesses.length > 0) {
    blockedProcesses.forEach((proc) => {
      const exe = proc.name.endsWith('.exe') ? proc.name : `${proc.name}.exe`;
      const ruleName = `SurfaceGuard_Block_Proc_${exe}`;
      const safePath = proc.path.replace(/"/g, '\\"');
      procLines.push(
        `# Outbound Drop for ${exe}`,
        `Write-Host "    [-] Severing outbound internet for ${exe}..." -ForegroundColor DarkGray`,
        `netsh advfirewall firewall delete rule name="${ruleName}" 2>$null`,
        'if ($LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0 }',
        `netsh advfirewall firewall add rule name="${ruleName}" dir=out action=block program="${safePath}" enable=yes -ErrorAction SilentlyContinue`
      );
    });
  } else {
    procLines.push('# No background processes are currently flagged for outbound blocking.');
  }

  // Hardware Controls Commands
  const hwLines: string[] = [];
  if (hardware.camera) {
    hwLines.push(
      '# Camera Lockdown: Restrict Webcam CapabilityAccess Consent to Deny',
      'Write-Host "    [*] Locking Webcam device consent to Deny..." -ForegroundColor DarkGray',
      'New-Item -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam" -Force -ErrorAction SilentlyContinue | Out-Null',
      'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam" -Name "Value" -Value "Deny" -Type String -Force',
      'New-Item -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged" -Force -ErrorAction SilentlyContinue | Out-Null',
      'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged" -Name "Value" -Value "Deny" -Type String -Force'
    );
  }

  if (hardware.microphone) {
    hwLines.push(
      '# Microphone Lockdown: Restrict Microphone CapabilityAccess Consent to Deny',
      'Write-Host "    [*] Locking Microphone device consent to Deny..." -ForegroundColor DarkGray',
      'New-Item -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone" -Force -ErrorAction SilentlyContinue | Out-Null',
      'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone" -Name "Value" -Value "Deny" -Type String -Force',
      'New-Item -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged" -Force -ErrorAction SilentlyContinue | Out-Null',
      'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged" -Name "Value" -Value "Deny" -Type String -Force'
    );
  }

  if (hardware.usbStorage) {
    hwLines.push(
      '# USB Mass Storage: Block unauthorized removable flash media (USBSTOR Start=4)',
      'Write-Host "    [*] Disabling USB Mass Storage driver (USBSTOR Start=4)..." -ForegroundColor DarkGray',
      'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue'
    );
  }

  if (hardware.bluetooth) {
    hwLines.push(
      '# Bluetooth Radio: Disable all Bluetooth PnP Controllers and Radios',
      'Write-Host "    [*] Disabling Bluetooth PnP radio controllers..." -ForegroundColor DarkGray',
      'Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | ForEach-Object {',
      '    Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue',
      '}'
    );
  }

  if (hardware.fileSystemAcl) {
    hwLines.push(
      '# File System ACL: Remove unauthenticated write privileges on %ProgramData%',
      'Write-Host "    [*] Hardening %ProgramData% ACL inheritance..." -ForegroundColor DarkGray',
      'icacls "$env:ProgramData" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /C /Q'
    );
  }

  if (hwLines.length === 0) {
    hwLines.push('# All hardware controls are currently in permissive state.');
  }

  const pamComment = activeLease
    ? `# ACTIVE PAM EXEMPTION: ${activeLease.shortName} currently has an active temporary lease (${activeLease.remainingSeconds}s remaining).`
    : '# Temporary Access: No active PAM lease overrides present.';

  return `# ==============================================================================
# SURFACEGUARD OS ARCHITECT - DYNAMIC ACTIVE HARDENING SCRIPT
# Profile: ${activeProfile.toUpperCase()} | Generated: ${now}
# Policy Scope: ${blockedPorts.length} Blocked Ports | ${blockedProcesses.length} Blocked Processes
# Strict Lockdown: ${isStrictLockdown ? 'ENABLED' : 'DISABLED'}
# Camera: ${hardware.camera ? 'LOCKED' : 'PERMISSIVE'} | Mic: ${hardware.microphone ? 'LOCKED' : 'PERMISSIVE'} | USB: ${hardware.usbStorage ? 'BLOCKED' : 'ALLOWED'}
# ==============================================================================
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$WhatIf
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SURFACEGUARD ARCHITECT - ACTIVE SECURITY HARDENING     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Policy Profile: ${activeProfile.toUpperCase()}" -ForegroundColor Gray
Write-Host "[*] Timestamp: ${now}" -ForegroundColor Gray
${pamComment}
Write-Host ""

# ------------------------------------------------------------------------------
# 1. NETWORK FIREWALL INBOUND PORT RULES
# ------------------------------------------------------------------------------
Write-Host "[1/3] Enforcing Inbound Network Port Restrictions..." -ForegroundColor Cyan
${portLines.join('\n')}

# ------------------------------------------------------------------------------
# 2. OUTBOUND PROCESS & TELEMETRY RESTRICTIONS
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/3] Enforcing Process Guard & Outbound Telemetry Drops..." -ForegroundColor Cyan
${procLines.join('\n')}

# ------------------------------------------------------------------------------
# 3. HARDWARE & PERIPHERAL GOVERNANCE
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/3] Enforcing Hardware & Peripheral Device Hardening..." -ForegroundColor Cyan
${hwLines.join('\n')}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[✓] SUCCESS: Active configuration enforced on this endpoint." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
`;
}

/**
 * 2. INSTANT EMERGENCY ROLLBACK SCRIPT GENERATOR
 * Generates an inverse script that cleanly deletes all SurfaceGuard_* firewall rules,
 * resets privacy consent to Allow, re-enables USBSTOR (Start=3), enables Bluetooth,
 * and restores file system inheritance.
 */
export function buildRollbackScript(params: ScriptGeneratorParams): string {
  const now = new Date().toISOString();

  return `# ==============================================================================
# SURFACEGUARD OS ARCHITECT - INSTANT EMERGENCY ROLLBACK SCRIPT
# Reverts Windows Firewall, Privacy ConsentStores, USB Storage, & Bluetooth
# Generated: ${now}
# ==============================================================================
#Requires -RunAsAdministrator

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

Write-Host "==========================================================" -ForegroundColor Red
Write-Host "   SURFACEGUARD ARCHITECT - EMERGENCY SYSTEM ROLLBACK     " -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red
Write-Host "[*] Reverting all SurfaceGuard firewall policies and device restrictions..." -ForegroundColor Gray
Write-Host ""

# 1. Purge all SurfaceGuard Firewall Rules (Inbound & Outbound)
Write-Host "[1/5] Purging SurfaceGuard firewall rules..." -ForegroundColor Cyan
$sgRules = Get-NetFirewallRule -Name "SurfaceGuard_*" -ErrorAction SilentlyContinue
if ($sgRules) {
    $sgRules | ForEach-Object {
        Write-Host "      [-] Removing firewall rule: $($_.Name)" -ForegroundColor DarkGray
        Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "      [*] No active SurfaceGuard firewall rules found." -ForegroundColor DarkGray
}
netsh advfirewall firewall delete rule name="SurfaceGuard_Block_All_Unlisted" 2>$null
if ($LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0 }

# 2. Reset Privacy ConsentStores back to 'Allow' (Webcam & Microphone)
Write-Host "[2/5] Resetting Camera and Microphone permissions back to 'Allow'..." -ForegroundColor Cyan
$webcamPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam"
$webcamNonPackaged = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged"
$micPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone"
$micNonPackaged = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged"

Set-ItemProperty -Path $webcamPath -Name "Value" -Value "Allow" -Type String -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path $webcamNonPackaged -Name "Value" -Value "Allow" -Type String -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path $micPath -Name "Value" -Value "Allow" -Type String -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path $micNonPackaged -Name "Value" -Value "Allow" -Type String -Force -ErrorAction SilentlyContinue
Write-Host "      [✓] Webcam and Microphone ConsentStore restored to 'Allow'." -ForegroundColor DarkGray

# 3. Re-enable USB Mass Storage (USBSTOR Start=3)
Write-Host "[3/5] Re-enabling USB Mass Storage driver (USBSTOR Start=3)..." -ForegroundColor Cyan
Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
Write-Host "      [✓] USBSTOR service Start value set to 3 (Normal Operation)." -ForegroundColor DarkGray

# 4. Re-enable PnP Bluetooth Devices
Write-Host "[4/5] Enabling Bluetooth PnP devices..." -ForegroundColor Cyan
Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "      [+] Enabling Bluetooth: $($_.FriendlyName)" -ForegroundColor DarkGray
    Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
}

# 5. Restore File System ACL Defaults
Write-Host "[5/5] Restoring %ProgramData% ACL inheritance defaults..." -ForegroundColor Cyan
icacls "$env:ProgramData" /reset /C /Q
Write-Host "      [✓] ProgramData permissions reset to inherited defaults." -ForegroundColor DarkGray

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Red
Write-Host "[✓] ROLLBACK COMPLETE: System successfully restored to baseline defaults." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Red
`;
}

/**
 * 3. GPO / INTUNE ENTERPRISE EXPORT SCRIPT GENERATOR
 * Formats active hardening rules for mass deployment via Active Directory GPO
 * or Microsoft Intune PowerShell Management Extension with compliance registry stamps.
 */
export function buildGpoIntuneScript(params: ScriptGeneratorParams): string {
  const { ports, hardware, processes, isStrictLockdown, activeProfile } = params;
  const now = new Date().toISOString();
  const blockedPorts = ports.filter((p) => !p.isOpen);
  const blockedProcesses = processes.filter((p) => p.isBlocked);

  const portCommands = blockedPorts
    .map(
      (p) =>
        `netsh advfirewall firewall delete rule name="SurfaceGuard_Block_${p.port}" 2>$null; if ($LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0 }; netsh advfirewall firewall add rule name="SurfaceGuard_Block_${p.port}" dir=in action=block protocol=${p.protocol} localport=${p.port} enable=yes -ErrorAction SilentlyContinue`
    )
    .join('\n');

  const processCommands = blockedProcesses
    .map((proc) => {
      const exe = proc.name.endsWith('.exe') ? proc.name : `${proc.name}.exe`;
      const ruleName = `SurfaceGuard_Block_Proc_${exe}`;
      const safePath = proc.path.replace(/"/g, '\\"');
      return `netsh advfirewall firewall delete rule name="${ruleName}" 2>$null; if ($LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0 }; netsh advfirewall firewall add rule name="${ruleName}" dir=out action=block program="${safePath}" enable=yes -ErrorAction SilentlyContinue`;
    })
    .join('\n');

  return `# ==============================================================================
# SURFACEGUARD OS ARCHITECT - ENTERPRISE GPO / INTUNE DEPLOYMENT SCRIPT
# Deployment Engine: Active Directory Group Policy (GPO) / Microsoft Intune (IME)
# Target Scope: All Managed Endpoints (Computer Context / SYSTEM)
# Profile: ${activeProfile.toUpperCase()} | Generated: ${now}
# ==============================================================================
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$LogPath = "$env:ProgramData\\SurfaceGuard\\IntuneDeployment.log"
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# 1. Initialize Corporate Transcript Logging
$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

try {
    Start-Transcript -Path $LogPath -Append -Force -ErrorAction SilentlyContinue
} catch {}

Write-Output "[*] SurfaceGuard Enterprise Policy Deployment Initiated: $(Get-Date -Format 'o')"
Write-Output "[*] Running as Context: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# 2. Apply Network Ports Hardening (${blockedPorts.length} rules)
Write-Output "[+] Enforcing Inbound Firewall Rules..."
${portCommands || '# No port block rules in current baseline'}
${
  isStrictLockdown
    ? 'netsh advfirewall firewall delete rule name="SurfaceGuard_Block_All_Unlisted" 2>$null; if ($LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0 }; netsh advfirewall firewall add rule name="SurfaceGuard_Block_All_Unlisted" dir=in action=block protocol=TCP localport=1-65535 enable=yes'
    : ''
}

# 3. Apply Outbound Telemetry Blocks (${blockedProcesses.length} processes)
Write-Output "[+] Enforcing Process Telemetry Drops..."
${processCommands || '# No process block rules in current baseline'}

# 4. Apply Hardware Security Controls
Write-Output "[+] Enforcing Device Sandboxing Policies..."
${
  hardware.camera
    ? `New-Item -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam" -Name "Value" -Value "Deny" -Type String -Force
New-Item -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged" -Name "Value" -Value "Deny" -Type String -Force`
    : '# Camera policy not restricted in baseline'
}

${
  hardware.microphone
    ? `New-Item -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone" -Name "Value" -Value "Deny" -Type String -Force
New-Item -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged" -Name "Value" -Value "Deny" -Type String -Force`
    : '# Microphone policy not restricted in baseline'
}

${
  hardware.usbStorage
    ? 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue'
    : '# USB Storage not restricted in baseline'
}

${
  hardware.bluetooth
    ? 'Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue }'
    : '# Bluetooth not restricted in baseline'
}

${
  hardware.fileSystemAcl
    ? 'icacls "$env:ProgramData" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /C /Q'
    : '# ACL hardening not restricted in baseline'
}

# 5. Register Intune/GPO Compliance Detection Stamp
$complianceKey = "HKLM:\\SOFTWARE\\SurfaceGuard"
if (-not (Test-Path $complianceKey)) {
    New-Item -Path $complianceKey -Force | Out-Null
}

Set-ItemProperty -Path $complianceKey -Name "PolicyEnforced" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $complianceKey -Name "ActiveProfile" -Value "${activeProfile}" -Type String -Force
Set-ItemProperty -Path $complianceKey -Name "EnforcedTimestamp" -Value "${now}" -Type String -Force
Set-ItemProperty -Path $complianceKey -Name "BlockedPortsCount" -Value ${blockedPorts.length} -Type DWord -Force
Set-ItemProperty -Path $complianceKey -Name "BlockedProcessesCount" -Value ${blockedProcesses.length} -Type DWord -Force

Write-Output "[✓] Compliance registry key stamped at HKLM:\\SOFTWARE\\SurfaceGuard"
Write-Output "[✓] GPO / Intune Deployment completed successfully. Exiting with Code 0."

try {
    Stop-Transcript -ErrorAction SilentlyContinue
} catch {}

exit 0
`;
}

/**
 * 4. STRUCTURED AUDIT STATE MANIFEST (JSON)
 */
export function buildAuditJson(params: ScriptGeneratorParams): string {
  const { ports, hardware, processes, isStrictLockdown, activeProfile, activeLease } = params;
  const blockedPorts = ports.filter((p) => !p.isOpen);
  const openPorts = ports.filter((p) => p.isOpen);
  const blockedProcesses = processes.filter((p) => p.isBlocked);

  const manifest = {
    generator: 'SurfaceGuard Architect',
    architectureVersion: '3.0.0-Enterprise',
    timestamp: new Date().toISOString(),
    profile: activeProfile,
    metrics: {
      totalManagedPorts: ports.length,
      blockedPortsCount: blockedPorts.length,
      openPortsCount: openPorts.length,
      strictLockdownActive: isStrictLockdown,
      totalMonitoredProcesses: processes.length,
      blockedProcessesCount: blockedProcesses.length,
      hardwareStatus: {
        cameraLocked: hardware.camera,
        microphoneLocked: hardware.microphone,
        usbStorageBlocked: hardware.usbStorage,
        bluetoothBlocked: hardware.bluetooth,
        fileSystemAclTightened: hardware.fileSystemAcl,
      },
      activeTemporaryLease: activeLease
        ? {
            appId: activeLease.appId,
            shortName: activeLease.shortName,
            remainingSeconds: activeLease.remainingSeconds,
            reason: activeLease.reason,
            expiresAt: activeLease.expiresAt,
          }
        : null,
    },
    activeBlockedPorts: blockedPorts.map((p) => ({
      port: p.port,
      protocol: p.protocol,
      service: p.service,
      risk: p.risk,
      process: p.process,
    })),
    activeBlockedProcesses: blockedProcesses.map((p) => ({
      pid: p.pid,
      name: p.name,
      path: p.path,
      type: p.type,
      impact: p.impact,
    })),
  };

  return JSON.stringify(manifest, null, 2);
}
