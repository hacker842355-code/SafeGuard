import { PortItem, HardwareState, BackgroundProcess } from '../types/security';

export interface SystemSnapshot {
  timestamp: string;
  targetOS: 'windows' | 'linux' | 'macos';
  ports: PortItem[];
  hardware: HardwareState;
  processes: BackgroundProcess[];
  isStrictLockdown: boolean;
  metadata?: {
    version: string;
    description: string;
  };
}

export interface HardeningActionRecord {
  id: string;
  timestamp: string;
  actionType: 'HARDWARE' | 'PORT' | 'PROCESS' | 'PROFILE' | 'STRICT_LOCKDOWN';
  target: string;
  commandExecuted: string;
  rollbackCommand: string;
}

const STORAGE_SNAPSHOT_KEY = 'surfaceguard_system_state_backup';
const STORAGE_ACTION_HISTORY_KEY = 'surfaceguard_action_history';

/**
 * Persists a complete system state snapshot.
 * In Electron native mode, attempts to persist to disk via IPC or APPDATA path if available;
 * always persists to localStorage as a fast cross-session reliable backup.
 */
export async function saveSystemStateSnapshot(snapshot: SystemSnapshot): Promise<boolean> {
  try {
    const serialized = JSON.stringify(snapshot, null, 2);

    // Save to localStorage for resilient web and Electron client persistence
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(STORAGE_SNAPSHOT_KEY, serialized);
    }

    // If running in native Windows Electron, write snapshot to %APPDATA%/SurfaceGuard/system_state_backup.json
    if (typeof window !== 'undefined' && window.electronAPI?.runPowerShell) {
      const b64Data = btoa(unescape(encodeURIComponent(serialized)));
      const psSaveScript = `$ErrorActionPreference = 'SilentlyContinue'; & {
        $backupDir = Join-Path $env:APPDATA 'SurfaceGuard'
        if (!(Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
        $backupPath = Join-Path $backupDir 'system_state_backup.json'
        $bytes = [System.Convert]::FromBase64String('${b64Data}')
        [System.IO.File]::WriteAllBytes($backupPath, $bytes)
      } -ErrorAction SilentlyContinue`;

      await window.electronAPI.runPowerShell(psSaveScript, false);
    }
    return true;
  } catch (err) {
    console.error('Failed to persist system state snapshot:', err);
    return false;
  }
}

/**
 * Retrieves the saved system state snapshot from storage.
 */
export async function loadSystemStateSnapshot(): Promise<SystemSnapshot | null> {
  try {
    if (typeof window !== 'undefined' && window.electronAPI?.runPowerShell) {
      const psReadScript = `$ErrorActionPreference = 'SilentlyContinue'; & {
        $backupPath = Join-Path (Join-Path $env:APPDATA 'SurfaceGuard') 'system_state_backup.json'
        if (Test-Path $backupPath) {
          $bytes = [System.IO.File]::ReadAllBytes($backupPath)
          [System.Convert]::ToBase64String($bytes)
        }
      } -ErrorAction SilentlyContinue`;

      const result = await window.electronAPI.runPowerShell(psReadScript, false);
      if (result.success && result.output && result.output.trim()) {
        try {
          const raw = decodeURIComponent(escape(atob(result.output.trim())));
          return JSON.parse(raw) as SystemSnapshot;
        } catch {
          // fallback to localStorage
        }
      }
    }

    if (typeof window !== 'undefined' && window.localStorage) {
      const stored = window.localStorage.getItem(STORAGE_SNAPSHOT_KEY);
      if (stored) {
        return JSON.parse(stored) as SystemSnapshot;
      }
    }
  } catch (err) {
    console.warn('Error reading system state snapshot:', err);
  }
  return null;
}

/**
 * Tracks the last hardening action for automated transaction rollback.
 */
let lastActionRecord: HardeningActionRecord | null = null;

export function recordLastAction(action: HardeningActionRecord): void {
  lastActionRecord = action;
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      window.sessionStorage.setItem(STORAGE_ACTION_HISTORY_KEY, JSON.stringify(action));
    }
  } catch (_) {}
}

export function getLastAction(): HardeningActionRecord | null {
  if (lastActionRecord) return lastActionRecord;
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      const item = window.sessionStorage.getItem(STORAGE_ACTION_HISTORY_KEY);
      if (item) {
        lastActionRecord = JSON.parse(item);
        return lastActionRecord;
      }
    }
  } catch (_) {}
  return null;
}

export function clearLastAction(): void {
  lastActionRecord = null;
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      window.sessionStorage.removeItem(STORAGE_ACTION_HISTORY_KEY);
    }
  } catch (_) {}
}

/**
 * Master commands to reset Windows network firewall and unblock hardware drivers in an atomic pass.
 */
export const EMERGENCY_SAFE_MODE_RESTORE_SCRIPT = `$ErrorActionPreference = 'SilentlyContinue'; & {
  # 1. Purge SurfaceGuard firewall rules & restore inbound notifications
  Get-NetFirewallRule -Name "SurfaceGuard_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  netsh advfirewall firewall delete rule name="SurfaceGuard_Block_All_Unlisted" 2>$null
  if ($LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0 }
  netsh advfirewall set allprofiles settings openinboundconnectionnotify enable 2>$null

  # 2. Restore Camera Consent and PnP Devices
  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam' -Name 'Value' -Value 'Allow' -Force -ErrorAction SilentlyContinue
  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged' -Name 'Value' -Value 'Allow' -Force -ErrorAction SilentlyContinue
  Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue

  # 3. Restore Microphone Consent
  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone' -Name 'Value' -Value 'Allow' -Force -ErrorAction SilentlyContinue
  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged' -Name 'Value' -Value 'Allow' -Force -ErrorAction SilentlyContinue

  # 4. Restore USB Mass Storage Service (Start = 3 Manual/Automatic)
  Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue

  # 5. Restore Bluetooth Radio Devices
  Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue

  # 6. Restore Multicast DNS and Filesystem ACLs
  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 1 -Force -ErrorAction SilentlyContinue
  icacls "$env:ProgramData" /reset /C 2>$null
  icacls "$env:SystemRoot\\System32\\vssadmin.exe" /reset 2>$null
} -ErrorAction SilentlyContinue`;
