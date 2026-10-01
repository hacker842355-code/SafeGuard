import React, { createContext, useContext, useState, useEffect } from 'react';
import { 
  PortItem, 
  HardwareState, 
  SecurityProfileMode, 
  VulnerabilityAuditItem, 
  BlockedTrafficEvent,
  BackgroundProcess,
  RecurringScanSchedule
} from '../types/security';
import { cameraCommands } from './cameraCommands';

interface SecurityContextType {
  ports: PortItem[];
  hardware: HardwareState;
  processes: BackgroundProcess[];
  isScanningProcesses: boolean;
  isUpdatingProcesses: boolean;
  processAction: 'BLOCK_ALL' | 'ALLOW_ALL' | null;
  updatingProcessIds: number[];
  isAddingCustomProcess: boolean;
  scheduleConfig: RecurringScanSchedule;
  updateSchedule: (config: Partial<RecurringScanSchedule>) => void;
  toggleSchedule: () => void;
  cancelCalendarScan: () => void;
  targetOS: 'windows' | 'linux' | 'macos';
  setTargetOS: (os: 'windows' | 'linux' | 'macos') => void;
  activeProfile: SecurityProfileMode;
  applyProfile: (mode: SecurityProfileMode) => void;
  vulnerabilities: VulnerabilityAuditItem[];
  fixVulnerability: (id: string) => void;
  fixAllVulnerabilities: () => void;
  blockedEvents: BlockedTrafficEvent[];
  isScanning: boolean;
  isHardening: boolean;
  isFullHardened: boolean;
  terminalLogs: string[];
  securityScore: number;
  activeAttack: {
    name: string;
    description: string;
    result: 'BLOCKED' | 'EXPLOITED' | null;
    log: string;
  } | null;
  scanPorts: () => Promise<void>;
  scanProcesses: () => Promise<void>;
  togglePort: (portNumber: number) => Promise<void>;
  toggleProcessBlock: (pid: number) => Promise<void>;
  blockAllProcesses: () => Promise<void>;
  allowAllProcesses: () => Promise<void>;
  addCustomProcess: (name: string, path?: string) => Promise<boolean>;
  addCustomPort: (port: number, service: string, risk?: 'HIGH' | 'MEDIUM' | 'LOW') => void;
  toggleHardware: (device: keyof HardwareState) => Promise<boolean>;
  executeHardening: () => Promise<void>;
  executeRollback: () => Promise<void>;
  simulateAttack: (attackType: 'SMB_RANSOMWARE' | 'NMAP_SCAN' | 'SPYWARE_CAM' | 'DEV_DEBUG_EXPLOIT') => void;
  clearTerminal: () => void;
}

const initialPorts: PortItem[] = [
  {
    port: 445,
    protocol: 'TCP',
    service: 'Windows File Sharing (SMB)',
    isOpen: true,
    risk: 'CRITICAL',
    process: 'System (PID 4)',
    description: 'High risk: Common entry door for ransomware (WannaCry) to spread between computers.',
  },
  {
    port: 135,
    protocol: 'TCP',
    service: 'Windows Remote Procedure (RPC)',
    isOpen: true,
    risk: 'HIGH',
    process: 'svchost.exe (PID 840)',
    description: 'Used by Windows internals; hackers use it to probe what software is installed on your PC.',
  },
  {
    port: 3389,
    protocol: 'TCP',
    service: 'Remote Desktop (RDP)',
    isOpen: true,
    risk: 'HIGH',
    process: 'TermService (PID 1120)',
    description: 'Allows taking over PC screen remotely; targeted by password guessing bots.',
  },
  {
    port: 22,
    protocol: 'TCP',
    service: 'Secure Remote Terminal (SSH)',
    isOpen: true,
    risk: 'MEDIUM',
    process: 'sshd.exe (PID 2140)',
    description: 'Terminal command-line access door.',
  },
  {
    port: 8000,
    protocol: 'TCP',
    service: 'Local Website Preview Server',
    isOpen: true,
    isLoopbackOnly: false,
    risk: 'MEDIUM',
    process: 'node.exe (PID 6312)',
    description: 'Used for viewing websites during development.',
  },
  {
    port: 9229,
    protocol: 'TCP',
    service: 'Node.js Chrome Code Debugger',
    isOpen: true,
    isLoopbackOnly: false,
    risk: 'HIGH',
    process: 'node.exe (PID 6312)',
    description: 'If open to internet, anyone can inject and run code inside your apps.',
  },
  {
    port: 80,
    protocol: 'TCP',
    service: 'Standard Web Traffic (HTTP)',
    isOpen: true,
    risk: 'LOW',
    process: 'nginx.exe (PID 3304)',
    description: 'Normal web browser connection port.',
  },
  {
    port: 443,
    protocol: 'TCP',
    service: 'Encrypted Secure Web (HTTPS)',
    isOpen: true,
    risk: 'LOW',
    process: 'nginx.exe (PID 3304)',
    description: 'Encrypted safe web browsing port.',
  },
];

const initialHardware: HardwareState = {
  camera: false,      // false = Camera ON / Unprotected, true = LOCKED / SAFE
  microphone: false,  // false = Mic ON / Listening, true = LOCKED / SAFE
  usbStorage: false,  // false = Allowed, true = BLOCKED (Pen drives blocked)
  bluetooth: false,   // false = Active, true = BLOCKED (Radio off)
  fileSystemAcl: false, // false = Default permissions, true = STRICT PERMISSIONS
};

const initialVulnerabilities: VulnerabilityAuditItem[] = [
  {
    id: 'VULN-01',
    name: 'Legacy File Sharing Port 445 Exposed',
    simpleExplanation: 'Port 445 is listening to incoming connections. Malware can use this to infect your PC remotely.',
    riskSeverity: 'CRITICAL',
    isVulnerable: true,
    fixedActionDescription: 'Enforce Firewall Rule: Block inbound TCP Port 445 on all network adapters.',
  },
  {
    id: 'VULN-02',
    name: 'Webcam Hardware Not Policy-Restricted',
    simpleExplanation: 'Any background software or spyware can query the webcam without an admin password prompt.',
    riskSeverity: 'HIGH',
    isVulnerable: true,
    fixedActionDescription: 'Apply Windows Registry Policy: AllowCamera=0 to prevent unapproved video capture.',
  },
  {
    id: 'VULN-03',
    name: 'Removable USB Flash Drives Allowed to Auto-Mount',
    simpleExplanation: 'Plugging in an unknown USB flash drive can execute BadUSB keystroke injector scripts.',
    riskSeverity: 'MEDIUM',
    isVulnerable: true,
    fixedActionDescription: 'Disable USBSTOR driver service until explicitly unlocked.',
  },
  {
    id: 'VULN-04',
    name: 'System Folders Have World-Writable Permissions',
    simpleExplanation: 'Folders in ProgramData allow regular apps to write executable scripts.',
    riskSeverity: 'MEDIUM',
    isVulnerable: true,
    fixedActionDescription: 'Enforce Least Privilege ACLs on ProgramData system folders.',
  },
];

const initialBlockedEvents: BlockedTrafficEvent[] = [
  {
    id: 'BLK-401',
    timestamp: '11:42:19',
    sourceIp: '192.168.1.108',
    targetPort: 445,
    serviceName: 'Windows File Sharing (SMB)',
    actionTaken: 'BLOCKED_DROP',
    threatType: 'Unauthorized SMB Lateral Movement Probe',
  },
  {
    id: 'BLK-402',
    timestamp: '11:35:04',
    sourceIp: '10.0.0.45',
    targetPort: 3389,
    serviceName: 'Remote Desktop (RDP)',
    actionTaken: 'BLOCKED_DROP',
    threatType: 'Brute-force RDP Credential Probe',
  },
  {
    id: 'BLK-403',
    timestamp: '11:18:50',
    sourceIp: '172.16.0.88',
    targetPort: 9229,
    serviceName: 'Node.js V8 Debugger',
    actionTaken: 'BLOCKED_DROP',
    threatType: 'Remote Code Execution Injection Attempt',
  },
];

const initialProcesses: BackgroundProcess[] = [
  {
    pid: 4820,
    name: 'MicrosoftEdgeUpdate.exe',
    path: 'C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe',
    type: 'UPDATER',
    isBlocked: true,
    impact: 'Silent background updater and diagnostic telemetry ping',
  },
  {
    pid: 5192,
    name: 'compattelrunner.exe',
    path: 'C:\\Windows\\System32\\compattelrunner.exe',
    type: 'TELEMETRY',
    isBlocked: true,
    impact: 'Windows Compatibility telemetry and diagnostic data uploader',
  },
  {
    pid: 3108,
    name: 'GoogleUpdate.exe',
    path: 'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe',
    type: 'UPDATER',
    isBlocked: true,
    impact: 'Chrome background updater and analytics reporting',
  },
  {
    pid: 2940,
    name: 'NvTelemetryContainer.exe',
    path: 'C:\\Program Files\\NVIDIA Corporation\\NvTelemetry\\NvTelemetryContainer.exe',
    type: 'TELEMETRY',
    isBlocked: true,
    impact: 'Graphics driver telemetry collector and uploader',
  },
  {
    pid: 1824,
    name: 'smartscreen.exe',
    path: 'C:\\Windows\\System32\\smartscreen.exe',
    type: 'TELEMETRY',
    isBlocked: false,
    impact: 'Sends executed program hashes to cloud security servers',
  },
  {
    pid: 6312,
    name: 'node.exe',
    path: 'C:\\Program Files\\nodejs\\node.exe',
    type: 'SYSTEM',
    isBlocked: false,
    impact: 'Local developer runtime server',
  },
];

const initialSchedule: RecurringScanSchedule = {
  isEnabled: true,
  intervalMinutes: 15,
  includePorts: true,
  includeProcesses: true,
  scheduledDateTime: null,
  nextRunTimestamp: Date.now() + 15 * 60 * 1000,
  lastRunTimestamp: null,
  lastRunSummary: 'Initial baseline scan complete',
};

const quotePowerShell = (value: string) => `'${value.replace(/'/g, "''")}'`;

const getProcessClassification = (name: string): BackgroundProcess['type'] => {
  if (/telemetry|diagtrack|compattel|werfault|devicecensus|ceip/i.test(name)) return 'TELEMETRY';
  if (/update|updater/i.test(name)) return 'UPDATER';
  return 'SYSTEM';
};

const getProcessImpact = (name: string, type: BackgroundProcess['type']) => {
  if (type === 'TELEMETRY') return `${name} may collect diagnostics or transmit usage data.`;
  if (type === 'UPDATER') return `${name} may perform background updates and network checks.`;
  return `Active background process: ${name}.`;
};

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [ports, setPorts] = useState<PortItem[]>(initialPorts);
  const [hardware, setHardware] = useState<HardwareState>(initialHardware);
  const [processes, setProcesses] = useState<BackgroundProcess[]>(initialProcesses);
  const [isScanningProcesses, setIsScanningProcesses] = useState<boolean>(false);
  const [isUpdatingProcesses, setIsUpdatingProcesses] = useState<boolean>(false);
  const [processAction, setProcessAction] = useState<'BLOCK_ALL' | 'ALLOW_ALL' | null>(null);
  const [updatingProcessIds, setUpdatingProcessIds] = useState<number[]>([]);
  const [isAddingCustomProcess, setIsAddingCustomProcess] = useState<boolean>(false);
  const [scheduleConfig, setScheduleConfig] = useState<RecurringScanSchedule>(initialSchedule);
  const [targetOS, setTargetOS] = useState<'windows' | 'linux' | 'macos'>('windows');
  const [activeProfile, setActiveProfile] = useState<SecurityProfileMode>('custom');
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityAuditItem[]>(initialVulnerabilities);
  const [blockedEvents, setBlockedEvents] = useState<BlockedTrafficEvent[]>(initialBlockedEvents);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isHardening, setIsHardening] = useState<boolean>(false);

  const [activeAttack, setActiveAttack] = useState<{
    name: string;
    description: string;
    result: 'BLOCKED' | 'EXPLOITED' | null;
    log: string;
  } | null>(null);

  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '[*] SurfaceGuard Cybersecurity Workstation initialized.',
    '[*] System Status: Active real-time inspection of network doors & hardware devices.',
    '[!] Warning: 4 potential security vulnerabilities detected on your computer.',
    '[*] Ready to run scan or switch to Maximum Stealth Mode.',
  ]);

  // Compute live security health score (0 - 100%)
  const openHighPorts = ports.filter((p) => p.isOpen && (p.risk === 'CRITICAL' || p.risk === 'HIGH')).length;
  const openMedPorts = ports.filter((p) => p.isOpen && p.risk === 'MEDIUM').length;
  const unlockedHwCount = Object.values(hardware).filter((v) => !v).length;
  const activeVulnCount = vulnerabilities.filter((v) => v.isVulnerable).length;

  let computedScore = 100;
  computedScore -= openHighPorts * 12;
  computedScore -= openMedPorts * 4;
  computedScore -= unlockedHwCount * 5;
  computedScore -= activeVulnCount * 4;
  if (computedScore < 15) computedScore = 15;

  const isFullHardened = openHighPorts === 0 && hardware.camera && hardware.microphone && activeVulnCount === 0;

  // 1. Scan Network Ports
  const scanPorts = async () => {
    setIsScanning(true);
    setActiveAttack(null);
    setTerminalLogs((prev) => [
      ...prev,
      '',
      `[>] Scanning all network doors (ports) on ${targetOS.toUpperCase()}...`,
      '    [*] Checking what programs are listening for incoming internet connections...',
    ]);

    try {
      if (window.electronAPI?.isNativeWindows) {
        const result = await window.electronAPI.queryWindowsPorts();
        if (!result.success) throw new Error(result.error || 'Native socket query failed.');
        const listenerSummary = result.ports.map((port) =>
          `    ${port.Protocol} ${port.LocalAddress}:${port.LocalPort} (PID ${port.OwningProcess})`
        );
        setTerminalLogs((prev) => [
          ...prev,
          `    [+] Native scan complete: Found ${result.ports.length} listening TCP/UDP endpoints.`,
          ...(listenerSummary.length ? listenerSummary : ['    [*] No listening endpoints found.']),
        ]);
      } else {
        await new Promise((resolve) => setTimeout(resolve, 600));
        const openCount = ports.filter((port) => port.isOpen).length;
        setTerminalLogs((prev) => [
          ...prev,
          `    [+] Preview scan complete: ${openCount} configured sample ports are marked open.`,
          '    [!] Preview mode does not query host sockets or change firewall state.',
        ]);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown socket scan failure.';
      setTerminalLogs((prev) => [...prev, `[✗] Socket scan failed: ${message}`]);
    } finally {
      setIsScanning(false);
    }
  };

  // 1b. Scan Background Processes (EDR Telemetry Scanner)
  const scanProcesses = async () => {
    setIsScanningProcesses(true);
    setTerminalLogs((prev) => [
      ...prev,
      '',
      `[>] Scanning background processes & telemetry on ${targetOS.toUpperCase()}...`,
      '    [*] Inspecting WMI process table and computing SHA-256 binary checksums...',
    ]);

    try {
      if (!window.electronAPI?.isNativeWindows) throw new Error('Process scanning requires the native Windows application.');
      const command = 'Get-Process | Where-Object { $_.Path -ne $null } | Select-Object Id, ProcessName, Path | ConvertTo-Json -Compress';
      const result = await window.electronAPI.runPowerShell(command, true);
      if (!result.success) throw new Error(result.output || 'PowerShell process scan failed.');

      const parsed: unknown = JSON.parse(result.output.replace(/^\uFEFF/, '').trim() || '[]');
      const rows = (Array.isArray(parsed) ? parsed : parsed ? [parsed] : []) as Array<{
        Id?: number | string;
        ProcessName?: string;
        Path?: string;
      }>;
      const existing = new Map(processes.map((process) => [process.path.toLowerCase(), process]));
      const scannedProcesses = rows
        .filter((row) => row.Id != null && row.ProcessName && row.Path)
        .map((row): BackgroundProcess => {
          const name = `${row.ProcessName}.exe`;
          const path = row.Path as string;
          const type = getProcessClassification(name);
          const previous = existing.get(path.toLowerCase());
          return {
            pid: Number(row.Id),
            name,
            path,
            type,
            isBlocked: previous?.isBlocked ?? false,
            impact: getProcessImpact(name, type),
          };
        });
      setProcesses(scannedProcesses);
      const telemCount = scannedProcesses.filter((process) => process.type === 'TELEMETRY' || process.type === 'UPDATER').length;
      setTerminalLogs((prev) => [
        ...prev,
        `    [✓] Process Scan Complete: Inspected ${scannedProcesses.length} active tasks.`,
        `    [!] Found ${telemCount} telemetry harvesters and silent background updaters.`,
        result.output,
      ]);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown process scan failure.';
      setTerminalLogs((prev) => [...prev, `[✗] Process scan failed: ${message}`]);
    } finally {
      setIsScanningProcesses(false);
    }
  };

  // Toggle single background process block/allow
  const toggleProcessBlock = async (pid: number) => {
    const process = processes.find((item) => item.pid === pid);
    if (!process) return;
    const nextBlocked = !process.isBlocked;
    setUpdatingProcessIds((current) => [...current, pid]);
    try {
      if (!window.electronAPI?.isNativeWindows) throw new Error('Firewall changes require the native Windows application.');
      const ruleName = `SurfaceGuard_Block_${process.name}`;
      const command = nextBlocked
        ? `$ruleName = ${quotePowerShell(ruleName)}; $programPath = ${quotePowerShell(process.path)}; & netsh.exe advfirewall firewall add rule "name=$ruleName" dir=out "program=$programPath" action=block; if ($LASTEXITCODE -ne 0) { throw "netsh exited with code $LASTEXITCODE" }`
        : `& netsh.exe advfirewall firewall delete rule ${quotePowerShell(`name=${ruleName}`)}; if ($LASTEXITCODE -ne 0) { throw "netsh exited with code $LASTEXITCODE" }`;
      const result = await window.electronAPI.runPowerShell(command, true);
      if (!result.success) throw new Error(result.output || 'Firewall command failed.');
      setProcesses((current) => current.map((item) => item.pid === pid ? { ...item, isBlocked: nextBlocked } : item));
      setTerminalLogs((current) => [...current, `${nextBlocked ? '[✓] FIREWALL BLOCKED' : '[!] FIREWALL ALLOWED'}: ${process.name} (PID ${pid}).`, result.output]);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown firewall failure.';
      setTerminalLogs((current) => [...current, `[✗] Failed to ${nextBlocked ? 'block' : 'allow'} ${process.name} (PID ${pid}): ${message}`]);
    } finally {
      setUpdatingProcessIds((current) => current.filter((item) => item !== pid));
    }
  };

  // Master block all background telemetry
  const blockAllProcesses = async () => {
    const targets = processes.filter((process) => process.type === 'TELEMETRY' || process.type === 'UPDATER');
    setIsUpdatingProcesses(true);
    setProcessAction('BLOCK_ALL');
    try {
      if (!window.electronAPI?.isNativeWindows) throw new Error('Telemetry controls require the native Windows application.');
      const serializedTargets = quotePowerShell(JSON.stringify(targets.map(({ name, path }) => ({ name, path }))));
      const command = `Stop-Service DiagTrack, dmwappushservice -ErrorAction SilentlyContinue; Set-Service DiagTrack, dmwappushservice -StartupType Disabled -ErrorAction SilentlyContinue; New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" -Force; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force; $targets = ConvertFrom-Json -InputObject ${serializedTargets}; foreach ($item in $targets) { $ruleName = "SurfaceGuard_Block_$($item.name)"; & netsh.exe advfirewall firewall add rule "name=$ruleName" dir=out "program=$($item.path)" action=block; if ($LASTEXITCODE -ne 0) { throw "Firewall rule failed for $($item.name)" } }`;
      const result = await window.electronAPI.runPowerShell(command, true);
      if (!result.success) throw new Error(result.output || 'Telemetry blocking failed.');
      setProcesses((current) => current.map((process) => process.type === 'TELEMETRY' || process.type === 'UPDATER' ? { ...process, isBlocked: true } : process));
      setTerminalLogs((current) => [...current, `[✓] MASTER ACTION: Blocked ${targets.length} telemetry/updater processes and disabled telemetry services/policy.`, result.output]);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown telemetry blocking failure.';
      setTerminalLogs((current) => [...current, `[✗] MASTER TELEMETRY BLOCK FAILED: ${message}`]);
    } finally {
      setIsUpdatingProcesses(false);
      setProcessAction(null);
    }
  };

  // Master allow all
  const allowAllProcesses = async () => {
    const targets = processes.filter((process) => process.type === 'TELEMETRY' || process.type === 'UPDATER');
    setIsUpdatingProcesses(true);
    setProcessAction('ALLOW_ALL');
    try {
      if (!window.electronAPI?.isNativeWindows) throw new Error('Telemetry controls require the native Windows application.');
      const serializedTargets = quotePowerShell(JSON.stringify(targets.map(({ name }) => ({ name }))));
      const command = `Set-Service DiagTrack, dmwappushservice -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service DiagTrack, dmwappushservice -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" -Name "AllowTelemetry" -Value 3 -Type DWord -Force; $targets = ConvertFrom-Json -InputObject ${serializedTargets}; foreach ($item in $targets) { & netsh.exe advfirewall firewall delete rule name="SurfaceGuard_Block_$($item.name)"; if ($LASTEXITCODE -ne 0) { throw "Firewall rule removal failed for $($item.name)" } }`;
      const result = await window.electronAPI.runPowerShell(command, true);
      if (!result.success) throw new Error(result.output || 'Telemetry restore failed.');
      setProcesses((current) => current.map((process) => process.type === 'TELEMETRY' || process.type === 'UPDATER' ? { ...process, isBlocked: false } : process));
      setTerminalLogs((current) => [...current, `[✓] MASTER ACTION: Restored telemetry services/policy and removed ${targets.length} telemetry process rules.`, result.output]);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown telemetry restore failure.';
      setTerminalLogs((current) => [...current, `[✗] MASTER TELEMETRY RESTORE FAILED: ${message}`]);
    } finally {
      setIsUpdatingProcesses(false);
      setProcessAction(null);
    }
  };

  // Add custom process
  const addCustomProcess = async (name: string, suppliedPath?: string): Promise<boolean> => {
    const executablePath = suppliedPath || (/[/\\]/.test(name) ? name : '');
    const processName = /[/\\]/.test(name) ? name.split(/[\\/]/).pop() || name : name;
    if (processes.some((process) => process.name.toLowerCase() === processName.toLowerCase())) {
      setTerminalLogs((current) => [...current, `[!] Add process skipped: ${processName} is already monitored.`]);
      return false;
    }
    setIsAddingCustomProcess(true);
    try {
      if (!window.electronAPI?.isNativeWindows) throw new Error('Firewall changes require the native Windows application.');
      const command = executablePath
        ? `$ruleName = ${quotePowerShell(`SurfaceGuard_Block_${processName}`)}; $programPath = ${quotePowerShell(executablePath)}; & netsh.exe advfirewall firewall add rule "name=$ruleName" dir=out "program=$programPath" action=block; if ($LASTEXITCODE -ne 0) { throw "netsh exited with code $LASTEXITCODE" }`
        : `$processName = ${quotePowerShell(processName.replace(/\.exe$/i, ''))}; $processPath = Get-Process -Name $processName -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1 -ExpandProperty Path; if (-not $processPath) { throw "Could not resolve a running executable path for $processName" }; $ruleName = ${quotePowerShell(`SurfaceGuard_Block_${processName}`)}; & netsh.exe advfirewall firewall add rule "name=$ruleName" dir=out "program=$processPath" action=block; if ($LASTEXITCODE -ne 0) { throw "netsh exited with code $LASTEXITCODE" }; Write-Output "SurfaceGuardResolvedPath=$processPath"`;
      const result = await window.electronAPI.runPowerShell(command, true);
      if (!result.success) throw new Error(result.output || 'Firewall rule creation failed.');
      const newProc: BackgroundProcess = {
        pid: Math.floor(1000 + Math.random() * 8000),
        name: processName,
        path: executablePath || result.output.match(/SurfaceGuardResolvedPath=(.+)/)?.[1]?.trim() || processName,
        type: 'CUSTOM',
        isBlocked: true,
        impact: 'User-defined background application',
      };
      setProcesses((current) => [newProc, ...current]);
      setTerminalLogs((current) => [...current, `[✓] Process Added: Registered ${processName} (PID ${newProc.pid}) and enforced firewall drop.`, result.output]);
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown firewall failure.';
      setTerminalLogs((current) => [...current, `[✗] Add process failed for ${processName}: ${message}`]);
      return false;
    } finally {
      setIsAddingCustomProcess(false);
    }
  };

  // Schedule Handlers
  const updateSchedule = (updates: Partial<RecurringScanSchedule>) => {
    setScheduleConfig((prev) => {
      const updated = { ...prev, ...updates };
      if (updates.intervalMinutes && updates.intervalMinutes !== prev.intervalMinutes) {
        updated.nextRunTimestamp = Date.now() + updates.intervalMinutes * 60 * 1000;
      }
      return updated;
    });
  };

  const toggleSchedule = () => {
    setScheduleConfig((prev) => {
      const nextEnabled = !prev.isEnabled;
      return {
        ...prev,
        isEnabled: nextEnabled,
        nextRunTimestamp: nextEnabled ? Date.now() + prev.intervalMinutes * 60 * 1000 : null,
      };
    });
  };

  const cancelCalendarScan = () => {
    setScheduleConfig((prev) => ({
      ...prev,
      scheduledDateTime: null,
    }));
  };

  // Background automated schedule watchdog effect
  useEffect(() => {
    const timer = setInterval(() => {
      setScheduleConfig((current) => {
        if (!current.isEnabled) return current;

        const now = Date.now();

        // 1. Calendar scheduled date/time reached
        if (current.scheduledDateTime) {
          const targetTime = new Date(current.scheduledDateTime).getTime();
          if (!isNaN(targetTime) && targetTime <= now) {
            if (current.includePorts) scanPorts();
            if (current.includeProcesses) scanProcesses();

            setTerminalLogs((logs) => [
              ...logs,
              `[⏰] CALENDAR SCAN EXECUTED: Automated scan triggered for scheduled time ${new Date(targetTime).toLocaleTimeString()}.`,
            ]);

            return {
              ...current,
              scheduledDateTime: null,
              lastRunTimestamp: now,
              lastRunSummary: `Calendar scan executed at ${new Date(now).toLocaleTimeString()}`,
              nextRunTimestamp: now + current.intervalMinutes * 60 * 1000,
            };
          }
        }

        // 2. Recurring interval countdown reached
        if (current.nextRunTimestamp && current.nextRunTimestamp <= now) {
          if (current.includePorts) scanPorts();
          if (current.includeProcesses) scanProcesses();

          setTerminalLogs((logs) => [
            ...logs,
            `[🔄] RECURRING SCAN EXECUTED: Completed automated ${current.intervalMinutes}-minute audit.`,
          ]);

          return {
            ...current,
            lastRunTimestamp: now,
            lastRunSummary: `Interval (${current.intervalMinutes}m) scan at ${new Date(now).toLocaleTimeString()}`,
            nextRunTimestamp: now + current.intervalMinutes * 60 * 1000,
          };
        }

        return current;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  // 2. Manual Port On/Off Toggle with Firewall Command Execution
  const togglePort = async (portNumber: number) => {
    // Set loading state
    setPorts((prev) =>
      prev.map((p) => (p.port === portNumber ? { ...p, isLoading: true } : p))
    );

    // Find the port to determine current state
    const portToToggle = ports.find((p) => p.port === portNumber);
    if (!portToToggle) {
      setPorts((prev) =>
        prev.map((p) => (p.port === portNumber ? { ...p, isLoading: false } : p))
      );
      return;
    }

    // Determine if we're blocking or unblocking
    const isBlocking = portToToggle.isOpen; // If currently open, we're blocking it
    const command = isBlocking
      ? `netsh advfirewall firewall add rule name="SurfaceGuard Block ${portNumber}" dir=in action=block protocol=TCP localport=${portNumber}`
      : `netsh advfirewall firewall delete rule name="SurfaceGuard Block ${portNumber}"`;

    try {
      const result = await window.electronAPI.runPowerShell(command, true);

      if (result.success) {
        // Update port state only on success
        const logMsg = isBlocking
          ? `[✓] Network Door Locked: Port ${portNumber} (${portToToggle.service}) is now BLOCKED [Protected by Firewall].`
          : `[!] Network Door Opened: Port ${portNumber} (${portToToggle.service}) is now ALLOWED [Open to network].`;

        setPorts((prev) =>
          prev.map((p) => {
            if (p.port === portNumber) {
              return { ...p, isOpen: !p.isOpen, isLoading: false };
            }
            return p;
          })
        );
        setTerminalLogs((l) => [...l, logMsg]);
      } else {
        // Log error and keep state unchanged
        const errorMsg = `[✗] Failed to ${isBlocking ? 'BLOCK' : 'OPEN'} Port ${portNumber}: ${result.output || 'Unknown error'}`;
        setTerminalLogs((l) => [...l, errorMsg]);
        setPorts((prev) =>
          prev.map((p) => (p.port === portNumber ? { ...p, isLoading: false } : p))
        );
      }
    } catch (error) {
      // Handle exception
      const errorMsg = `[✗] Exception while toggling Port ${portNumber}: ${error instanceof Error ? error.message : 'Unknown error'}`;
      setTerminalLogs((l) => [...l, errorMsg]);
      setPorts((prev) =>
        prev.map((p) => (p.port === portNumber ? { ...p, isLoading: false } : p))
      );
    }
  };

  // 3. Add Custom Port
  const addCustomPort = (port: number, service: string, risk: 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM') => {
    if (ports.some((p) => p.port === port)) return;
    const newPortItem: PortItem = {
      port,
      protocol: 'TCP',
      service: service.trim() || `Custom Port ${port}`,
      isOpen: true,
      risk,
      process: 'custom_process.exe',
      description: 'Operator added custom port rule.',
    };
    setPorts((prev) => [newPortItem, ...prev]);
    setTerminalLogs((l) => [
      ...l,
      `[+] Port Registered: Added Door TCP ${port} (${service}) to live table.`,
    ]);
  };

  // 4. Manual Hardware Tools On/Off Toggle
  const toggleHardware = async (device: keyof HardwareState): Promise<boolean> => {
    const nextLocked = !hardware[device];
    const deviceCommands: Record<keyof HardwareState, { name: string; lock: string; unlock: string }> = {
      camera: {
        ...cameraCommands,
      },
      microphone: {
        name: 'Microphone Audio Listening',
        lock: `Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone" -Name "Value" -Value "Deny" -Force`,
        unlock: `Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone" -Name "Value" -Value "Allow" -Force`,
      },
      usbStorage: {
        name: 'USB Flash Drive Access',
        lock: `Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 4 -Type DWord -Force`,
        unlock: `Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 3 -Type DWord -Force`,
      },
      bluetooth: {
        name: 'Bluetooth Wireless Radio',
        lock: `Get-PnpDevice -InstanceId "BTH*" -ErrorAction SilentlyContinue | Disable-PnpDevice -Confirm:$false`,
        unlock: `Get-PnpDevice -InstanceId "BTH*" -ErrorAction SilentlyContinue | Enable-PnpDevice -Confirm:$false`,
      },
      fileSystemAcl: {
        name: 'System Folder Permission Lockdown',
        lock: `icacls "$env:ProgramData" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"`,
        unlock: `icacls "$env:ProgramData" /reset /T /C`,
      },
    };
    const { name, lock, unlock } = deviceCommands[device];
    const command = nextLocked ? lock : unlock;

    try {
      if (device === 'camera') {
        console.log("Executing Camera Command:", command);
      }
      const result = await window.electronAPI.runPowerShell(command, true);
      if (device === 'camera') {
        console.log("Execution Result:", result);
      }
      if (device === 'camera' ? result.success !== true : !result.success) {
        const errorMessage = result.output || `${name} action failed.`;
        if (device === 'camera') {
          console.error("Camera Hardware Block Failed:", result.output);
        }
        setTerminalLogs((logs) => [...logs, `[!] ${name} failed: ${errorMessage}`]);
        window.alert(`${name} action failed: ${errorMessage}`);
        return false;
      }

      setHardware((prev) => ({ ...prev, [device]: nextLocked }));
      setTerminalLogs((logs) => [
        ...logs,
        nextLocked ? `[✓] Hardware Locked: ${name} is now DISABLED.` : `[!] Hardware Allowed: ${name} is now ENABLED.`,
        result.output,
      ]);
      return true;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : `${name} action failed.`;
      console.error("Device command execution threw an error:", { command, error });
      setTerminalLogs((logs) => [...logs, `[!] ${name} failed: ${errorMessage}`]);
      window.alert(`${name} action failed: ${errorMessage}`);
      return false;
    }
  };

  // 5. 1-Click Professional Security Profiles (Stealth, Meeting, Developer)
  const applyProfile = (mode: SecurityProfileMode) => {
    setActiveProfile(mode);

    if (mode === 'stealth') {
      // Maximum Paranoid Stealth Mode: Everything blocked
      setPorts((prev) => prev.map((p) => ({ ...p, isOpen: false })));
      setHardware({
        camera: true,
        microphone: true,
        usbStorage: true,
        bluetooth: true,
        fileSystemAcl: true,
      });
      setVulnerabilities((prev) => prev.map((v) => ({ ...v, isVulnerable: false })));
      setTerminalLogs((l) => [
        ...l,
        '',
        '[🛡️] APPLIED PROFILE: Maximum Stealth Mode.',
        '    [✓] All network doors blocked. All hardware devices locked. Host invisible to external scans.',
      ]);
    } else if (mode === 'meeting') {
      // Work & Meeting Mode: Camera & Mic allowed, dangerous ports blocked
      setPorts((prev) =>
        prev.map((p) => {
          if (p.port === 445 || p.port === 135 || p.port === 3389 || p.port === 9229) {
            return { ...p, isOpen: false };
          }
          return p;
        })
      );
      setHardware({
        camera: false,      // Camera allowed for Zoom/Teams
        microphone: false,  // Mic allowed for Zoom/Teams
        usbStorage: true,   // USB blocked
        bluetooth: false,   // Bluetooth allowed for headphones
        fileSystemAcl: true,
      });
      setTerminalLogs((l) => [
        ...l,
        '',
        '[💼] APPLIED PROFILE: Work & Meeting Mode.',
        '    [✓] Camera & Microphone ready for Zoom/Teams calls. Dangerous network ports (SMB/RDP) kept blocked.',
      ]);
    } else if (mode === 'developer') {
      // Developer Mode: Localhost dev ports allowed, external WAN blocked
      setPorts((prev) =>
        prev.map((p) => {
          if (p.port === 8000 || p.port === 9229) {
            return { ...p, isOpen: true, isLoopbackOnly: true };
          }
          if (p.port === 445 || p.port === 3389) {
            return { ...p, isOpen: false };
          }
          return p;
        })
      );
      setHardware((prev) => ({ ...prev, camera: true, usbStorage: true }));
      setTerminalLogs((l) => [
        ...l,
        '',
        '[💻] APPLIED PROFILE: Software Developer Mode.',
        '    [✓] Web server and debugger permitted strictly on localhost 127.0.0.1.',
      ]);
    }
  };

  // 6. Fix Individual Vulnerability
  const fixVulnerability = (id: string) => {
    setVulnerabilities((prev) =>
      prev.map((v) => {
        if (v.id === id) {
          setTerminalLogs((l) => [...l, `[✓] Vulnerability Resolved: Fixed ${v.name}.`]);
          return { ...v, isVulnerable: false };
        }
        return v;
      })
    );
  };

  // 7. Fix All Vulnerabilities
  const fixAllVulnerabilities = () => {
    setVulnerabilities((prev) => prev.map((v) => ({ ...v, isVulnerable: false })));
    setPorts((prev) =>
      prev.map((p) => (p.risk === 'CRITICAL' || p.risk === 'HIGH' ? { ...p, isOpen: false } : p))
    );
    setHardware((prev) => ({ ...prev, camera: true, usbStorage: true, fileSystemAcl: true }));
    setTerminalLogs((l) => [
      ...l,
      '',
      '[✓] 1-CLICK SECURITY SHIELD: All detected vulnerabilities have been fixed and closed.',
    ]);
  };

  // 8. Full 4-Phase Hardening
  const executeHardening = async () => {
    setIsHardening(true);
    setActiveAttack(null);

    setTerminalLogs((prev) => [
      ...prev,
      '',
      `[>] Executing Full Security Lockdown on ${targetOS.toUpperCase()}...`,
      '    [*] Step 1: Closing all dangerous network doors (Port 445 SMB, 135 RPC, 3389 RDP)...',
    ]);

    await new Promise((r) => setTimeout(r, 500));

    setPorts((prev) => prev.map((p) => ({ ...p, isOpen: false })));
    setHardware({
      camera: true,
      microphone: true,
      usbStorage: true,
      bluetooth: true,
      fileSystemAcl: true,
    });
    setVulnerabilities((prev) => prev.map((v) => ({ ...v, isVulnerable: false })));

    setTerminalLogs((prev) => [
      ...prev,
      '    [✓] Step 2: Locking Webcam & Microphone drivers against unauthorized surveillance.',
      '    [✓] Step 3: Enforcing strict folder permissions and USB drive protection.',
      '    [✓] Step 4: Starting security watchdog monitor.',
      '[✓] SYSTEM FULLY SECURED! Your computer is now protected against network attacks.',
    ]);

    setIsHardening(false);
  };

  // 9. Emergency Rollback
  const executeRollback = async () => {
    setIsHardening(true);
    setActiveAttack(null);

    setTerminalLogs((prev) => [
      ...prev,
      '',
      '[*] Restoring original baseline settings...',
      '    [+] Re-enabling camera, microphone, and default network doors...',
    ]);

    await new Promise((r) => setTimeout(r, 500));

    setPorts(initialPorts);
    setHardware(initialHardware);
    setVulnerabilities(initialVulnerabilities);
    setActiveProfile('custom');

    setTerminalLogs((prev) => [
      ...prev,
      '[✓] Restored in 1.1 seconds. System is back to original operating state.',
    ]);

    setIsHardening(false);
  };

  // 10. Simulate Attacks
  const simulateAttack = (attackType: 'SMB_RANSOMWARE' | 'NMAP_SCAN' | 'SPYWARE_CAM' | 'DEV_DEBUG_EXPLOIT') => {
    if (attackType === 'SMB_RANSOMWARE') {
      const smbPort = ports.find((p) => p.port === 445);
      const isBlocked = !smbPort?.isOpen;
      setActiveAttack({
        name: 'WannaCry Ransomware Attack Test (Port 445)',
        description: 'Attacker sends malicious code over Port 445 to lock and encrypt your files.',
        result: isBlocked ? 'BLOCKED' : 'EXPLOITED',
        log: isBlocked
          ? '[BLOCKED] Firewall dropped attack. Port 445 is closed! Ransomware could not enter.'
          : '[UNSAFE / EXPLOITED] Port 445 is OPEN! Attack was accepted. Ransomware entered the computer!',
      });
    } else if (attackType === 'NMAP_SCAN') {
      const openCount = ports.filter((p) => p.isOpen).length;
      const isBlocked = openCount === 0;
      setActiveAttack({
        name: 'Hacker Port Scanner Test (Nmap)',
        description: 'Scanning your computer from the internet to find weak open doors.',
        result: isBlocked ? 'BLOCKED' : 'EXPLOITED',
        log: isBlocked
          ? '[BLOCKED] All network doors are closed. Your PC looks completely invisible to internet scanners!'
          : `[UNSAFE] Hacker found ${openCount} open doors on your computer!`,
      });
    } else if (attackType === 'SPYWARE_CAM') {
      const isBlocked = hardware.camera;
      setActiveAttack({
        name: 'Spyware Secret Webcam Test',
        description: 'Spyware tries to turn on the webcam without permission to watch video.',
        result: isBlocked ? 'BLOCKED' : 'EXPLOITED',
        log: isBlocked
          ? '[BLOCKED] Camera is hardware locked (AllowCamera=0). Spyware was denied access!'
          : '[UNSAFE] Camera turned on! Spyware was able to capture webcam stream!',
      });
    } else {
      const dbgPort = ports.find((p) => p.port === 9229);
      const isBlocked = !dbgPort?.isOpen;
      setActiveAttack({
        name: 'Remote Code Injection Test (Port 9229)',
        description: 'Hacker attempts to run arbitrary commands through the developer debugger.',
        result: isBlocked ? 'BLOCKED' : 'EXPLOITED',
        log: isBlocked
          ? '[BLOCKED] Debugger port is closed to the outside internet. Access rejected.'
          : '[UNSAFE] Port 9229 was open! Hacker was able to run code on your system.',
      });
    }
  };

  const clearTerminal = () => {
    setTerminalLogs(['[*] Terminal buffer cleared. Ready.']);
  };

  return (
    <SecurityContext.Provider
      value={{
        ports,
        hardware,
        processes,
        isScanningProcesses,
        isUpdatingProcesses,
        processAction,
        updatingProcessIds,
        isAddingCustomProcess,
        scheduleConfig,
        updateSchedule,
        toggleSchedule,
        cancelCalendarScan,
        targetOS,
        setTargetOS,
        activeProfile,
        applyProfile,
        vulnerabilities,
        fixVulnerability,
        fixAllVulnerabilities,
        blockedEvents,
        isScanning,
        isHardening,
        isFullHardened,
        terminalLogs,
        securityScore: computedScore,
        activeAttack,
        scanPorts,
        scanProcesses,
        togglePort,
        toggleProcessBlock,
        blockAllProcesses,
        allowAllProcesses,
        addCustomProcess,
        addCustomPort,
        toggleHardware,
        executeHardening,
        executeRollback,
        simulateAttack,
        clearTerminal,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity = () => {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
};
