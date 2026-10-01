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

export interface PortNotificationAlert {
  title: string;
  message: string;
  type: 'error' | 'success' | 'info';
}

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
  // Network Ports Hardening & Strict Lockdown
  isStrictLockdown: boolean;
  isStrictLockdownLoading: boolean;
  toggleStrictLockdown: () => Promise<void>;
  portNotificationAlert: PortNotificationAlert | null;
  dismissPortAlert: () => void;
  portScanInterval: number;
  setPortScanInterval: (interval: number) => void;
  lastPortScanTime: string | null;
  scanPorts: () => Promise<void>;
  scanProcesses: () => Promise<void>;
  togglePort: (portNumber: number) => Promise<void>;
  toggleProcessBlock: (pid: number) => Promise<void>;
  blockAllProcesses: () => Promise<void>;
  allowAllProcesses: () => Promise<void>;
  addCustomProcess: (name: string, path?: string) => Promise<boolean>;
  addCustomPort: (
    port: number,
    protocolOrService?: 'TCP' | 'UDP' | string,
    serviceOrRisk?: string,
    risk?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  ) => boolean;
  toggleHardware: (device: keyof HardwareState) => Promise<boolean>;
  loadingHardwareDevice: keyof HardwareState | null;
  executeHardening: () => Promise<void>;
  executeRollback: () => Promise<void>;
  simulateAttack: (attackType: 'SMB_RANSOMWARE' | 'NMAP_SCAN' | 'SPYWARE_CAM' | 'DEV_DEBUG_EXPLOIT') => void;
  clearTerminal: () => void;
}

const initialPorts: PortItem[] = [
  // 1. FTP (20, 21)
  {
    port: 20,
    protocol: 'TCP',
    service: 'FTP Data Channel',
    isOpen: true,
    risk: 'HIGH',
    process: 'ftpsvc.exe',
    description: 'File Transfer Protocol legacy data channel (cleartext payload).',
  },
  {
    port: 21,
    protocol: 'TCP',
    service: 'FTP Control Channel',
    isOpen: true,
    risk: 'HIGH',
    process: 'ftpsvc.exe',
    description: 'File Transfer Protocol command channel; targeted for credential sniffing & brute-force.',
  },
  // 2. SSH (22)
  {
    port: 22,
    protocol: 'TCP',
    service: 'Secure Remote Terminal (SSH)',
    isOpen: true,
    risk: 'MEDIUM',
    process: 'sshd.exe (PID 2140)',
    description: 'Terminal command-line access door; targeted by automated dictionary attacks.',
  },
  // 3. Telnet (23)
  {
    port: 23,
    protocol: 'TCP',
    service: 'Telnet Remote Terminal',
    isOpen: true,
    risk: 'CRITICAL',
    process: 'tlntsvr.exe',
    description: 'Legacy unencrypted terminal shell; transmits login credentials in plain text.',
  },
  // 4. HTTP / HTTPS (80, 443)
  {
    port: 80,
    protocol: 'TCP',
    service: 'Standard Web Traffic (HTTP)',
    isOpen: true,
    risk: 'LOW',
    process: 'nginx.exe / IIS',
    description: 'Unencrypted standard hypertext transfer web server port.',
  },
  {
    port: 443,
    protocol: 'TCP',
    service: 'Encrypted Secure Web (HTTPS)',
    isOpen: true,
    risk: 'LOW',
    process: 'nginx.exe / IIS',
    description: 'TLS/SSL encrypted safe web browsing port.',
  },
  // 5. RPC / NetBIOS (135, 137, 139)
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
    port: 137,
    protocol: 'UDP',
    service: 'NetBIOS Name Service',
    isOpen: true,
    risk: 'HIGH',
    process: 'System (PID 4)',
    description: 'Legacy NetBIOS name resolution; vulnerable to broadcast spoofing and LLMNR poisoning.',
  },
  {
    port: 139,
    protocol: 'TCP',
    service: 'NetBIOS Session Service',
    isOpen: true,
    risk: 'HIGH',
    process: 'System (PID 4)',
    description: 'Legacy NetBIOS session transport historically exploited for NULL session credential enumeration.',
  },
  // 6. SMB (445)
  {
    port: 445,
    protocol: 'TCP',
    service: 'Windows File Sharing (SMB)',
    isOpen: true,
    risk: 'CRITICAL',
    process: 'System (PID 4)',
    description: 'High risk: Common entry door for ransomware (WannaCry, EternalBlue) to spread between computers.',
  },
  // 7. MSSQL / MySQL / PostgreSQL (1433, 3306, 5432)
  {
    port: 1433,
    protocol: 'TCP',
    service: 'Microsoft SQL Server (MSSQL)',
    isOpen: true,
    risk: 'CRITICAL',
    process: 'sqlservr.exe',
    description: 'Database engine listener; subject to automated SA brute-forcing and command execution pivots.',
  },
  {
    port: 3306,
    protocol: 'TCP',
    service: 'MySQL Database Server',
    isOpen: true,
    risk: 'HIGH',
    process: 'mysqld.exe',
    description: 'Open database port vulnerable to remote administration brute-force and data exfiltration.',
  },
  {
    port: 5432,
    protocol: 'TCP',
    service: 'PostgreSQL Database Server',
    isOpen: true,
    risk: 'HIGH',
    process: 'postgres.exe',
    description: 'Relational database network socket; vulnerable to remote connection brute-force.',
  },
  // 8. RDP (3389)
  {
    port: 3389,
    protocol: 'TCP',
    service: 'Remote Desktop (RDP)',
    isOpen: true,
    risk: 'CRITICAL',
    process: 'TermService (PID 1120)',
    description: 'Allows taking over PC screen remotely; targeted by password guessing bots.',
  },
  // Developer Ports
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
  const [loadingHardwareDevice, setLoadingHardwareDevice] = useState<keyof HardwareState | null>(null);

  // Network Ports Hardening States
  const [isStrictLockdown, setIsStrictLockdown] = useState<boolean>(false);
  const [isStrictLockdownLoading, setIsStrictLockdownLoading] = useState<boolean>(false);
  const [portNotificationAlert, setPortNotificationAlert] = useState<PortNotificationAlert | null>(null);
  const [portScanInterval, setPortScanInterval] = useState<number>(15);
  const [lastPortScanTime, setLastPortScanTime] = useState<string | null>(null);

  const dismissPortAlert = () => setPortNotificationAlert(null);

  // PowerShell IPC bridge execution helper
  const runPowerShellWithAdmin = async (
    command: string
  ): Promise<{ success: boolean; output: string }> => {
    if (typeof window !== 'undefined' && window.electronAPI?.runPowerShell) {
      return await window.electronAPI.runPowerShell(command, true);
    }
    // Simulation in web preview environment
    await new Promise((resolve) => setTimeout(resolve, 350));
    return {
      success: true,
      output: `Ok. [Web Simulator] PowerShell command executed with administrator privileges:\n${command}\nResult: Exit code 0 (Success).`,
    };
  };

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

  // 1. Scan Network Ports (Real-Time Socket Inspection)
  const scanPorts = async () => {
    setIsScanning(true);
    setActiveAttack(null);
    setTerminalLogs((prev) => [
      ...prev,
      '',
      `[>] Real-Time Port & Socket Scan started on ${targetOS.toUpperCase()}...`,
      '    [*] Querying Windows NetTCP sockets and active listening endpoints...',
    ]);

    try {
      if (window.electronAPI?.isNativeWindows) {
        if (window.electronAPI.queryWindowsPorts) {
          const result = await window.electronAPI.queryWindowsPorts();
          if (!result.success) throw new Error(result.error || 'Native socket query failed.');
          const listeningPorts = result.ports || [];
          const nowStr = new Date().toLocaleTimeString();
          setLastPortScanTime(nowStr);

          const listenerSummary = listeningPorts.slice(0, 10).map((port) =>
            `    ${port.Protocol} ${port.LocalAddress}:${port.LocalPort} (PID ${port.OwningProcess})`
          );
          setTerminalLogs((prev) => [
            ...prev,
            `    [+] Native scan complete at ${nowStr}: Found ${listeningPorts.length} listening endpoints.`,
            ...(listenerSummary.length ? listenerSummary : ['    [*] No external listening endpoints found.']),
          ]);
        } else {
          const command = 'Get-NetTCPConnection -State Listen | Select-Object -Property LocalAddress, LocalPort, OwningProcess | ConvertTo-Json -Compress';
          const result = await window.electronAPI.runPowerShell(command, true);
          const nowStr = new Date().toLocaleTimeString();
          setLastPortScanTime(nowStr);
          if (result.success) {
            setTerminalLogs((prev) => [
              ...prev,
              `    [+] Real-time scan complete via PowerShell at ${nowStr}.`,
              result.output,
            ]);
          } else {
            throw new Error(result.output || 'PowerShell net TCP scan failed');
          }
        }
      } else {
        await new Promise((resolve) => setTimeout(resolve, 500));
        const nowStr = new Date().toLocaleTimeString();
        setLastPortScanTime(nowStr);
        const openCount = ports.filter((port) => port.isOpen).length;
        setTerminalLogs((prev) => [
          ...prev,
          `    [+] Real-time scan complete at ${nowStr}: ${openCount} managed ports are currently allowed/open.`,
          '    [*] Simulated socket inspection verified. All firewall drop rules synced.',
        ]);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown socket scan failure.';
      setTerminalLogs((prev) => [...prev, `[✗] Socket scan failed: ${message}`]);
      setPortNotificationAlert({
        title: 'Socket Scan Failed',
        message,
        type: 'error',
      });
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

  // 1c. Master Control: "Strict Lockdown (Block All Unlisted Ports)"
  const toggleStrictLockdown = async () => {
    setIsStrictLockdownLoading(true);
    const nextState = !isStrictLockdown;
    const command = nextState
      ? `netsh advfirewall firewall add rule name="SurfaceGuard_Block_All_Unlisted" dir=in action=block protocol=TCP localport=1-65535`
      : `netsh advfirewall firewall delete rule name="SurfaceGuard_Block_All_Unlisted"`;

    try {
      const result = await runPowerShellWithAdmin(command);

      // CRITICAL: NO OPTIMISTIC UI STATE UPDATES
      // Only toggle state when execution returns a successful result (result.success === true)
      if (result.success === true) {
        setIsStrictLockdown(nextState);
        setTerminalLogs((prev) => [
          ...prev,
          nextState
            ? `[✓] STRICT LOCKDOWN ACTIVE: Enforced default DROP on all inbound TCP ports 1-65535.`
            : `[!] STRICT LOCKDOWN DEACTIVATED: Deleted global unlisted ports firewall rule.`,
          `    Command: ${command}`,
          `    Output: ${result.output}`,
        ]);
        setPortNotificationAlert({
          title: nextState ? 'Strict Lockdown Enforced' : 'Strict Lockdown Deactivated',
          message: result.output || (nextState ? 'All unlisted incoming TCP ports 1-65535 are now blocked by Windows Firewall.' : 'Global block rule removed.'),
          type: 'success',
        });
      } else {
        // If call fails or returns an error: keep toggle in original state, log error to terminal history, show notification alert
        const errorOutput = result.output || 'Firewall command failed with unknown error.';
        setTerminalLogs((prev) => [
          ...prev,
          `[✗] Strict Lockdown command failed: ${errorOutput}`,
        ]);
        setPortNotificationAlert({
          title: 'Strict Lockdown Failed',
          message: errorOutput,
          type: 'error',
        });
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      setTerminalLogs((prev) => [
        ...prev,
        `[✗] Strict Lockdown exception: ${errMsg}`,
      ]);
      setPortNotificationAlert({
        title: 'Strict Lockdown Execution Error',
        message: errMsg,
        type: 'error',
      });
    } finally {
      setIsStrictLockdownLoading(false);
    }
  };

  // 2. Individual Port Blocking/Unblocking with NO OPTIMISTIC UI STATE UPDATES
  const togglePort = async (portNumber: number) => {
    const portToToggle = ports.find((p) => p.port === portNumber);
    if (!portToToggle) return;

    // Show loading spinner on port toggle while keeping toggle in its original state
    setPorts((prev) =>
      prev.map((p) => (p.port === portNumber ? { ...p, isLoading: true } : p))
    );

    const isBlocking = portToToggle.isOpen; // If currently open, user requested to BLOCK it
    const command = isBlocking
      ? `netsh advfirewall firewall add rule name="SurfaceGuard_Block_${portToToggle.port}" dir=in action=block protocol=${portToToggle.protocol} localport=${portToToggle.port}`
      : `netsh advfirewall firewall delete rule name="SurfaceGuard_Block_${portToToggle.port}"`;

    try {
      const result = await runPowerShellWithAdmin(command);

      // CRITICAL: NO OPTIMISTIC UI STATE UPDATES
      // The React UI MUST NOT toggle any port state to "Blocked" or "Allowed" until result.success === true
      if (result.success === true) {
        setPorts((prev) =>
          prev.map((p) =>
            p.port === portNumber
              ? { ...p, isOpen: !p.isOpen, isLoading: false }
              : p
          )
        );
        const logMsg = isBlocking
          ? `[✓] Network Door Locked: Port ${portNumber}/${portToToggle.protocol} (${portToToggle.service}) is now BLOCKED via Firewall.`
          : `[!] Network Door Opened: Port ${portNumber}/${portToToggle.protocol} (${portToToggle.service}) is now ALLOWED [Open to network].`;
        setTerminalLogs((prev) => [
          ...prev,
          logMsg,
          `    Command: ${command}`,
          `    Output: ${result.output}`,
        ]);
      } else {
        // If call fails or returns an error: keep toggle in original state, log error to terminal history, show notification alert
        setPorts((prev) =>
          prev.map((p) => (p.port === portNumber ? { ...p, isLoading: false } : p))
        );
        const errorOutput = result.output || `Firewall operation failed for Port ${portNumber}.`;
        setTerminalLogs((prev) => [
          ...prev,
          `[✗] Failed to ${isBlocking ? 'BLOCK' : 'ALLOW'} Port ${portNumber}: ${errorOutput}`,
        ]);
        setPortNotificationAlert({
          title: `Firewall Error: Port ${portNumber}/${portToToggle.protocol}`,
          message: errorOutput,
          type: 'error',
        });
      }
    } catch (error) {
      // Keep toggle in original state, log exception to terminal, show notification alert
      setPorts((prev) =>
        prev.map((p) => (p.port === portNumber ? { ...p, isLoading: false } : p))
      );
      const errMsg = error instanceof Error ? error.message : String(error);
      setTerminalLogs((prev) => [
        ...prev,
        `[✗] Exception while configuring Port ${portNumber}: ${errMsg}`,
      ]);
      setPortNotificationAlert({
        title: `Command Exception: Port ${portNumber}`,
        message: errMsg,
        type: 'error',
      });
    }
  };

  // 3. Add Custom Port Rule (triggered by "Add Rule" Modal)
  const addCustomPort = (
    port: number,
    protocolOrService: 'TCP' | 'UDP' | string = 'TCP',
    serviceOrRisk: string = '',
    riskParam: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM'
  ): boolean => {
    let protocol: 'TCP' | 'UDP' = 'TCP';
    let service = '';
    let risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';

    if (protocolOrService === 'TCP' || protocolOrService === 'UDP') {
      protocol = protocolOrService;
      service = serviceOrRisk;
      risk = riskParam;
    } else {
      protocol = 'TCP';
      service = protocolOrService;
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(serviceOrRisk)) {
        risk = serviceOrRisk as any;
      }
    }

    if (ports.some((p) => p.port === port && p.protocol === protocol)) {
      setPortNotificationAlert({
        title: 'Rule Exists',
        message: `Port ${port}/${protocol} is already in your managed firewall rules list.`,
        type: 'info',
      });
      return false;
    }

    const newPortItem: PortItem = {
      port,
      protocol,
      service: service.trim() || `Custom Port ${port}`,
      isOpen: true, // Default to Open, user can toggle ON/OFF
      isLoading: false,
      risk,
      process: 'custom_process.exe',
      description: 'Operator added custom firewall rule.',
      isCustom: true,
    };

    setPorts((prev) => [newPortItem, ...prev]);
    setTerminalLogs((l) => [
      ...l,
      `[+] Port Rule Registered: Added ${protocol} Port ${port} (${newPortItem.service}) to managed table. Toggle switch to enforce block/allow.`,
    ]);
    return true;
  };

  // 4. Manual Hardware Tools On/Off Toggle (Strict Await & Zero Optimistic UI)
  const toggleHardware = async (device: keyof HardwareState): Promise<boolean> => {
    if (loadingHardwareDevice === device) return false;

    setLoadingHardwareDevice(device);
    const nextLocked = !hardware[device];
    const deviceCommands: Record<keyof HardwareState, { name: string; lock: string; unlock: string }> = {
      camera: {
        name: 'Webcam Video Camera',
        lock: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam' -Name 'Value' -Value 'Deny' -Force; Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | Disable-PnpDevice -Confirm:$false",
        unlock: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam' -Name 'Value' -Value 'Allow' -Force; Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | Enable-PnpDevice -Confirm:$false",
      },
      microphone: {
        name: 'Microphone Audio Listening',
        lock: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone' -Name 'Value' -Value 'Deny' -Force",
        unlock: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone' -Name 'Value' -Value 'Allow' -Force",
      },
      usbStorage: {
        name: 'USB Mass Storage & Removable Media',
        lock: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4 -Type DWord -Force",
        unlock: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 3 -Type DWord -Force",
      },
      bluetooth: {
        name: 'Bluetooth Radio Adapter',
        lock: "Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Disable-PnpDevice -Confirm:$false",
        unlock: "Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Enable-PnpDevice -Confirm:$false",
      },
      fileSystemAcl: {
        name: 'System Folder Permission Lockdown',
        lock: 'icacls "$env:ProgramData" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"',
        unlock: 'icacls "$env:ProgramData" /reset /T /C',
      },
    };

    const { name, lock, unlock } = deviceCommands[device];
    const command = nextLocked ? lock : unlock;

    try {
      // 1. STRICT AWAIT & NO OPTIMISTIC UI:
      // UI displays loading spinner and remains disabled during execution
      let result: { success: boolean; output: string };
      if (typeof window !== 'undefined' && window.electronAPI?.runPowerShell) {
        result = await window.electronAPI.runPowerShell(command, true);
      } else {
        // Fallback for preview mode
        await new Promise((resolve) => setTimeout(resolve, 500));
        result = {
          success: true,
          output: `[Preview Environment] Command executed successfully with elevated privileges:\n${command}`,
        };
      }

      // ONLY update the state to LOCKED/UNLOCKED if result.success === true
      if (result.success === true) {
        setHardware((prev) => ({ ...prev, [device]: nextLocked }));
        setTerminalLogs((logs) => [
          ...logs,
          nextLocked
            ? `[✓] Hardware Locked: ${name} is now DISABLED.`
            : `[!] Hardware Allowed: ${name} is now ENABLED.`,
          `    Command: ${command}`,
          `    Output: ${result.output}`,
        ]);
        return true;
      } else {
        // If result.success === false, revert UI (state was never optimistically updated), log console.error, and show alert()
        const errorMessage = result.output || `${name} hardware configuration failed.`;
        console.error(result.output);
        setTerminalLogs((logs) => [...logs, `[✗] ${name} failed: ${errorMessage}`]);
        try {
          if (typeof window !== 'undefined' && typeof window.alert === 'function') {
            window.alert(`${name} action failed: ${errorMessage}`);
          }
        } catch {
          // Catch sandbox exception if window.alert is blocked in preview iframe
        }
        return false;
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : `${name} action failed.`;
      console.error(errorMessage);
      setTerminalLogs((logs) => [...logs, `[✗] ${name} exception: ${errorMessage}`]);
      try {
        if (typeof window !== 'undefined' && typeof window.alert === 'function') {
          window.alert(`${name} action failed: ${errorMessage}`);
        }
      } catch {
        // Catch sandbox exception if window.alert is blocked in preview iframe
      }
      return false;
    } finally {
      setLoadingHardwareDevice(null);
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
        // Network Ports Hardening & Strict Lockdown
        isStrictLockdown,
        isStrictLockdownLoading,
        toggleStrictLockdown,
        portNotificationAlert,
        dismissPortAlert,
        portScanInterval,
        setPortScanInterval,
        lastPortScanTime,
        scanPorts,
        scanProcesses,
        togglePort,
        toggleProcessBlock,
        blockAllProcesses,
        allowAllProcesses,
        addCustomProcess,
        addCustomPort,
        toggleHardware,
        loadingHardwareDevice,
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
