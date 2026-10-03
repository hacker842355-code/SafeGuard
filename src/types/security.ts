export type ComponentCategory = 'network' | 'hardware' | 'filesystem' | 'pam' | 'crossplatform';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type OperatingSystem = 'all' | 'windows' | 'linux' | 'macos';

export interface ThreatItem {
  id: string; // e.g. A1, A2, B1, P2, W1, etc.
  code: string; // e.g. FIN-001
  title: string;
  component: ComponentCategory;
  componentName: string;
  osScope: OperatingSystem[];
  description: string;
  attackVector: string;
  impactLevel: 1 | 2 | 3 | 4; // 1-4
  likelihoodLevel: 1 | 2 | 3 | 4; // 1-4
  riskScore: number; // Impact x Likelihood (1-16)
  severity: SeverityLevel;
  currentMitigation: string;
  gapAnalysis: string;
  improvedDefense: string[];
  remediationTimeline: string;
  remediationEffort: string;
  owner: string;
  phase: number;
}

export interface PlatformThreat {
  id: string;
  platform: 'windows' | 'linux' | 'macos' | 'abstraction';
  platformName: string;
  title: string;
  description: string;
  vector: string;
  attackScenario: string;
  mitigations: string[];
  nativeApi: string;
  fallbackRisk: string;
}

export interface ZeroTrustPrinciple {
  id: string;
  number: 1 | 2 | 3 | 4;
  title: string;
  tagline: string;
  percentImplemented: number;
  implemented: string[];
  notImplemented: string[];
  recommendations: string[];
}

export interface TemporaryAppLease {
  id: string; // 'zoom', 'teams', 'meet', 'scanner', 'audio', 'vite', 'debugger', 'ssh', 'rdp', 'smb', 'custom'
  appName: string;
  shortName: string;
  resourceType: 'CONFERENCE' | 'CAMERA' | 'MIC' | 'PORT';
  underlyingResource: string;
  totalSeconds: number;
  remainingSeconds: number;
  justification: string;
  startedAt: string;
  expiresAt: string;
  portsUnlocked?: number[];
  devicesUnlocked?: (keyof HardwareState)[];
}

export interface PamRequestLog {
  id: string;
  timestamp: string;
  actor: string;
  actionType: 'PORT_OPEN' | 'PORT_CLOSE' | 'CAMERA_ENABLE' | 'CAMERA_DISABLE' | 'MIC_ENABLE' | 'MIC_DISABLE';
  target: string;
  durationMinutes: number;
  expiresAt: string;
  justification: string;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'BLOCKED_SUSPICIOUS';
  cryptoSignature: string;
  threatWarning?: string;
}

export interface HardeningConfig {
  targetOs: 'windows' | 'linux' | 'macos';
  strictAtomic: boolean;
  dryRunMode: boolean;
  allowDevPorts: boolean;
  devPorts: number[];
  videoConfProfile: boolean;
  watchdogDaemon: boolean;
  autoRollbackOnError: boolean;
  lockdownCamera: boolean;
  lockdownMicrophone: boolean;
  tightenFileSystem: boolean;
  closeUnusedPorts: boolean;
}

export interface PortItem {
  port: number;
  protocol: 'TCP' | 'UDP';
  service: string;
  isOpen: boolean; // true = OPEN (listening), false = CLOSED (blocked/dropped)
  isLoopbackOnly?: boolean;
  isLoading?: boolean; // true = firewall command in progress
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  process: string;
  description: string;
  isCustom?: boolean;
}

export interface HardwareState {
  camera: boolean; // true = LOCKED/PROTECTED, false = UNPROTECTED/PERMISSIVE
  microphone: boolean;
  usbStorage: boolean;
  bluetooth: boolean;
  fileSystemAcl: boolean;
}

export type SecurityProfileMode = 'stealth' | 'corporate' | 'home' | 'meeting' | 'developer' | 'reset' | 'custom';

export interface VulnerabilityAuditItem {
  id: string;
  name: string;
  simpleExplanation: string;
  riskSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  isVulnerable: boolean;
  fixedActionDescription: string;
}

export interface BlockedTrafficEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  targetPort: number;
  serviceName: string;
  actionTaken: 'BLOCKED_DROP';
  threatType: string;
}

export interface BackgroundProcess {
  pid: number;
  name: string;
  path: string;
  type: 'TELEMETRY' | 'UPDATER' | 'SYSTEM' | 'CUSTOM';
  isBlocked: boolean; // true = Blocked, false = Allowed
  impact: string;
  company?: string;
  description?: string;
  hasActiveSocket?: boolean;
  socketInfo?: string;
}

export interface RecurringScanSchedule {
  isEnabled: boolean;
  intervalMinutes: number; // 5, 15, 30, 60
  includePorts: boolean;
  includeProcesses: boolean;
  scheduledDateTime: string | null; // ISO / datetime-local string (e.g. "2026-09-25T14:30")
  nextRunTimestamp: number | null; // epoch ms
  lastRunTimestamp: number | null;
  lastRunSummary: string | null;
}



