import React, { useState } from 'react';
import { 
  KeyRound, 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  Camera, 
  Mic, 
  Network, 
  AlertTriangle, 
  CheckCircle2, 
  FileText,
  RotateCcw,
  Video,
  Monitor,
  Code2,
  FolderSync,
  Info,
  SlidersHorizontal,
  X,
  Loader2,
  LayoutGrid,
  FileCheck2
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import TemporaryAppPermissions from './TemporaryAppPermissions';

interface AppPreset {
  id: string;
  appName: string;
  category: 'Video & Collaboration' | 'Developer Tools' | 'Remote Administration' | 'Network Sharing' | 'Custom';
  resourceType: 'CONFERENCE' | 'CAMERA' | 'MIC' | 'PORT';
  underlyingResource: string;
  defaultMinutes: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  description: string;
  permissionDetails: string;
  isDangerous?: boolean;
}

const APP_PRESETS: AppPreset[] = [
  {
    id: 'zoom',
    appName: 'Zoom Meeting',
    category: 'Video & Collaboration',
    resourceType: 'CONFERENCE',
    underlyingResource: 'Webcam + Microphone',
    defaultMinutes: 30,
    riskLevel: 'LOW',
    description: 'Enables video camera and microphone audio capture for attending Zoom video conferences.',
    permissionDetails: 'Unlocks OS camera driver (AllowCamera=1) and microphone audio consent store.',
  },
  {
    id: 'teams',
    appName: 'Microsoft Teams Call',
    category: 'Video & Collaboration',
    resourceType: 'CONFERENCE',
    underlyingResource: 'Webcam + Microphone',
    defaultMinutes: 30,
    riskLevel: 'LOW',
    description: 'Enables video and audio capture for Microsoft Teams meetings and presentations.',
    permissionDetails: 'Unlocks webcam and mic drivers with automatic revocation upon call termination.',
  },
  {
    id: 'meet',
    appName: 'Google Meet / WebRTC Browser Conference',
    category: 'Video & Collaboration',
    resourceType: 'CONFERENCE',
    underlyingResource: 'Browser Camera + Microphone',
    defaultMinutes: 30,
    riskLevel: 'LOW',
    description: 'Permits Chrome/Edge/Firefox to access microphone and webcam for web conference calls.',
    permissionDetails: 'Grants temporary WebRTC capture lease with automatic timeout.',
  },
  {
    id: 'camera_only',
    appName: 'Webcam Document Scanner / ID Verification',
    category: 'Video & Collaboration',
    resourceType: 'CAMERA',
    underlyingResource: 'Webcam Only (No Microphone)',
    defaultMinutes: 15,
    riskLevel: 'LOW',
    description: 'Enables webcam for taking badge photos or scanning QR codes without enabling audio listening.',
    permissionDetails: 'Opens camera hardware node while keeping microphone strictly muted.',
  },
  {
    id: 'mic_only',
    appName: 'Voice Recording / Discord Voice Audio',
    category: 'Video & Collaboration',
    resourceType: 'MIC',
    underlyingResource: 'Microphone Only (No Camera)',
    defaultMinutes: 30,
    riskLevel: 'LOW',
    description: 'Enables microphone for voice chats, podcast recording, or voice memos without exposing video.',
    permissionDetails: 'Opens audio capture pipeline while camera remains disabled.',
  },
  {
    id: 'vscode_dev',
    appName: 'VS Code & Vite Local Web Server',
    category: 'Developer Tools',
    resourceType: 'PORT',
    underlyingResource: 'Port 8000 & 5173 (Loopback 127.0.0.1)',
    defaultMinutes: 30,
    riskLevel: 'LOW',
    description: 'Allows local web development preview strictly on localhost 127.0.0.1 (WAN remains blocked).',
    permissionDetails: 'Loopback binding exemption; zero external exposure to external network adapters.',
  },
  {
    id: 'node_debug',
    appName: 'Node.js Chrome DevTools Debugger',
    category: 'Developer Tools',
    resourceType: 'PORT',
    underlyingResource: 'Port 9229 (V8 Debugger)',
    defaultMinutes: 30,
    riskLevel: 'MEDIUM',
    description: 'Allows attaching Chrome DevTools debugger to local Node.js application process.',
    permissionDetails: 'Temporary debugging socket lease; auto-closes when debug session ends.',
  },
  {
    id: 'ssh_support',
    appName: 'Secure IT Remote Terminal (SSH Shell)',
    category: 'Remote Administration',
    resourceType: 'PORT',
    underlyingResource: 'Port 22 (SSH Protocol)',
    defaultMinutes: 30,
    riskLevel: 'MEDIUM',
    description: 'Allows authorized IT administrator or DevOps engineer to access command line via SSH.',
    permissionDetails: 'Inbound port 22 firewall exception with cryptographically signed lease.',
  },
  {
    id: 'rdp_support',
    appName: 'Windows Remote Desktop (RDP / TeamViewer)',
    category: 'Remote Administration',
    resourceType: 'PORT',
    underlyingResource: 'Port 3389 (RDP Protocol)',
    defaultMinutes: 15,
    riskLevel: 'HIGH',
    isDangerous: true,
    description: 'Remote screen control assistance. High-risk brute-force attack surface.',
    permissionDetails: '⚠️ Restricted: Requires security verification before opening remote desktop.',
  },
  {
    id: 'smb_drive',
    appName: 'Windows Shared Drive / File Sharing (SMB)',
    category: 'Network Sharing',
    resourceType: 'PORT',
    underlyingResource: 'Port 445 (SMB File Sharing)',
    defaultMinutes: 15,
    riskLevel: 'HIGH',
    isDangerous: true,
    description: 'Windows network shared drive access. High-risk lateral movement ransomware vector.',
    permissionDetails: '⚠️ Critical Risk: Port 445 is commonly targeted by WannaCry/NotPetya malware.',
  },
  {
    id: 'custom_port',
    appName: 'Custom Software / Specific Port Number...',
    category: 'Custom',
    resourceType: 'PORT',
    underlyingResource: 'User-specified TCP/UDP Port',
    defaultMinutes: 30,
    riskLevel: 'MEDIUM',
    description: 'Request a custom port number for specialized software or enterprise applications.',
    permissionDetails: 'Manual port binding requiring explicit operational justification.',
  },
];

export const PamSimulator: React.FC = () => {
  const {
    activeLease,
    isLeaseLoading,
    leaseLedger,
    grantTemporaryLease,
    revokeTemporaryLease,
  } = useSecurity();

  const [selectedAppId, setSelectedAppId] = useState<string>('zoom');
  const [viewMode, setViewMode] = useState<'console' | 'executive'>('console');
  const [customPortNumber, setCustomPortNumber] = useState<string>('');
  const [customPortName, setCustomPortName] = useState<string>('');
  const [durationMinutes, setDurationMinutes] = useState<number>(30);
  const [justification, setJustification] = useState<string>('');
  const [socialEngineeringModal, setSocialEngineeringModal] = useState<boolean>(false);

  const selectedPreset = APP_PRESETS.find((a) => a.id === selectedAppId) || APP_PRESETS[0];

  const handleGrantRequest = async (e: React.FormEvent) => {
    e.preventDefault();

    // Check for high-risk presets (SMB or RDP)
    if (selectedPreset.isDangerous) {
      setSocialEngineeringModal(true);
      return;
    }

    const displayName =
      selectedPreset.id === 'custom_port'
        ? `${customPortName || 'Custom App'} (Port ${customPortNumber || '?'})`
        : selectedPreset.appName;

    await grantTemporaryLease({
      appId: selectedPreset.id === 'custom_port' ? 'custom' : selectedPreset.id,
      label: selectedPreset.permissionDetails,
      shortName: displayName,
      icon: selectedPreset.resourceType === 'PORT' ? '💻' : '📹',
      durationMinutes,
      reason: justification.trim() || `User requested temporary access for ${displayName}`,
      customPort: selectedPreset.id === 'custom_port' ? Number(customPortNumber) : undefined,
    });

    setJustification('');
  };

  const handleRevokeNow = async () => {
    if (!activeLease) return;
    await revokeTemporaryLease();
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const percentLeft = activeLease && activeLease.totalSeconds > 0
    ? Math.round((activeLease.remainingSeconds / activeLease.totalSeconds) * 100)
    : 0;

  if (viewMode === 'executive') {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between bg-slate-900/80 border border-slate-800 rounded-lg p-3">
          <div className="text-xs text-slate-300">
            Viewing: <span className="font-semibold text-emerald-400">Executive Audit Document Layout</span>
          </div>
          <button
            onClick={() => setViewMode('console')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold rounded-md border border-slate-700 transition-colors"
          >
            <LayoutGrid className="w-3.5 h-3.5" />
            <span>Switch to Dark Security Console</span>
          </button>
        </div>
        <TemporaryAppPermissions />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with View Toggle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
            Temporary App Permissions
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Grant temporary 15, 30, or 60-minute access for Zoom, Teams, or developer tools with automatic timer lockdown.
          </p>
        </div>
        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg shrink-0">
          <button
            onClick={() => setViewMode('console')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 text-cyan-400 shadow-sm transition-colors"
          >
            <LayoutGrid className="w-3.5 h-3.5" />
            <span>Console View</span>
          </button>
          <button
            onClick={() => setViewMode('executive')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md text-slate-400 hover:text-slate-200 transition-colors"
          >
            <FileCheck2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Executive View</span>
          </button>
        </div>
      </div>

      {/* Active Grant Status Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider">
                Current Temporary Access Lease
              </span>
              <span
                className={`text-xs px-2.5 py-0.5 rounded font-mono font-semibold ${
                  activeLease
                    ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                    : 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30'
                }`}
              >
                {activeLease ? 'TEMPORARY ACCESS ACTIVE' : 'FULL SYSTEM LOCKDOWN (NO ACCESS)'}
              </span>
            </div>

            {activeLease ? (
              <div>
                <h3 className="text-lg font-bold text-white font-sans flex items-center gap-2">
                  <span>{activeLease.shortName}</span>
                  <span className="text-xs font-normal text-slate-400 font-mono">
                    ({activeLease.label})
                  </span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Justification: <span className="text-slate-300 italic">"{activeLease.reason}"</span>
                </p>
              </div>
            ) : (
              <div>
                <h3 className="text-base font-semibold text-slate-300">
                  Zero active elevation leases. All applications and peripherals locked.
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  When you need to attend a Zoom call or run a local dev server, request a temporary lease below.
                </p>
              </div>
            )}
          </div>

          {activeLease && (
            <div className="flex items-center gap-6 shrink-0 bg-slate-950/70 p-4 rounded-xl border border-slate-800">
              <div className="text-right">
                <div className="text-xs text-slate-400 flex items-center gap-1 justify-end font-mono">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Remaining Time</span>
                </div>
                <div className="text-2xl font-mono font-bold text-cyan-400 tabular-nums">
                  {formatTime(activeLease.remainingSeconds)}
                </div>
                <div className="text-[11px] text-slate-500 font-mono">
                  {percentLeft}% of lease remaining
                </div>
              </div>

              <button
                onClick={handleRevokeNow}
                disabled={isLeaseLoading}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm whitespace-nowrap flex items-center gap-1.5"
              >
                {isLeaseLoading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                <span>Revoke &amp; Lock Now</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Grant Request Form & App Details Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form Column */}
        <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <KeyRound className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-sans">
              Request Access by Application
            </h3>
          </div>

          <form onSubmit={handleGrantRequest} className="space-y-4">
            {/* App Selection Dropdown */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Select Application / Service You Want to Use</span>
                <span className="text-[11px] text-slate-500 font-mono">Real-World Name</span>
              </label>
              <select
                value={selectedAppId}
                onChange={(e) => setSelectedAppId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2.5 focus:outline-none focus:border-cyan-500"
              >
                <optgroup label="Video Conferencing & Meetings">
                  <option value="zoom">📹 Zoom Meeting (Camera + Microphone)</option>
                  <option value="teams">📹 Microsoft Teams Call (Camera + Microphone)</option>
                  <option value="meet">📹 Google Meet / WebRTC Browser Conference</option>
                  <option value="camera_only">📷 Webcam Photo / ID Document Scanner Only</option>
                  <option value="mic_only">🎙️ Voice Recording / Discord Audio Only</option>
                </optgroup>

                <optgroup label="Development & Debugging">
                  <option value="vscode_dev">💻 VS Code & Vite Web Server (Port 8000 / 5173)</option>
                  <option value="node_debug">🛠️ Node.js Chrome DevTools Debugger (Port 9229)</option>
                </optgroup>

                <optgroup label="Remote Administration & IT Support">
                  <option value="ssh_support">🔒 Secure Remote IT Shell (SSH Port 22)</option>
                  <option value="rdp_support">⚠️ Windows Remote Desktop / TeamViewer (Port 3389)</option>
                </optgroup>

                <optgroup label="File & Network Sharing">
                  <option value="smb_drive">⚠️ Windows Shared Drive / File Sharing (SMB Port 445)</option>
                </optgroup>

                <optgroup label="Custom Option">
                  <option value="custom_port">⚙️ Custom Application / Specific Port Number...</option>
                </optgroup>
              </select>
            </div>

            {/* Custom port inputs if custom selected */}
            {selectedAppId === 'custom_port' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 bg-slate-950/80 rounded-lg border border-slate-800">
                <div className="space-y-1">
                  <label className="text-[11px] font-semibold text-slate-300">Application Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Docker, PostgreSQL, Blender"
                    value={customPortName}
                    onChange={(e) => setCustomPortName(e.target.value)}
                    required
                    className="w-full bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded p-2 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] font-semibold text-slate-300">Port Number (1-65535)</label>
                  <input
                    type="number"
                    placeholder="e.g. 5432, 27017, 8080"
                    value={customPortNumber}
                    onChange={(e) => setCustomPortNumber(e.target.value)}
                    required
                    className="w-full bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded p-2 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>
            )}

            {/* Duration Selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">
                How Long Do You Need Access? (Time Window)
              </label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { value: 15, label: '15 Minutes', sub: 'Quick Meeting / Scan' },
                  { value: 30, label: '30 Minutes', sub: 'Standard Meeting / Dev' },
                  { value: 60, label: '60 Minutes', sub: 'Maximum Allowed Limit' },
                ].map((dur) => (
                  <button
                    key={dur.value}
                    type="button"
                    onClick={() => setDurationMinutes(dur.value)}
                    className={`p-2.5 rounded-lg border text-left transition-colors ${
                      durationMinutes === dur.value
                        ? 'bg-slate-800 border-cyan-500 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <div className="text-xs font-bold font-mono">{dur.label}</div>
                    <div className="text-[10px] text-slate-500">{dur.sub}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Justification input */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Reason for Access (Mandatory Audit Trail)</span>
                <span className="text-[11px] text-slate-500">Why do you need this?</span>
              </label>
              <input
                type="text"
                placeholder={`e.g. Attending team sprint review on ${selectedPreset.appName}`}
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2.5 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Submit Action */}
            <div className="pt-2 flex items-center justify-between">
              <span className="text-[11px] text-slate-500">
                Access automatically locks down when the timer reaches 00:00.
              </span>

              <button
                type="submit"
                disabled={isLeaseLoading}
                className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm flex items-center gap-1.5"
              >
                {isLeaseLoading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                <span>Authorize {selectedPreset.appName} ({durationMinutes}m)</span>
              </button>
            </div>
          </form>
        </div>

        {/* Selected App Details & Security Transparency Card */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <Info className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-sans">
              Access Details & Security Impact
            </h3>
          </div>

          <div className="space-y-3 text-xs">
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px]">Selected Application</div>
              <div className="text-sm font-bold text-white font-sans">
                {selectedPreset.appName}
              </div>
              <div className="text-cyan-400 font-mono text-[11px]">
                {selectedPreset.underlyingResource}
              </div>
            </div>

            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px]">What will be enabled:</div>
              <p className="text-slate-300 text-xs leading-relaxed">
                {selectedPreset.description}
              </p>
            </div>

            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px]">Underlying OS Mechanism:</div>
              <p className="text-slate-400 text-[11px] font-mono leading-relaxed">
                {selectedPreset.permissionDetails}
              </p>
            </div>

            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400">Security Risk Rating:</span>
              <span
                className={`font-mono font-bold text-[11px] px-2 py-0.5 rounded ${
                  selectedPreset.riskLevel === 'HIGH'
                    ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                    : selectedPreset.riskLevel === 'MEDIUM'
                    ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                }`}
              >
                {selectedPreset.riskLevel} RISK
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Social Engineering Challenge Modal (When High Risk like SMB or RDP is requested) */}
      {socialEngineeringModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-red-500/80 rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-950/80 border border-red-800 flex items-center justify-center text-red-400 shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white font-sans">
                  High-Risk Lateral Movement Vector Intercepted
                </h3>
                <span className="text-xs font-mono text-red-400">
                  ZERO-TRUST PAM SECURITY VETO
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
              You selected <strong className="text-red-400">{selectedPreset.appName}</strong> ({selectedPreset.underlyingResource}).
              This protocol is globally classified as a high-risk lateral movement vector historically exploited by ransomware (WannaCry, NotPetya).
            </p>

            <div className="bg-red-950/30 border border-red-900/50 p-3 rounded-lg text-xs space-y-2">
              <div className="text-red-300 font-semibold">
                SurfaceGuard Security Policy:
              </div>
              <ul className="text-slate-300 space-y-1 list-disc list-inside text-[11px]">
                <li>Opening network file shares via standard user elevation is restricted.</li>
                <li>Requires out-of-band administrative dual-key approval.</li>
                <li>This request has been recorded in the security audit trail.</li>
              </ul>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setSocialEngineeringModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors"
              >
                Acknowledge & Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Audit Trail Table */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 sm:px-6 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-sans">
              Immutable Cryptographic Audit Trail (SHA-256 Ledger)
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {leaseLedger.length} Journal Entries
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Event ID</th>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Authorized Application</th>
                <th className="py-2.5 px-4">Duration</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">SHA-256 Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {leaseLedger.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-4 font-mono text-cyan-400 font-semibold whitespace-nowrap">
                    {log.id}
                  </td>
                  <td className="py-3 px-4 text-slate-300 font-mono whitespace-nowrap">
                    {log.timestamp}
                  </td>
                  <td className="py-3 px-4">
                    <div className="text-slate-200 font-medium">{log.app}</div>
                    <div className="text-slate-500 text-[11px] truncate max-w-xs">
                      {log.reason}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                    {log.duration}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${
                        log.status === 'ACTIVE'
                          ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                          : log.status === 'EXPIRED'
                          ? 'bg-slate-800 text-slate-400 border border-slate-700'
                          : log.status === 'REVOKED'
                          ? 'bg-blue-500/10 text-blue-300 border border-blue-500/30'
                          : 'bg-red-500/10 text-red-300 border border-red-500/30'
                      }`}
                    >
                      {log.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-500 max-w-[160px] truncate">
                    {log.hash}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
