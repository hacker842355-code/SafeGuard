import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Terminal, 
  Camera, 
  Mic, 
  Usb, 
  Bluetooth, 
  FolderLock, 
  Network, 
  Play, 
  RotateCcw, 
  Radar, 
  ArrowRight,
  CheckCircle2, 
  AlertTriangle, 
  Wrench,
  Zap,
  Lock,
  Unlock,
  Shield,
  Briefcase,
  Code,
  Cpu
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

interface CommandCenterProps {
  onNavigate: (tab: string) => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({ onNavigate }) => {
  const {
    ports,
    hardware,
    securityScore,
    isScanning,
    isHardening,
    isFullHardened,
    targetOS,
    activeProfile,
    applyProfile,
    vulnerabilities,
    fixVulnerability,
    fixAllVulnerabilities,
    blockedEvents,
    scanPorts,
    togglePort,
    toggleHardware,
    loadingHardwareDevice,
    executeHardening,
    executeRollback,
  } = useSecurity();

  const openPortsCount = ports.filter((p) => p.isOpen).length;
  const lockedHardwareCount = Object.values(hardware).filter(Boolean).length;
  const openVulnsCount = vulnerabilities.filter((v) => v.isVulnerable).length;

  return (
    <div className="space-y-6">
      {/* Hero Security Health Status Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 sm:p-8">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-3 max-w-2xl">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <span>PC Security Workstation</span>
              <span aria-hidden="true">·</span>
              <span className="capitalize">{targetOS} Operating System</span>
              <span aria-hidden="true">·</span>
              <span>Real-Time Defense Active</span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-sans text-balance">
              Computer Security & Defense Center
            </h1>

            <p className="text-sm text-slate-300 leading-relaxed">
              Real-time protection against hackers, network eavesdropping, and spyware. Close vulnerable network doors (ports), lock your webcam & microphone, and fix security vulnerabilities with 1 click.
            </p>

            {/* Quick Profile Switcher Buttons */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className="text-xs text-slate-400 font-semibold mr-1 font-sans">Quick Modes:</span>
              <button
                onClick={() => applyProfile('stealth')}
                className={`px-3 py-1 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
                  activeProfile === 'stealth'
                    ? 'bg-emerald-600 text-white'
                    : 'bg-slate-950 text-slate-300 border border-slate-800 hover:border-slate-700'
                }`}
              >
                <Shield className="w-3.5 h-3.5" />
                <span>Stealth Mode</span>
              </button>

              <button
                onClick={() => applyProfile('meeting')}
                className={`px-3 py-1 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
                  activeProfile === 'meeting'
                    ? 'bg-cyan-600 text-slate-950'
                    : 'bg-slate-950 text-slate-300 border border-slate-800 hover:border-slate-700'
                }`}
              >
                <Briefcase className="w-3.5 h-3.5" />
                <span>Meeting Mode (Zoom/Teams)</span>
              </button>

              <button
                onClick={() => applyProfile('developer')}
                className={`px-3 py-1 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
                  activeProfile === 'developer'
                    ? 'bg-purple-600 text-white'
                    : 'bg-slate-950 text-slate-300 border border-slate-800 hover:border-slate-700'
                }`}
              >
                <Code className="w-3.5 h-3.5" />
                <span>Developer Mode</span>
              </button>

              <button
                onClick={() => onNavigate('processes')}
                className="px-3 py-1 rounded-lg text-xs font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/80 hover:bg-cyan-900 transition-colors flex items-center gap-1.5"
              >
                <Cpu className="w-3.5 h-3.5" />
                <span>Process Blocker</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>

          {/* Security Score Meter & Primary Action */}
          <div className="flex flex-col sm:flex-row lg:flex-col items-center lg:items-end gap-4 shrink-0 bg-slate-950/70 p-5 rounded-xl border border-slate-800">
            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-xs text-slate-400">Security Health Score</div>
                <div
                  className={`text-3xl font-extrabold font-mono tabular-nums ${
                    securityScore >= 80
                      ? 'text-emerald-400'
                      : securityScore >= 50
                      ? 'text-amber-400'
                      : 'text-red-400'
                  }`}
                >
                  {securityScore}%
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  {securityScore >= 80 ? 'PROTECTED / SAFE' : 'ACTION RECOMMENDED'}
                </div>
              </div>

              <div
                className={`w-12 h-12 rounded-xl flex items-center justify-center border ${
                  securityScore >= 80
                    ? 'bg-emerald-950/60 border-emerald-800/80 text-emerald-400'
                    : 'bg-red-950/60 border-red-800/80 text-red-400'
                }`}
              >
                {securityScore >= 80 ? (
                  <ShieldCheck className="w-6 h-6" />
                ) : (
                  <ShieldAlert className="w-6 h-6" />
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 w-full">
              <button
                onClick={scanPorts}
                disabled={isScanning}
                className="flex-1 flex items-center justify-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap"
              >
                <Radar className={`w-3.5 h-3.5 text-cyan-400 ${isScanning ? 'animate-spin' : ''}`} />
                <span>{isScanning ? 'Scanning...' : 'Scan Doors (Ports)'}</span>
              </button>

              {!isFullHardened ? (
                <button
                  onClick={executeHardening}
                  disabled={isHardening}
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 text-xs font-bold rounded-lg transition-colors whitespace-nowrap shadow-sm"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{isHardening ? 'Locking...' : 'Lockdown All'}</span>
                </button>
              ) : (
                <button
                  onClick={executeRollback}
                  disabled={isHardening}
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-slate-950 text-xs font-bold rounded-lg transition-colors whitespace-nowrap shadow-sm"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Rollback Baseline</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Live Counters Ribbon */}
        <div className="mt-6 pt-6 border-t border-slate-800/80 grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
            <div className="text-[11px] text-slate-400">Open Network Doors</div>
            <div className="text-xl font-bold font-mono text-white mt-1 tabular-nums">
              {openPortsCount} <span className="text-xs font-normal text-slate-500 font-sans">of {ports.length}</span>
            </div>
            <div className="text-[11px] text-amber-400 mt-0.5">
              {openPortsCount > 0 ? `${openPortsCount} doors open to network` : 'All doors locked'}
            </div>
          </div>

          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
            <div className="text-[11px] text-slate-400">Hardware Devices Locked</div>
            <div className="text-xl font-bold font-mono text-cyan-400 mt-1 tabular-nums">
              {lockedHardwareCount} <span className="text-xs font-normal text-slate-500 font-sans">of 5 devices</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Camera, Mic, USB, Bluetooth
            </div>
          </div>

          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
            <div className="text-[11px] text-slate-400">Vulnerabilities Detected</div>
            <div className="text-xl font-bold font-mono text-white mt-1 tabular-nums">
              {openVulnsCount} <span className="text-xs font-normal text-slate-500 font-sans">items</span>
            </div>
            <div className="text-[11px] text-amber-400 mt-0.5">
              {openVulnsCount > 0 ? 'Fixable with 1 click' : 'All resolved'}
            </div>
          </div>

          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
            <div className="text-[11px] text-slate-400">Firewall Drop Status</div>
            <div className="text-sm font-semibold font-mono text-emerald-400 mt-1 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>DEFAULT DROP ACTIVE</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Blocks unauthorized scans
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerability Checklist with 1-Click Fix All (Cybersecurity Expert Feature) */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 sm:p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-bold text-white font-sans">
              System Vulnerabilities & Security Weaknesses
            </h3>
          </div>

          {openVulnsCount > 0 && (
            <button
              onClick={fixAllVulnerabilities}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
            >
              <Wrench className="w-3.5 h-3.5" />
              <span>1-Click Fix All Weaknesses</span>
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          {vulnerabilities.map((v) => (
            <div
              key={v.id}
              className={`p-3.5 rounded-lg border flex items-start justify-between gap-3 transition-colors ${
                v.isVulnerable
                  ? 'bg-slate-950/70 border-amber-900/50'
                  : 'bg-slate-950/30 border-slate-800/60 opacity-60'
              }`}
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`font-mono text-[10px] font-bold px-1.5 py-0.2 rounded ${
                      v.riskSeverity === 'CRITICAL'
                        ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {v.riskSeverity} RISK
                  </span>
                  <span className="font-bold text-white font-sans">{v.name}</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  {v.simpleExplanation}
                </p>
                <div className="text-[10px] text-slate-500 font-mono">
                  Fix: {v.fixedActionDescription}
                </div>
              </div>

              <div className="shrink-0 pt-0.5">
                {v.isVulnerable ? (
                  <button
                    onClick={() => fixVulnerability(v.id)}
                    className="px-2.5 py-1 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-[11px] rounded transition-colors whitespace-nowrap"
                  >
                    Fix Now
                  </button>
                ) : (
                  <span className="flex items-center gap-1 text-emerald-400 font-bold text-[11px]">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Fixed</span>
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 2-Column: Quick Switches for Hardware & Network Doors */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Hardware Devices On/Off Switches */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 sm:p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Camera className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white font-sans">
                Camera & Device On/Off Switches
              </h3>
            </div>
            <button
              onClick={() => onNavigate('hardware')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
            >
              <span>All Hardware</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {/* Camera */}
            <div className="flex items-center justify-between p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${hardware.camera ? 'bg-emerald-950/60 text-emerald-400' : 'bg-red-950/60 text-red-400'}`}>
                  <Camera className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-xs font-semibold text-white">Webcam Video Camera</div>
                  <div className="text-[11px] text-slate-400">
                    {hardware.camera ? 'LOCKED (Safe from spyware)' : 'ACTIVE (Watching)'}
                  </div>
                </div>
              </div>

              <button
                onClick={() => toggleHardware('camera')}
                disabled={loadingHardwareDevice === 'camera'}
                className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  hardware.camera ? 'bg-emerald-600' : 'bg-slate-700'
                } ${loadingHardwareDevice === 'camera' ? 'opacity-70 cursor-wait' : ''}`}
              >
                {loadingHardwareDevice === 'camera' ? (
                  <span className="absolute inset-0 flex items-center justify-center">
                    <span className="h-3 w-3 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                  </span>
                ) : null}
                <span
                  className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                    hardware.camera ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Microphone */}
            <div className="flex items-center justify-between p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${hardware.microphone ? 'bg-emerald-950/60 text-emerald-400' : 'bg-red-950/60 text-red-400'}`}>
                  <Mic className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-xs font-semibold text-white">Microphone Audio Listening</div>
                  <div className="text-[11px] text-slate-400">
                    {hardware.microphone ? 'MUTED (Safe from eavesdropping)' : 'ACTIVE (Listening)'}
                  </div>
                </div>
              </div>

              <button
                onClick={() => toggleHardware('microphone')}
                disabled={loadingHardwareDevice === 'microphone'}
                className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  hardware.microphone ? 'bg-emerald-600' : 'bg-slate-700'
                } ${loadingHardwareDevice === 'microphone' ? 'opacity-70 cursor-wait' : ''}`}
              >
                {loadingHardwareDevice === 'microphone' ? (
                  <span className="absolute inset-0 flex items-center justify-center">
                    <span className="h-3 w-3 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                  </span>
                ) : null}
                <span
                  className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                    hardware.microphone ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* USB Flash Drives */}
            <div className="flex items-center justify-between p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${hardware.usbStorage ? 'bg-emerald-950/60 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
                  <Usb className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-xs font-semibold text-white">USB Flash Drives & Pen Drives</div>
                  <div className="text-[11px] text-slate-400">
                    {hardware.usbStorage ? 'BLOCKED (Safe from USB viruses)' : 'ALLOWED (Pen drives work)'}
                  </div>
                </div>
              </div>

              <button
                onClick={() => toggleHardware('usbStorage')}
                disabled={loadingHardwareDevice === 'usbStorage'}
                className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  hardware.usbStorage ? 'bg-emerald-600' : 'bg-slate-700'
                } ${loadingHardwareDevice === 'usbStorage' ? 'opacity-70 cursor-wait' : ''}`}
              >
                {loadingHardwareDevice === 'usbStorage' ? (
                  <span className="absolute inset-0 flex items-center justify-center">
                    <span className="h-3 w-3 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                  </span>
                ) : null}
                <span
                  className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                    hardware.usbStorage ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
          </div>
        </div>

        {/* Network Doors (Ports) Quick Switches */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 sm:p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white font-sans">
                Network Doors (Ports) Quick-Switch
              </h3>
            </div>
            <button
              onClick={() => onNavigate('ports')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
            >
              <span>All Ports Table</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {ports.slice(0, 4).map((p) => (
              <div
                key={p.port}
                className="flex items-center justify-between p-3 bg-slate-950/60 rounded-lg border border-slate-800"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      Door {p.port}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold ${
                        p.risk === 'CRITICAL' || p.risk === 'HIGH'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {p.risk} RISK
                    </span>
                  </div>
                  <div className="text-xs text-slate-200 font-medium">{p.service}</div>
                </div>

                <div className="flex items-center gap-3">
                  <span
                    className={`text-[11px] font-mono font-semibold ${
                      p.isOpen ? 'text-red-400' : 'text-emerald-400'
                    }`}
                  >
                    {p.isOpen ? 'OPEN' : 'BLOCKED'}
                  </span>

                  <button
                    onClick={() => togglePort(p.port)}
                    disabled={p.isLoading}
                    title={p.isLoading ? 'Executing firewall command...' : p.isOpen ? 'Click to BLOCK this port' : 'Click to OPEN this port'}
                    className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                      p.isLoading
                        ? 'bg-gray-500 cursor-not-allowed opacity-60'
                        : !p.isOpen
                        ? 'bg-emerald-600'
                        : 'bg-red-600'
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                        p.isLoading
                          ? 'translate-x-2 animate-pulse'
                          : !p.isOpen
                          ? 'translate-x-5'
                          : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Live Intrusion Attempts Blocked Feed (Real-Time Cyber Threat Proof) */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 sm:px-6 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-sans">
              Recent Attacks Blocked by Firewall (Live Protection Feed)
            </h3>
          </div>
          <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Active Real-Time Drop</span>
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Time</th>
                <th className="py-2.5 px-4">Attacker IP</th>
                <th className="py-2.5 px-4">Targeted Door</th>
                <th className="py-2.5 px-4">Threat Type</th>
                <th className="py-2.5 px-4">Defense Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {blockedEvents.map((evt) => (
                <tr key={evt.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                    {evt.timestamp}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-amber-400 whitespace-nowrap">
                    {evt.sourceIp}
                  </td>
                  <td className="py-2.5 px-4 text-slate-200 font-medium">
                    Port {evt.targetPort} ({evt.serviceName})
                  </td>
                  <td className="py-2.5 px-4 text-slate-400">
                    {evt.threatType}
                  </td>
                  <td className="py-2.5 px-4 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                      DROPPED & BLOCKED
                    </span>
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
