import React, { useState, useMemo } from 'react';
import { 
  Terminal, 
  Copy, 
  Check, 
  Download, 
  RotateCcw, 
  ShieldCheck, 
  Code, 
  FileText,
  Shield, 
  ShieldAlert,
  Network,
  Cpu,
  Lock,
  Unlock,
  Building2,
  FileCode,
  Clock,
  Activity,
  Layers
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { 
  buildHardeningScript, 
  buildRollbackScript, 
  buildGpoIntuneScript, 
  buildAuditJson 
} from '../utils/scriptBuilders';

type ScriptViewTab = 'hardening' | 'rollback' | 'gpo' | 'audit';

export const ScriptGenerator: React.FC = () => {
  const {
    ports,
    hardware,
    processes,
    isStrictLockdown,
    activeProfile,
    activeLease,
    targetOS,
    securityScore,
  } = useSecurity();

  const [activeTab, setActiveTab] = useState<ScriptViewTab>('hardening');
  const [copied, setCopied] = useState<boolean>(false);

  // Derived metrics from live state
  const blockedPorts = useMemo(() => ports.filter((p) => !p.isOpen), [ports]);
  const openPorts = useMemo(() => ports.filter((p) => p.isOpen), [ports]);
  const blockedProcesses = useMemo(() => processes.filter((p) => p.isBlocked), [processes]);

  const lockedHardwareCount = useMemo(() => {
    let count = 0;
    if (hardware.camera) count++;
    if (hardware.microphone) count++;
    if (hardware.usbStorage) count++;
    if (hardware.bluetooth) count++;
    if (hardware.fileSystemAcl) count++;
    return count;
  }, [hardware]);

  // Dynamically generated real-time scripts
  const scriptParams = useMemo(() => ({
    ports,
    hardware,
    processes,
    isStrictLockdown,
    activeProfile,
    activeLease,
    targetOS,
  }), [ports, hardware, processes, isStrictLockdown, activeProfile, activeLease, targetOS]);

  const hardeningScript = useMemo(() => buildHardeningScript(scriptParams), [scriptParams]);
  const rollbackScript = useMemo(() => buildRollbackScript(scriptParams), [scriptParams]);
  const gpoScript = useMemo(() => buildGpoIntuneScript(scriptParams), [scriptParams]);
  const auditJson = useMemo(() => buildAuditJson(scriptParams), [scriptParams]);

  // Active tab selection details
  const currentContent = useMemo(() => {
    switch (activeTab) {
      case 'hardening':
        return hardeningScript;
      case 'rollback':
        return rollbackScript;
      case 'gpo':
        return gpoScript;
      case 'audit':
        return auditJson;
    }
  }, [activeTab, hardeningScript, rollbackScript, gpoScript, auditJson]);

  const currentFilename = useMemo(() => {
    switch (activeTab) {
      case 'hardening':
        return 'SurfaceGuard_Hardening_Baseline.ps1';
      case 'rollback':
        return 'SurfaceGuard_Emergency_Rollback.ps1';
      case 'gpo':
        return 'SurfaceGuard_GPO_Intune_Deploy.ps1';
      case 'audit':
        return 'SurfaceGuard_Security_Audit_Manifest.json';
    }
  }, [activeTab]);

  const handleCopy = () => {
    navigator.clipboard.writeText(currentContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadFile = (filename: string, content: string) => {
    const isJson = filename.endsWith('.json');
    const mime = isJson ? 'application/json;charset=utf-8' : 'text/plain;charset=utf-8';
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
            <Code className="w-3.5 h-3.5" />
            <span>Dynamic Script Generator & Audit Engine</span>
            <span aria-hidden="true">·</span>
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Live Context Synchronized
            </span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans mt-0.5">
            Export Scripts & Audit Log
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
            Generate production-grade, real-time PowerShell enforcement scripts and 1-click disaster recovery manifests reflecting your live system configuration.
          </p>
        </div>

        {/* Global Primary Download Actions */}
        <div className="flex flex-wrap items-center gap-2 self-start md:self-auto">
          {/* 1. Download Hardening Script */}
          <button
            onClick={() => downloadFile('SurfaceGuard_Hardening_Baseline.ps1', hardeningScript)}
            className="flex items-center gap-1.5 px-3 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
            title="Download Active Hardening Script (.ps1)"
          >
            <Download className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>Download Hardening Script (.ps1)</span>
          </button>

          {/* 2. Download Rollback Script */}
          <button
            onClick={() => downloadFile('SurfaceGuard_Emergency_Rollback.ps1', rollbackScript)}
            className="flex items-center gap-1.5 px-3 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
            title="Download Instant Emergency Rollback Script (.ps1)"
          >
            <RotateCcw className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>Download Rollback Script (.ps1)</span>
          </button>

          {/* 3. Export GPO Policy */}
          <button
            onClick={() => downloadFile('SurfaceGuard_GPO_Intune_Deploy.ps1', gpoScript)}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap"
            title="Export GPO / Intune Enterprise Deployment Script"
          >
            <Building2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export GPO Policy</span>
          </button>
        </div>
      </div>

      {/* Live Configuration State Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-red-950/60 border border-red-800/80 flex items-center justify-center text-red-400 shrink-0">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Blocked Ports</div>
            <div className="text-base font-bold text-white font-sans">{blockedPorts.length} / {ports.length}</div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-purple-950/60 border border-purple-800/80 flex items-center justify-center text-purple-400 shrink-0">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Telemetry Blocks</div>
            <div className="text-base font-bold text-white font-sans">{blockedProcesses.length} / {processes.length}</div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-950/60 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shrink-0">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Device Controls</div>
            <div className="text-base font-bold text-white font-sans">{lockedHardwareCount} / 5 Active</div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-emerald-950/60 border border-emerald-800/80 flex items-center justify-center text-emerald-400 shrink-0">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Current Profile</div>
            <div className="text-base font-bold text-white font-sans capitalize">{activeProfile}</div>
          </div>
        </div>
      </div>

      {/* Main Workspace Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Active Configuration Inspector (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-sans uppercase tracking-wider">
                  Active Configuration Inspector
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                LIVE
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              These active rules are inspected in real time from your live workstation state and injected directly into the generated PowerShell manifests.
            </p>

            {/* Strict Lockdown Status */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-slate-200 block font-sans">Strict Global Inbound Drop</span>
                <span className="text-[11px] text-slate-500">Ports 1-65535 drop rule</span>
              </div>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                isStrictLockdown
                  ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                  : 'bg-slate-800 text-slate-400'
              }`}>
                {isStrictLockdown ? 'ENFORCED' : 'OFF'}
              </span>
            </div>

            {/* Blocked Ports Pill List */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300 font-sans">Active Blocked Ports:</span>
                <span className="font-mono text-cyan-400 text-[11px]">{blockedPorts.length} rules</span>
              </div>
              <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 rounded-lg bg-slate-950 border border-slate-800/80">
                {blockedPorts.length === 0 ? (
                  <span className="text-xs text-slate-500 italic">No ports currently blocked</span>
                ) : (
                  blockedPorts.map((p) => (
                    <span
                      key={`${p.port}-${p.protocol}`}
                      className="px-2 py-0.5 rounded text-[11px] font-mono bg-red-950/60 text-red-300 border border-red-800/60 flex items-center gap-1"
                      title={`${p.service} (${p.description})`}
                    >
                      <Lock className="w-2.5 h-2.5 text-red-400" />
                      <span>{p.port}/{p.protocol}</span>
                    </span>
                  ))
                )}
              </div>
            </div>

            {/* Blocked Processes Pill List */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300 font-sans">Blocked Processes & Telemetry:</span>
                <span className="font-mono text-purple-400 text-[11px]">{blockedProcesses.length} tasks</span>
              </div>
              <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 rounded-lg bg-slate-950 border border-slate-800/80">
                {blockedProcesses.length === 0 ? (
                  <span className="text-xs text-slate-500 italic">No processes currently blocked</span>
                ) : (
                  blockedProcesses.map((proc) => (
                    <span
                      key={proc.pid}
                      className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-950/60 text-purple-300 border border-purple-800/60 truncate max-w-full flex items-center gap-1"
                      title={`${proc.name} [${proc.path}]`}
                    >
                      <Cpu className="w-2.5 h-2.5 text-purple-400 shrink-0" />
                      <span className="truncate">{proc.name}</span>
                    </span>
                  ))
                )}
              </div>
            </div>

            {/* Hardware Controls Status */}
            <div className="space-y-1.5">
              <span className="font-semibold text-slate-300 font-sans text-xs block">
                Hardware Sandboxing Controls:
              </span>
              <div className="grid grid-cols-2 gap-1.5 text-[11px]">
                <div className={`p-2 rounded border flex items-center justify-between ${
                  hardware.camera ? 'bg-cyan-950/30 border-cyan-800/50 text-cyan-300' : 'bg-slate-950 border-slate-800 text-slate-500'
                }`}>
                  <span>Webcam</span>
                  <span className="font-mono font-bold">{hardware.camera ? 'DENY' : 'ALLOW'}</span>
                </div>

                <div className={`p-2 rounded border flex items-center justify-between ${
                  hardware.microphone ? 'bg-cyan-950/30 border-cyan-800/50 text-cyan-300' : 'bg-slate-950 border-slate-800 text-slate-500'
                }`}>
                  <span>Microphone</span>
                  <span className="font-mono font-bold">{hardware.microphone ? 'DENY' : 'ALLOW'}</span>
                </div>

                <div className={`p-2 rounded border flex items-center justify-between ${
                  hardware.usbStorage ? 'bg-cyan-950/30 border-cyan-800/50 text-cyan-300' : 'bg-slate-950 border-slate-800 text-slate-500'
                }`}>
                  <span>USB Storage</span>
                  <span className="font-mono font-bold">{hardware.usbStorage ? 'BLOCK' : 'ALLOW'}</span>
                </div>

                <div className={`p-2 rounded border flex items-center justify-between ${
                  hardware.bluetooth ? 'bg-cyan-950/30 border-cyan-800/50 text-cyan-300' : 'bg-slate-950 border-slate-800 text-slate-500'
                }`}>
                  <span>Bluetooth</span>
                  <span className="font-mono font-bold">{hardware.bluetooth ? 'DISABLED' : 'ENABLED'}</span>
                </div>
              </div>
            </div>

            {/* Temporary Lease Notice */}
            {activeLease && (
              <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/60 text-amber-200 text-xs flex items-start gap-2">
                <Clock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold">Active PAM Exemption Detected</div>
                  <div className="text-[11px] text-amber-300/90 mt-0.5">
                    {activeLease.shortName} currently has temporary access ({activeLease.remainingSeconds}s remaining). Hardening baseline will note this temporary exemption.
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Dynamic Script Preview & Tabs (8 cols) */}
        <div className="lg:col-span-8 bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-xl">
          {/* Navigation Tab Bar */}
          <div className="p-2 sm:px-3 bg-slate-950 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1">
              <button
                onClick={() => setActiveTab('hardening')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                  activeTab === 'hardening'
                    ? 'bg-slate-800 text-cyan-400 border border-cyan-800/60 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Hardening Script (.ps1)</span>
              </button>

              <button
                onClick={() => setActiveTab('rollback')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                  activeTab === 'rollback'
                    ? 'bg-slate-800 text-amber-400 border border-amber-800/60 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Emergency Rollback (.ps1)</span>
              </button>

              <button
                onClick={() => setActiveTab('gpo')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                  activeTab === 'gpo'
                    ? 'bg-slate-800 text-purple-400 border border-purple-800/60 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Building2 className="w-3.5 h-3.5" />
                <span>GPO / Intune Policy (.ps1)</span>
              </button>

              <button
                onClick={() => setActiveTab('audit')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                  activeTab === 'audit'
                    ? 'bg-slate-800 text-emerald-400 border border-emerald-800/60 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>Audit Manifest (.json)</span>
              </button>
            </div>

            {/* Quick Actions (Copy & Download current) */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors border border-slate-700"
                title="Copy current script to clipboard"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-300 font-bold">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>

              <button
                onClick={() => downloadFile(currentFilename, currentContent)}
                className="flex items-center gap-1.5 px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
                title={`Download ${currentFilename}`}
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download</span>
              </button>
            </div>
          </div>

          {/* Script Details Bar */}
          <div className="px-4 py-2 bg-slate-950/70 border-b border-slate-800/70 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span className="text-cyan-400 font-semibold">{currentFilename}</span>
            <div className="flex items-center gap-3">
              <span>{currentContent.split('\n').length} lines</span>
              <span aria-hidden="true">·</span>
              <span>{(new Blob([currentContent]).size / 1024).toFixed(1)} KB</span>
            </div>
          </div>

          {/* Syntax-Highlighted Monospace Code Box */}
          <div className="p-4 bg-slate-950 font-mono text-xs text-slate-300 overflow-x-auto overflow-y-auto max-h-[580px] leading-relaxed selection:bg-cyan-500/20">
            <pre className="whitespace-pre">
              {currentContent.split('\n').map((line, idx) => {
                const isComment = line.trim().startsWith('#');
                const isHeading = isComment && (line.includes('===') || line.includes('---'));
                const isCmdlet = !isComment && (line.includes('netsh') || line.includes('Set-ItemProperty') || line.includes('Get-NetFirewallRule') || line.includes('icacls') || line.includes('Disable-PnpDevice') || line.includes('Enable-PnpDevice'));
                const isParam = !isComment && line.includes('param(');

                let lineClass = 'text-slate-300';
                if (isHeading) lineClass = 'text-slate-500 font-bold';
                else if (isComment) lineClass = 'text-emerald-400/80 italic';
                else if (isCmdlet) lineClass = 'text-cyan-300';
                else if (isParam) lineClass = 'text-purple-300';

                return (
                  <div key={idx} className="flex">
                    <span className="select-none text-slate-600 text-[10px] w-9 shrink-0 text-right pr-3 font-mono opacity-50">
                      {idx + 1}
                    </span>
                    <span className={lineClass}>{line}</span>
                  </div>
                );
              })}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
