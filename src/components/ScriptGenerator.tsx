import React, { useState } from 'react';
import { 
  Terminal, 
  Copy, 
  Check, 
  Download, 
  RotateCcw, 
  ShieldCheck, 
  Code, 
  Sliders, 
  AlertTriangle 
} from 'lucide-react';
import { generateHardeningScript } from '../data/scriptTemplates';
import { HardeningConfig } from '../types/security';

export const ScriptGenerator: React.FC = () => {
  const [config, setConfig] = useState<HardeningConfig>({
    targetOs: 'windows',
    strictAtomic: true,
    dryRunMode: false,
    allowDevPorts: true,
    devPorts: [3000, 5173, 8000, 9229],
    videoConfProfile: true,
    watchdogDaemon: true,
    autoRollbackOnError: true,
    lockdownCamera: true,
    lockdownMicrophone: true,
    tightenFileSystem: true,
    closeUnusedPorts: true,
  });

  const [activeView, setActiveView] = useState<'script' | 'rollback'>('script');
  const [copied, setCopied] = useState<boolean>(false);

  const { script, rollback, filename, rollbackFilename } = generateHardeningScript(config);

  const activeContent = activeView === 'script' ? script : rollback;
  const currentFilename = activeView === 'script' ? filename : rollbackFilename;

  const handleCopy = () => {
    navigator.clipboard.writeText(activeContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([activeContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = currentFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
          Automated Hardening Script & Rollback Generator
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
          Generate production-grade, atomic attack surface reduction scripts and 1-click rollback manifests tailored for Windows, Linux, and macOS.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration Panel */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 sm:p-6 space-y-5">
          <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-sans">
              Hardening Engine Configuration
            </h3>
          </div>

          {/* OS Selector */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">
              Target Operating System
            </label>
            <div className="grid grid-cols-3 gap-1.5">
              {[
                { id: 'windows', label: 'Windows' },
                { id: 'linux', label: 'Linux' },
                { id: 'macos', label: 'macOS' },
              ].map((os) => (
                <button
                  key={os.id}
                  onClick={() => setConfig({ ...config, targetOs: os.id as any })}
                  className={`py-2 text-xs font-semibold rounded-lg transition-colors capitalize ${
                    config.targetOs === os.id
                      ? 'bg-slate-800 text-cyan-400 border border-cyan-800/50'
                      : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
                  }`}
                >
                  {os.label}
                </button>
              ))}
            </div>
          </div>

          {/* Toggles */}
          <div className="space-y-3 pt-2 text-xs">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={config.dryRunMode}
                onChange={(e) => setConfig({ ...config, dryRunMode: e.target.checked })}
                className="mt-0.5 rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
              />
              <div>
                <span className="font-semibold text-slate-200">Dry-Run Simulation Mode</span>
                <p className="text-slate-500 text-[11px]">
                  Outputs planned actions without committing changes to disk/firewall.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={config.allowDevPorts}
                onChange={(e) => setConfig({ ...config, allowDevPorts: e.target.checked })}
                className="mt-0.5 rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
              />
              <div>
                <span className="font-semibold text-slate-200">Developer Localhost Whitelist</span>
                <p className="text-slate-500 text-[11px]">
                  Permits ports 3000, 5173, 8000, 9229 strictly on 127.0.0.1 (F2 fix).
                </p>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={config.lockdownCamera}
                onChange={(e) => setConfig({ ...config, lockdownCamera: e.target.checked })}
                className="mt-0.5 rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
              />
              <div>
                <span className="font-semibold text-slate-200">Hardware Camera Lockdown</span>
                <p className="text-slate-500 text-[11px]">
                  Disables driver access via Registry / udev rules.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={config.lockdownMicrophone}
                onChange={(e) => setConfig({ ...config, lockdownMicrophone: e.target.checked })}
                className="mt-0.5 rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
              />
              <div>
                <span className="font-semibold text-slate-200">Microphone Consent Lockdown</span>
                <p className="text-slate-500 text-[11px]">
                  Sets default OS microphone consent to Deny.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={config.tightenFileSystem}
                onChange={(e) => setConfig({ ...config, tightenFileSystem: e.target.checked })}
                className="mt-0.5 rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
              />
              <div>
                <span className="font-semibold text-slate-200">File System ACL Hardening</span>
                <p className="text-slate-500 text-[11px]">
                  Removes unauthenticated write privileges on system directories.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={config.watchdogDaemon}
                onChange={(e) => setConfig({ ...config, watchdogDaemon: e.target.checked })}
                className="mt-0.5 rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
              />
              <div>
                <span className="font-semibold text-slate-200">Monotonic Watchdog State Commit</span>
                <p className="text-slate-500 text-[11px]">
                  Writes baseline state snapshot journal for rollback verification.
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Script Viewer Panel */}
        <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
          {/* Action Bar */}
          <div className="p-3 sm:px-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between gap-3">
            <div className="flex items-center gap-1.5 bg-slate-900 p-1 rounded-lg border border-slate-800">
              <button
                onClick={() => setActiveView('script')}
                className={`flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-md transition-colors ${
                  activeView === 'script'
                    ? 'bg-slate-800 text-cyan-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Hardening Script</span>
              </button>
              <button
                onClick={() => setActiveView('rollback')}
                className={`flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-md transition-colors ${
                  activeView === 'rollback'
                    ? 'bg-slate-800 text-amber-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Emergency Rollback</span>
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors border border-slate-700"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>

              <button
                onClick={handleDownload}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold rounded-lg transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download {currentFilename}</span>
              </button>
            </div>
          </div>

          {/* Code Viewer */}
          <div className="p-4 bg-slate-950 font-mono text-xs text-slate-300 overflow-x-auto overflow-y-auto max-h-[560px] leading-relaxed selection:bg-cyan-500/20">
            <pre>{activeContent}</pre>
          </div>
        </div>
      </div>
    </div>
  );
};
