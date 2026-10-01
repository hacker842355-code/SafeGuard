import React, { useState } from 'react';
import { 
  Play, 
  RotateCcw, 
  Radar, 
  Terminal, 
  Network, 
  Camera, 
  Mic, 
  Plus, 
  CheckCircle2, 
  AlertTriangle, 
  Bug, 
  Zap, 
  X,
  Trash2
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const EndpointSimulator: React.FC = () => {
  const {
    ports,
    hardware,
    targetOS,
    setTargetOS,
    isScanning,
    isHardening,
    isFullHardened,
    terminalLogs,
    activeAttack,
    scanPorts,
    togglePort,
    addCustomPort,
    toggleHardware,
    executeHardening,
    executeRollback,
    simulateAttack,
    clearTerminal,
  } = useSecurity();

  // Add Custom Port Modal / Form state
  const [showAddPort, setShowAddPort] = useState<boolean>(false);
  const [customPortNum, setCustomPortNum] = useState<string>('');
  const [customPortService, setCustomPortService] = useState<string>('');
  const [customPortRisk, setCustomPortRisk] = useState<'HIGH' | 'MEDIUM' | 'LOW'>('MEDIUM');

  const handleAddPortSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const portVal = parseInt(customPortNum, 10);
    if (!isNaN(portVal) && portVal > 0 && portVal <= 65535) {
      addCustomPort(portVal, customPortService || `Custom Service ${portVal}`, customPortRisk);
      setCustomPortNum('');
      setCustomPortService('');
      setShowAddPort(false);
    }
  };

  const openPortsCount = ports.filter((p) => p.isOpen).length;

  return (
    <div className="space-y-6">
      {/* Header and OS Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
            Network Ports & Firewall
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit open network doors, toggle firewall drop rules on or off, and test penetration attacks.
          </p>
        </div>

        {/* OS selector */}
        <div className="flex items-center gap-1.5 bg-slate-900 p-1.5 rounded-lg border border-slate-800 self-start sm:self-auto">
          {(['windows', 'linux', 'macos'] as const).map((os) => (
            <button
              key={os}
              onClick={() => setTargetOS(os)}
              className={`px-3 py-1 text-xs font-semibold rounded-md capitalize transition-colors ${
                targetOS === os
                  ? 'bg-slate-800 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {os}
            </button>
          ))}
        </div>
      </div>

      {/* Main Execution & Scan Controls Ribbon */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div
            className={`w-3.5 h-3.5 rounded-full ${
              isFullHardened
                ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.8)]'
                : 'bg-red-400 shadow-[0_0_12px_rgba(248,113,113,0.8)]'
            }`}
          />
          <div>
            <div className="text-sm font-bold text-white font-sans flex items-center gap-2">
              <span>Status: {isFullHardened ? 'HARDENED · DEFAULT DROP ENFORCED' : 'EXPOSED · PORTS LISTENING'}</span>
            </div>
            <div className="text-xs text-slate-400">
              {openPortsCount} ports listening on external interfaces · {targetOS.toUpperCase()} packet filter active
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Scan Button */}
          <button
            onClick={scanPorts}
            disabled={isScanning}
            className="flex items-center gap-1.5 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap"
          >
            <Radar className={`w-3.5 h-3.5 text-cyan-400 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Scanning Sockets...' : 'Scan Ports Now'}</span>
          </button>

          {/* Add Port Button */}
          <button
            onClick={() => setShowAddPort(!showAddPort)}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5 text-cyan-400" />
            <span>Add Custom Port</span>
          </button>

          {/* Hardening & Rollback Action */}
          {!isFullHardened ? (
            <button
              onClick={executeHardening}
              disabled={isHardening}
              className="flex items-center gap-2 px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isHardening ? 'Hardening...' : 'Execute 4-Phase Hardening'}</span>
            </button>
          ) : (
            <button
              onClick={executeRollback}
              disabled={isHardening}
              className="flex items-center gap-2 px-5 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Emergency 1-Click Rollback</span>
            </button>
          )}
        </div>
      </div>

      {/* Add Custom Port Drawer Form (collapsible) */}
      {showAddPort && (
        <form
          onSubmit={handleAddPortSubmit}
          className="bg-slate-900/90 border border-cyan-800/60 p-4 rounded-xl space-y-3"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white uppercase tracking-wider font-sans">
              Add Port Rule to Scanner & Firewall
            </span>
            <button
              type="button"
              onClick={() => setShowAddPort(false)}
              className="text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                Port Number (1-65535)
              </label>
              <input
                type="number"
                placeholder="e.g. 8080, 5432, 27017"
                value={customPortNum}
                onChange={(e) => setCustomPortNum(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                Service Name / Process
              </label>
              <input
                type="text"
                placeholder="e.g. PostgreSQL, Redis, Flask"
                value={customPortService}
                onChange={(e) => setCustomPortService(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                Risk Classification
              </label>
              <select
                value={customPortRisk}
                onChange={(e) => setCustomPortRisk(e.target.value as any)}
                className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2 focus:outline-none focus:border-cyan-500"
              >
                <option value="HIGH">High Risk</option>
                <option value="MEDIUM">Medium Risk</option>
                <option value="LOW">Low Risk</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end pt-1">
            <button
              type="submit"
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold rounded-lg transition-colors"
            >
              Add Port
            </button>
          </div>
        </form>
      )}

      {/* Main Grid: Live Ports Table & Execution Console */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Interactive Ports Table with On/Off switches */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-3.5 sm:px-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider font-sans">
                  Active Socket & Port Table (Click switches to turn ON / OFF)
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                {openPortsCount} Open / {ports.length} Registered
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-4">Port / Proto</th>
                    <th className="py-2.5 px-4">Service & Process</th>
                    <th className="py-2.5 px-4">Risk</th>
                    <th className="py-2.5 px-4">Firewall Status</th>
                    <th className="py-2.5 px-4 text-right">Manual Toggle</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {ports.map((p) => (
                    <tr key={p.port} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-mono font-bold text-cyan-400 whitespace-nowrap">
                        {p.port}/{p.protocol}
                      </td>

                      <td className="py-3 px-4">
                        <div className="text-slate-200 font-medium">{p.service}</div>
                        <div className="text-slate-500 font-mono text-[11px]">{p.process}</div>
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                            p.risk === 'CRITICAL'
                              ? 'text-red-400 bg-red-950/50 border border-red-800/50'
                              : p.risk === 'HIGH'
                              ? 'text-amber-400 bg-amber-950/50 border border-amber-800/50'
                              : p.risk === 'MEDIUM'
                              ? 'text-blue-400 bg-blue-950/50'
                              : 'text-slate-400 bg-slate-900'
                          }`}
                        >
                          {p.risk}
                        </span>
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded font-mono font-semibold text-[11px] ${
                            !p.isOpen
                              ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30'
                              : p.isLoopbackOnly
                              ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                              : 'bg-red-500/10 text-red-300 border border-red-500/30'
                          }`}
                        >
                          {!p.isOpen
                            ? 'BLOCKED (DROP)'
                            : p.isLoopbackOnly
                            ? '127.0.0.1 ONLY'
                            : 'OPEN / EXPOSED'}
                        </span>
                      </td>

                      {/* Manual On/Off Switch Button */}
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <button
                          onClick={() => togglePort(p.port)}
                          disabled={p.isLoading}
                          title={p.isLoading ? 'Executing firewall command...' : p.isOpen ? 'Click to BLOCK this port' : 'Click to OPEN this port'}
                          className={`relative inline-flex h-5 w-10 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                            p.isLoading
                              ? 'bg-gray-500 cursor-not-allowed opacity-60'
                              : !p.isOpen
                              ? 'bg-emerald-600'
                              : 'bg-red-600'
                          }`}
                        >
                          <span
                            className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                              p.isLoading
                                ? 'translate-x-2 animate-pulse'
                                : !p.isOpen
                                ? 'translate-x-5'
                                : 'translate-x-0'
                            }`}
                          />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Col: Attack Simulations & Terminal Logs */}
        <div className="space-y-4">
          {/* Adversarial Attack Tests */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 font-sans">
              <Bug className="w-3.5 h-3.5 text-red-400" />
              <span>Simulate Adversarial Attacks</span>
            </h3>

            <div className="space-y-2">
              <button
                onClick={() => simulateAttack('SMB_RANSOMWARE')}
                className="w-full text-left p-2.5 bg-slate-950 hover:bg-slate-800/60 rounded-lg border border-slate-800 transition-colors text-xs text-slate-200 flex items-center justify-between group"
              >
                <div>
                  <div className="font-semibold text-white group-hover:text-cyan-400 font-sans">SMB WannaCry Exploit (445)</div>
                  <div className="text-[11px] text-slate-500">Lateral movement exploit probe</div>
                </div>
                <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              </button>

              <button
                onClick={() => simulateAttack('NMAP_SCAN')}
                className="w-full text-left p-2.5 bg-slate-950 hover:bg-slate-800/60 rounded-lg border border-slate-800 transition-colors text-xs text-slate-200 flex items-center justify-between group"
              >
                <div>
                  <div className="font-semibold text-white group-hover:text-cyan-400 font-sans">External Nmap Port Sweep</div>
                  <div className="text-[11px] text-slate-500">Full 65,535 port vulnerability scan</div>
                </div>
                <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              </button>

              <button
                onClick={() => simulateAttack('SPYWARE_CAM')}
                className="w-full text-left p-2.5 bg-slate-950 hover:bg-slate-800/60 rounded-lg border border-slate-800 transition-colors text-xs text-slate-200 flex items-center justify-between group"
              >
                <div>
                  <div className="font-semibold text-white group-hover:text-cyan-400 font-sans">Covert Webcam Stream Probe</div>
                  <div className="text-[11px] text-slate-500">Unauthorized video capture hook</div>
                </div>
                <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              </button>
            </div>

            {/* Attack Feedback Banner if active */}
            {activeAttack && (
              <div
                className={`p-3 rounded-lg border text-xs space-y-1 ${
                  activeAttack.result === 'BLOCKED'
                    ? 'bg-emerald-950/40 border-emerald-500/60 text-emerald-200'
                    : 'bg-red-950/60 border-red-500/80 text-red-200'
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span>{activeAttack.name}</span>
                  <span className="font-mono text-[11px]">
                    {activeAttack.result}
                  </span>
                </div>
                <p className="font-mono text-[11px] opacity-90">{activeAttack.log}</p>
              </div>
            )}
          </div>

          {/* Hardening Script Output Terminal */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden font-mono text-xs shadow-inner">
            <div className="bg-slate-900 px-3.5 py-2 border-b border-slate-800 flex items-center justify-between text-slate-400">
              <div className="flex items-center gap-1.5 text-[11px]">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>SurfaceGuard Live Log</span>
              </div>
              <button
                onClick={clearTerminal}
                className="text-[11px] text-slate-500 hover:text-slate-300 flex items-center gap-1"
              >
                <Trash2 className="w-3 h-3" />
                <span>Clear</span>
              </button>
            </div>

            <div className="p-3.5 space-y-1 text-slate-300 max-h-52 overflow-y-auto leading-relaxed select-text text-[11px]">
              {terminalLogs.map((log, idx) => (
                <div
                  key={idx}
                  className={`${
                    log.includes('[✓]')
                      ? 'text-emerald-400 font-semibold'
                      : log.includes('[!]')
                      ? 'text-amber-400'
                      : log.includes('[>]')
                      ? 'text-cyan-400 font-bold'
                      : log.includes('[-]')
                      ? 'text-red-400'
                      : 'text-slate-400'
                  }`}
                >
                  {log}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
