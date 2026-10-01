import React, { useState } from 'react';
import { 
  Play, 
  RotateCcw, 
  Radar, 
  Terminal, 
  Network, 
  Plus, 
  Bug, 
  Zap, 
  X,
  Trash2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Clock,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Filter
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const EndpointSimulator: React.FC = () => {
  const {
    ports,
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
    executeHardening,
    executeRollback,
    simulateAttack,
    clearTerminal,
    // Strict Lockdown & Port Hardening additions
    isStrictLockdown,
    isStrictLockdownLoading,
    toggleStrictLockdown,
    portNotificationAlert,
    dismissPortAlert,
    portScanInterval,
    setPortScanInterval,
    lastPortScanTime,
  } = useSecurity();

  // "Add Rule" Custom Port Modal / Form state
  const [showAddRuleModal, setShowAddRuleModal] = useState<boolean>(false);
  const [customPortNum, setCustomPortNum] = useState<string>('');
  const [customPortProtocol, setCustomPortProtocol] = useState<'TCP' | 'UDP'>('TCP');
  const [customPortService, setCustomPortService] = useState<string>('');
  const [customPortRisk, setCustomPortRisk] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('MEDIUM');
  const [formError, setFormError] = useState<string>('');

  // Port filter state
  const [filterMode, setFilterMode] = useState<'all' | 'vulnerable' | 'custom' | 'open' | 'blocked'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const handleAddRuleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    const portVal = parseInt(customPortNum, 10);
    if (isNaN(portVal) || portVal < 1 || portVal > 65535) {
      setFormError('Port number must be between 1 and 65535.');
      return;
    }

    const success = addCustomPort(
      portVal,
      customPortProtocol,
      customPortService.trim() || `Port ${portVal}`,
      customPortRisk
    );

    if (success) {
      setCustomPortNum('');
      setCustomPortService('');
      setCustomPortProtocol('TCP');
      setCustomPortRisk('MEDIUM');
      setShowAddRuleModal(false);
    }
  };

  const openPortsCount = ports.filter((p) => p.isOpen).length;
  const blockedPortsCount = ports.length - openPortsCount;

  // Filtered port list
  const filteredPorts = ports.filter((p) => {
    // Category filter
    if (filterMode === 'vulnerable' && p.isCustom) return false;
    if (filterMode === 'custom' && !p.isCustom) return false;
    if (filterMode === 'open' && !p.isOpen) return false;
    if (filterMode === 'blocked' && p.isOpen) return false;

    // Search query filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchPort = p.port.toString().includes(q);
      const matchService = p.service.toLowerCase().includes(q);
      const matchProcess = p.process.toLowerCase().includes(q);
      const matchProto = p.protocol.toLowerCase().includes(q);
      return matchPort || matchService || matchProcess || matchProto;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header and OS Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans flex items-center gap-2.5">
            <Network className="w-6 h-6 text-cyan-400" />
            <span>Network Monitor & Port Hardening</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time socket inspection, attack target presets, custom rule management, and automated firewall enforcement.
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

      {/* Notification Alert Banner (shows result.output from failed firewall calls) */}
      {portNotificationAlert && (
        <div
          className={`p-4 rounded-xl border flex items-start justify-between gap-3 text-xs transition-all ${
            portNotificationAlert.type === 'error'
              ? 'bg-red-950/70 border-red-700/80 text-red-200'
              : portNotificationAlert.type === 'success'
              ? 'bg-emerald-950/70 border-emerald-700/80 text-emerald-200'
              : 'bg-cyan-950/70 border-cyan-700/80 text-cyan-200'
          }`}
        >
          <div className="flex items-start gap-3 min-w-0">
            {portNotificationAlert.type === 'error' ? (
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            ) : portNotificationAlert.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <Shield className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
            )}
            <div className="space-y-1 min-w-0">
              <div className="font-bold text-sm tracking-tight">
                {portNotificationAlert.title}
              </div>
              <p className="font-mono text-[11px] leading-relaxed break-words whitespace-pre-wrap opacity-95 bg-slate-950/60 p-2 rounded-lg border border-slate-800/80">
                {portNotificationAlert.message}
              </p>
            </div>
          </div>
          <button
            onClick={dismissPortAlert}
            className="p-1 hover:bg-slate-800/50 rounded text-slate-400 hover:text-white shrink-0 transition-colors"
            title="Dismiss notification"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Master Control: "Strict Lockdown (Block All Unlisted Ports)" */}
      <div className={`p-4 sm:p-5 rounded-xl border transition-all ${
        isStrictLockdown 
          ? 'bg-red-950/30 border-red-500/50 shadow-[0_0_25px_rgba(239,68,68,0.15)] ring-1 ring-red-500/30'
          : 'bg-slate-900/60 border-slate-800'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border ${
              isStrictLockdown 
                ? 'bg-red-950/80 border-red-700/80 text-red-400' 
                : 'bg-slate-950 border-slate-800 text-slate-400'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="text-sm font-bold text-white font-sans">
                  Strict Lockdown (Block All Unlisted Ports)
                </span>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                  isStrictLockdown
                    ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}>
                  {isStrictLockdown ? 'ACTIVE · GLOBAL BLOCK ENFORCED' : 'INACTIVE · INDIVIDUAL RULES'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed max-w-2xl">
                When enabled, Windows Firewall immediately drops all unlisted inbound TCP traffic across local ports <span className="font-mono text-slate-300">1-65535</span> using <code className="font-mono text-[11px] text-cyan-400 bg-slate-950 px-1 py-0.5 rounded">SurfaceGuard_Block_All_Unlisted</code>.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 self-end md:self-center shrink-0">
            <span className="text-xs font-mono font-semibold text-slate-300">
              {isStrictLockdown ? 'Strict Active' : 'Strict Disabled'}
            </span>
            <button
              onClick={toggleStrictLockdown}
              disabled={isStrictLockdownLoading}
              title={
                isStrictLockdownLoading
                  ? 'Applying firewall rule...'
                  : isStrictLockdown
                  ? 'Click to turn OFF Strict Lockdown'
                  : 'Click to turn ON Strict Lockdown'
              }
              aria-label="Toggle Strict Lockdown (Block All Unlisted Ports)"
              className={`relative inline-flex h-6 w-12 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                isStrictLockdownLoading
                  ? 'bg-slate-700 opacity-60 cursor-wait'
                  : isStrictLockdown
                  ? 'bg-red-600'
                  : 'bg-slate-700 hover:bg-slate-600'
              }`}
            >
              <span
                className={`pointer-events-none flex items-center justify-center h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  isStrictLockdown ? 'translate-x-6' : 'translate-x-0'
                }`}
              >
                {isStrictLockdownLoading && (
                  <Loader2 className="w-3 h-3 text-slate-900 animate-spin" />
                )}
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Execution, Real-Time Scan & Schedule Ribbon */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
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
            <div className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
              <span>{openPortsCount} Open / {blockedPortsCount} Blocked</span>
              <span aria-hidden="true">·</span>
              {lastPortScanTime && (
                <span className="text-cyan-400 font-mono text-[11px]">
                  Last Scan: {lastPortScanTime}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Automated Recurring Scan Schedule Timer Dropdown */}
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300">
            <Clock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <select
              value={portScanInterval}
              onChange={(e) => setPortScanInterval(Number(e.target.value))}
              aria-label="Automated recurring scan interval"
              className="bg-transparent text-slate-200 text-xs focus:outline-none cursor-pointer pr-1"
            >
              <option value={15} className="bg-slate-900 text-slate-200">Auto: Every 15 min</option>
              <option value={30} className="bg-slate-900 text-slate-200">Auto: Every 30 min</option>
              <option value={60} className="bg-slate-900 text-slate-200">Auto: Every 1 hour</option>
            </select>
          </div>

          {/* Real-Time Scan Button */}
          <button
            onClick={scanPorts}
            disabled={isScanning}
            className="flex items-center gap-1.5 px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 border border-slate-700 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shadow-sm"
          >
            {isScanning ? (
              <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
            ) : (
              <Radar className="w-3.5 h-3.5 text-cyan-400" />
            )}
            <span>{isScanning ? 'Scanning Sockets...' : 'Real-Time Scan'}</span>
          </button>

          {/* "Add Rule" Custom Port Button */}
          <button
            onClick={() => setShowAddRuleModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
          >
            <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>Add Rule</span>
          </button>

          {/* Hardening & Rollback Action */}
          {!isFullHardened ? (
            <button
              onClick={executeHardening}
              disabled={isHardening}
              className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isHardening ? 'Hardening...' : '4-Phase Harden'}</span>
            </button>
          ) : (
            <button
              onClick={executeRollback}
              disabled={isHardening}
              className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Emergency Rollback</span>
            </button>
          )}
        </div>
      </div>

      {/* "Add Rule" Modal Input Dialog */}
      {showAddRuleModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-slate-900 border border-cyan-800/80 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-sans uppercase tracking-wider">
                  Add Port Rule
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAddRuleModal(false)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddRuleSubmit} className="space-y-4">
              {formError && (
                <div className="p-2.5 rounded-lg bg-red-950/60 border border-red-800/80 text-red-300 text-xs">
                  {formError}
                </div>
              )}

              {/* Port Number */}
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Port Number <span className="text-cyan-400 font-mono">(1 - 65535)</span> *
                </label>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  placeholder="e.g. 27017, 8080, 5000"
                  value={customPortNum}
                  onChange={(e) => setCustomPortNum(e.target.value)}
                  required
                  autoFocus
                  className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-100 rounded-lg p-2.5 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              {/* Protocol Selection */}
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                  Protocol (Layer 4)
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {(['TCP', 'UDP'] as const).map((proto) => (
                    <button
                      key={proto}
                      type="button"
                      onClick={() => setCustomPortProtocol(proto)}
                      className={`py-2 px-3 rounded-lg text-xs font-mono font-bold border transition-colors ${
                        customPortProtocol === proto
                          ? 'bg-cyan-600 text-slate-950 border-cyan-500 shadow-sm'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {proto}
                    </button>
                  ))}
                </div>
              </div>

              {/* Service / Process Name */}
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Label / Process Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. MongoDB, Redis, Local Game Server"
                  value={customPortService}
                  onChange={(e) => setCustomPortService(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-100 rounded-lg p-2.5 focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Risk Level */}
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Risk Classification
                </label>
                <select
                  value={customPortRisk}
                  onChange={(e) => setCustomPortRisk(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2.5 focus:outline-none focus:border-cyan-500"
                >
                  <option value="CRITICAL">Critical Risk</option>
                  <option value="HIGH">High Risk</option>
                  <option value="MEDIUM">Medium Risk</option>
                  <option value="LOW">Low Risk</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddRuleModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold rounded-lg transition-colors shadow-sm"
                >
                  Save & Manage Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Main Grid: Live Ports Table & Execution Console */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Interactive Ports Table with On/Off switches */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            {/* Table Header with Filters and Search */}
            <div className="p-3.5 sm:px-4 bg-slate-950/80 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider font-sans">
                  Managed Ports List ({ports.length})
                </h3>
              </div>

              {/* Filter Pills */}
              <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                {(
                  [
                    { id: 'all', label: 'All' },
                    { id: 'vulnerable', label: 'Presets (14)' },
                    { id: 'custom', label: 'Custom' },
                    { id: 'open', label: `Open (${openPortsCount})` },
                    { id: 'blocked', label: `Blocked (${blockedPortsCount})` },
                  ] as const
                ).map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setFilterMode(tab.id)}
                    className={`px-2.5 py-1 rounded-md transition-colors font-semibold ${
                      filterMode === tab.id
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Quick Search */}
            <div className="px-4 py-2.5 bg-slate-950/40 border-b border-slate-800/80 flex items-center justify-between gap-3">
              <div className="relative flex-1 max-w-xs">
                <input
                  type="text"
                  placeholder="Filter by port number, protocol, service..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-sans"
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2.5 top-2 text-slate-400 hover:text-white"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
              <span className="text-[11px] font-mono text-slate-400 whitespace-nowrap">
                Showing {filteredPorts.length} rules
              </span>
            </div>

            {/* Ports Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-4">Port / Proto</th>
                    <th className="py-2.5 px-4">Service & Process</th>
                    <th className="py-2.5 px-4">Risk</th>
                    <th className="py-2.5 px-4">Firewall Status</th>
                    <th className="py-2.5 px-4 text-right">Switch (ON / OFF)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {filteredPorts.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500 text-xs">
                        No ports found matching your filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredPorts.map((p) => (
                      <tr key={`${p.port}-${p.protocol}`} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3 px-4 font-mono font-bold text-cyan-400 whitespace-nowrap">
                          <span>{p.port}</span>
                          <span className="text-[11px] text-slate-400 font-normal">/{p.protocol}</span>
                          {p.isCustom && (
                            <span className="ml-1.5 px-1.5 py-0.2 rounded text-[9px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30">
                              CUSTOM
                            </span>
                          )}
                        </td>

                        <td className="py-3 px-4">
                          <div className="text-slate-200 font-medium">{p.service}</div>
                          <div className="text-slate-500 font-mono text-[11px] truncate max-w-xs" title={p.description}>
                            {p.process}
                          </div>
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
                            className={`px-2 py-0.5 rounded font-mono font-semibold text-[11px] inline-flex items-center gap-1.5 ${
                              !p.isOpen
                                ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30'
                                : p.isLoopbackOnly
                                ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                                : 'bg-red-500/10 text-red-300 border border-red-500/30'
                            }`}
                          >
                            {!p.isOpen ? (
                              <>
                                <Lock className="w-3 h-3 text-emerald-400" />
                                <span>BLOCKED (via Firewall)</span>
                              </>
                            ) : p.isLoopbackOnly ? (
                              <>
                                <ShieldCheck className="w-3 h-3 text-cyan-400" />
                                <span>127.0.0.1 ONLY</span>
                              </>
                            ) : (
                              <>
                                <Unlock className="w-3 h-3 text-red-400" />
                                <span>OPEN / ALLOWED</span>
                              </>
                            )}
                          </span>
                        </td>

                        {/* Explicit ON/OFF Toggle Switch (ON = Open/Allowed, OFF = Blocked via Firewall) */}
                        <td className="py-3 px-4 text-right whitespace-nowrap">
                          <div className="inline-flex items-center gap-2">
                            <span className={`text-[10px] font-mono font-bold ${
                              p.isOpen ? 'text-red-400' : 'text-emerald-400'
                            }`}>
                              {p.isOpen ? 'ON' : 'OFF'}
                            </span>
                            <button
                              onClick={() => togglePort(p.port)}
                              disabled={p.isLoading}
                              title={
                                p.isLoading
                                  ? 'Applying firewall command...'
                                  : p.isOpen
                                  ? `Click to BLOCK Port ${p.port} via Firewall`
                                  : `Click to ALLOW Port ${p.port}`
                              }
                              aria-label={`Toggle port ${p.port}`}
                              className={`relative inline-flex h-5 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                p.isLoading
                                  ? 'bg-slate-700 opacity-60 cursor-wait'
                                  : p.isOpen
                                  ? 'bg-red-600'
                                  : 'bg-emerald-600'
                              }`}
                            >
                              <span
                                className={`pointer-events-none flex items-center justify-center h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                                  p.isOpen ? 'translate-x-6' : 'translate-x-0'
                                }`}
                              >
                                {p.isLoading && (
                                  <Loader2 className="w-2.5 h-2.5 text-slate-900 animate-spin" />
                                )}
                              </span>
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
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
                className="text-[11px] text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors"
              >
                <Trash2 className="w-3 h-3" />
                <span>Clear</span>
              </button>
            </div>

            <div className="p-3.5 space-y-1 text-slate-300 max-h-56 overflow-y-auto leading-relaxed select-text text-[11px]">
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
                      : log.includes('[✗]') || log.includes('[-]')
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
