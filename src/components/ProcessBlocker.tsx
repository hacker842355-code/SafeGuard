import React, { useState } from 'react';
import { 
  Radar, 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  Unlock, 
  Plus, 
  X, 
  Terminal, 
  Activity, 
  Search,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const ProcessBlocker: React.FC = () => {
  const {
    processes,
    isScanningProcesses,
    isUpdatingProcesses,
    processAction,
    updatingProcessIds,
    isAddingCustomProcess,
    scanProcesses,
    toggleProcessBlock,
    blockAllProcesses,
    allowAllProcesses,
    addCustomProcess,
  } = useSecurity();

  const [filter, setFilter] = useState<'ALL' | 'BLOCKED' | 'ALLOWED' | 'TELEMETRY'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [customName, setCustomName] = useState<string>('');
  const [customPath, setCustomPath] = useState<string>('');

  const blockedCount = processes.filter((p) => p.isBlocked).length;
  const telemetryCount = processes.filter((p) => p.type === 'TELEMETRY' || p.type === 'UPDATER').length;
  const telemetryBlockedCount = processes.filter((p) => (p.type === 'TELEMETRY' || p.type === 'UPDATER') && p.isBlocked).length;

  const filteredProcesses = processes.filter((p) => {
    const matchesSearch = 
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.pid.toString().includes(searchQuery);

    if (!matchesSearch) return false;
    if (filter === 'BLOCKED') return p.isBlocked;
    if (filter === 'ALLOWED') return !p.isBlocked;
    if (filter === 'TELEMETRY') return p.type === 'TELEMETRY' || p.type === 'UPDATER';
    return true;
  });

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (customName.trim()) {
      const added = await addCustomProcess(customName.trim(), customPath.trim() || undefined);
      if (added) {
        setCustomName('');
        setCustomPath('');
        setShowAddModal(false);
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Metrics */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 sm:p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Activity className="w-3.5 h-3.5" />
              <span>Real-Time Process Guard</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
              Background Process & Telemetry Blocker
            </h2>
            <p className="text-xs text-slate-400">
              Monitor active background tasks, prevent silent telemetry data leaks, and toggle outbound internet access on or off.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={scanProcesses}
              disabled={isScanningProcesses || isUpdatingProcesses || isAddingCustomProcess}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap"
            >
              <Radar className={`w-3.5 h-3.5 text-cyan-400 ${isScanningProcesses ? 'animate-spin' : ''}`} />
              <span>{isScanningProcesses ? 'Scanning Tasks...' : 'Scan Processes'}</span>
            </button>

            <button
              onClick={blockAllProcesses}
              disabled={isUpdatingProcesses || isScanningProcesses || isAddingCustomProcess}
              className="px-3.5 py-2 bg-red-600 hover:bg-red-500 text-white font-bold text-xs rounded-lg transition-colors whitespace-nowrap shadow-sm"
            >
              {isUpdatingProcesses && processAction === 'BLOCK_ALL' && <Activity className="w-3.5 h-3.5 inline mr-1 animate-spin" />}
              {isUpdatingProcesses && processAction === 'BLOCK_ALL' ? 'Blocking Telemetry...' : 'Block All Telemetry'}
            </button>

            <button
              onClick={allowAllProcesses}
              disabled={isUpdatingProcesses || isScanningProcesses || isAddingCustomProcess}
              className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap"
            >
              {isUpdatingProcesses && processAction === 'ALLOW_ALL' && <Activity className="w-3.5 h-3.5 inline mr-1 animate-spin" />}
              {isUpdatingProcesses && processAction === 'ALLOW_ALL' ? 'Restoring Telemetry...' : 'Allow All'}
            </button>

            <button
              onClick={() => setShowAddModal(true)}
              className="px-3 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors flex items-center gap-1 whitespace-nowrap shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Process</span>
            </button>
          </div>
        </div>

        {/* Live Counters */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Total Monitored Tasks</span>
            <span className="text-lg font-bold font-mono text-white tabular-nums">
              {processes.length} Active
            </span>
          </div>

          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Blocked From Internet</span>
            <span className="text-lg font-bold font-mono text-red-400 tabular-nums">
              {blockedCount} Dropped
            </span>
          </div>

          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Telemetry Harvesters</span>
            <span className="text-lg font-bold font-mono text-amber-400 tabular-nums">
              {telemetryCount} Detected / {telemetryBlockedCount} Blocked
            </span>
          </div>

          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Firewall Policy</span>
            <span className="text-xs font-bold font-mono text-emerald-400 mt-1 block">
              OUTBOUND DROP ACTIVE
            </span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-1.5 w-full sm:w-auto">
          {(['ALL', 'BLOCKED', 'ALLOWED', 'TELEMETRY'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setFilter(mode)}
              className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-colors capitalize ${
                filter === mode
                  ? 'bg-cyan-600 text-slate-950'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {mode === 'ALL'
                ? `All (${processes.length})`
                : mode === 'BLOCKED'
                ? `Blocked (${blockedCount})`
                : mode === 'ALLOWED'
                ? `Allowed (${processes.length - blockedCount})`
                : `Telemetry (${telemetryCount})`}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search process name or PID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Process Table with Direct ON/OFF Switches */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">PID / Process Name</th>
                <th className="py-2.5 px-4">Classification</th>
                <th className="py-2.5 px-4">Description / Impact</th>
                <th className="py-2.5 px-4">Firewall Network Status</th>
                <th className="py-2.5 px-4 text-right">Block On/Off</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredProcesses.map((p) => (
                <tr key={p.pid} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-mono font-bold text-white flex items-center gap-2">
                      <span className="text-cyan-400">PID {p.pid}</span>
                      <span>{p.name}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono truncate max-w-xs">
                      {p.path}
                    </div>
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        p.type === 'TELEMETRY'
                          ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                          : p.type === 'UPDATER'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                          : p.type === 'CUSTOM'
                          ? 'bg-purple-500/10 text-purple-400 border border-purple-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {p.type}
                    </span>
                  </td>

                  <td className="py-3 px-4 text-slate-300 text-xs">
                    {p.impact}
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded font-mono font-semibold text-[11px] ${
                        p.isBlocked
                          ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {p.isBlocked ? 'BLOCKED (OUTBOUND DROP)' : 'ALLOWED (INTERNET ACTIVE)'}
                    </span>
                  </td>

                  {/* Manual ON/OFF Toggle Switch */}
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <button
                      onClick={() => toggleProcessBlock(p.pid)}
                      disabled={isUpdatingProcesses || isScanningProcesses || isAddingCustomProcess || updatingProcessIds.includes(p.pid)}
                      title={p.isBlocked ? 'Click to ALLOW process' : 'Click to BLOCK process'}
                      className={`relative inline-flex h-5 w-10 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                        p.isBlocked ? 'bg-red-600' : 'bg-emerald-600'
                      }`}
                    >
                      <span
                        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                          p.isBlocked ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                      {updatingProcessIds.includes(p.pid) && <Activity className="absolute left-1/2 top-1/2 h-3 w-3 -translate-x-1/2 -translate-y-1/2 animate-spin text-white" />}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Custom Process Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleAddSubmit}
            className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <h3 className="text-sm font-bold text-white font-sans">
                Add Process to Firewall Blocker
              </h3>
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">
                  Executable Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. telemetry.exe, background_updater.exe"
                  value={customName}
                  onChange={(e) => setCustomName(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2.5 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">
                  Path (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. C:\Program Files\App\telemetry.exe"
                  value={customPath}
                  onChange={(e) => setCustomPath(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2.5 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800/80">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isAddingCustomProcess}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold rounded-lg transition-colors"
              >
                {isAddingCustomProcess ? 'Adding & Blocking...' : 'Add & Block'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
