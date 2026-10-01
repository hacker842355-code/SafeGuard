import React from 'react';
import { Shield, ShieldAlert, FileText } from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

interface TopBarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenReport: () => void;
  onEmergencyLock: () => void;
  isLockedDown: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  setActiveTab,
  onOpenReport,
  onEmergencyLock,
  isLockedDown,
}) => {
  const { activeLease } = useSecurity();

  const navItems = [
    { id: 'dashboard', label: 'Overview' },
    { id: 'processes', label: 'Process Blocker' },
    { id: 'ports', label: 'Network Ports' },
    { id: 'hardware', label: 'Camera & Devices' },
    { id: 'pam', label: 'App Permissions' },
    { id: 'profiles', label: 'Defense Modes' },
    { id: 'windows-app', label: 'Windows .exe App' },
    { id: 'generator', label: 'Export Scripts' },
  ];

  return (
    <header className="sticky top-0 z-40 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80 px-6 py-3">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
            <Shield className="w-4 h-4" />
          </div>
          <span className="text-base font-bold tracking-tight text-white font-sans">
            SurfaceGuard Architect
          </span>
        </div>

        {/* Zone 2: Clean text navigation links / interactive filter controls */}
        <nav className="hidden lg:flex items-center gap-1 bg-slate-900/60 p-1 rounded-lg border border-slate-800">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap flex items-center gap-1.5 ${
                activeTab === item.id
                  ? 'bg-slate-800 text-cyan-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>{item.label}</span>
              {item.id === 'pam' && activeLease && (
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" title="Temporary Access Active" />
              )}
            </button>
          ))}
        </nav>

        {/* Zone 3: 1-2 primary actions */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={onOpenReport}
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-slate-200 bg-slate-800/80 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors whitespace-nowrap"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>Audit Report</span>
          </button>

          <button
            onClick={onEmergencyLock}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
              isLockedDown
                ? 'bg-red-500/20 text-red-300 border border-red-500/50'
                : 'bg-red-600 hover:bg-red-500 text-white shadow-sm'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>{isLockedDown ? 'Lockdown Active' : 'Panic Lockdown'}</span>
          </button>
        </div>
      </div>

      {/* Mobile nav drawer row */}
      <div className="flex lg:hidden overflow-x-auto gap-1 pt-2.5 pb-0.5 border-t border-slate-800/50 mt-2.5">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`px-2.5 py-1 text-xs font-medium rounded-md whitespace-nowrap ${
              activeTab === item.id
                ? 'bg-slate-800 text-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>
    </header>
  );
};
