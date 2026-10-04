/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { SecurityProvider, useSecurity } from './context/SecurityContext';
import { TopBar } from './components/TopBar';
import { CommandCenter } from './components/CommandCenter';
import { ProcessBlocker } from './components/ProcessBlocker';
import { EndpointSimulator } from './components/EndpointSimulator';
import { HardwareControl } from './components/HardwareControl';
import { PamSimulator } from './components/PamSimulator';
import { SecurityProfiles } from './components/SecurityProfiles';
import { ScriptGenerator } from './components/ScriptGenerator';
import { ExecutiveReportModal } from './components/ExecutiveReportModal';
import { ShieldAlert } from 'lucide-react';

function AppLayout() {
  const [activeTab, setActiveTab] = useState<string>('profiles');
  const [isReportOpen, setIsReportOpen] = useState<boolean>(false);
  const [isLockedDown, setIsLockedDown] = useState<boolean>(false);
  const { executeEmergencyLockdown } = useSecurity();

  const handleEmergencyLock = async () => {
    const nextLocked = !isLockedDown;
    setIsLockedDown(nextLocked);
    if (nextLocked) {
      await executeEmergencyLockdown();
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Bar with 3-zone contract */}
      <TopBar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenReport={() => setIsReportOpen(true)}
        onEmergencyLock={handleEmergencyLock}
        isLockedDown={isLockedDown}
      />

      {/* Emergency Lockdown Active Alert Banner */}
      {isLockedDown && (
        <div className="bg-red-950/80 border-b border-red-800/80 px-6 py-2.5 text-xs text-red-200">
          <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
              <span>
                <strong>EMERGENCY PANIC LOCKDOWN ACTIVE:</strong> All network ports closed, video4linux & audio subsystems severed, and temporary PAM windows revoked.
              </span>
            </div>
            <button
              onClick={() => setIsLockedDown(false)}
              className="text-white bg-red-800 hover:bg-red-700 px-2.5 py-1 rounded font-semibold text-[11px] transition-colors whitespace-nowrap"
            >
              Deactivate
            </button>
          </div>
        </div>
      )}

      {/* Main Content Workspace Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 sm:py-8">
        {activeTab === 'dashboard' && (
          <CommandCenter onNavigate={(tab) => setActiveTab(tab)} />
        )}

        {activeTab === 'processes' && <ProcessBlocker />}

        {activeTab === 'ports' && <EndpointSimulator />}

        {activeTab === 'hardware' && <HardwareControl />}

        {activeTab === 'pam' && <PamSimulator />}

        {activeTab === 'profiles' && <SecurityProfiles />}

        {activeTab === 'generator' && <ScriptGenerator />}
      </main>

      {/* Formal Audit Report Modal */}
      <ExecutiveReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
      />

      {/* Minimalist Compliant Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/60 py-6 px-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-400">SurfaceGuard OS Architect</span>
            <span aria-hidden="true">·</span>
            <span>Zero-Trust Endpoint Security</span>
            <span aria-hidden="true">·</span>
            <span>Windows, Linux & macOS</span>
          </div>

          <div className="flex items-center gap-4 text-slate-400">
            <span>NIST CSF 2.0 Compliant</span>
            <span aria-hidden="true">·</span>
            <span>CIS Benchmark Aligned</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <SecurityProvider>
      <AppLayout />
    </SecurityProvider>
  );
}
