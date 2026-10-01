import React, { useState } from 'react';
import { 
  Search, 
  Filter, 
  ChevronDown, 
  ChevronUp, 
  ShieldAlert, 
  ShieldCheck, 
  AlertCircle, 
  Clock, 
  User, 
  ExternalLink,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { THREAT_ITEMS } from '../data/threatData';
import { ThreatItem, ComponentCategory, SeverityLevel } from '../types/security';

export const AttackSurfaceExplorer: React.FC = () => {
  const [selectedComponent, setSelectedComponent] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedId, setExpandedId] = useState<string | null>('A1');

  const filteredThreats = THREAT_ITEMS.filter((threat) => {
    const matchesComponent =
      selectedComponent === 'all' || threat.component === selectedComponent;
    const matchesSeverity =
      selectedSeverity === 'all' || threat.severity === selectedSeverity;
    const matchesSearch =
      threat.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      threat.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      threat.code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      threat.id.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesComponent && matchesSeverity && matchesSearch;
  });

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return 'text-red-400 bg-red-950/60 border-red-800/80';
      case 'HIGH':
        return 'text-amber-400 bg-amber-950/60 border-amber-800/80';
      case 'MEDIUM':
        return 'text-blue-400 bg-blue-950/60 border-blue-800/80';
      case 'LOW':
        return 'text-slate-400 bg-slate-900 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Description */}
      <div>
        <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
          Attack Surface & Threat Register
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
          Comprehensive threat modeling matrix covering 14 audited entry points across Network Ports, Hardware Sandboxing, File System ACLs, and Privilege Access Management.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
        <div className="flex flex-wrap items-center gap-1.5">
          {/* Component Tabs */}
          {[
            { id: 'all', label: 'All Entry Points' },
            { id: 'network', label: 'Network (A)' },
            { id: 'hardware', label: 'Hardware (B)' },
            { id: 'filesystem', label: 'Filesystem (C)' },
            { id: 'pam', label: 'PAM (P)' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedComponent(tab.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap ${
                selectedComponent === tab.id
                  ? 'bg-slate-800 text-cyan-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          {/* Severity selector */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="HIGH">High Severity (8-11)</option>
            <option value="MEDIUM">Medium Severity (4-7)</option>
            <option value="LOW">Low Severity (1-3)</option>
          </select>

          {/* Search box */}
          <div className="relative min-w-[200px]">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search threat, ID, CVE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-sans"
            />
          </div>
        </div>
      </div>

      {/* Threats List */}
      <div className="space-y-3">
        {filteredThreats.length === 0 ? (
          <div className="text-center py-12 bg-slate-900/30 rounded-xl border border-slate-800">
            <AlertCircle className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <div className="text-sm font-medium text-slate-300">No threats match current criteria</div>
            <div className="text-xs text-slate-500 mt-1">Try resetting the component or severity filters.</div>
          </div>
        ) : (
          filteredThreats.map((threat) => {
            const isExpanded = expandedId === threat.id;
            return (
              <div
                key={threat.id}
                className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden transition-all"
              >
                {/* Threat Header Summary Bar */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : threat.id)}
                  className="p-4 sm:px-6 cursor-pointer flex items-center justify-between gap-4 hover:bg-slate-800/40 transition-colors"
                >
                  <div className="flex items-center gap-3 sm:gap-4 min-w-0">
                    <span className="font-mono text-xs font-bold text-cyan-400 bg-slate-950 px-2 py-1 rounded border border-slate-800 shrink-0">
                      {threat.id} · {threat.code}
                    </span>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-semibold text-white truncate font-sans">
                          {threat.title}
                        </h3>
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                        <span>{threat.componentName}</span>
                        <span aria-hidden="true">·</span>
                        <span>Phase 0{threat.phase}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="hidden sm:flex items-center gap-1.5 font-mono text-xs text-slate-300 tabular-nums">
                      <span className="text-slate-400">Score:</span>
                      <span className="font-bold text-white bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                        {threat.impactLevel} × {threat.likelihoodLevel} = {threat.riskScore}
                      </span>
                    </div>

                    <span
                      className={`text-xs font-semibold px-2.5 py-0.5 rounded border font-mono ${getSeverityBadge(
                        threat.severity
                      )}`}
                    >
                      {threat.severity}
                    </span>

                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Detailed Analysis */}
                {isExpanded && (
                  <div className="px-4 pb-6 sm:px-6 pt-2 border-t border-slate-800/80 space-y-5 bg-slate-950/40">
                    {/* Description and Attack Vector */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                          Attack Scenario
                        </div>
                        <p className="text-xs text-slate-200 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                          {threat.description}
                        </p>
                      </div>

                      <div className="space-y-1.5">
                        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                          Attack Vector
                        </div>
                        <p className="text-xs text-slate-200 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-800 font-mono">
                          {threat.attackVector}
                        </p>
                      </div>
                    </div>

                    {/* Mitigation vs Identified Gap */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <div className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Current Mitigation in Script</span>
                        </div>
                        <p className="text-xs text-slate-300 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                          {threat.currentMitigation}
                        </p>
                      </div>

                      <div className="space-y-1.5">
                        <div className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>Identified Architectural Gap</span>
                        </div>
                        <p className="text-xs text-slate-300 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                          {threat.gapAnalysis}
                        </p>
                      </div>
                    </div>

                    {/* Concrete Improved Defenses */}
                    <div className="space-y-2">
                      <div className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">
                        Architectural Defense Recommendations
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {threat.improvedDefense.map((defense, idx) => (
                          <div
                            key={idx}
                            className="flex items-start gap-2 bg-slate-900/70 p-2.5 rounded-lg border border-slate-800/80 text-xs text-slate-200"
                          >
                            <span className="text-cyan-400 font-mono font-bold mt-0.5">□</span>
                            <span>{defense}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Remediation Metadata Footer */}
                    <div className="pt-3 border-t border-slate-800/60 flex flex-wrap items-center justify-between text-xs text-slate-400 gap-3 font-mono">
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Timeline: {threat.remediationTimeline}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span>Effort: {threat.remediationEffort}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <User className="w-3.5 h-3.5 text-slate-400" />
                        <span>Owner: {threat.owner}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
