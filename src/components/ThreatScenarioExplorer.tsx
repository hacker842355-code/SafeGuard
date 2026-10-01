import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Layers, 
  Terminal, 
  Network, 
  MicOff, 
  FolderLock, 
  KeyRound, 
  Cpu, 
  Search, 
  Filter, 
  ChevronDown, 
  ChevronUp, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  FileText, 
  Download, 
  Copy, 
  Check, 
  Sparkles, 
  Play, 
  ArrowRight,
  Monitor,
  Apple
} from 'lucide-react';
import { 
  PROJECT2_SCENARIOS, 
  ATTACK_SURFACE_SUBCOMPONENTS, 
  INITIAL_OBSERVATIONS,
  Project2ThreatScenario 
} from '../data/project2ScenariosData';

export const ThreatScenarioExplorer: React.FC = () => {
  const [selectedComponent, setSelectedComponent] = useState<string>('all');
  const [selectedThreatActor, setSelectedThreatActor] = useState<string>('all');
  const [selectedLikelihood, setSelectedLikelihood] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedScenarioId, setExpandedScenarioId] = useState<string | null>('SCN-A1');
  const [activeStepIndex, setActiveStepIndex] = useState<{ [key: string]: number }>({});
  const [copied, setCopied] = useState<boolean>(false);
  const [activeSubTab, setActiveSubTab] = useState<'scenarios' | 'tree' | 'observations'>('scenarios');

  const filteredScenarios = PROJECT2_SCENARIOS.filter((s) => {
    const matchesComponent = selectedComponent === 'all' || s.componentLetter === selectedComponent;
    const matchesThreatActor =
      selectedThreatActor === 'all' ||
      s.threatActors.some((ta) => ta.toLowerCase().includes(selectedThreatActor.toLowerCase()));
    const matchesLikelihood = selectedLikelihood === 'all' || s.likelihood === selectedLikelihood;
    const matchesSearch =
      s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.attackDescription.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.subComponentName.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesComponent && matchesThreatActor && matchesLikelihood && matchesSearch;
  });

  const getLikelihoodBadge = (lh: string) => {
    switch (lh) {
      case 'VERY HIGH':
        return 'text-red-400 bg-red-950/60 border-red-800';
      case 'HIGH':
        return 'text-amber-400 bg-amber-950/60 border-amber-800';
      case 'MEDIUM':
        return 'text-blue-400 bg-blue-950/60 border-blue-800';
      case 'LOW':
      case 'VERY LOW':
        return 'text-slate-400 bg-slate-900 border-slate-700';
      default:
        return 'text-slate-400 bg-slate-900 border-slate-800';
    }
  };

  const getImpactBadge = (impact: string) => {
    switch (impact) {
      case 'CRITICAL':
        return 'text-red-400 bg-red-950/80 border-red-700';
      case 'HIGH':
        return 'text-amber-400 bg-amber-950/80 border-amber-700';
      case 'MEDIUM':
        return 'text-blue-400 bg-blue-950/80 border-blue-700';
      default:
        return 'text-slate-400 bg-slate-900 border-slate-800';
    }
  };

  const handleCopyReport = () => {
    let report = `# PROJECT 2 - PART 1: ATTACK SURFACE MAPPING & THREAT SCENARIO DEVELOPMENT\n\n`;
    report += `## EXECUTIVE SUMMARY\n`;
    report += `- Total Attack Surface Components Analyzed: 5 (A, B, C, D, E)\n`;
    report += `- Total Detailed Threat Scenarios: ${PROJECT2_SCENARIOS.length}\n`;
    report += `- Component Breakdown:\n`;
    report += `  • Component A (Network Port Management): 5 scenarios\n`;
    report += `  • Component B (Hardware Sandboxing): 5 scenarios\n`;
    report += `  • Component C (File System Hardening): 4 scenarios\n`;
    report += `  • Component D (Privilege Access Management): 5 scenarios\n`;
    report += `  • Component E (Cross-Platform Implementation): 6 scenarios\n\n`;

    PROJECT2_SCENARIOS.forEach((s) => {
      report += `================================================================================\n`;
      report += `SCENARIO NAME: [${s.id}] ${s.name}\n`;
      report += `Affected Component: Component ${s.componentLetter} (${s.componentName}) -> Sub-component ${s.subComponentCode}: ${s.subComponentName}\n`;
      report += `Attack Vector: ${s.attackVector}\n`;
      report += `Likelihood of Exploitation: ${s.likelihood} (Justification: ${s.likelihoodJustification})\n`;
      report += `Impact if Compromised: ${s.impact} (Consequences: ${s.impactConsequences})\n\n`;
      report += `Attack Description:\n${s.attackDescription}\n\n`;
      report += `Attack Steps:\n${s.attackSteps.map((st) => `  ${st}`).join('\n')}\n\n`;
      report += `Current Mitigation/Defense:\n${s.currentMitigation}\n\n`;
      report += `Gaps in Current Defense:\n${s.gapsInDefense}\n\n`;
      report += `Recommended Improvements:\n${s.recommendedImprovements.map((imp) => `  □ ${imp}`).join('\n')}\n\n`;
      report += `Cross-Platform Nuance:\n`;
      report += `  • Windows: ${s.crossPlatformNuance.windows}\n`;
      report += `  • Linux: ${s.crossPlatformNuance.linux}\n`;
      report += `  • macOS: ${s.crossPlatformNuance.macos}\n\n`;
    });

    navigator.clipboard.writeText(report);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Headline Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 sm:p-8 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Project 2 · Part 1 Deliverable</span>
              <span aria-hidden="true">·</span>
              <span>25 Structured Threat Scenarios</span>
              <span aria-hidden="true">·</span>
              <span>NIST Attack Surface Framework</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white font-sans text-balance">
              Attack Surface Mapping & Threat Scenario Development
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed">
              Systematic Chain-of-Thought (CoT) threat scenario modeling dissecting all 5 core components across 31 sub-components, mapping exploit chains against Passive Adversaries, Active Exploiters, and Sophisticated APTs.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleCopyReport}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-slate-950" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied Full Report' : 'Copy Part 1 Report'}</span>
            </button>
          </div>
        </div>

        {/* Executive Summary Metrics Grid */}
        <div className="pt-4 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs font-mono">
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[11px]">Comp A: Network</div>
            <div className="text-base font-bold text-cyan-400 mt-0.5">5 Scenarios</div>
            <div className="text-[10px] text-slate-400">TOCTOU, Injections, Tunnels</div>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[11px]">Comp B: Hardware</div>
            <div className="text-base font-bold text-indigo-400 mt-0.5">5 Scenarios</div>
            <div className="text-[10px] text-slate-400">DMA, Audio Bypass, Sleep</div>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[11px]">Comp C: Filesystem</div>
            <div className="text-base font-bold text-emerald-400 mt-0.5">4 Scenarios</div>
            <div className="text-[10px] text-slate-400">OS Patch DoS, ADS, Race</div>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[11px]">Comp D: PAM</div>
            <div className="text-base font-bold text-purple-400 mt-0.5">5 Scenarios</div>
            <div className="text-[10px] text-slate-400">Log Wipe, Time Tamper</div>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[11px]">Comp E: Cross-Platform</div>
            <div className="text-base font-bold text-amber-400 mt-0.5">6 Scenarios</div>
            <div className="text-[10px] text-slate-400">GPO, Reboot Loss, Spoof</div>
          </div>
        </div>
      </div>

      {/* Sub-Tabs: Scenarios vs Attack Tree vs Initial Observations */}
      <div className="flex items-center gap-1.5 bg-slate-900/60 p-1.5 rounded-xl border border-slate-800 w-fit">
        <button
          onClick={() => setActiveSubTab('scenarios')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeSubTab === 'scenarios'
              ? 'bg-slate-800 text-cyan-400 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          25 Detailed Threat Scenarios
        </button>
        <button
          onClick={() => setActiveSubTab('tree')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeSubTab === 'tree'
              ? 'bg-slate-800 text-cyan-400 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Attack Surface Tree & Hierarchy
        </button>
        <button
          onClick={() => setActiveSubTab('observations')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeSubTab === 'observations'
              ? 'bg-slate-800 text-cyan-400 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Initial Observations & Gaps
        </button>
      </div>

      {/* SUB-TAB 1: DETAILED SCENARIOS */}
      {activeSubTab === 'scenarios' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
            <div className="flex flex-wrap items-center gap-1.5">
              {[
                { id: 'all', label: 'All Components' },
                { id: 'A', label: 'Comp A: Network' },
                { id: 'B', label: 'Comp B: Hardware' },
                { id: 'C', label: 'Comp C: Filesystem' },
                { id: 'D', label: 'Comp D: PAM' },
                { id: 'E', label: 'Comp E: Platforms' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setSelectedComponent(tab.id)}
                  className={`px-2.5 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap ${
                    selectedComponent === tab.id
                      ? 'bg-slate-800 text-cyan-400 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* Threat Actor Filter */}
              <select
                value={selectedThreatActor}
                onChange={(e) => setSelectedThreatActor(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Threat Actors</option>
                <option value="Passive">Level 1: Passive Adversaries</option>
                <option value="Active">Level 2: Active Exploiters</option>
                <option value="Sophisticated">Level 3: Sophisticated APTs</option>
              </select>

              {/* Likelihood Selector */}
              <select
                value={selectedLikelihood}
                onChange={(e) => setSelectedLikelihood(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Likelihoods</option>
                <option value="VERY HIGH">Very High Likelihood</option>
                <option value="HIGH">High Likelihood</option>
                <option value="MEDIUM">Medium Likelihood</option>
                <option value="LOW">Low Likelihood</option>
              </select>

              {/* Search box */}
              <div className="relative min-w-[200px]">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search scenarios..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>
            </div>
          </div>

          {/* Scenario Cards */}
          <div className="space-y-4">
            {filteredScenarios.map((scenario) => {
              const isExpanded = expandedScenarioId === scenario.id;
              const currentStep = activeStepIndex[scenario.id] || 0;

              return (
                <div
                  key={scenario.id}
                  className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden transition-all"
                >
                  {/* Scenario Bar */}
                  <div
                    onClick={() => setExpandedScenarioId(isExpanded ? null : scenario.id)}
                    className="p-4 sm:px-6 cursor-pointer flex items-center justify-between gap-4 hover:bg-slate-800/40 transition-colors"
                  >
                    <div className="flex items-center gap-3 sm:gap-4 min-w-0">
                      <span className="font-mono text-xs font-bold text-cyan-400 bg-slate-950 px-2 py-1 rounded border border-slate-800 shrink-0">
                        {scenario.id}
                      </span>
                      <div className="min-w-0">
                        <h3 className="text-sm font-semibold text-white truncate font-sans">
                          {scenario.name}
                        </h3>
                        <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                          <span className="text-cyan-400 font-mono">Comp {scenario.componentLetter}</span>
                          <span aria-hidden="true">·</span>
                          <span>Sub-comp {scenario.subComponentCode}: {scenario.subComponentName}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2.5 shrink-0">
                      <span
                        className={`text-[11px] font-semibold px-2 py-0.5 rounded border font-mono ${getLikelihoodBadge(
                          scenario.likelihood
                        )}`}
                      >
                        {scenario.likelihood} LIKELIHOOD
                      </span>
                      <span
                        className={`text-[11px] font-semibold px-2 py-0.5 rounded border font-mono ${getImpactBadge(
                          scenario.impact
                        )}`}
                      >
                        {scenario.impact} IMPACT
                      </span>
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-slate-400" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-400" />
                      )}
                    </div>
                  </div>

                  {/* Expanded Scenario Details */}
                  {isExpanded && (
                    <div className="px-4 pb-6 sm:px-6 pt-3 border-t border-slate-800/80 space-y-5 bg-slate-950/40 text-xs">
                      {/* Step-by-Step Attack Execution Chain Simulator */}
                      <div className="bg-slate-900/70 p-4 rounded-xl border border-slate-800 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 text-cyan-400 font-semibold">
                            <Play className="w-3.5 h-3.5" />
                            <span>Interactive Attack Flow Chain (Kill Chain Walkthrough)</span>
                          </div>
                          <span className="text-[11px] font-mono text-slate-400">
                            Step {currentStep + 1} of {scenario.attackSteps.length}
                          </span>
                        </div>

                        {/* Step Tabs */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
                          {scenario.attackSteps.map((step, idx) => (
                            <button
                              key={idx}
                              onClick={(e) => {
                                e.stopPropagation();
                                setActiveStepIndex({ ...activeStepIndex, [scenario.id]: idx });
                              }}
                              className={`p-2 text-left rounded-lg transition-colors border ${
                                currentStep === idx
                                  ? 'bg-cyan-950/80 text-cyan-300 border-cyan-800'
                                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                              }`}
                            >
                              <div className="font-mono text-[10px] font-bold">Stage 0{idx + 1}</div>
                              <div className="text-[11px] truncate mt-0.5">{step.split(':')[1] || step}</div>
                            </button>
                          ))}
                        </div>

                        {/* Active Step Highlight Box */}
                        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-200 font-mono text-xs leading-relaxed flex items-start gap-2">
                          <ArrowRight className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                          <span>{scenario.attackSteps[currentStep]}</span>
                        </div>
                      </div>

                      {/* Attack Description & Vector */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-1.5">
                          <span className="text-slate-400 font-semibold uppercase tracking-wider text-[11px] block">
                            Detailed Exploit Description
                          </span>
                          <p className="text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-800 font-sans">
                            {scenario.attackDescription}
                          </p>
                        </div>

                        <div className="space-y-1.5">
                          <span className="text-slate-400 font-semibold uppercase tracking-wider text-[11px] block">
                            Attack Vector & Affected Sub-Component
                          </span>
                          <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 space-y-2">
                            <div>
                              <span className="text-slate-500 text-[11px] block">Vector Path:</span>
                              <p className="text-amber-400 font-mono text-xs">{scenario.attackVector}</p>
                            </div>
                            <div>
                              <span className="text-slate-500 text-[11px] block">Target Threat Actors:</span>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {scenario.threatActors.map((ta, i) => (
                                  <span key={i} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-[11px]">
                                    {ta}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Likelihood & Impact Justifications */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-400 font-semibold">Likelihood Evaluation:</span>
                            <span className="font-mono font-bold text-amber-400">{scenario.likelihood}</span>
                          </div>
                          <p className="text-slate-300 text-[11px] leading-relaxed">
                            {scenario.likelihoodJustification}
                          </p>
                        </div>

                        <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-400 font-semibold">Impact Consequences:</span>
                            <span className="font-mono font-bold text-red-400">{scenario.impact}</span>
                          </div>
                          <p className="text-slate-300 text-[11px] leading-relaxed">
                            {scenario.impactConsequences}
                          </p>
                        </div>
                      </div>

                      {/* Mitigation vs Gaps */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-1.5">
                          <div className="text-emerald-400 font-semibold flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>Current Mitigation</span>
                          </div>
                          <p className="text-slate-300 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                            {scenario.currentMitigation}
                          </p>
                        </div>

                        <div className="space-y-1.5">
                          <div className="text-amber-400 font-semibold flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            <span>Identified Defense Gaps</span>
                          </div>
                          <p className="text-slate-300 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                            {scenario.gapsInDefense}
                          </p>
                        </div>
                      </div>

                      {/* Recommended Improvements Checklist */}
                      <div className="space-y-1.5">
                        <span className="text-cyan-400 font-semibold uppercase tracking-wider text-[11px] block">
                          Recommended Actionable Improvements (Project 2 Defense Blueprint)
                        </span>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {scenario.recommendedImprovements.map((imp, idx) => (
                            <div
                              key={idx}
                              className="flex items-start gap-2 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 text-slate-200"
                            >
                              <span className="text-cyan-400 font-mono font-bold mt-0.5">□</span>
                              <span>{imp}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Cross-Platform Nuances */}
                      <div className="space-y-1.5 pt-2 border-t border-slate-800/60">
                        <span className="text-slate-400 font-semibold uppercase tracking-wider text-[11px] block">
                          Cross-Platform Vulnerability Nuances
                        </span>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                          <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 space-y-1">
                            <div className="flex items-center gap-1.5 text-cyan-400 font-semibold text-[11px]">
                              <Monitor className="w-3.5 h-3.5" />
                              <span>Windows Nuance</span>
                            </div>
                            <p className="text-slate-400 text-[11px]">{scenario.crossPlatformNuance.windows}</p>
                          </div>

                          <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 space-y-1">
                            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-[11px]">
                              <Terminal className="w-3.5 h-3.5" />
                              <span>Linux Nuance</span>
                            </div>
                            <p className="text-slate-400 text-[11px]">{scenario.crossPlatformNuance.linux}</p>
                          </div>

                          <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 space-y-1">
                            <div className="flex items-center gap-1.5 text-indigo-400 font-semibold text-[11px]">
                              <Apple className="w-3.5 h-3.5" />
                              <span>macOS Nuance</span>
                            </div>
                            <p className="text-slate-400 text-[11px]">{scenario.crossPlatformNuance.macos}</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SUB-TAB 2: ATTACK SURFACE TREE & HIERARCHY */}
      {activeSubTab === 'tree' && (
        <div className="space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl text-xs text-slate-300">
            Structural decomposition mapping <strong>Component (A–E) → Sub-Component (A1–E6) → Threat Scenarios</strong> with likelihood profile distribution.
          </div>

          <div className="space-y-5">
            {ATTACK_SURFACE_SUBCOMPONENTS.map((comp) => {
              const compScenarios = PROJECT2_SCENARIOS.filter(
                (s) => s.componentLetter === comp.letter
              );
              return (
                <div key={comp.letter} className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                    <div className="flex items-center gap-2">
                      <span className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-800/80 flex items-center justify-center font-mono font-bold text-cyan-400 text-xs">
                        {comp.letter}
                      </span>
                      <h3 className="text-base font-bold text-white font-sans">
                        Component {comp.letter}: {comp.name}
                      </h3>
                    </div>
                    <span className="text-xs font-mono text-cyan-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                      {compScenarios.length} Analyzed Scenarios
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {comp.subComponents.map((sub) => {
                      const linked = compScenarios.filter((s) => s.subComponentCode === sub.code);
                      return (
                        <div
                          key={sub.code}
                          className="bg-slate-950/70 p-3.5 rounded-lg border border-slate-800 space-y-2"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-xs font-bold text-cyan-400">
                              {sub.code}
                            </span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 font-mono">
                              {linked.length} {linked.length === 1 ? 'threat' : 'threats'}
                            </span>
                          </div>
                          <div className="text-xs font-semibold text-slate-200">
                            {sub.name}
                          </div>
                          {linked.length > 0 && (
                            <div className="pt-1 border-t border-slate-800/60 space-y-1">
                              {linked.map((l) => (
                                <div key={l.id} className="text-[11px] text-slate-400 flex items-center gap-1.5">
                                  <span className="text-cyan-400 font-mono">↳</span>
                                  <span className="truncate">{l.name}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SUB-TAB 3: INITIAL OBSERVATIONS & GAPS */}
      {activeSubTab === 'observations' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Most Critical */}
            <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-red-400 font-semibold text-xs uppercase tracking-wider">
                <ShieldAlert className="w-4 h-4" />
                <span>Most Critical Architectural Vulnerabilities</span>
              </div>
              <h4 className="text-sm font-bold text-white font-sans">
                {INITIAL_OBSERVATIONS.mostCriticalVulnerability.title}
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                {INITIAL_OBSERVATIONS.mostCriticalVulnerability.explanation}
              </p>
            </div>

            {/* Most Likely Vector */}
            <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" />
                <span>Most Likely Real-World Attack Vectors</span>
              </div>
              <h4 className="text-sm font-bold text-white font-sans">
                {INITIAL_OBSERVATIONS.mostLikelyAttackVector.title}
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                {INITIAL_OBSERVATIONS.mostLikelyAttackVector.explanation}
              </p>
            </div>

            {/* Largest Gap */}
            <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs uppercase tracking-wider">
                <Layers className="w-4 h-4" />
                <span>Largest Gap in Current Defenses</span>
              </div>
              <h4 className="text-sm font-bold text-white font-sans">
                {INITIAL_OBSERVATIONS.largestGapInDefense.title}
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                {INITIAL_OBSERVATIONS.largestGapInDefense.explanation}
              </p>
            </div>

            {/* PAM Vulnerabilities */}
            <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-purple-400 font-semibold text-xs uppercase tracking-wider">
                <KeyRound className="w-4 h-4" />
                <span>Privilege Access Management (PAM) Risks</span>
              </div>
              <h4 className="text-sm font-bold text-white font-sans">
                {INITIAL_OBSERVATIONS.pamModuleVulnerabilities.title}
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                {INITIAL_OBSERVATIONS.pamModuleVulnerabilities.explanation}
              </p>
            </div>
          </div>

          {/* Cross Platform Inconsistency Callout */}
          <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl space-y-2">
            <div className="flex items-center gap-2 text-indigo-400 font-semibold text-xs uppercase tracking-wider">
              <Cpu className="w-4 h-4" />
              <span>Cross-Platform Inconsistency & Abstraction Blindspots</span>
            </div>
            <h4 className="text-sm font-bold text-white font-sans">
              {INITIAL_OBSERVATIONS.crossPlatformInconsistencyRisks.title}
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
              {INITIAL_OBSERVATIONS.crossPlatformInconsistencyRisks.explanation}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
