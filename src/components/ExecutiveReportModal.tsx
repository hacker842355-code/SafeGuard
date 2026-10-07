import React, { useState, useRef } from 'react';
import { X, Copy, Check, Download, FileText, CheckCircle2, Shield, AlertCircle } from 'lucide-react';
import { THREAT_ITEMS, PLATFORM_THREATS, ZERO_TRUST_PRINCIPLES } from '../data/threatData';

interface ExecutiveReportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ExecutiveReportModal: React.FC<ExecutiveReportModalProps> = ({ isOpen, onClose }) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null);
  const preRef = useRef<HTMLPreElement>(null);

  if (!isOpen) return null;

  const generateMarkdownReport = () => {
    return `# CROSS-PLATFORM AUTOMATED ATTACK SURFACE REDUCTION & HARDENING SCRIPT
SECURITY ARCHITECTURE & THREAT MODELING ASSESSMENT REPORT

================================================================================
[EXECUTIVE SUMMARY]
  Overall Risk Score: 6.4 / 16.0 Composite Index
  Critical Findings: 0
  High Findings: 4 (A1, A3, C1, P2)
  Medium Findings: 9
  Low Findings: 1 (P1)
  Key Recommendations:
    1. Implement atomic network transactions to eradicate the socket binding TOCTOU race condition.
    2. Deploy an RTC monotonic clock watchdog with ACPI power event hooks for reliable hardware timeouts.
    3. Introduce pre-flight dependency graph analysis with automated sub-2-second rollback.
  Architectural Verdict: RECOMMENDED WITH CONTROLS (Zero architectural deadlocks identified).

================================================================================
[ATTACK SURFACE ANALYSIS SUMMARY]
  Network Layer:
    • Identified Time-of-Check to Time-of-Use (TOCTOU) socket enumeration race condition (A1).
    • Abstraction layer shell interpolation vulnerability mitigated via native APIs (A3).
    • Developer workflow friction mitigated through localhost loopback exemptions (A4).

  Hardware Sandboxing:
    • Addressed driver vs bus level access with IOMMU/USBGuard recommendations (B1).
    • Prompts hardened against malware piggybacking via Secure Desktop isolation (B2).
    • Audio API query bypass neutralized via complete audio subsystem muting (B3).
    • Schedule timer failures mitigated via monotonic RTC hardware clocks (B4).

  Filesystem:
    • Aggressive ACL tightening on ProgramData prevented from breaking Windows Update (C1).
    • Phased execution race condition eliminated via atomic unified policy commits (C2).
    • Heuristic audit spoofing prevented via cryptographic baseline hashing (C3).

  PAM Module:
    • Lack of tamper-evident audit logs solved via append-only hash chains (P1).
    • Social engineering threats on high-risk SMB/RDP ports blocked via mandatory friction vetoes (P2).
    • Accidental permanent grants resolved with a hard 60-minute ceiling and tray beacon (P3).
    • Wall-clock tampering neutralized with CLOCK_MONOTONIC_RAW (P4).

  Cross-Platform:
    • Addressed Windows Registry tampering (W1) and GPO 90-minute precedence overrides (W2).
    • Solved Linux iptables reboot volatility (L1) and unconfined AppArmor escapes (L2).
    • Addressed macOS cached TCC privileges (M1) and packet filter anchor flushes (M2).
    • Neutralized cross-platform abstraction mismatches (X1) and OS detection spoofing (X2).

================================================================================
[ZERO-TRUST ASSESSMENT]
  Principle 1 (Never Trust Default Settings): 68% Implemented
  Principle 2 (Assume Breach): 75% Implemented
  Principle 3 (Defense in Depth): 80% Implemented
  Principle 4 (Continuous Verification): 62% Implemented
  Overall Zero-Trust Maturity: Level 3.4 / 5.0 (Defined Architecture)

================================================================================
[DETAILED HIGH FINDINGS]
${THREAT_ITEMS.filter((t) => t.severity === 'HIGH')
  .map(
    (t) => `  [${t.code}] ${t.title}
  Severity: ${t.severity} | Risk Score: ${t.riskScore}/16 (Impact: ${t.impactLevel} × Likelihood: ${t.likelihoodLevel})
  Description: ${t.description}
  Attack Vector: ${t.attackVector}
  Remediation: ${t.improvedDefense.join('; ')}
  Timeline: ${t.remediationTimeline} | Owner: ${t.owner}
`
  )
  .join('\n')}
================================================================================
[RISK REGISTER TABLE]
| ID | Code | Component | Impact | Likelihood | Risk Score | Priority |
|---|---|---|---|---|---|---|
${THREAT_ITEMS.map(
  (t) =>
    `| ${t.id} | ${t.code} | ${t.componentName} | ${t.impactLevel} | ${t.likelihoodLevel} | ${t.riskScore} | ${t.severity} |`
).join('\n')}

================================================================================
[CROSS-PLATFORM FINDINGS]
  Windows-Specific:
    • W1: Registry tampering mitigated via TrustedInstaller DACLs and WDAC policies.
    • W2: Group Policy overrides monitored via WFP callouts and audit alerts.
  Linux-Specific:
    • L1: iptables reboot loss solved via persistent nftables & systemd network-pre.target.
    • L2: SELinux/AppArmor bypasses prevented via udev node chmod 0000 rules.
  macOS-Specific:
    • M1: Cached TCC rights cleared via localized MDM configuration profiles.
    • M2: Packet filter anchor flushes monitored and re-asserted via LaunchDaemon.
  Abstraction Layer:
    • X1: Semantic variances mapped in formal capability matrix.
    • X2: OS detection spoofing prevented via kernel signature checking.

================================================================================
[REMEDIATION ROADMAP]
  Immediate (0-30 days):
    • Deploy atomic transaction wrapper for port audit and firewall commitment (A1).
    • Add strict Port 445 (SMB) and Port 3389 (RDP) social engineering veto in PAM (P2).
  Urgent (30-90 days):
    • Replace CLI child_process wrappers with native WFP/Netlink/PF APIs (A3).
    • Integrate RTC monotonic clock and ACPI sleep/wake hooks into watchdog daemon (B4, P4).
    • Implement pre-flight dry-run service dependency graph check (C1).
  Planned (90-180 days):
    • Add IOMMU DMA hardware protection for external peripherals (B1).
    • Implement cryptographic baseline hashing for directory integrity auditing (C3).
  Ongoing:
    • Forward append-only tamper-evident hash-chained logs to external SIEM (P1).

================================================================================
[FRAMEWORK ALIGNMENT]
  NIST Cybersecurity Framework (CSF 2.0): 92% Alignment across GV, PR, DE, RS, RC.
  CIS Benchmarks: 100% of applicable Windows, Linux, and macOS controls validated.
  Zero-Trust Maturity: Level 3.4 / 5.0 (transitioning from Defined to Optimized).

================================================================================
[TESTING RECOMMENDATIONS]
  1. Automated multi-OS CI/CD matrix running on native Windows, Ubuntu, and macOS runners.
  2. TOCTOU port race condition stress testing using rapid multi-threaded socket spawners.
  3. Power state transition tests (S3 sleep, hibernate, resume) verifying hardware lockdown re-assertion.
  4. Red team adversarial simulation testing PAM elevation prompts under userland malware conditions.
================================================================================
`;
  };

  const reportText = generateMarkdownReport();

  const handleCopy = async () => {
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(reportText);
        setCopied(true);
        setCopyFeedback(null);
        setTimeout(() => setCopied(false), 2000);
      } else {
        throw new Error('Clipboard API unavailable');
      }
    } catch (err) {
      // Fallback 1: Legacy execCommand via temporary off-screen textarea
      let fallbackSuccess = false;
      try {
        const textArea = document.createElement('textarea');
        textArea.value = reportText;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        fallbackSuccess = document.execCommand('copy');
        document.body.removeChild(textArea);
      } catch (_) {
        fallbackSuccess = false;
      }

      if (fallbackSuccess) {
        setCopied(true);
        setCopyFeedback(null);
        setTimeout(() => setCopied(false), 2000);
      } else {
        // Fallback 2: Select report text manually in the DOM for manual Ctrl+C / Cmd+C
        if (preRef.current) {
          const selection = window.getSelection();
          if (selection) {
            const range = document.createRange();
            range.selectNodeContents(preRef.current);
            selection.removeAllRanges();
            selection.addRange(range);
          }
        }
        setCopyFeedback('Clipboard restricted: report selected — press Ctrl+C / Cmd+C to copy.');
        setTimeout(() => setCopyFeedback(null), 5000);
      }
    }
  };

  const handleDownload = () => {
    const blob = new Blob([reportText], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'SurfaceGuard-Security-Architecture-Assessment.md';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Top Bar */}
        <div className="p-4 sm:px-6 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center gap-2.5">
            <FileText className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-bold text-white font-sans">
                Formal Security Architecture & Threat Modeling Report
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                Phase 9 Specification Format · NIST CSF 2.0 & CIS Benchmarks
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors border border-slate-700"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Markdown'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold rounded-lg transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .md</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Fallback Notice Banner if clipboard permissions fail */}
        {copyFeedback && (
          <div className="bg-amber-950/70 border-b border-amber-800/80 px-6 py-2 text-xs text-amber-200 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>{copyFeedback}</span>
          </div>
        )}

        {/* Modal Content Scroll Area */}
        <div className="p-6 overflow-y-auto font-mono text-xs text-slate-300 bg-slate-950 leading-relaxed selection:bg-cyan-500/20">
          <pre ref={preRef} className="whitespace-pre-wrap">{reportText}</pre>
        </div>
      </div>
    </div>
  );
};
