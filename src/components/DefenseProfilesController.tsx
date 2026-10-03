import React from 'react';
import { 
  Shield, 
  Building2, 
  Home,
  Code, 
  RotateCcw, 
  CheckCircle2, 
  Zap, 
  Loader2, 
  Terminal, 
  Layers,
  Network,
  Lock,
  Cpu,
  Tv,
  Printer,
  Wifi,
  Radio,
  EyeOff,
  Flame,
  ShieldAlert
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { SecurityProfileMode } from '../types/security';

interface ProfileCardConfig {
  id: SecurityProfileMode;
  name: string;
  badge: string;
  tagline: string;
  icon: React.ComponentType<{ className?: string }>;
  accentColor: string;
  accentBg: string;
  borderActive: string;
  bgActive: string;
  buttonBg: string;
  categories: {
    title: string;
    points: string[];
  }[];
  technicalCommands: string[];
  bestFor: string;
}

export const DefenseProfilesController: React.FC = () => {
  const { 
    activeProfile, 
    applyProfile, 
    profileLoading, 
    isApplyingProfile,
    terminalLogs 
  } = useSecurity();

  const profiles: ProfileCardConfig[] = [
    // 1. MAXIMUM STEALTH / PUBLIC WI-FI MODE
    {
      id: 'stealth',
      name: 'Maximum Stealth / Public Wi-Fi Mode',
      badge: 'ANTI-RESPONDER & ZERO TRUST',
      tagline: 'Completely seals your PC against external network probes, LLMNR poisoning, and Wi-Fi eavesdropping.',
      icon: Shield,
      accentColor: 'text-emerald-400',
      accentBg: 'bg-emerald-950/60 border-emerald-800/80',
      borderActive: 'border-emerald-500 shadow-[0_0_25px_rgba(16,185,129,0.2)] ring-1 ring-emerald-500',
      bgActive: 'bg-emerald-950/20',
      buttonBg: 'bg-emerald-600 hover:bg-emerald-500 text-slate-950',
      categories: [
        {
          title: 'Network & Stealth',
          points: [
            'Inbound Drop All: blocks all incoming unsolicited packets (TCP 1-65535)',
            'Windows Stealth Mode active (silent drop, suppresses ICMP unreachable)',
            'Inbound connection notification prompts suppressed',
          ],
        },
        {
          title: 'Poisoning Defense',
          points: [
            'Disable LLMNR via Registry (EnableMulticast=0 to prevent Responder theft)',
            'Hard-block NetBIOS Name (UDP 137), Datagram (UDP 138), Session (TCP 139)',
          ],
        },
        {
          title: 'Device Governance',
          points: [
            'Disable USB Mass Storage driver (USBSTOR Start=4 to stop BadUSB)',
            'Disable Bluetooth radio discovery & pairing',
            'Lock Webcam & Microphone ConsentStore to "Deny"',
          ],
        },
      ],
      technicalCommands: [
        'netsh advfirewall set allprofiles settings openinboundconnectionnotify disable',
        'netsh advfirewall firewall add rule name="SurfaceGuard_Block_All_Unlisted" dir=in action=block protocol=TCP localport=1-65535',
        'Set-ItemProperty "HKLM:\\SOFTWARE\\Policies\\...\\DNSClient" -Name "EnableMulticast" -Value 0',
        'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 4',
      ],
      bestFor: 'Public Wi-Fi networks (cafes, airports, hotels), high-risk operations, travel, and untrusted LANs.',
    },

    // 2. CORPORATE / ENTERPRISE LOCKDOWN MODE
    {
      id: 'corporate',
      name: 'Corporate / Enterprise Lockdown Mode',
      badge: 'DLP & ANTI-RANSOMWARE',
      tagline: 'Blocks lateral movement exploit vectors, locks down removable media, and protects Volume Shadow Copies.',
      icon: Building2,
      accentColor: 'text-cyan-400',
      accentBg: 'bg-cyan-950/60 border-cyan-800/80',
      borderActive: 'border-cyan-500 shadow-[0_0_25px_rgba(6,182,212,0.2)] ring-1 ring-cyan-500',
      bgActive: 'bg-cyan-950/20',
      buttonBg: 'bg-cyan-600 hover:bg-cyan-500 text-slate-950',
      categories: [
        {
          title: 'Lateral Attack Prevention',
          points: [
            'Block SMB Port 445 (WannaCry / EternalBlue / lateral worm defense)',
            'Block Remote Desktop Protocol (RDP Port 3389)',
            'Block Remote Procedure Call (RPC Port 135)',
            'Block WinRM PowerShell Remote Management (Ports 5985 & 5986)',
          ],
        },
        {
          title: 'Data Loss Prevention (DLP)',
          points: [
            'Restrict USB Mass Storage (USBSTOR Start=4) against flash drive exfiltration',
            'Lock Camera & Microphone ConsentStores to "Deny"',
          ],
        },
        {
          title: 'Ransomware Precaution',
          points: [
            'Restrict vssadmin.exe execution to Administrators and SYSTEM (prevents shadow copy purging)',
          ],
        },
      ],
      technicalCommands: [
        'netsh advfirewall firewall add rule name="SurfaceGuard_Block_445" dir=in action=block localport=445',
        'netsh advfirewall firewall add rule name="SurfaceGuard_Block_3389" dir=in action=block localport=3389',
        'netsh advfirewall firewall add rule name="SurfaceGuard_Block_5985" dir=in action=block localport=5985',
        'icacls "$env:SystemRoot\\System32\\vssadmin.exe" /inheritance:r /grant Administrators:F SYSTEM:F',
      ],
      bestFor: 'Corporate laptops, enterprise workstations, defense against lateral malware, and strict compliance.',
    },

    // 3. HOME & EVERYDAY USER MODE (NEW 5TH PROFILE)
    {
      id: 'home',
      name: 'Home & Everyday User Mode',
      badge: 'BALANCED DAILY BASELINE',
      tagline: 'Ensures frictionless daily gaming, streaming, video calls, and printing while keeping background OS defenses hardened.',
      icon: Home,
      accentColor: 'text-blue-400',
      accentBg: 'bg-blue-950/60 border-blue-800/80',
      borderActive: 'border-blue-500 shadow-[0_0_25px_rgba(59,130,246,0.2)] ring-1 ring-blue-500',
      bgActive: 'bg-blue-950/20',
      buttonBg: 'bg-blue-600 hover:bg-blue-500 text-white',
      categories: [
        {
          title: 'Network & Local Subnet',
          points: [
            'Inbound SMB 445 and NetBIOS (137, 138, 139) dropped from untrusted sources',
            'Permits local LAN subnet discovery for wireless printers (TCP 9100)',
            'Enables mDNS discovery for Smart TVs & Chromecast (UDP 5353 localsubnet)',
          ],
        },
        {
          title: 'Defense & Privacy',
          points: [
            'Disable LLMNR Multicast (EnableMulticast=0) against credential spoofing',
            'Block background telemetry daemons (compattelrunner.exe, diagtrack.exe)',
          ],
        },
        {
          title: 'Daily Usability',
          points: [
            'USB Storage, Bluetooth, Webcam, and Mic fully ENABLED (USBSTOR Start=3, ConsentStore=Allow)',
            'Zero interruption for Zoom/Teams calls, Steam gaming, and wireless headsets',
          ],
        },
      ],
      technicalCommands: [
        'netsh advfirewall firewall add rule name="SurfaceGuard_Block_445" dir=in action=block localport=445',
        'netsh advfirewall firewall add rule name="SurfaceGuard_Allow_LAN_Printers" dir=in action=allow localport=9100 remoteip=localsubnet',
        'Set-ItemProperty "HKLM:\\SOFTWARE\\Policies\\...\\DNSClient" -Name "EnableMulticast" -Value 0',
        'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 3',
      ],
      bestFor: 'Home PCs, casual web browsing, streaming media, home office Zoom calls, gaming, and local network printing.',
    },

    // 4. DEVELOPER SANDBOX MODE
    {
      id: 'developer',
      name: 'Developer Sandbox Mode',
      badge: 'ISOLATED LOCALHOST & DEBUGGER SHIELD',
      tagline: 'Permits local development preview on 127.0.0.1 while strictly shielding debuggers from external LAN/WAN.',
      icon: Code,
      accentColor: 'text-purple-400',
      accentBg: 'bg-purple-950/60 border-purple-800/80',
      borderActive: 'border-purple-500 shadow-[0_0_25px_rgba(168,85,247,0.2)] ring-1 ring-purple-500',
      bgActive: 'bg-purple-950/20',
      buttonBg: 'bg-purple-600 hover:bg-purple-500 text-white',
      categories: [
        {
          title: 'Loopback Isolation',
          points: [
            'Permit development web servers (3000, 5173, 8000, 8080) strictly on 127.0.0.1',
            'Block external LAN/WAN addresses from reaching local development servers',
          ],
        },
        {
          title: 'Debugger Protection',
          points: [
            'Lock Chrome & Node.js Debugger (Port 9229) strictly to loopback (!127.0.0.1 remote IP drop)',
            'Prevents remote arbitrary code execution via exposed inspector endpoints',
          ],
        },
        {
          title: 'Telemetry Blocker',
          points: [
            'Block Windows Compatibility Telemetry (compattelrunner.exe)',
            'Block Connected User Experiences Telemetry (diagtrack.exe)',
          ],
        },
      ],
      technicalCommands: [
        'netsh advfirewall firewall add rule name="SurfaceGuard_Block_9229" dir=in action=block remoteip="!127.0.0.1"',
        'netsh advfirewall firewall add rule name="SurfaceGuard_Block_Proc_compattelrunner.exe" dir=out action=block',
        'netsh advfirewall firewall add rule name="SurfaceGuard_Block_Proc_diagtrack.exe" dir=out action=block',
      ],
      bestFor: 'Full-stack software engineers, web developers, local Docker testing, and secure debugging.',
    },

    // 5. FACTORY RESET / DEFAULT BASELINE
    {
      id: 'reset',
      name: 'Factory Reset / Default Baseline',
      badge: '1-CLICK NATIVE RESTORATION',
      tagline: 'Restores Windows to clean native defaults, re-enabling standard network and device permissions.',
      icon: RotateCcw,
      accentColor: 'text-amber-400',
      accentBg: 'bg-amber-950/60 border-amber-800/80',
      borderActive: 'border-amber-500 shadow-[0_0_25px_rgba(245,158,11,0.2)] ring-1 ring-amber-500',
      bgActive: 'bg-amber-950/20',
      buttonBg: 'bg-amber-600 hover:bg-amber-500 text-slate-950',
      categories: [
        {
          title: 'Rule Cleanup',
          points: [
            'Delete all SurfaceGuard_* firewall rules across all Windows profiles',
            'Delete global unlisted ports block rule',
            'Re-enable inbound connection notification alerts',
          ],
        },
        {
          title: 'Service Restoration',
          points: [
            'Re-enable LLMNR Multicast resolution (EnableMulticast = 1)',
            'Re-enable USB Mass Storage driver (USBSTOR Start=3)',
            'Re-enable Bluetooth PnP radio controllers',
          ],
        },
        {
          title: 'Privacy Permissions',
          points: [
            'Restore Camera and Microphone ConsentStore to Allow',
            'Restore standard ProgramData and vssadmin ACL inheritance',
          ],
        },
      ],
      technicalCommands: [
        'Get-NetFirewallRule -Name "SurfaceGuard_*" | Remove-NetFirewallRule',
        'Set-ItemProperty "HKLM:\\SOFTWARE\\Policies\\...\\DNSClient" -Name "EnableMulticast" -Value 1',
        'Set-ItemProperty "HKLM:\\SYSTEM\\...\\Services\\USBSTOR" -Name "Start" -Value 3',
        'Set-ItemProperty "HKLM:\\SOFTWARE\\...\\ConsentStore\\webcam" -Name "Value" -Value "Allow"',
      ],
      bestFor: 'Restoring standard Windows defaults, uninstalling hardening rules, and troubleshooting network software.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header and Live Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
            <Layers className="w-3.5 h-3.5" />
            <span>Multi-Tier Defense Controller</span>
            <span aria-hidden="true">·</span>
            <span className="capitalize">{activeProfile} Baseline Active</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans mt-0.5">
            Defense Modes & Security Profiles
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
            Instantly reconfigure your entire PC firewall, registry poisoning defenses, and hardware access controls with a single click. Zero optimistic UI—state commits strictly upon verified OS execution.
          </p>
        </div>

        {/* Active Profile Status Badge */}
        <div className="bg-slate-900 border border-slate-800 p-2.5 rounded-xl flex items-center gap-3 self-start sm:self-auto shadow-inner">
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          <div className="text-xs">
            <span className="text-slate-400 block text-[10px] font-mono uppercase tracking-wider">Active Policy:</span>
            <span className="font-bold text-white capitalize font-sans">{activeProfile} Profile</span>
          </div>
        </div>
      </div>

      {/* Profiles Cards Grid (5 Profiles) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {profiles.map((p) => {
          const Icon = p.icon;
          const isActive = activeProfile === p.id;
          const isLoading = profileLoading === p.id;

          return (
            <div
              key={p.id}
              className={`p-5 rounded-2xl border flex flex-col justify-between transition-all duration-200 ${
                isActive
                  ? `${p.bgActive} ${p.borderActive}`
                  : 'bg-slate-900/50 border-slate-800 hover:border-slate-700/80 shadow-lg'
              }`}
            >
              <div className="space-y-4">
                {/* Header Row */}
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-center ${p.accentColor} shadow-inner shrink-0`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm sm:text-base font-bold text-white font-sans leading-snug">
                        {p.name}
                      </h3>
                      <span className="text-[10px] font-mono text-slate-400 block tracking-wider mt-0.5">
                        {p.badge}
                      </span>
                    </div>
                  </div>

                  {isActive && (
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 whitespace-nowrap shadow-sm">
                      ACTIVE
                    </span>
                  )}
                  {isLoading && (
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 flex items-center gap-1 whitespace-nowrap">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      ENFORCING...
                    </span>
                  )}
                </div>

                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {p.tagline}
                </p>

                {/* Structured Feature Categories */}
                <div className="space-y-3 pt-3 border-t border-slate-800/80">
                  {p.categories.map((cat, cIdx) => (
                    <div key={cIdx} className="space-y-1.5">
                      <div className="text-[11px] font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full ${p.accentColor.replace('text-', 'bg-')}`} />
                        <span>{cat.title}</span>
                      </div>
                      <ul className="space-y-1 text-xs text-slate-400 pl-3">
                        {cat.points.map((pt, pIdx) => (
                          <li key={pIdx} className="flex items-start gap-2 leading-relaxed">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400/90 shrink-0 mt-0.5" />
                            <span>{pt}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>

                {/* Live PowerShell Command Preview Box */}
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-[10px] text-slate-400 space-y-1 overflow-x-auto">
                  <div className="text-slate-500 text-[9px] uppercase tracking-wider font-semibold">
                    OS PowerShell Command Preview:
                  </div>
                  {p.technicalCommands.slice(0, 2).map((cmd, cmdIdx) => (
                    <div key={cmdIdx} className="truncate text-slate-400" title={cmd}>
                      <span className="text-cyan-500">&gt;</span> {cmd}
                    </div>
                  ))}
                </div>

                {/* Best For Note */}
                <div className="pt-1 text-[11px] text-slate-400">
                  <strong className="text-slate-300 font-sans">Best for: </strong>
                  <span>{p.bestFor}</span>
                </div>
              </div>

              {/* Action Button with Loading Spinner */}
              <div className="pt-4 mt-5 border-t border-slate-800/80">
                <button
                  onClick={() => applyProfile(p.id)}
                  disabled={isLoading || isApplyingProfile}
                  className={`w-full py-2.5 px-4 rounded-xl font-bold text-xs transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed ${
                    isActive
                      ? 'bg-slate-800 text-cyan-300 border border-cyan-500/50 hover:bg-slate-750'
                      : p.buttonBg
                  }`}
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Enforcing OS Hardening via PowerShell...</span>
                    </>
                  ) : isActive ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Profile Currently Active (Re-enforce)</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-3.5 h-3.5 fill-current" />
                      <span>Activate {p.name}</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Execution History & Verification Log */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="bg-slate-950 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2 font-mono">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Profile Enforcement Log History</span>
          </div>
          <span className="text-[11px] font-mono text-slate-500">Live OS Stream</span>
        </div>
        <div className="p-4 font-mono text-xs text-slate-300 max-h-44 overflow-y-auto space-y-1 bg-slate-950/80 select-text leading-relaxed">
          {terminalLogs
            .filter((l) => l.includes('PROFILE') || l.includes('ENFORCING') || l.includes('RESET') || l.includes('HARDENING') || l.includes('[✓]'))
            .slice(-8)
            .map((log, idx) => (
              <div
                key={idx}
                className={
                  log.includes('[✓]')
                    ? 'text-emerald-400 font-semibold'
                    : log.includes('[>]')
                    ? 'text-cyan-400 font-bold'
                    : log.includes('[✗]')
                    ? 'text-red-400'
                    : 'text-slate-400'
                }
              >
                {log}
              </div>
            ))}
        </div>
      </div>
    </div>
  );
};
