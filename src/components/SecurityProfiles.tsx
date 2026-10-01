import React from 'react';
import { Shield, Briefcase, Code, Sliders, CheckCircle2, Zap } from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { SecurityProfileMode } from '../types/security';

export const SecurityProfiles: React.FC = () => {
  const { activeProfile, applyProfile } = useSecurity();

  const profiles: {
    id: SecurityProfileMode;
    name: string;
    tagline: string;
    icon: any;
    color: string;
    details: string[];
    bestFor: string;
  }[] = [
    {
      id: 'stealth',
      name: 'Maximum Stealth Mode',
      tagline: 'Completely seals your PC against external network probes and spyware.',
      icon: Shield,
      color: 'emerald',
      details: [
        'All incoming network doors (ports) closed & dropped',
        'Webcam camera driver hardware-locked (AllowCamera=0)',
        'Microphone audio capture muted at OS policy level',
        'USB flash drive auto-mounting blocked (anti-BadUSB)',
        'PC appears invisible/offline to external port scans',
      ],
      bestFor: 'Public Wi-Fi (cafes, airports), high-security work, travel',
    },
    {
      id: 'meeting',
      name: 'Work & Meeting Mode',
      tagline: 'Enables Zoom, Microsoft Teams & Google Meet while keeping dangerous ports blocked.',
      icon: Briefcase,
      color: 'cyan',
      details: [
        'Webcam & Microphone allowed for video meetings',
        'Dangerous ransomware doors (Port 445 SMB, Port 3389 RDP) strictly blocked',
        'Bluetooth allowed for wireless headsets',
        'USB flash drives remain blocked',
      ],
      bestFor: 'Daily office work, attending video calls and team presentations',
    },
    {
      id: 'developer',
      name: 'Software Developer Mode',
      tagline: 'Permits local website preview (Vite/Node) on localhost while shielding the outside internet.',
      icon: Code,
      color: 'purple',
      details: [
        'Localhost ports (3000, 5173, 8000) allowed strictly on 127.0.0.1',
        'Node.js V8 Debugger port (9229) allowed on local loopback',
        'External WAN connections to your computer remain blocked',
        'Webcam remains disabled unless requested via PAM',
      ],
      bestFor: 'Software engineering, building React apps, local testing',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
          1-Click Security Profiles
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
          Instantly reconfigure your entire computer's network firewall and hardware permissions with a single click based on what you are currently doing.
        </p>
      </div>

      {/* Profiles Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {profiles.map((p) => {
          const Icon = p.icon;
          const isActive = activeProfile === p.id;
          return (
            <div
              key={p.id}
              className={`p-6 rounded-xl border flex flex-col justify-between transition-all ${
                isActive
                  ? 'bg-slate-900 border-cyan-500 shadow-[0_0_20px_rgba(6,182,212,0.15)] ring-1 ring-cyan-500'
                  : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="w-10 h-10 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-center text-cyan-400">
                    <Icon className="w-5 h-5" />
                  </div>
                  {isActive && (
                    <span className="text-[11px] font-mono font-bold px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                      ACTIVE NOW
                    </span>
                  )}
                </div>

                <div>
                  <h3 className="text-base font-bold text-white font-sans">{p.name}</h3>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{p.tagline}</p>
                </div>

                <div className="space-y-2 pt-2 border-t border-slate-800/80">
                  <span className="text-[11px] font-semibold text-slate-300 block font-sans">
                    What this profile enforces:
                  </span>
                  <ul className="space-y-1.5 text-xs text-slate-300">
                    {p.details.map((d, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{d}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="pt-2 text-[11px] text-slate-400 font-sans">
                  <strong className="text-slate-300">Best for: </strong>
                  {p.bestFor}
                </div>
              </div>

              <div className="pt-5 mt-5 border-t border-slate-800/80">
                <button
                  onClick={() => applyProfile(p.id)}
                  className={`w-full py-2.5 px-4 rounded-lg font-bold text-xs transition-colors flex items-center justify-center gap-2 ${
                    isActive
                      ? 'bg-slate-800 text-cyan-300 border border-cyan-500/50 cursor-default'
                      : 'bg-cyan-600 hover:bg-cyan-500 text-slate-950 shadow-sm'
                  }`}
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>{isActive ? 'Profile Currently Active' : `Activate ${p.name}`}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
