import React from 'react';
import { 
  Camera, 
  Mic, 
  Usb, 
  Bluetooth, 
  FolderLock, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle,
  Cpu,
  Zap,
  RotateCcw
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { HardwareState } from '../types/security';

export const HardwareControl: React.FC = () => {
  const { hardware, toggleHardware, targetOS } = useSecurity();
  const [loadingDevice, setLoadingDevice] = React.useState<keyof HardwareState | null>(null);

  const handleHardwareToggle = async (device: keyof HardwareState) => {
    setLoadingDevice(device);
    try {
      await toggleHardware(device);
    } finally {
      setLoadingDevice(null);
    }
  };

  const hardwareItems = [
    {
      id: 'camera' as const,
      name: 'Integrated Webcam & Video Capture',
      icon: Camera,
      isLocked: hardware.camera,
      driverPath: targetOS === 'windows' 
        ? 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Camera (AllowCamera=0)'
        : targetOS === 'linux'
        ? '/etc/udev/rules.d/99-video.rules (MODE="0000")'
        : 'tccutil reset Camera & MDM Profile',
      description: 'Disables physical camera hardware at OS driver and policy layers to prevent video surveillance.',
      attackVector: 'Trojan RATs initiating silent video streaming without activating notification LEDs.',
    },
    {
      id: 'microphone' as const,
      name: 'Microphone & Audio Capture Subsystem',
      icon: Mic,
      isLocked: hardware.microphone,
      driverPath: targetOS === 'windows'
        ? 'CapabilityAccessManager\\ConsentStore\\microphone (Value=Deny)'
        : targetOS === 'linux'
        ? '/dev/snd/* mode 0600 root-only'
        : 'tccutil reset Microphone',
      description: 'Mutes and isolates system audio capture pipeline, blocking background room eavesdropping.',
      attackVector: 'Malware recording ambient microphone conversations or querying DirectSound APIs.',
    },
    {
      id: 'usbStorage' as const,
      name: 'USB Mass Storage & Removable Media',
      icon: Usb,
      isLocked: hardware.usbStorage,
      driverPath: targetOS === 'windows'
        ? 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR (Start=4)'
        : targetOS === 'linux'
        ? 'echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb.conf'
        : 'systemextensionsctl Developer Storage Block',
      description: 'Prevents mounting of unauthorized USB thumb drives, blocking BadUSB attacks and data exfiltration.',
      attackVector: 'Physical drop attacks, malicious rubber ducky keystroke injectors, and offline data leakage.',
    },
    {
      id: 'bluetooth' as const,
      name: 'Bluetooth Radio Adapter',
      icon: Bluetooth,
      isLocked: hardware.bluetooth,
      driverPath: targetOS === 'windows'
        ? 'Disable-PnpDevice -InstanceId "BTH*" -Confirm:$false'
        : targetOS === 'linux'
        ? 'rfkill block bluetooth'
        : 'blueutil --power 0',
      description: 'Disables short-range wireless radio transmitters to eliminate remote proximity hijacking.',
      attackVector: 'BlueBorne, BLE spoofing, and rogue peripheral pair injection.',
    },
    {
      id: 'fileSystemAcl' as const,
      name: 'File System ACL Strict Isolation',
      icon: FolderLock,
      isLocked: hardware.fileSystemAcl,
      driverPath: targetOS === 'windows'
        ? 'Set-Acl %ProgramData% (Inheritance=Disabled, TrustedInstaller only)'
        : targetOS === 'linux'
        ? 'chmod 0000 /etc/shadow /etc/gshadow'
        : 'System Integrity Protection (SIP) Enforced',
      description: 'Tightens overly permissive directories to prevent unauthorized local privilege escalation.',
      attackVector: 'Local binary replacement, DLL search order hijacking, and unauthenticated scratchpad writes.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
          Camera & Device Controls
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Toggle webcam, microphone, USB drives, and Bluetooth devices on or off.
        </p>
      </div>

      {/* Hardware Control Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {hardwareItems.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.id}
              className={`p-5 rounded-xl border transition-all ${
                item.isLocked
                  ? 'bg-slate-900/60 border-emerald-800/60 shadow-sm'
                  : 'bg-slate-900/40 border-slate-800'
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div
                    className={`p-2.5 rounded-xl ${
                      item.isLocked
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/80'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white font-sans">
                      {item.name}
                    </h3>
                    <div className="text-[11px] font-mono mt-0.5">
                      <span
                        className={item.isLocked ? 'text-emerald-400 font-semibold' : 'text-amber-400'}
                      >
                        {item.isLocked ? 'STATUS: HARDWARE LOCKED (PROTECTED)' : 'STATUS: PERMISSIVE (ACTIVE)'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Direct On/Off Switch */}
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <button
                    onClick={() => handleHardwareToggle(item.id)}
                    title={item.isLocked ? 'Click to UNLOCK hardware' : 'Click to LOCK hardware'}
                    disabled={loadingDevice === item.id}
                    className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                      item.isLocked ? 'bg-emerald-600' : 'bg-slate-700'
                    } ${loadingDevice === item.id ? 'opacity-70 cursor-not-allowed' : ''}`}
                  >
                    {loadingDevice === item.id ? (
                      <span className="absolute inset-0 flex items-center justify-center">
                        <span className="h-3 w-3 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                      </span>
                    ) : null}
                    <span
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                        item.isLocked ? 'translate-x-5' : 'translate-x-0'
                      }`}
                    />
                  </button>
                  <span className="text-[10px] font-mono text-slate-500">
                    {item.isLocked ? 'LOCKED' : 'ENABLED'}
                  </span>
                </div>
              </div>

              <p className="text-xs text-slate-300 mt-3 leading-relaxed">
                {item.description}
              </p>

              <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-1.5 text-xs">
                <div className="bg-slate-950/70 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 truncate">
                  <span className="text-slate-500 font-sans">Target: </span>
                  {item.driverPath}
                </div>

                <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>Mitigates: {item.attackVector}</span>
                </div>

              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

