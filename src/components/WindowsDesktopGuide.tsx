import React, { useState } from 'react';
import { 
  Monitor, 
  Terminal, 
  Download, 
  Copy, 
  Check, 
  Zap, 
  ShieldCheck, 
  FileCode, 
  ExternalLink, 
  CheckCircle2, 
  Play,
  ArrowRight
} from 'lucide-react';

export const WindowsDesktopGuide: React.FC = () => {
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(id);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const downloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const launcherBatContent = `@echo off
title SurfaceGuard Architect - Windows Desktop
color 0B
cls
echo [*] Checking Node.js...
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Node.js not found. Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)
if not exist "node_modules\\" (
    echo [*] Installing dependencies...
    call npm install
)
echo [*] Starting local application server...
start /b cmd /c "npm run dev"
timeout /t 3 /nobreak >nul
echo [✓] Launching SurfaceGuard in dedicated Windows App Window...
start msedge.exe --app="http://localhost:3000" --new-window --window-size=1440,900
`;

  const buildExeBatContent = `@echo off
title Build Windows .exe - SurfaceGuard Architect
color 0A
cls
echo [*] Step 1/3: Installing Electron & Electron-Builder...
call npm install --save-dev electron electron-builder
echo [*] Step 2/3: Building React application...
call npm run build
echo [*] Step 3/3: Packaging Windows Native .exe...
call npx electron-builder --win --x64
echo [✓] SUCCESS! SurfaceGuard Setup.exe is ready in the dist-electron folder!
pause
`;

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 sm:p-8 space-y-3">
        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
          <Monitor className="w-4 h-4" />
          <span>Windows Desktop Application Converter · Native .exe Build Kit</span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-sans text-balance">
          Windows Application (.exe) Kaise Banayein & Direct Run Karein
        </h2>
        <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
          Aap is project ko apne Windows PC par **2 aasan tariko** se direct desktop application bana kar run kar sakte hain:
          ek <strong>1-Click Instant Desktop Window (.bat)</strong> aur dusra <strong>Permanent Standalone Windows .exe Installer</strong>.
        </p>

        {/* Quick Summary Pill Ribbon */}
        <div className="pt-3 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-cyan-400 font-semibold font-mono block mb-0.5">TARIKA 1 (Subse Tez - 10 Seconds)</span>
            <span className="text-slate-300">
              1-Click Batch Launcher: Bina kisi extra package ke direct dedicated Windows App window me open hoga.
            </span>
          </div>

          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-emerald-400 font-semibold font-mono block mb-0.5">TARIKA 2 (Permanent .exe File)</span>
            <span className="text-slate-300">
              Electron Builder: Ek single <strong>SurfaceGuard-Setup.exe</strong> banayega jo direct install aur run hota hai.
            </span>
          </div>
        </div>
      </div>

      {/* METHOD 1: 1-Click Instant Windows App Launcher */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400 font-bold font-mono text-xs">
              01
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-sans">
                Tarika 1: 1-Click Windows Batch Launcher (Subse Aasan)
              </h3>
              <p className="text-xs text-slate-400">
                Is tarike se browser tab ke bajaye ek **asli Windows application window** khulegi (Microsoft Edge App Mode).
              </p>
            </div>
          </div>

          <button
            onClick={() => downloadFile('SurfaceGuard-Launcher.bat', launcherBatContent)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download SurfaceGuard-Launcher.bat</span>
          </button>
        </div>

        {/* Steps */}
        <div className="space-y-3 text-xs">
          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800 space-y-2">
            <div className="font-semibold text-cyan-300">Steps to Run on Windows:</div>
            <ol className="list-decimal list-inside space-y-1.5 text-slate-300 leading-relaxed">
              <li>
                Upar diya gaya <strong>SurfaceGuard-Launcher.bat</strong> download karein aur apne project folder me rakhein.
              </li>
              <li>
                Bas <strong>SurfaceGuard-Launcher.bat</strong> par <strong>Double Click</strong> karein.
              </li>
              <li>
                Yeh automatically local server start karega aur dedicated borderless Windows Application window me app open kar dega!
              </li>
            </ol>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-slate-400 flex items-center justify-between">
            <span>File Location in Repo: <code>/scripts/SurfaceGuard-Launcher.bat</code></span>
            <button
              onClick={() => copyToClipboard(launcherBatContent, 'launcher')}
              className="text-cyan-400 hover:text-cyan-300 font-sans text-xs font-semibold flex items-center gap-1"
            >
              {copiedIndex === 'launcher' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedIndex === 'launcher' ? 'Copied' : 'Copy Script'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* METHOD 2: Compile to Standalone .exe Installer */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-emerald-950 border border-emerald-800/60 flex items-center justify-center text-emerald-400 font-bold font-mono text-xs">
              02
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-sans">
                Tarika 2: Native Windows .exe File Generate Karein (Electron)
              </h3>
              <p className="text-xs text-slate-400">
                Agar aapko kisi aur PC par install karne ke liye proper <strong>SurfaceGuard-Setup.exe</strong> chahiye.
              </p>
            </div>
          </div>

          <button
            onClick={() => downloadFile('build-windows-exe.bat', buildExeBatContent)}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download build-windows-exe.bat</span>
          </button>
        </div>

        {/* 3 Commands to compile */}
        <div className="space-y-3 text-xs">
          <div className="text-slate-300">
            Apne Windows Terminal (CMD ya PowerShell) me project folder ke andar bas yeh 3 commands chalayein:
          </div>

          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3 font-mono text-xs">
            <div className="space-y-1">
              <span className="text-slate-500 text-[11px] block font-sans">1. Electron builder install karein:</span>
              <div className="flex items-center justify-between bg-slate-900/80 px-3 py-2 rounded border border-slate-800">
                <code className="text-cyan-400">npm install --save-dev electron electron-builder</code>
                <button
                  onClick={() => copyToClipboard('npm install --save-dev electron electron-builder', 'cmd1')}
                  className="text-slate-400 hover:text-white"
                >
                  {copiedIndex === 'cmd1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-slate-500 text-[11px] block font-sans">2. Windows .exe build karein:</span>
              <div className="flex items-center justify-between bg-slate-900/80 px-3 py-2 rounded border border-slate-800">
                <code className="text-cyan-400">npm run electron:build</code>
                <button
                  onClick={() => copyToClipboard('npm run electron:build', 'cmd2')}
                  className="text-slate-400 hover:text-white"
                >
                  {copiedIndex === 'cmd2' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-slate-500 text-[11px] block font-sans">3. Result:</span>
              <div className="bg-emerald-950/30 text-emerald-300 p-2.5 rounded border border-emerald-900/50">
                [✓] Aapke project ke andar <strong>dist-electron\SurfaceGuard Setup.exe</strong> ban jayegi! Double click karke kisi bhi PC par install karein.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* HOW NATIVE EXECUTION WORKS ON WINDOWS */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white font-sans">
            Yeh Windows Application Real PC par Kaise Kaam Karti Hai?
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800 space-y-1.5">
            <div className="font-semibold text-cyan-300 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Native PowerShell Call</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Jab aap app me "Execute Hardening" par click karte hain, Electron main process Windows PowerShell ko Administrator (RunAs) mode me trigger karta hai.
            </p>
          </div>

          <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800 space-y-1.5">
            <div className="font-semibold text-emerald-300 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Asli Firewall Block</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Windows Defender Firewall me automatically rules add hote hain jo TCP 445 (SMB) aur TCP 135 (RPC) ko block kar dete hain.
            </p>
          </div>

          <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800 space-y-1.5">
            <div className="font-semibold text-amber-300 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Asli Registry Lockdown</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Windows Registry key <code>HKLM:\SOFTWARE\Policies\Microsoft\Camera</code> me <code>AllowCamera = 0</code> set ho jata hai, jisse webcam disable ho jati hai!
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
