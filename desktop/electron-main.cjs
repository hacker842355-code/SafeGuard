// ==============================================================================
// SURFACEGUARD OS ARCHITECT - ELECTRON NATIVE WINDOWS DESKTOP RUNNER
// Enables native execution of Windows PowerShell Hardening Scripts directly on PC
// ==============================================================================

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { exec, execFile } = require('child_process');
const fs = require('fs');
const { parseWindowsListenerJson } = require('./windows-network.cjs');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#020617', // slate-950
    title: 'SurfaceGuard Architect - Endpoint Security Studio',
    icon: path.join(__dirname, 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    autoHideMenuBar: true,
  });

  // Safe path using app.getAppPath() for packaged apps
  const indexPath = path.join(app.getAppPath(), 'dist/index.html');

  if (app.isPackaged) {
    mainWindow.loadFile(indexPath);
  } else {
    const devUrl = process.env.VITE_DEV_SERVER_URL || 'http://localhost:3000';
    if (fs.existsSync(indexPath)) {
      mainWindow.loadFile(indexPath);
    } else {
      mainWindow.loadURL(devUrl);
    }
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Ensure single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(createWindow);
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Security: Command Validation & Sanitization Policy
const FORBIDDEN_COMMAND_PATTERNS = [
  /\b(invoke-webrequest|invoke-restmethod|iwr|irm|downloadfile|downloadstring|net\.webclient|start-bitstransfer|bitsadmin)\b/i,
  /\b(start-process|invoke-expression|iex|cmd\.exe|powershell\.exe|pwsh\.exe|mshta|rundll32|regsvr32|cscript|wscript|bash|sh)\b/i,
  /\b(add-type|system\.reflection|system\.runtime\.interopservices|system\.activator)\b/i,
  /-e(nc(odedcommand)?)?\b/i,
  /\b(format-volume|diskpart|bcdedit)\b/i,
];

const ALLOWED_COMMAND_SIGNATURES = [
  /netsh(\.exe)?\s+advfirewall/i,
  /set-itemproperty/i,
  /new-item/i,
  /get-pnpdevice/i,
  /disable-pnpdevice/i,
  /enable-pnpdevice/i,
  /icacls/i,
  /get-netfirewallrule/i,
  /get-netfirewallportfilter/i,
  /get-nettcpconnection/i,
  /get-netudpendpoint/i,
  /get-process/i,
  /get-ciminstance/i,
  /write-host/i,
];

function validatePowerShellCommand(command) {
  if (typeof command !== 'string' || !command.trim()) {
    return { valid: false, error: 'Command payload must be a non-empty string.' };
  }
  if (command.length > 32768) {
    return { valid: false, error: 'Command payload exceeds maximum allowed size (32KB).' };
  }
  for (const pattern of FORBIDDEN_COMMAND_PATTERNS) {
    if (pattern.test(command)) {
      return { valid: false, error: 'Command rejected: Contains restricted or potentially dangerous instruction.' };
    }
  }
  const isAllowed = ALLOWED_COMMAND_SIGNATURES.some((sig) => sig.test(command));
  if (!isAllowed) {
    return { valid: false, error: 'Command rejected: Operation does not match allowed security hardening profiles.' };
  }
  return { valid: true };
}

// IPC Handler: Execute Windows PowerShell / Netsh Hardening as Administrator
ipcMain.handle('run-powershell-command', async (event, { command, requireAdmin }) => {
  // 1. Strict Sender Verification
  if (!mainWindow || !mainWindow.webContents || event.sender !== mainWindow.webContents) {
    return { success: false, output: 'Access Denied: Untrusted IPC sender.' };
  }

  // 2. Strict Input Validation & Sanitization
  const validation = validatePowerShellCommand(command);
  if (!validation.valid) {
    return { success: false, output: validation.error };
  }

  return new Promise((resolve) => {
    // 3. Parameterized execution via static runner script and Base64 payload
    const runnerScriptPath = path.join(
      app.getPath('temp'),
      `surfaceguard_runner_${Date.now()}_${Math.random().toString(36).substring(2, 8)}.ps1`
    );
    const resultPath = `${runnerScriptPath}.result`;

    // Static runner script - ZERO user-supplied string interpolation in template
    const staticRunnerScript = [
      '[CmdletBinding()]',
      'param(',
      '  [Parameter(Mandatory=$true)]',
      '  [string]$Base64Payload,',
      '  [Parameter(Mandatory=$true)]',
      '  [string]$ResultFile',
      ')',
      '$ErrorActionPreference = "Stop"',
      'try {',
      '  $decodedBytes = [System.Convert]::FromBase64String($Base64Payload)',
      '  $commandText = [System.Text.Encoding]::UTF8.GetString($decodedBytes)',
      '  $scriptBlock = [scriptblock]::Create($commandText)',
      '  $output = & $scriptBlock 2>&1 | Out-String',
      '  [System.IO.File]::WriteAllText($ResultFile, $output, [System.Text.Encoding]::UTF8)',
      '  exit 0',
      '} catch {',
      '  $errorOutput = ($_ | Out-String)',
      '  [System.IO.File]::WriteAllText($ResultFile, $errorOutput, [System.Text.Encoding]::UTF8)',
      '  exit 1',
      '}',
    ].join('\n');

    try {
      fs.writeFileSync(runnerScriptPath, staticRunnerScript, 'utf8');
    } catch (writeErr) {
      resolve({ success: false, output: `Failed to initialize execution environment: ${writeErr.message}` });
      return;
    }

    const base64Payload = Buffer.from(command, 'utf8').toString('base64');

    const handleProcessCompletion = (error, stdout, stderr) => {
      let scriptOutput = stdout || stderr || '';
      try {
        if (fs.existsSync(resultPath)) {
          scriptOutput = fs.readFileSync(resultPath, 'utf8').trim() || scriptOutput;
        }
      } catch (readError) {
        scriptOutput = `${scriptOutput}\n${readError.message}`.trim();
      } finally {
        try { if (fs.existsSync(runnerScriptPath)) fs.unlinkSync(runnerScriptPath); } catch (_) {}
        try { if (fs.existsSync(resultPath)) fs.unlinkSync(resultPath); } catch (_) {}
      }

      if (error) {
        const errorText = `${error.message || ''} ${scriptOutput}`.toLowerCase();
        const isUacCanceled =
          error.code === 1223 ||
          error.code === 0x800704c7 ||
          errorText.includes('1223') ||
          errorText.includes('0x800704c7') ||
          errorText.includes('canceled by the user') ||
          errorText.includes('cancelled by the user');

        if (isUacCanceled) {
          resolve({
            success: false,
            output: 'Execution canceled: Windows Administrator UAC prompt was denied.',
          });
        } else {
          resolve({ success: false, output: scriptOutput || error.message });
        }
      } else {
        resolve({ success: true, output: scriptOutput || 'Command executed successfully.' });
      }
    };

    try {
      if (requireAdmin) {
        // Elevated execution using execFile with direct argv array tokens (no shell string interpolation)
        const elevatedWrapper = [
          'param($runner, $b64, $result)',
          'try {',
          '  $proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $runner, "-Base64Payload", $b64, "-ResultFile", $result) -Verb RunAs -Wait -PassThru -ErrorAction Stop',
          '  exit $proc.ExitCode',
          '} catch {',
          '  $ex = $_.Exception',
          '  $isUacCanceled = ($ex.HResult -eq [int]0x800704C7) -or ($ex.NativeErrorCode -eq 1223) -or ($_.ToString() -match "0x800704C7|canceled by the user|1223")',
          '  if ($isUacCanceled) {',
          '    exit 1223',
          '  }',
          '  $errStr = $_ | Out-String',
          '  [System.IO.File]::WriteAllText($result, $errStr, [System.Text.Encoding]::UTF8)',
          '  exit 1',
          '}',
        ].join('\n');

        execFile('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-ExecutionPolicy',
          'Bypass',
          '-Command',
          elevatedWrapper,
          runnerScriptPath,
          base64Payload,
          resultPath,
        ], { windowsHide: true, timeout: 60000 }, handleProcessCompletion);
      } else {
        // Non-elevated execution via direct argv array tokens
        execFile('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-ExecutionPolicy',
          'Bypass',
          '-File',
          runnerScriptPath,
          '-Base64Payload',
          base64Payload,
          '-ResultFile',
          resultPath,
        ], { windowsHide: true, timeout: 30000 }, handleProcessCompletion);
      }
    } catch (execError) {
      handleProcessCompletion(execError, '', '');
    }
  });
});

// IPC Handler: Query active Windows TCP and UDP listeners.
ipcMain.handle('query-windows-ports', async (event) => {
  if (!mainWindow || event.sender !== mainWindow.webContents) {
    return { success: false, ports: [], error: 'Untrusted IPC sender.' };
  }

  const psQuery = [
    '$listeners = @(',
    "  Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; OwningProcess = $_.OwningProcess } }",
    "  Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Protocol = 'UDP'; LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; OwningProcess = $_.OwningProcess } }",
    ')',
    '$listeners | ConvertTo-Json -Compress -Depth 3',
  ].join('; ');

  return new Promise((resolve) => {
    execFile('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      psQuery,
    ], { windowsHide: true, timeout: 15000, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        resolve({ success: false, ports: [], error: (stderr || error.message).trim() });
        return;
      }

      try {
        resolve({ success: true, ports: parseWindowsListenerJson(stdout) });
      } catch (parseError) {
        resolve({ success: false, ports: [], error: parseError.message });
      }
    });
  });
});