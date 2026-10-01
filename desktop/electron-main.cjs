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
      sandbox: false,
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

// IPC Handler: Execute Windows PowerShell / Netsh Hardening as Administrator
ipcMain.handle('run-powershell-command', async (event, { command, requireAdmin }) => {
  return new Promise((resolve) => {
    // Write temporary script to %TEMP%
    const tempScriptPath = path.join(app.getPath('temp'), `surfaceguard_${Date.now()}.ps1`);
    const resultPath = `${tempScriptPath}.result`;
    const script = [
      '$ErrorActionPreference = "Stop"',
      'try {',
      `  $output = & { ${command} } 2>&1 | Out-String`,
      `  Set-Content -LiteralPath '${resultPath.replace(/'/g, "''")}' -Value $output -Encoding UTF8`,
      '  exit 0',
      '}',
      'catch {',
      `  $errorOutput = ($_ | Out-String)`,
      `  Set-Content -LiteralPath '${resultPath.replace(/'/g, "''")}' -Value $errorOutput -Encoding UTF8`,
      '  exit 1',
      '}',
    ].join('\n');
    fs.writeFileSync(tempScriptPath, script, 'utf8');

    let execCmd;
    if (requireAdmin) {
      // Forcing Windows UAC Prompt to run script as Administrator
      execCmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "$process = Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \\\"${tempScriptPath}\\\"' -Verb RunAs -Wait -PassThru; exit $process.ExitCode"`;
    } else {
      execCmd = `powershell -NoProfile -ExecutionPolicy Bypass -File "${tempScriptPath}"`;
    }

    exec(execCmd, (error, stdout, stderr) => {
      let scriptOutput = stdout || stderr || '';
      try {
        if (fs.existsSync(resultPath)) {
          scriptOutput = fs.readFileSync(resultPath, 'utf8').trim() || scriptOutput;
        }
      } catch (readError) {
        scriptOutput = `${scriptOutput}\n${readError.message}`.trim();
      }

      // Clean up temp file
      try { fs.unlinkSync(tempScriptPath); } catch (e) {}
      try { fs.unlinkSync(resultPath); } catch (e) {}

      if (error) {
        resolve({ success: false, output: scriptOutput || error.message });
      } else {
        resolve({ success: true, output: scriptOutput || 'Command executed successfully.' });
      }
    });
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
    '$listeners | ConvertTo-Json -Compress',
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