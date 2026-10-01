// ==============================================================================
// SURFACEGUARD PRELOAD SCRIPT
// Secure bridge between React UI and Windows Native Operating System
// ==============================================================================

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isNativeWindows: true,
  runPowerShell: (command, requireAdmin = true) =>
    ipcRenderer.invoke('run-powershell-command', { command, requireAdmin }),
  queryWindowsPorts: () => ipcRenderer.invoke('query-windows-ports'),
});
