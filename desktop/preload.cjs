// ==============================================================================
// SURFACEGUARD PRELOAD SCRIPT
// Secure bridge between React UI and Windows Native Operating System
// ==============================================================================

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isNativeWindows: true,
  runPowerShell: (command, requireAdmin = true) => {
    if (typeof command !== 'string' || !command.trim()) {
      return Promise.reject(new Error('Invalid command payload: must be a non-empty string.'));
    }
    return ipcRenderer.invoke('run-powershell-command', {
      command: command.trim(),
      requireAdmin: Boolean(requireAdmin),
    });
  },
  queryWindowsPorts: () => ipcRenderer.invoke('query-windows-ports'),
});

