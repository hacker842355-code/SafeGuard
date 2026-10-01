/**
 * Electron API Bridge Declaration
 * Exposes native Electron IPC methods to React frontend
 */

interface ElectronAPI {
  isNativeWindows: boolean;
  runPowerShell: (command: string, requireAdmin?: boolean) => Promise<{
    success: boolean;
    output: string;
  }>;
  queryWindowsPorts: () => Promise<{
    success: boolean;
    error?: string;
    ports: Array<{
      Protocol: 'TCP' | 'UDP';
      LocalAddress: string;
      LocalPort: number;
      OwningProcess: number;
    }>;
  }>;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}

export {};
