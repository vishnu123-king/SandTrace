import { execSync } from 'child_process';
import fs from 'fs';

export interface SystemSandboxCapabilities {
  podmanAvailable: boolean;
  podmanVersion?: string;
  dockerAvailable: boolean;
  dockerVersion?: string;
  unshareAvailable: boolean;
  seccompSupported: boolean;
  appArmorSupported: boolean;
  preferredIsolation: 'podman_rootless' | 'docker_rootless' | 'linux_namespace' | 'isolated_workspace';
  activeRuntimeDescription: string;
  scannerImageTag: string;
  securityPolicies: {
    noNewPrivileges: boolean;
    readOnlyFilesystem: boolean;
    dropCapabilities: string[];
    seccompProfile: string;
    networkIsolationAnalysisPhase: boolean;
    cpuLimit: string;
    memoryLimit: string;
    diskLimit: string;
    timeoutSeconds: number;
  };
}

export function detectSystemCapabilities(): SystemSandboxCapabilities {
  let podmanAvailable = false;
  let podmanVersion: string | undefined;
  let dockerAvailable = false;
  let dockerVersion: string | undefined;
  let unshareAvailable = false;
  let seccompSupported = false;
  let appArmorSupported = false;

  // Check Podman
  try {
    const out = execSync('podman --version', { stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000 }).toString().trim();
    podmanAvailable = true;
    podmanVersion = out;
  } catch {
    podmanAvailable = false;
  }

  // Check Docker
  try {
    const out = execSync('docker --version', { stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000 }).toString().trim();
    dockerAvailable = true;
    dockerVersion = out;
  } catch {
    dockerAvailable = false;
  }

  // Check unshare
  try {
    execSync('which unshare', { stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000 });
    unshareAvailable = true;
  } catch {
    unshareAvailable = false;
  }

  // Check Seccomp / Kernel security
  try {
    if (fs.existsSync('/proc/sys/kernel/seccomp') || fs.existsSync('/proc/self/status')) {
      const status = fs.readFileSync('/proc/self/status', 'utf-8');
      seccompSupported = status.includes('Seccomp:') && !status.includes('Seccomp:\t0');
    }
  } catch {
    seccompSupported = false;
  }

  // Check AppArmor
  try {
    if (fs.existsSync('/sys/kernel/security/apparmor')) {
      appArmorSupported = true;
    }
  } catch {
    appArmorSupported = false;
  }

  // Determine isolation mode
  let preferredIsolation: 'podman_rootless' | 'docker_rootless' | 'linux_namespace' | 'isolated_workspace' = 'isolated_workspace';
  let activeRuntimeDescription = 'Isolated Linux Scan Workspace with Read-Only Mounts & Process Isolation';

  if (podmanAvailable) {
    preferredIsolation = 'podman_rootless';
    activeRuntimeDescription = `Rootless Podman OCI Container (${podmanVersion})`;
  } else if (dockerAvailable) {
    preferredIsolation = 'docker_rootless';
    activeRuntimeDescription = `Docker Container Runtime (${dockerVersion})`;
  } else if (unshareAvailable) {
    preferredIsolation = 'linux_namespace';
    activeRuntimeDescription = 'Linux Unshare (IPC/PID/Mount/Network Namespace Sandbox)';
  }

  return {
    podmanAvailable,
    podmanVersion,
    dockerAvailable,
    dockerVersion,
    unshareAvailable,
    seccompSupported,
    appArmorSupported,
    preferredIsolation,
    activeRuntimeDescription,
    scannerImageTag: 'sandtrace-scanner:1.4.2-pinned',
    securityPolicies: {
      noNewPrivileges: true,
      readOnlyFilesystem: true,
      dropCapabilities: ['ALL', 'CAP_NET_RAW', 'CAP_SYS_ADMIN', 'CAP_DAC_OVERRIDE'],
      seccompProfile: 'default-strict-seccomp.json',
      networkIsolationAnalysisPhase: true,
      cpuLimit: '2 Cores (200%)',
      memoryLimit: '2048 MB',
      diskLimit: '500 MB',
      timeoutSeconds: 300,
    },
  };
}
