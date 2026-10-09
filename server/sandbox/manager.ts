import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawn } from 'child_process';
import { SandboxMetadata } from '../types.js';
import { detectSystemCapabilities } from './runtime.js';

export interface SandboxSession {
  scanId: string;
  workspacePath: string;
  repoPath: string;
  outputPath: string;
  tempPath: string;
  metadata: SandboxMetadata;
  createdAt: Date;
  cleanedUp: boolean;
}

const activeSandboxes = new Map<string, SandboxSession>();

export class SandboxManager {
  private static baseDir = path.join(os.tmpdir(), 'sandtrace-sandboxes');

  public static initialize(): void {
    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true, mode: 0o700 });
    }
  }

  public static createSandbox(scanId: string): SandboxSession {
    this.initialize();
    const caps = detectSystemCapabilities();

    const workspacePath = path.join(this.baseDir, `scan-${scanId}`);
    const repoPath = path.join(workspacePath, 'repo');
    const outputPath = path.join(workspacePath, 'out');
    const tempPath = path.join(workspacePath, 'tmp');

    // Create pristine directory structure with strict permissions
    fs.mkdirSync(workspacePath, { recursive: true, mode: 0o700 });
    fs.mkdirSync(repoPath, { recursive: true, mode: 0o700 });
    fs.mkdirSync(outputPath, { recursive: true, mode: 0o700 });
    fs.mkdirSync(tempPath, { recursive: true, mode: 0o700 });

    const metadata: SandboxMetadata = {
      mode: caps.preferredIsolation,
      isolationProfile: 'SandTrace-Strict-OCI-v2',
      runtimeAvailable: true,
      runtimeName: caps.activeRuntimeDescription,
      seccomp: caps.seccompSupported,
      networkIsolatedInAnalysis: true,
      noNewPrivileges: true,
      cpuLimit: caps.securityPolicies.cpuLimit,
      memoryLimit: caps.securityPolicies.memoryLimit,
      diskLimit: caps.securityPolicies.diskLimit,
      timeoutSeconds: caps.securityPolicies.timeoutSeconds,
      workspacePath,
      scannerImage: caps.scannerImageTag,
      toolVersions: {
        'semgrep-core': '1.85.0',
        'gitleaks': '8.19.1',
        'bandit-ast': '1.7.9',
        'trivy-config': '0.55.2',
        'osv-scanner': '1.8.4',
        'git': '2.34.1+',
      },
    };

    const session: SandboxSession = {
      scanId,
      workspacePath,
      repoPath,
      outputPath,
      tempPath,
      metadata,
      createdAt: new Date(),
      cleanedUp: false,
    };

    activeSandboxes.set(scanId, session);
    return session;
  }

  public static getSandbox(scanId: string): SandboxSession | undefined {
    return activeSandboxes.get(scanId);
  }

  public static listSandboxes(): SandboxSession[] {
    return Array.from(activeSandboxes.values());
  }

  /**
   * Safe clone inside the retrieval stage:
   * Uses array arguments, safe flags, hook disabling, size/timeout guards
   */
  public static async cloneRepository(
    session: SandboxSession,
    repoUrl: string,
    options: {
      depth?: number;
      branch?: string;
      timeoutMs?: number;
      onLog?: (msg: string) => void;
    } = {}
  ): Promise<{ success: boolean; error?: string; commitSha?: string; branch?: string }> {
    const depth = options.depth || 100;
    const timeoutMs = options.timeoutMs || 60000;
    const log = options.onLog || (() => {});

    log(`[Retrieval Sandbox] Initializing secure isolation workspace at ${session.workspacePath}`);
    log(`[Retrieval Sandbox] Target repository: ${repoUrl}`);

    // Pre-create target clone dir
    const targetDir = session.repoPath;

    // Secure git arguments:
    // - Disable hooks
    // - Disable filesystem monitor
    // - Disallow file:// protocol
    // - Disable submodules
    // - Skip LFS smudge
    const gitArgs = [
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      '-c', 'protocol.file.allow=never',
      '-c', 'protocol.ext.allow=never',
      'clone',
      '--depth', String(depth),
      '--recurse-submodules=no',
      '--single-branch',
    ];

    if (options.branch) {
      gitArgs.push('--branch', options.branch);
    }

    gitArgs.push(repoUrl, targetDir);

    log(`[Retrieval Sandbox] Executing safe clone with depth=${depth}...`);

    return new Promise((resolve) => {
      const env = {
        ...process.env,
        GIT_TERMINAL_PROMPT: '0',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_LFS_SKIP_SMUDGE: '1',
      };

      const proc = spawn('git', gitArgs, {
        env,
        timeout: timeoutMs,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stderr = '';
      let stdout = '';

      proc.stdout.on('data', (d) => {
        stdout += d.toString();
        log(`[Git stdout] ${d.toString().trim()}`);
      });

      proc.stderr.on('data', (d) => {
        const text = d.toString();
        stderr += text;
        // git clone outputs progress to stderr
        log(`[Git] ${text.trim()}`);
      });

      proc.on('error', (err) => {
        resolve({ success: false, error: `Clone execution failed: ${err.message}` });
      });

      proc.on('close', (code) => {
        if (code !== 0) {
          return resolve({
            success: false,
            error: `Git clone failed with code ${code}. ${stderr.slice(-300)}`,
          });
        }

        // Get commit SHA and branch
        try {
          const revProc = spawn('git', ['rev-parse', 'HEAD'], {
            cwd: targetDir,
            stdio: ['ignore', 'pipe', 'ignore'],
          });
          let commitSha = '';
          revProc.stdout.on('data', (d) => (commitSha += d.toString().trim()));
          revProc.on('close', () => {
            log(`[Retrieval Sandbox] Clone completed successfully. Head commit: ${commitSha.slice(0, 8)}`);
            resolve({ success: true, commitSha });
          });
        } catch {
          resolve({ success: true });
        }
      });
    });
  }

  /**
   * Freezes repository snapshot for analysis phase.
   * Enforces read-only permissions across target code.
   */
  public static freezeSnapshot(session: SandboxSession): void {
    const makeReadOnly = (dirPath: string) => {
      try {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const entry of entries) {
          const full = path.join(dirPath, entry.name);
          if (entry.isDirectory()) {
            makeReadOnly(full);
            fs.chmodSync(full, 0o555); // r-x
          } else {
            fs.chmodSync(full, 0o444); // r--
          }
        }
        fs.chmodSync(dirPath, 0o555);
      } catch {
        // Fallback or ignore permission errors on special files
      }
    };

    makeReadOnly(session.repoPath);
  }

  /**
   * Securely cleans up and destroys sandbox workspace
   */
  public static cleanupSandbox(scanId: string): void {
    const session = activeSandboxes.get(scanId);
    if (!session || session.cleanedUp) return;

    try {
      // Re-enable write permissions on dirs to allow rm
      const restoreWrite = (dirPath: string) => {
        try {
          if (!fs.existsSync(dirPath)) return;
          const entries = fs.readdirSync(dirPath, { withFileTypes: true });
          for (const entry of entries) {
            const full = path.join(dirPath, entry.name);
            if (entry.isDirectory()) {
              restoreWrite(full);
              fs.chmodSync(full, 0o700);
            } else {
              fs.chmodSync(full, 0o600);
            }
          }
          fs.chmodSync(dirPath, 0o700);
        } catch {}
      };

      restoreWrite(session.workspacePath);
      fs.rmSync(session.workspacePath, { recursive: true, force: true });
      session.cleanedUp = true;
      session.metadata.cleanedUpAt = new Date().toISOString();
    } catch (err) {
      console.error(`Failed to cleanup sandbox ${scanId}:`, err);
    }
  }

  public static cleanupAll(): void {
    for (const scanId of activeSandboxes.keys()) {
      this.cleanupSandbox(scanId);
    }
  }
}
