import { spawn } from 'child_process';
import { ContributorInfo, ExposureTimelineEvent, Finding } from '../types.js';

export function maskEmail(email: string): string {
  if (!email || !email.includes('@')) return 'anonymous@masked';
  const [local, domain] = email.split('@');
  if (local.length <= 2) return `${local[0]}*@${domain}`;
  return `${local[0]}${'*'.repeat(Math.min(4, local.length - 2))}${local[local.length - 1]}@${domain}`;
}

const SENSITIVE_FILE_PATTERNS = [
  /auth/i,
  /security/i,
  /secret/i,
  /\.env/i,
  /key/i,
  /token/i,
  /password/i,
  /docker-compose/i,
  /k8s/i,
  /cert/i,
  /crypto/i,
  /permission/i,
  /rbac/i,
];

export class GitAnalysisEngine {
  /**
   * Analyzes Git metadata: commit count, branches, tags, contributors, and activity patterns
   */
  public static async analyzeRepository(
    repoDir: string,
    findings: Finding[]
  ): Promise<{
    totalCommits: number;
    branches: string[];
    tags: string[];
    contributors: ContributorInfo[];
    timelineEvents: ExposureTimelineEvent[];
    latestCommitSha: string;
    defaultBranch: string;
  }> {
    const branches = await this.getBranches(repoDir);
    const tags = await this.getTags(repoDir);
    const latestCommitSha = await this.getLatestSha(repoDir);
    const defaultBranch = branches[0] || 'main';

    // Parse commits log: hash, author, email, date, message
    const { commits, contributorsMap, sensitiveChanges } = await this.parseCommitHistory(repoDir);

    const totalCommits = commits.length;
    const contributors: ContributorInfo[] = [];

    for (const [authorKey, data] of contributorsMap.entries()) {
      const pct = totalCommits > 0 ? Math.round((data.count / totalCommits) * 100) : 0;
      const reviewSignals: string[] = [];

      if (pct >= 50) {
        reviewSignals.push(`Primary maintainer: author contributed ${pct}% of repository commits.`);
      } else if (pct >= 25) {
        reviewSignals.push(`Key contributor representing ${pct}% of codebase commits.`);
      }
      if (data.sensitiveTouched.length > 0) {
        reviewSignals.push(`Touched ${data.sensitiveTouched.length} sensitive security or configuration paths.`);
      }
      if (reviewSignals.length === 0) {
        reviewSignals.push('Active contributor with verified repository commit activity.');
      }

      contributors.push({
        name: data.name,
        maskedEmail: maskEmail(data.email),
        commitCount: data.count,
        firstCommitDate: data.firstDate,
        lastCommitDate: data.lastDate,
        percentageOfCommits: pct,
        sensitiveFilesTouched: Array.from(new Set(data.sensitiveTouched)).slice(0, 10),
        reviewSignals,
      });
    }

    // Sort contributors by commit count descending
    contributors.sort((a, b) => b.commitCount - a.commitCount);

    // Build timeline events
    const timelineEvents: ExposureTimelineEvent[] = [];

    // Add findings events
    for (const f of findings) {
      if (f.category === 'secret') {
        timelineEvents.push({
          id: `tl-${f.id}`,
          timestamp: f.firstSeenAt,
          commitHash: f.commitHash || latestCommitSha.slice(0, 8),
          author: f.commitAuthor || 'Repository Contributor',
          type: f.exposureType === 'HISTORICAL' ? 'secret_removed_head' : 'secret_introduced',
          title: f.title,
          description: f.evidence,
          filePath: f.filePath,
          findingId: f.id,
          severity: f.severity,
        });
      }
    }

    // Add sensitive file changes events
    for (const sc of sensitiveChanges.slice(0, 20)) {
      timelineEvents.push({
        id: `tl-sens-${sc.hash}`,
        timestamp: sc.date,
        commitHash: sc.hash,
        author: sc.author,
        type: 'sensitive_config_changed',
        title: `Security-Sensitive File Modified: ${sc.file}`,
        description: `Commit "${sc.message}" touched security or credential file: ${sc.file}.`,
        filePath: sc.file,
      });
    }

    // Sort timeline chronologically descending
    timelineEvents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    return {
      totalCommits,
      branches,
      tags,
      contributors,
      timelineEvents,
      latestCommitSha,
      defaultBranch,
    };
  }

  private static async getBranches(repoDir: string): Promise<string[]> {
    return new Promise((resolve) => {
      const proc = spawn('git', ['branch', '-a'], { cwd: repoDir, stdio: ['ignore', 'pipe', 'ignore'] });
      let out = '';
      proc.stdout.on('data', (d) => (out += d.toString()));
      proc.on('close', () => {
        const list = out
          .split('\n')
          .map((s) => s.replace(/^\*?\s+/, '').replace(/^remotes\/origin\//, '').trim())
          .filter((s) => s && !s.includes('HEAD ->'));
        resolve(Array.from(new Set(list)));
      });
      proc.on('error', () => resolve(['main']));
    });
  }

  private static async getTags(repoDir: string): Promise<string[]> {
    return new Promise((resolve) => {
      const proc = spawn('git', ['tag'], { cwd: repoDir, stdio: ['ignore', 'pipe', 'ignore'] });
      let out = '';
      proc.stdout.on('data', (d) => (out += d.toString()));
      proc.on('close', () => {
        const list = out.split('\n').map((s) => s.trim()).filter(Boolean);
        resolve(list.slice(0, 30));
      });
      proc.on('error', () => resolve([]));
    });
  }

  private static async getLatestSha(repoDir: string): Promise<string> {
    return new Promise((resolve) => {
      const proc = spawn('git', ['rev-parse', 'HEAD'], { cwd: repoDir, stdio: ['ignore', 'pipe', 'ignore'] });
      let out = '';
      proc.stdout.on('data', (d) => (out += d.toString()));
      proc.on('close', () => resolve(out.trim() || 'unknown'));
      proc.on('error', () => resolve('unknown'));
    });
  }

  private static async parseCommitHistory(repoDir: string): Promise<{
    commits: Array<{ hash: string; author: string; email: string; date: string; message: string }>;
    contributorsMap: Map<string, { name: string; email: string; count: number; firstDate: string; lastDate: string; sensitiveTouched: string[] }>;
    sensitiveChanges: Array<{ hash: string; author: string; date: string; file: string; message: string }>;
  }> {
    return new Promise((resolve) => {
      // Use format string: %H|%an|%ae|%aI|%s
      const proc = spawn('git', ['log', '-n', '250', '--name-only', '--format=COMMIT:%H|%an|%ae|%aI|%s'], {
        cwd: repoDir,
        stdio: ['ignore', 'pipe', 'ignore'],
      });

      let out = '';
      proc.stdout.on('data', (d) => (out += d.toString()));

      proc.on('close', () => {
        const lines = out.split('\n');
        const commits: Array<{ hash: string; author: string; email: string; date: string; message: string }> = [];
        const contributorsMap = new Map<string, { name: string; email: string; count: number; firstDate: string; lastDate: string; sensitiveTouched: string[] }>();
        const sensitiveChanges: Array<{ hash: string; author: string; date: string; file: string; message: string }> = [];

        let currentCommit: { hash: string; author: string; email: string; date: string; message: string } | null = null;

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (line.startsWith('COMMIT:')) {
            const parts = line.replace('COMMIT:', '').split('|');
            currentCommit = {
              hash: (parts[0] || '').slice(0, 8),
              author: parts[1] || 'Unknown',
              email: parts[2] || 'unknown@example.com',
              date: parts[3] || new Date().toISOString(),
              message: parts[4] || '',
            };
            commits.push(currentCommit);

            const key = `${currentCommit.author}:${currentCommit.email}`;
            const existing = contributorsMap.get(key);
            if (existing) {
              existing.count++;
              existing.firstDate = currentCommit.date; // older as we go down
            } else {
              contributorsMap.set(key, {
                name: currentCommit.author,
                email: currentCommit.email,
                count: 1,
                firstDate: currentCommit.date,
                lastDate: currentCommit.date,
                sensitiveTouched: [],
              });
            }
          } else if (line && currentCommit) {
            // File changed in this commit
            const isSensitive = SENSITIVE_FILE_PATTERNS.some((pat) => pat.test(line));
            if (isSensitive) {
              const key = `${currentCommit.author}:${currentCommit.email}`;
              const authorData = contributorsMap.get(key);
              if (authorData) {
                authorData.sensitiveTouched.push(line);
              }
              sensitiveChanges.push({
                hash: currentCommit.hash,
                author: currentCommit.author,
                date: currentCommit.date,
                file: line,
                message: currentCommit.message,
              });
            }
          }
        }

        resolve({ commits, contributorsMap, sensitiveChanges });
      });

      proc.on('error', () => {
        resolve({ commits: [], contributorsMap: new Map(), sensitiveChanges: [] });
      });
    });
  }
}
