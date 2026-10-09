import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { Finding, Severity } from '../types.js';

// Server-side HMAC key for secret fingerprinting
const HMAC_SECRET = process.env.SECRET_FINGERPRINT_KEY || crypto.randomBytes(32).toString('hex');

interface SecretRule {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  minEntropy?: number;
  description: string;
}

const SECRET_RULES: SecretRule[] = [
  {
    id: 'SEC-AWS-KEY',
    name: 'AWS Access Key ID',
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: 'CRITICAL',
    description: 'Direct AWS Access Key ID exposed in source code.',
  },
  {
    id: 'SEC-AWS-SECRET',
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_sec_key|secret_key)\s*[:=]\s*['"]([0-9a-zA-Z/+]{40})['"]/gi,
    severity: 'CRITICAL',
    minEntropy: 3.2,
    description: 'AWS Secret Access Key exposed.',
  },
  {
    id: 'SEC-GITHUB-TOKEN',
    name: 'GitHub Personal Access Token',
    pattern: /\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{60,82}|gho_[0-9a-zA-Z]{36})\b/g,
    severity: 'CRITICAL',
    description: 'GitHub Personal or OAuth Access Token exposed.',
  },
  {
    id: 'SEC-GITLAB-TOKEN',
    name: 'GitLab Personal Access Token',
    pattern: /\b(glpat-[0-9a-zA-Z\-_]{20,30})\b/g,
    severity: 'CRITICAL',
    description: 'GitLab Personal Access Token exposed.',
  },
  {
    id: 'SEC-SLACK-TOKEN',
    name: 'Slack API Token',
    pattern: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g,
    severity: 'HIGH',
    description: 'Slack Bot, User, or App Token exposed.',
  },
  {
    id: 'SEC-SLACK-WEBHOOK',
    name: 'Slack Incoming Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8,12}\/[0-9a-zA-Z]{24}/g,
    severity: 'HIGH',
    description: 'Slack Incoming Webhook URL exposed.',
  },
  {
    id: 'SEC-STRIPE-KEY',
    name: 'Stripe Secret Key',
    pattern: /\b(sk_live_[0-9a-zA-Z]{24,34}|rk_live_[0-9a-zA-Z]{24,34})\b/g,
    severity: 'CRITICAL',
    description: 'Stripe Live Secret Key with billing API access.',
  },
  {
    id: 'SEC-PRIVATE-KEY',
    name: 'Private Encryption Key (RSA/OpenSSH/PGP)',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    severity: 'CRITICAL',
    description: 'Private cryptographic key block detected.',
  },
  {
    id: 'SEC-DB-URI',
    name: 'Database Connection String with Credentials',
    pattern: /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::\d+)?\/[^\s'"]+/gi,
    severity: 'CRITICAL',
    description: 'Database connection URI contains embedded authentication password.',
  },
  {
    id: 'SEC-JWT-SECRET',
    name: 'Hardcoded JWT Secret',
    pattern: /(?:jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-!@#$%^&*]{8,64})['"]/gi,
    severity: 'HIGH',
    minEntropy: 2.5,
    description: 'Hardcoded secret used for signing and verifying JSON Web Tokens.',
  },
  {
    id: 'SEC-OPENAI-KEY',
    name: 'OpenAI API Secret Key',
    pattern: /\b(sk-[a-zA-Z0-9T3BlbkFJ]{32,60}|sk-proj-[a-zA-Z0-9_\-]{40,90})\b/g,
    severity: 'HIGH',
    description: 'OpenAI API authorization token detected.',
  },
  {
    id: 'SEC-SENDGRID-KEY',
    name: 'SendGrid API Key',
    pattern: /\b(SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})\b/g,
    severity: 'HIGH',
    description: 'SendGrid email service API key detected.',
  },
  {
    id: 'SEC-HARDCODED-PASSWORD',
    name: 'Hardcoded Password in Source Code',
    pattern: /(?:password|passwd|db_pass|admin_pass)\s*[:=]\s*['"]([a-zA-Z0-9!@#$%^&*()_+]{8,36})['"]/gi,
    severity: 'HIGH',
    minEntropy: 2.8,
    description: 'Potential plaintext password assignment in source code.',
  },
  {
    id: 'SEC-FIREBASE-KEY',
    name: 'Google / Firebase API Key',
    pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    severity: 'HIGH',
    description: 'Firebase or Google Cloud API Key exposed in client configuration.',
  },
  {
    id: 'SEC-ANTHROPIC-KEY',
    name: 'Anthropic Claude API Key',
    pattern: /\b(sk-ant-[a-zA-Z0-9_\-]{30,90})\b/g,
    severity: 'CRITICAL',
    description: 'Anthropic Claude model API key detected.',
  },
  {
    id: 'SEC-HUGGINGFACE-TOKEN',
    name: 'Hugging Face Access Token',
    pattern: /\b(hf_[a-zA-Z0-9]{34})\b/g,
    severity: 'HIGH',
    description: 'Hugging Face API inference and repository token detected.',
  },
  {
    id: 'SEC-TWILIO-SID',
    name: 'Twilio Account SID & Token',
    pattern: /\b(AC[a-z0-9]{32})\b/g,
    severity: 'HIGH',
    description: 'Twilio communication platform Account SID detected.',
  },
  {
    id: 'SEC-NPM-TOKEN',
    name: 'NPM Registry Authentication Token',
    pattern: /\b(npm_[a-zA-Z0-9]{36})\b/g,
    severity: 'CRITICAL',
    description: 'NPM package publisher access token detected.',
  },
  {
    id: 'SEC-DISCORD-WEBHOOK',
    name: 'Discord Incoming Webhook URL',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_\-]{60,70}/g,
    severity: 'MEDIUM',
    description: 'Discord incoming webhook URL exposed.',
  },
  {
    id: 'SEC-GENERIC-API-TOKEN',
    name: 'Generic High-Entropy API Token',
    pattern: /(?:api_key|access_token|secret_token|auth_token|client_secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{24,72})['"]/gi,
    severity: 'HIGH',
    minEntropy: 3.2,
    description: 'High-entropy generic authentication or API secret key detected.',
  },
];

// Calculate Shannon entropy to filter out low-entropy strings
function calculateEntropy(str: string): number {
  const map: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    map[str[i]] = (map[str[i]] || 0) + 1;
  }
  let entropy = 0;
  for (const char in map) {
    const p = map[char] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Generate keyed HMAC fingerprint
export function computeSecretFingerprint(secret: string): string {
  return crypto.createHmac('sha256', HMAC_SECRET).update(secret).digest('hex').slice(0, 16);
}

// Mask secret string: "ghp_••••••••••••••••••••[7a3b]"
export function maskSecretValue(secret: string): string {
  if (secret.length <= 8) {
    return '••••••••';
  }
  const prefix = secret.slice(0, Math.min(4, Math.floor(secret.length / 4)));
  const suffix = secret.slice(-4);
  const maskedLen = Math.max(8, secret.length - prefix.length - suffix.length);
  return `${prefix}${'•'.repeat(maskedLen)}[${suffix}]`;
}

export class SecretScanner {
  /**
   * Scans current files in the repository directory
   */
  public static scanCurrentFiles(scanId: string, repoDir: string, relativeFiles: string[]): Finding[] {
    const findings: Finding[] = [];
    const seenFingerprints = new Set<string>();

    for (const relPath of relativeFiles) {
      // Skip binary, lock, and heavy asset files
      if (this.shouldSkipFile(relPath)) continue;

      const fullPath = path.join(repoDir, relPath);
      let content = '';
      try {
        const stats = fs.statSync(fullPath);
        if (stats.size > 1024 * 1024) continue; // Skip files > 1MB
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');

      for (const rule of SECRET_RULES) {
        // Reset regex state
        rule.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = rule.pattern.exec(content)) !== null) {
          const rawSecret = match[1] || match[0];
          
          if (rule.minEntropy && calculateEntropy(rawSecret) < rule.minEntropy) {
            continue;
          }

          // Compute line number
          const matchIndex = match.index;
          let lineNumber = 1;
          for (let i = 0; i < matchIndex; i++) {
            if (content[i] === '\n') lineNumber++;
          }

          const fingerprint = computeSecretFingerprint(rawSecret);
          const dedupKey = `${fingerprint}:${relPath}:${lineNumber}`;
          if (seenFingerprints.has(dedupKey)) continue;
          seenFingerprints.add(dedupKey);

          const lineContent = lines[lineNumber - 1] || '';
          const maskedLine = lineContent.replace(rawSecret, maskSecretValue(rawSecret));

          findings.push({
            id: `sec-${scanId}-${findings.length + 1}`,
            scanId,
            title: `Exposed ${rule.name}`,
            category: 'secret',
            severity: rule.severity,
            confidence: 'HIGH',
            filePath: relPath,
            lineNumber,
            scannerName: 'SecretShield-Gitleaks-Engine',
            ruleId: rule.id,
            cweId: 'CWE-798: Use of Hard-coded Credentials',
            owasp: 'A07:2021-Identification and Authentication Failures',
            evidence: `Found pattern matching ${rule.name} with HMAC fingerprint ${fingerprint}.`,
            maskedSnippet: maskedLine.trim().slice(0, 160),
            rawSecretFingerprint: fingerprint,
            remediation: 'Immediately revoke and rotate this credential. Move credentials to environment variables, a secure secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager), and add the file or pattern to .gitignore.',
            status: 'OPEN',
            exposureType: 'CURRENT',
            firstSeenAt: new Date().toISOString(),
            lastSeenAt: new Date().toISOString(),
            tags: ['secret', 'credential', rule.id],
            referenceUrls: [
              'https://cwe.mitre.org/data/definitions/798.html',
              'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
            ],
          });
        }
      }
    }

    return findings;
  }

  /**
   * Scans Git commit history for credentials that were added and potentially deleted later
   */
  public static async scanGitHistory(
    scanId: string,
    repoDir: string,
    currentFindings: Finding[]
  ): Promise<Finding[]> {
    const historicalFindings: Finding[] = [];
    const currentFingerprints = new Set(currentFindings.map((f) => f.rawSecretFingerprint).filter(Boolean));

    return new Promise((resolve) => {
      // Run git log -p -n 30 to check recent commits diff rapidly
      const proc = spawn('git', ['log', '-p', '-n', '30', '--no-color'], {
        cwd: repoDir,
        stdio: ['ignore', 'pipe', 'ignore'],
      });

      let buffer = '';
      let currentCommit = '';
      let currentAuthor = '';
      let currentDate = '';
      let currentFile = '';

      proc.stdout.on('data', (d) => {
        buffer += d.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('commit ')) {
            currentCommit = line.split(' ')[1] || '';
          } else if (line.startsWith('Author: ')) {
            currentAuthor = line.replace('Author: ', '').trim();
          } else if (line.startsWith('Date:   ')) {
            currentDate = line.replace('Date:   ', '').trim();
          } else if (line.startsWith('diff --git ')) {
            const parts = line.split(' ');
            currentFile = (parts[3] || '').replace(/^b\//, '');
          } else if (line.startsWith('+') && !line.startsWith('+++')) {
            // Added line in commit
            const addedCode = line.slice(1);
            for (const rule of SECRET_RULES) {
              rule.pattern.lastIndex = 0;
              let match: RegExpExecArray | null;
              while ((match = rule.pattern.exec(addedCode)) !== null) {
                const rawSecret = match[1] || match[0];
                if (rule.minEntropy && calculateEntropy(rawSecret) < rule.minEntropy) continue;

                const fingerprint = computeSecretFingerprint(rawSecret);

                // If not in current findings, it was removed from current HEAD but still in Git history!
                const isHistoricalOnly = !currentFingerprints.has(fingerprint);

                if (isHistoricalOnly && !historicalFindings.some((h) => h.rawSecretFingerprint === fingerprint)) {
                  historicalFindings.push({
                    id: `sec-hist-${scanId}-${historicalFindings.length + 1}`,
                    scanId,
                    title: `Historical Exposure: ${rule.name} in Git Commit History`,
                    category: 'secret',
                    severity: rule.severity,
                    confidence: 'HIGH',
                    filePath: currentFile || 'Git History',
                    commitHash: currentCommit.slice(0, 8),
                    commitAuthor: currentAuthor,
                    commitDate: currentDate,
                    scannerName: 'SecretShield-Gitleaks-History-Engine',
                    ruleId: `${rule.id}-HISTORICAL`,
                    cweId: 'CWE-798: Use of Hard-coded Credentials in Git History',
                    owasp: 'A07:2021-Identification and Authentication Failures',
                    evidence: `Secret was introduced in commit ${currentCommit.slice(0, 8)} by ${currentAuthor}. Although absent or modified in HEAD, it remains fully recoverable in Git history.`,
                    maskedSnippet: addedCode.replace(rawSecret, maskSecretValue(rawSecret)).trim().slice(0, 160),
                    rawSecretFingerprint: fingerprint,
                    remediation: 'Do not assume a secret is safe because it was removed from HEAD! The credential must be immediately revoked and rotated. To purge from history, use git-filter-repo or BFG Repo-Cleaner and force-push.',
                    status: 'OPEN',
                    exposureType: 'HISTORICAL',
                    firstSeenAt: currentDate || new Date().toISOString(),
                    lastSeenAt: new Date().toISOString(),
                    tags: ['secret', 'historical', 'git-history'],
                    referenceUrls: [
                      'https://git-scm.com/docs/git-filter-repo',
                      'https://cwe.mitre.org/data/definitions/798.html',
                    ],
                  });
                }
              }
            }
          }
        }
      });

      proc.on('close', () => {
        resolve(historicalFindings);
      });

      proc.on('error', () => {
        resolve([]);
      });
    });
  }

  private static shouldSkipFile(relPath: string): boolean {
    const lower = relPath.toLowerCase();
    const skipExtensions = [
      '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf', '.zip', '.tar', '.gz',
      '.lock', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.min.js', '.min.css',
      '.map',
    ];
    return (
      lower.startsWith('.git/') ||
      lower.includes('node_modules/') ||
      lower.includes('vendor/') ||
      skipExtensions.some((ext) => lower.endsWith(ext))
    );
  }
}
