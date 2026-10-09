import fs from 'fs';
import path from 'path';
import { Finding, Severity } from '../types.js';

interface ConfigRule {
  id: string;
  title: string;
  severity: Severity;
  fileMatcher: (relPath: string) => boolean;
  checker: (content: string, lines: string[]) => { line?: number; snippet?: string; detail?: string } | null;
  cwe: string;
  owasp: string;
  remediation: string;
}

const CONFIG_RULES: ConfigRule[] = [
  {
    id: 'CONF-DOCKER-ROOT-USER',
    title: 'Dockerfile Executes as Root (Missing USER Instruction)',
    severity: 'MEDIUM',
    fileMatcher: (p) => path.basename(p).toLowerCase().startsWith('dockerfile'),
    checker: (content) => {
      const hasFrom = /^\s*FROM\s+/im.test(content);
      const hasUser = /^\s*USER\s+[a-zA-Z0-9_\-]+/im.test(content);
      if (hasFrom && !hasUser) {
        return {
          line: 1,
          snippet: 'FROM ... (No USER declaration specified)',
          detail: 'Container executes under UID 0 (root) by default, increasing blast radius in container escape scenarios.',
        };
      }
      return null;
    },
    cwe: 'CWE-250: Execution with Unnecessary Privileges',
    owasp: 'A05:2021-Security Misconfiguration',
    remediation: 'Create and switch to a non-privileged system user before running application processes: `RUN addgroup -S app && adduser -S app -G app && USER app`.',
  },
  {
    id: 'CONF-DOCKER-SECRET-ENV',
    title: 'Secret or Sensitive Token Hardcoded in Dockerfile ENV/ARG',
    severity: 'HIGH',
    fileMatcher: (p) => path.basename(p).toLowerCase().startsWith('dockerfile'),
    checker: (content, lines) => {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*(?:ENV|ARG)\s+.*?(?:SECRET|PASSWORD|PASSWD|API_KEY|TOKEN)\s*=\s*['"]?[a-zA-Z0-9_\-!@#$%^&*]{6,}['"]?/i.test(line)) {
          return {
            line: i + 1,
            snippet: line.trim().slice(0, 140),
            detail: 'Secrets in ENV/ARG instructions persist into container image layer metadata and are inspectable via `docker history`.',
          };
        }
      }
      return null;
    },
    cwe: 'CWE-312: Cleartext Storage of Sensitive Information',
    owasp: 'A05:2021-Security Misconfiguration',
    remediation: 'Do not bake secrets into container images. Use BuildKit secret mounts (`--mount=type=secret`) or inject credentials at runtime using environment variables.',
  },
  {
    id: 'CONF-COMPOSE-PRIVILEGED',
    title: 'Docker Compose Container Runs in Privileged Mode',
    severity: 'CRITICAL',
    fileMatcher: (p) => /docker-compose.*\.ya?ml$/i.test(p) || /compose.*\.ya?ml$/i.test(p),
    checker: (content, lines) => {
      for (let i = 0; i < lines.length; i++) {
        if (/^\s*privileged\s*:\s*true/i.test(lines[i])) {
          return {
            line: i + 1,
            snippet: lines[i].trim(),
            detail: '`privileged: true` grants full root capabilities on host devices, bypassing container isolation boundaries.',
          };
        }
      }
      return null;
    },
    cwe: 'CWE-250: Execution with Unnecessary Privileges',
    owasp: 'A05:2021-Security Misconfiguration',
    remediation: 'Remove `privileged: true`. Grant only the granular Linux capabilities required using `cap_add: [ "CAP_NET_BIND_SERVICE" ]`.',
  },
  {
    id: 'CONF-K8S-HOSTPATH-MOUNT',
    title: 'Kubernetes Pod Mounts Host Path Filesystem (hostPath)',
    severity: 'HIGH',
    fileMatcher: (p) => /\.ya?ml$/i.test(p) && (p.includes('k8s') || p.includes('deploy') || p.includes('manifest')),
    checker: (content, lines) => {
      for (let i = 0; i < lines.length; i++) {
        if (/^\s*hostPath\s*:/i.test(lines[i])) {
          return {
            line: i + 1,
            snippet: lines[i].trim(),
            detail: 'Mounting host directories (`hostPath`) inside Pod containers creates a critical path to host root filesystem tampering.',
          };
        }
      }
      return null;
    },
    cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
    owasp: 'A05:2021-Security Misconfiguration',
    remediation: 'Use Kubernetes PersistentVolumes (PV/PVC) or emptyDir volumes rather than hostPath mounts.',
  },
  {
    id: 'CONF-GHA-PERMISSIONS-ALL',
    title: 'GitHub Actions Workflow Grants Broad Write Permissions',
    severity: 'HIGH',
    fileMatcher: (p) => p.includes('.github/workflows/') && /\.ya?ml$/i.test(p),
    checker: (content, lines) => {
      for (let i = 0; i < lines.length; i++) {
        if (/^\s*permissions\s*:\s*write-all/i.test(lines[i])) {
          return {
            line: i + 1,
            snippet: lines[i].trim(),
            detail: '`permissions: write-all` gives the GITHUB_TOKEN write access across repositories, packages, and releases, elevating risk in supply chain attacks.',
          };
        }
      }
      return null;
    },
    cwe: 'CWE-276: Incorrect Default Permissions',
    owasp: 'A05:2021-Security Misconfiguration',
    remediation: 'Follow the principle of least privilege. Grant only specific required permissions (e.g., `permissions: { contents: read }`).',
  },
];

export class ConfigScanner {
  public static scanFiles(scanId: string, repoDir: string, relativeFiles: string[]): Finding[] {
    const findings: Finding[] = [];

    for (const relPath of relativeFiles) {
      const applicableRules = CONFIG_RULES.filter((r) => r.fileMatcher(relPath));
      if (applicableRules.length === 0) continue;

      const fullPath = path.join(repoDir, relPath);
      let content = '';
      try {
        const stats = fs.statSync(fullPath);
        if (stats.size > 500 * 1024) continue;
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');

      for (const rule of applicableRules) {
        const result = rule.checker(content, lines);
        if (result) {
          findings.push({
            id: `conf-${scanId}-${findings.length + 1}`,
            scanId,
            title: rule.title,
            category: 'configuration',
            severity: rule.severity,
            confidence: 'HIGH',
            filePath: relPath,
            lineNumber: result.line,
            scannerName: 'SecretShield-Trivy-Config-Adapter',
            ruleId: rule.id,
            cweId: rule.cwe,
            owasp: rule.owasp,
            evidence: result.detail || 'Insecure configuration detected.',
            maskedSnippet: result.snippet || '',
            remediation: rule.remediation,
            status: 'OPEN',
            exposureType: 'CURRENT',
            firstSeenAt: new Date().toISOString(),
            lastSeenAt: new Date().toISOString(),
            tags: ['configuration', 'iac', 'docker', rule.id],
            referenceUrls: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html',
            ],
          });
        }
      }
    }

    return findings;
  }
}
