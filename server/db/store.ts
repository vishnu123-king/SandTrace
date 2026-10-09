import fs from 'fs';
import path from 'path';
import os from 'os';
import { Finding, RepositoryMetadata, ScanJob, FindingStatus } from '../types.js';

const DATA_DIR = path.join(os.tmpdir(), 'sandtrace-data');
const SCANS_FILE = path.join(DATA_DIR, 'scans.json');
const REPOS_FILE = path.join(DATA_DIR, 'repos.json');
const FINDINGS_FILE = path.join(DATA_DIR, 'findings.json');

export class DataStore {
  private static scans: Map<string, ScanJob> = new Map();
  private static repos: Map<string, RepositoryMetadata> = new Map();
  private static findings: Map<string, Finding[]> = new Map(); // scanId -> Finding[]

  public static initialize(): void {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    // Load from disk if exists
    try {
      if (fs.existsSync(SCANS_FILE)) {
        const raw = JSON.parse(fs.readFileSync(SCANS_FILE, 'utf-8'));
        for (const item of raw) this.scans.set(item.id, item);
      }
      if (fs.existsSync(REPOS_FILE)) {
        const raw = JSON.parse(fs.readFileSync(REPOS_FILE, 'utf-8'));
        for (const item of raw) this.repos.set(item.id, item);
      }
      if (fs.existsSync(FINDINGS_FILE)) {
        const raw = JSON.parse(fs.readFileSync(FINDINGS_FILE, 'utf-8'));
        for (const [scanId, list] of Object.entries(raw)) {
          this.findings.set(scanId, list as Finding[]);
        }
      }
    } catch (err) {
      console.error('Failed to load existing data store:', err);
    }

    // If store is empty, seed initial demonstration repositories
    if (this.scans.size === 0) {
      this.seedInitialDemos();
    }
  }

  private static persist(): void {
    try {
      fs.writeFileSync(SCANS_FILE, JSON.stringify(Array.from(this.scans.values()), null, 2));
      fs.writeFileSync(REPOS_FILE, JSON.stringify(Array.from(this.repos.values()), null, 2));
      const obj: Record<string, Finding[]> = {};
      for (const [k, v] of this.findings.entries()) obj[k] = v;
      fs.writeFileSync(FINDINGS_FILE, JSON.stringify(obj, null, 2));
    } catch (err) {
      console.error('Failed to persist store:', err);
    }
  }

  public static getScan(id: string): ScanJob | undefined {
    return this.scans.get(id);
  }

  public static getAllScans(): ScanJob[] {
    return Array.from(this.scans.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  public static saveScan(scan: ScanJob): void {
    this.scans.set(scan.id, scan);
    this.persist();
  }

  public static deleteScan(id: string): void {
    this.scans.delete(id);
    this.findings.delete(id);
    this.persist();
  }

  public static getFindings(scanId: string): Finding[] {
    return this.findings.get(scanId) || [];
  }

  public static saveFindings(scanId: string, findingsList: Finding[]): void {
    this.findings.set(scanId, findingsList);
    this.persist();
  }

  public static updateFindingStatus(scanId: string, findingId: string, newStatus: FindingStatus): Finding | undefined {
    const list = this.findings.get(scanId);
    if (!list) return undefined;
    const target = list.find((f) => f.id === findingId);
    if (target) {
      target.status = newStatus;
      target.lastSeenAt = new Date().toISOString();
      this.persist();
    }
    return target;
  }

  public static getRepos(): RepositoryMetadata[] {
    return Array.from(this.repos.values()).sort(
      (a, b) => new Date(b.lastScannedAt || 0).getTime() - new Date(a.lastScannedAt || 0).getTime()
    );
  }

  public static getRepo(id: string): RepositoryMetadata | undefined {
    return this.repos.get(id);
  }

  public static saveRepo(repo: RepositoryMetadata): void {
    this.repos.set(repo.id, repo);
    this.persist();
  }

  /**
   * Seeds demo repositories so the user can immediately inspect the Security Observatory
   */
  private static seedInitialDemos(): void {
    const demoScanId1 = 'scan-demo-payment-api';
    const demoRepoId1 = 'repo-demo-payment-api';

    const repo1: RepositoryMetadata = {
      id: demoRepoId1,
      url: 'https://github.com/fintech-corp/payment-gateway-service.git',
      name: 'payment-gateway-service',
      owner: 'fintech-corp',
      provider: 'GitHub',
      defaultBranch: 'main',
      latestCommitSha: 'a7c92b84ef91024bc6',
      totalCommits: 342,
      totalContributors: 11,
      totalFiles: 86,
      languages: { TypeScript: 58000, Python: 32000, Shell: 4200 },
      lastScannedAt: new Date(Date.now() - 3600000 * 4).toISOString(),
      lastRiskScore: 88,
      scanCount: 3,
    };

    const scan1: ScanJob = {
      id: demoScanId1,
      repoUrl: repo1.url,
      repoName: repo1.name,
      provider: 'GitHub',
      defaultBranch: 'main',
      commitHash: 'a7c92b84',
      profile: 'deep',
      status: 'completed',
      progress: 100,
      currentStage: 'Report preparation',
      stages: [
        { name: 'Sandbox initialization', status: 'completed', durationMs: 410 },
        { name: 'Repository retrieval', status: 'completed', durationMs: 2300 },
        { name: 'File inventory', status: 'completed', durationMs: 180 },
        { name: 'Source-code analysis', status: 'completed', durationMs: 1420 },
        { name: 'Dependency analysis', status: 'completed', durationMs: 2890 },
        { name: 'Secret detection', status: 'completed', durationMs: 950 },
        { name: 'Git-history analysis', status: 'completed', durationMs: 1640 },
        { name: 'Contributor analysis', status: 'completed', durationMs: 510 },
        { name: 'Finding correlation', status: 'completed', durationMs: 310 },
        { name: 'Report preparation', status: 'completed', durationMs: 220 },
      ],
      summary: {
        total: 7,
        critical: 3,
        high: 2,
        medium: 2,
        low: 0,
        info: 0,
        secretsCount: 2,
        sastCount: 2,
        dependencyCount: 1,
        configCount: 1,
        authCount: 1,
        historicalCount: 1,
        currentCount: 6,
      },
      riskScore: 88,
      riskRating: 'CRITICAL',
      sandbox: {
        mode: 'isolated_workspace',
        isolationProfile: 'SecretShield-Strict-OCI-v2',
        runtimeAvailable: true,
        runtimeName: 'Linux Rootless Container Isolation Engine (OCI Compliant)',
        seccomp: true,
        networkIsolatedInAnalysis: true,
        noNewPrivileges: true,
        cpuLimit: '2 Cores (200%)',
        memoryLimit: '2048 MB',
        diskLimit: '500 MB',
        timeoutSeconds: 300,
        workspacePath: '/tmp/secretshield-sandboxes/scan-demo-payment-api',
        scannerImage: 'secretshield-scanner:1.4.2-pinned',
        toolVersions: {
          'semgrep-core': '1.85.0',
          'gitleaks': '8.19.1',
          'bandit-ast': '1.7.9',
          'trivy-config': '0.55.2',
          'osv-scanner': '1.8.4',
          'git': '2.34.1',
        },
      },
      createdAt: new Date(Date.now() - 3600000 * 4).toISOString(),
      startedAt: new Date(Date.now() - 3600000 * 4).toISOString(),
      completedAt: new Date(Date.now() - 3600000 * 4 + 10830).toISOString(),
      durationMs: 10830,
      filesScanned: 86,
      linesAnalyzed: 14250,
    };

    const findings1: Finding[] = [
      {
        id: `sec-${demoScanId1}-1`,
        scanId: demoScanId1,
        title: 'Exposed Stripe Live Secret Key',
        category: 'secret',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        filePath: 'src/config/stripe.ts',
        lineNumber: 14,
        scannerName: 'SecretShield-Gitleaks-Engine',
        ruleId: 'SEC-STRIPE-KEY',
        cweId: 'CWE-798: Use of Hard-coded Credentials',
        owasp: 'A07:2021-Identification and Authentication Failures',
        evidence: 'Active production Stripe Live API key found hardcoded in billing configuration.',
        maskedSnippet: 'export const STRIPE_KEY = "sk_live_••••••••••••••••••••[88bc]";',
        rawSecretFingerprint: '9f84a1e9c20184b2',
        remediation: 'Immediately roll and rotate this key in Stripe Dashboard. Transfer configuration to process.env.STRIPE_SECRET_KEY and verify that no charges or webhook spoofing occurred.',
        status: 'OPEN',
        exposureType: 'CURRENT',
        firstSeenAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        lastSeenAt: new Date().toISOString(),
        tags: ['secret', 'stripe', 'critical-credential'],
        referenceUrls: ['https://stripe.com/docs/keys'],
      },
      {
        id: `sec-${demoScanId1}-2`,
        scanId: demoScanId1,
        title: 'Historical Exposure: AWS Secret Access Key in Git Commit History',
        category: 'secret',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        filePath: 'deploy/scripts/backup.sh',
        commitHash: 'e39a194b',
        commitAuthor: 'Marcus Vance <m***e@fintech.io>',
        scannerName: 'SecretShield-Gitleaks-History-Engine',
        ruleId: 'SEC-AWS-SECRET-HISTORICAL',
        cweId: 'CWE-798: Use of Hard-coded Credentials in Git History',
        owasp: 'A07:2021-Identification and Authentication Failures',
        evidence: 'AWS Secret Key was committed in commit e39a194b. While removed from current HEAD, it is still readable via git history.',
        maskedSnippet: 'aws_secret_access_key="wJalrXUtn••••••••••••••••••••[7xLz]"',
        rawSecretFingerprint: 'a1b72e094c3917de',
        remediation: 'Do not assume removing a secret in a subsequent commit neutralizes the threat. Rotate this IAM key immediately in AWS IAM, and purge git history using git-filter-repo.',
        status: 'OPEN',
        exposureType: 'HISTORICAL',
        firstSeenAt: '2026-08-14T10:12:00Z',
        lastSeenAt: new Date().toISOString(),
        tags: ['secret', 'aws', 'historical'],
        referenceUrls: ['https://aws.amazon.com/security/'],
      },
      {
        id: `sast-${demoScanId1}-3`,
        scanId: demoScanId1,
        title: 'SQL Injection: Dynamic Query String Concatenation',
        category: 'sast',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        filePath: 'src/services/transactions.ts',
        lineNumber: 52,
        scannerName: 'SecretShield-Semgrep-Adapter',
        ruleId: 'SAST-SQLI-RAW',
        cweId: 'CWE-89: SQL Injection',
        owasp: 'A03:2021-Injection',
        evidence: 'User-provided search filter concatenated directly into raw PostgreSQL query string.',
        maskedSnippet: 'const q = `SELECT * FROM tx WHERE account_id = ${req.query.id} AND status = \'settled\'`;',
        remediation: 'Replace string template literal with parameterized query: `db.query("SELECT * FROM tx WHERE account_id = $1 AND status = \'settled\'", [req.query.id])`.',
        status: 'OPEN',
        exposureType: 'CURRENT',
        firstSeenAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        lastSeenAt: new Date().toISOString(),
        tags: ['sast', 'sqli'],
        referenceUrls: ['https://owasp.org/www-community/attacks/SQL_Injection'],
      },
      {
        id: `dep-${demoScanId1}-4`,
        scanId: demoScanId1,
        title: 'Vulnerable Dependency: jsonwebtoken@8.5.1 (GHSA-8cf7-32gw-wr33)',
        category: 'dependency',
        severity: 'HIGH',
        confidence: 'HIGH',
        filePath: 'package.json',
        scannerName: 'SecretShield-OSV-Adapter',
        ruleId: 'GHSA-8cf7-32gw-wr33',
        cweId: 'CWE-1395: Vulnerable Dependency',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        evidence: 'jsonwebtoken versions prior to 9.0.0 are vulnerable to algorithm confusion and insecure verification.',
        maskedSnippet: '"jsonwebtoken": "8.5.1"',
        remediation: 'Upgrade jsonwebtoken to version 9.0.0 or later in package.json and verify signature algorithms.',
        status: 'OPEN',
        exposureType: 'CURRENT',
        firstSeenAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        lastSeenAt: new Date().toISOString(),
        tags: ['dependency', 'npm', 'cve'],
        referenceUrls: ['https://osv.dev/vulnerability/GHSA-8cf7-32gw-wr33'],
      },
      {
        id: `conf-${demoScanId1}-5`,
        scanId: demoScanId1,
        title: 'Docker Compose Container Runs in Privileged Mode',
        category: 'configuration',
        severity: 'HIGH',
        confidence: 'HIGH',
        filePath: 'docker-compose.yml',
        lineNumber: 18,
        scannerName: 'SecretShield-Trivy-Config-Adapter',
        ruleId: 'CONF-COMPOSE-PRIVILEGED',
        cweId: 'CWE-250: Execution with Unnecessary Privileges',
        owasp: 'A05:2021-Security Misconfiguration',
        evidence: 'Container execution flag `privileged: true` bypasses Linux namespace protections.',
        maskedSnippet: 'privileged: true',
        remediation: 'Remove privileged mode from docker-compose.yml and restrict capabilities.',
        status: 'OPEN',
        exposureType: 'CURRENT',
        firstSeenAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        lastSeenAt: new Date().toISOString(),
        tags: ['configuration', 'docker'],
        referenceUrls: ['https://docs.docker.com/engine/security/'],
      },
      {
        id: `auth-${demoScanId1}-6`,
        scanId: demoScanId1,
        title: 'JWT Generated Without Expiration Claim (exp)',
        category: 'auth_security',
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        filePath: 'src/auth/tokenService.ts',
        lineNumber: 38,
        scannerName: 'SecretShield-Auth-Analyzer',
        ruleId: 'AUTH-MISSING-TOKEN-EXPIRATION',
        cweId: 'CWE-613: Insufficient Session Expiration',
        owasp: 'A07:2021-Identification and Authentication Failures',
        evidence: 'Token generation omitted expiresIn attribute, resulting in indefinitely valid credentials.',
        maskedSnippet: 'return jwt.sign({ sub: user.id, role: user.role }, secret);',
        remediation: 'Add `expiresIn: "1h"` to jwt.sign options to enforce session expiration.',
        status: 'OPEN',
        exposureType: 'CURRENT',
        firstSeenAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        lastSeenAt: new Date().toISOString(),
        tags: ['auth', 'jwt'],
        referenceUrls: ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'],
      },
      {
        id: `sast-${demoScanId1}-7`,
        scanId: demoScanId1,
        title: 'Permissive CORS: Wildcard Origin with Credentials Allowed',
        category: 'sast',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        filePath: 'src/server.ts',
        lineNumber: 22,
        scannerName: 'SecretShield-Semgrep-Adapter',
        ruleId: 'SAST-CORS-WILDCARD-CREDS',
        cweId: 'CWE-942: Permissive Cross-domain Policy',
        owasp: 'A01:2021-Broken Access Control',
        evidence: 'CORS policy configured with wildcard origin alongside credentials: true.',
        maskedSnippet: 'app.use(cors({ origin: "*", credentials: true }));',
        remediation: 'Define an explicit origin whitelist instead of using wildcard `*`.',
        status: 'OPEN',
        exposureType: 'CURRENT',
        firstSeenAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        lastSeenAt: new Date().toISOString(),
        tags: ['sast', 'cors'],
        referenceUrls: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
      },
    ];

    this.repos.set(repo1.id, repo1);
    this.scans.set(scan1.id, scan1);
    this.findings.set(demoScanId1, findings1);
    this.persist();
  }
}
