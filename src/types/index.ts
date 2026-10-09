export type ScanProfile = 'quick' | 'deep' | 'investigation' | 'changed_code';

export type FindingCategory =
  | 'secret'
  | 'sast'
  | 'dependency'
  | 'configuration'
  | 'auth_security'
  | 'privacy';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type FindingStatus =
  | 'OPEN'
  | 'INVESTIGATING'
  | 'CONFIRMED'
  | 'FALSE_POSITIVE'
  | 'RESOLVED';

export type ExposureType = 'CURRENT' | 'HISTORICAL';

export interface Finding {
  id: string;
  scanId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  filePath: string;
  lineNumber?: number;
  endLineNumber?: number;
  commitHash?: string;
  commitAuthor?: string;
  commitDate?: string;
  scannerName: string;
  ruleId: string;
  cweId?: string;
  owasp?: string;
  evidence: string;
  maskedSnippet: string;
  rawSecretFingerprint?: string;
  remediation: string;
  status: FindingStatus;
  exposureType: ExposureType;
  firstSeenAt: string;
  lastSeenAt: string;
  tags?: string[];
  referenceUrls?: string[];
}

export type ScanStageName =
  | 'Sandbox initialization'
  | 'Repository retrieval'
  | 'File inventory'
  | 'Source-code analysis'
  | 'Dependency analysis'
  | 'Secret detection'
  | 'Git-history analysis'
  | 'Contributor analysis'
  | 'Finding correlation'
  | 'Report preparation';

export interface ScanStage {
  name: ScanStageName;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
  message?: string;
}

export interface SandboxMetadata {
  mode: 'podman_rootless' | 'docker_rootless' | 'linux_namespace' | 'isolated_workspace';
  isolationProfile: string;
  runtimeAvailable: boolean;
  runtimeName: string;
  seccomp: boolean;
  networkIsolatedInAnalysis: boolean;
  noNewPrivileges: boolean;
  cpuLimit: string;
  memoryLimit: string;
  diskLimit: string;
  timeoutSeconds: number;
  workspacePath: string;
  scannerImage: string;
  toolVersions: Record<string, string>;
  cleanedUpAt?: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  secretsCount: number;
  sastCount: number;
  dependencyCount: number;
  configCount: number;
  authCount: number;
  historicalCount: number;
  currentCount: number;
}

export interface ScanJob {
  id: string;
  repoUrl: string;
  repoName: string;
  provider: 'GitHub' | 'GitLab' | 'Forgejo' | 'Gitea' | 'Bitbucket' | 'Generic Git';
  defaultBranch?: string;
  commitHash?: string;
  profile: ScanProfile;
  status: 'queued' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  currentStage: ScanStageName;
  stages: ScanStage[];
  summary: ScanSummary;
  riskScore: number;
  riskRating: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'MODERATE' | 'LOW';
  sandbox: SandboxMetadata;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
  filesScanned: number;
  linesAnalyzed: number;
  errorMessage?: string;
  contributors?: ContributorInfo[];
  timelineEvents?: ExposureTimelineEvent[];
  dependencies?: DependencyItem[];
}

export interface RepositoryMetadata {
  id: string;
  url: string;
  name: string;
  owner: string;
  provider: string;
  defaultBranch: string;
  latestCommitSha?: string;
  totalCommits: number;
  totalContributors: number;
  totalFiles: number;
  languages: Record<string, number>;
  lastScannedAt?: string;
  lastRiskScore?: number;
  scanCount: number;
}

export interface ContributorInfo {
  name: string;
  maskedEmail: string;
  commitCount: number;
  firstCommitDate: string;
  lastCommitDate: string;
  percentageOfCommits: number;
  sensitiveFilesTouched: string[];
  reviewSignals: string[];
}

export interface DependencyVulnerability {
  id: string;
  cve?: string;
  summary: string;
  severity: Severity;
  cvss?: number;
  fixedVersion?: string;
  advisoryUrl: string;
}

export interface DependencyItem {
  name: string;
  version: string;
  ecosystem: 'npm' | 'pypi' | 'go' | 'maven' | 'cargo' | 'other';
  manifestPath: string;
  isDirect: boolean;
  vulnerabilities: DependencyVulnerability[];
}

export interface ExposureTimelineEvent {
  id: string;
  timestamp: string;
  commitHash: string;
  author: string;
  type:
    | 'secret_introduced'
    | 'secret_removed_head'
    | 'sensitive_config_changed'
    | 'auth_logic_modified'
    | 'dependency_vulnerable_added'
    | 'scan_performed';
  title: string;
  description: string;
  filePath: string;
  findingId?: string;
  severity?: Severity;
}
