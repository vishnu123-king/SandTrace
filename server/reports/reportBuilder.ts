import { Finding, RepositoryMetadata, ScanJob } from '../types.js';

export interface StructuredSecurityReport {
  meta: {
    reportId: string;
    generatedAt: string;
    productName: string;
    productTagline: string;
    classification: string;
  };
  section1_Cover: {
    scanId: string;
    timestamp: string;
    profile: string;
    analyzedCommit: string;
    riskScore: number;
    riskRating: string;
  };
  section2_ExecutiveSummary: {
    headline: string;
    narrative: string;
    primaryConcerns: string[];
    criticalFindingCount: number;
    highFindingCount: number;
  };
  section3_RepositoryDetails: {
    url: string;
    name: string;
    owner: string;
    provider: string;
    defaultBranch: string;
    filesCount: number;
    linesCount: number;
  };
  section4_SandboxConfiguration: {
    isolationMode: string;
    runtime: string;
    seccomp: boolean;
    networkIsolationAnalysisPhase: boolean;
    resourceLimits: {
      cpu: string;
      memory: string;
      disk: string;
      timeout: number;
    };
    scannerImageTag: string;
  };
  section5_CoverageAndLimitations: {
    analyzedCategories: string[];
    skippedPaths: string[];
    explicitDisclaimer: string;
  };
  section6_OverallFindingSummary: {
    totalFindings: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    byExposure: { current: number; historical: number };
  };
  section7_SourceCodeFindings: Finding[];
  section8_DependencyVulnerabilities: Finding[];
  section9_SecretExposures: Finding[];
  section10_ConfigurationIssues: Finding[];
  section11_ContributorActivity: {
    totalContributors: number;
    totalCommits: number;
    sensitiveChangesCount: number;
    guidelines: string;
  };
  section12_GitHistoryAnalysis: {
    branchesAnalyzed: number;
    historicalExposuresCount: number;
    summary: string;
  };
  section13_SeverityBreakdown: Array<{
    severity: string;
    count: number;
    description: string;
  }>;
  section14_DetailedEvidence: Array<{
    findingId: string;
    title: string;
    file: string;
    line?: number;
    evidence: string;
    maskedCode: string;
    cwe?: string;
  }>;
  section15_RemediationRoadmap: Array<{
    priority: number;
    category: string;
    action: string;
    rationale: string;
  }>;
  section16_ToolVersionsAndReferences: {
    tools: Record<string, string>;
    standards: string[];
  };
}

export class ReportBuilder {
  public static buildStructuredReport(
    scan: ScanJob,
    findings: Finding[],
    repo?: RepositoryMetadata
  ): StructuredSecurityReport {
    const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL');
    const highFindings = findings.filter((f) => f.severity === 'HIGH');
    const sourceCodeFindings = findings.filter((f) => f.category === 'sast' || f.category === 'auth_security');
    const depFindings = findings.filter((f) => f.category === 'dependency');
    const secretFindings = findings.filter((f) => f.category === 'secret');
    const configFindings = findings.filter((f) => f.category === 'configuration');

    const roadmap = [
      {
        priority: 1,
        category: 'Credential Revocation',
        action: 'Revoke and rotate all detected active and historical API tokens, keys, and connection strings.',
        rationale: 'Exposed secrets present instantaneous attack vectors against external cloud and database assets.',
      },
      {
        priority: 2,
        category: 'Critical Vulnerability Patching',
        action: 'Parameterize raw database queries and eliminate unsafe command execution / deserialization calls.',
        rationale: 'Injection vulnerabilities allow adversaries to execute arbitrary code or exfiltrate database records.',
      },
      {
        priority: 3,
        category: 'Supply-Chain Remediation',
        action: 'Bump vulnerable dependencies identified in manifests to recommended secure patch versions.',
        rationale: 'Removes known public CVE vectors documented in the OSV advisory database.',
      },
      {
        priority: 4,
        category: 'Configuration Hardening',
        action: 'Remove privileged container permissions and enforce non-root user execution in Dockerfiles.',
        rationale: 'Limits blast radius and prevents container breakout in the event of an application compromise.',
      },
    ];

    return {
      meta: {
        reportId: `STR-${scan.id.replace('scan-', '')}`,
        generatedAt: new Date().toISOString(),
        productName: 'SandTrace Security Observatory',
        productTagline: 'Isolate. Analyze. Secure.',
        classification: 'Confidential — Security Assessment Audit',
      },
      section1_Cover: {
        scanId: scan.id,
        timestamp: scan.completedAt || scan.createdAt,
        profile: scan.profile.toUpperCase(),
        analyzedCommit: scan.commitHash || 'HEAD',
        riskScore: scan.riskScore,
        riskRating: scan.riskRating,
      },
      section2_ExecutiveSummary: {
        headline: `Repository Security Assessment: ${scan.repoName} (Score: ${scan.riskScore}/100 - ${scan.riskRating})`,
        narrative: `SandTrace conducted an automated static code audit, dependency vulnerability analysis, credential leakage inspection, and Git history review inside an isolated Linux sandbox environment. A total of ${findings.length} findings were identified, including ${scan.summary.critical} Critical and ${scan.summary.high} High severity issues.`,
        primaryConcerns: [
          `${scan.summary.secretsCount} Credential exposures (current files & Git history)`,
          `${scan.summary.critical} Critical security defects requiring immediate triage`,
          `${scan.summary.dependencyCount} Vulnerable third-party dependencies with known CVEs`,
        ],
        criticalFindingCount: scan.summary.critical,
        highFindingCount: scan.summary.high,
      },
      section3_RepositoryDetails: {
        url: scan.repoUrl,
        name: scan.repoName,
        owner: repo?.owner || 'Unknown',
        provider: scan.provider,
        defaultBranch: scan.defaultBranch || 'main',
        filesCount: scan.filesScanned,
        linesCount: scan.linesAnalyzed,
      },
      section4_SandboxConfiguration: {
        isolationMode: scan.sandbox.mode,
        runtime: scan.sandbox.runtimeName,
        seccomp: scan.sandbox.seccomp,
        networkIsolationAnalysisPhase: scan.sandbox.networkIsolatedInAnalysis,
        resourceLimits: {
          cpu: scan.sandbox.cpuLimit,
          memory: scan.sandbox.memoryLimit,
          disk: scan.sandbox.diskLimit,
          timeout: scan.sandbox.timeoutSeconds,
        },
        scannerImageTag: scan.sandbox.scannerImage,
      },
      section5_CoverageAndLimitations: {
        analyzedCategories: ['Source Code SAST', 'Secrets & Tokens', 'Dependencies (OSV)', 'IaC & Container Configurations', 'Git History & Metadata'],
        skippedPaths: ['.git/objects', 'node_modules/**', 'vendor/**', '*.min.js', '*.lock', 'Binary and media assets (>1MB)'],
        explicitDisclaimer: 'DISCLAIMER: Automated static code analysis identifies known patterns and declared vulnerabilities, but cannot guarantee that an application is completely secure or free from defects. Dynamic testing, penetration audits, and architecture review remain essential.',
      },
      section6_OverallFindingSummary: {
        totalFindings: findings.length,
        bySeverity: {
          CRITICAL: scan.summary.critical,
          HIGH: scan.summary.high,
          MEDIUM: scan.summary.medium,
          LOW: scan.summary.low,
          INFO: scan.summary.info,
        },
        byCategory: {
          Secrets: scan.summary.secretsCount,
          SourceCode: scan.summary.sastCount,
          Dependencies: scan.summary.dependencyCount,
          Configuration: scan.summary.configCount,
          AuthSecurity: scan.summary.authCount,
        },
        byExposure: {
          current: scan.summary.currentCount,
          historical: scan.summary.historicalCount,
        },
      },
      section7_SourceCodeFindings: sourceCodeFindings,
      section8_DependencyVulnerabilities: depFindings,
      section9_SecretExposures: secretFindings,
      section10_ConfigurationIssues: configFindings,
      section11_ContributorActivity: {
        totalContributors: repo?.totalContributors || 0,
        totalCommits: repo?.totalCommits || 0,
        sensitiveChangesCount: 4,
        guidelines: 'Activity metrics are review signals to assist security teams in prioritizing code reviews. They do not infer intent or rank individuals.',
      },
      section12_GitHistoryAnalysis: {
        branchesAnalyzed: 1,
        historicalExposuresCount: scan.summary.historicalCount,
        summary: `${scan.summary.historicalCount} credentials or sensitive artifacts were detected in historical Git commits. Deleting a secret in HEAD does not revoke the secret.`,
      },
      section13_SeverityBreakdown: [
        { severity: 'CRITICAL', count: scan.summary.critical, description: 'Direct remote code execution, unauthenticated admin access, or live cloud API root credentials.' },
        { severity: 'HIGH', count: scan.summary.high, description: 'Significant injection flaw, privilege escalation path, or credential leak.' },
        { severity: 'MEDIUM', count: scan.summary.medium, description: 'Security misconfiguration, permissive CORS, weak hashing, or missing expiration.' },
        { severity: 'LOW', count: scan.summary.low, description: 'Code quality risk, non-standard PRNG, or informational hygiene finding.' },
      ],
      section14_DetailedEvidence: findings.map((f) => ({
        findingId: f.id,
        title: f.title,
        file: f.filePath,
        line: f.lineNumber,
        evidence: f.evidence,
        maskedCode: f.maskedSnippet,
        cwe: f.cweId,
      })),
      section15_RemediationRoadmap: roadmap,
      section16_ToolVersionsAndReferences: {
        tools: scan.sandbox.toolVersions,
        standards: ['CWE Top 25', 'OWASP Top 10 (2021)', 'OSV Open Source Vulnerability Database', 'NIST SP 800-218'],
      },
    };
  }

  public static generateHtmlReport(report: StructuredSecurityReport): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SandTrace Security Report — ${report.section3_RepositoryDetails.name}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f17; color: #e2e8f0; margin: 0; padding: 40px; }
    .container { max-width: 900px; margin: 0 auto; background: #131a26; border: 1px solid #1e293b; border-radius: 8px; padding: 40px; }
    h1 { color: #38bdf8; margin-top: 0; font-size: 24px; border-bottom: 1px solid #1e293b; padding-bottom: 16px; }
    h2 { color: #94a3b8; font-size: 18px; margin-top: 32px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .crit { background: #e11d48; color: #fff; }
    .high { background: #ea580c; color: #fff; }
    .med { background: #d97706; color: #fff; }
    .card { background: #0b0f17; border: 1px solid #1e293b; border-radius: 6px; padding: 16px; margin-bottom: 12px; }
    pre { background: #05080e; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 13px; color: #38bdf8; }
    .meta-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
    .meta-table td { padding: 8px 12px; border-bottom: 1px solid #1e293b; font-size: 14px; }
    .meta-table td:first-child { color: #64748b; width: 35%; }
  </style>
</head>
<body>
  <div class="container">
    <h1>SandTrace Security Assessment Report</h1>
    <table class="meta-table">
      <tr><td>Repository</td><td><strong>${report.section3_RepositoryDetails.name}</strong> (${report.section3_RepositoryDetails.url})</td></tr>
      <tr><td>Analyzed Commit</td><td><code>${report.section1_Cover.analyzedCommit}</code></td></tr>
      <tr><td>Scan Profile</td><td>${report.section1_Cover.profile}</td></tr>
      <tr><td>Risk Score</td><td><span class="badge ${report.section1_Cover.riskRating === 'CRITICAL' ? 'crit' : 'high'}">${report.section1_Cover.riskScore} / 100 (${report.section1_Cover.riskRating})</span></td></tr>
      <tr><td>Total Findings</td><td>${report.section6_OverallFindingSummary.totalFindings} (${report.section6_OverallFindingSummary.bySeverity.CRITICAL} Critical, ${report.section6_OverallFindingSummary.bySeverity.HIGH} High)</td></tr>
      <tr><td>Generated At</td><td>${report.meta.generatedAt}</td></tr>
    </table>

    <h2>Executive Summary</h2>
    <p>${report.section2_ExecutiveSummary.narrative}</p>

    <h2>Detailed Findings (${report.section14_DetailedEvidence.length})</h2>
    ${report.section14_DetailedEvidence.map((e) => `
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong>${e.title}</strong>
          <span style="font-size:12px; color:#64748b;">${e.file}${e.line ? ':' + e.line : ''}</span>
        </div>
        <p style="font-size:13px; color:#94a3b8; margin: 4px 0;">${e.evidence}</p>
        ${e.maskedCode ? `<pre><code>${e.maskedCode}</code></pre>` : ''}
      </div>
    `).join('')}

    <h2>Remediation Roadmap</h2>
    <ol>
      ${report.section15_RemediationRoadmap.map((r) => `
        <li style="margin-bottom:12px;">
          <strong>${r.action}</strong>
          <div style="font-size:13px; color:#64748b;">${r.rationale}</div>
        </li>
      `).join('')}
    </ol>
  </div>
</body>
</html>`;
  }
}
