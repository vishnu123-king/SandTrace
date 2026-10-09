import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { Finding, RepositoryMetadata, ScanJob } from '../types';

export function generatePdfSecurityReport(
  scan: ScanJob,
  findings: Finding[],
  repo?: RepositoryMetadata
): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const primaryColor: [number, number, number] = [15, 23, 42]; // Slate 900
  const accentColor: [number, number, number] = [14, 165, 233]; // Sky 500
  const textColor: [number, number, number] = [30, 41, 59]; // Slate 800
  const mutedColor: [number, number, number] = [100, 116, 139]; // Slate 500

  // PAGE 1: COVER & ASSESSMENT INFORMATION (Section 1)
  doc.setFillColor(...primaryColor);
  doc.rect(0, 0, 210, 297, 'F');

  // Decorative accent line
  doc.setFillColor(...accentColor);
  doc.rect(0, 0, 8, 297, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(28);
  doc.text('SANDTRACE', 24, 45);

  doc.setFontSize(12);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text('SECURITY OBSERVATORY — REPOSITORY AUDIT REPORT', 24, 53);
  doc.text('Isolate. Analyze. Secure.', 24, 60);

  // Divider
  doc.setDrawColor(51, 65, 85);
  doc.line(24, 75, 190, 75);

  // Target Repository Box
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(24, 90, 166, 70, 3, 3, 'F');

  doc.setTextColor(56, 189, 248);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text('ASSESSMENT TARGET', 32, 102);

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(18);
  doc.text(scan.repoName, 32, 114);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(203, 213, 225);
  doc.text(`Repository URL: ${scan.repoUrl}`, 32, 124);
  doc.text(`Git Provider: ${scan.provider}  |  Branch: ${scan.defaultBranch || 'main'}`, 32, 131);
  doc.text(`Analyzed Commit: ${scan.commitHash || 'HEAD'}`, 32, 138);
  doc.text(`Scan Profile: ${scan.profile.toUpperCase()} AUDIT`, 32, 145);

  // Risk Score Badge on Cover
  const riskBoxColor: [number, number, number] =
    scan.riskRating === 'CRITICAL'
      ? [225, 29, 72]
      : scan.riskRating === 'HIGH'
      ? [234, 88, 12]
      : scan.riskRating === 'ELEVATED'
      ? [217, 119, 6]
      : [16, 185, 129];

  doc.setFillColor(...riskBoxColor);
  doc.roundedRect(24, 175, 166, 32, 3, 3, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.text(`OVERALL RISK SCORE: ${scan.riskScore} / 100 (${scan.riskRating})`, 32, 188);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.text(`${scan.summary.total} Total Findings  |  ${scan.summary.critical} Critical  |  ${scan.summary.high} High  |  ${scan.summary.medium} Medium`, 32, 198);

  // Metadata Footer on Cover
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text(`Scan ID: ${scan.id}`, 24, 250);
  doc.text(`Execution Date: ${scan.completedAt || scan.createdAt}`, 24, 256);
  doc.text(`Isolation Runtime: ${scan.sandbox.runtimeName}`, 24, 262);
  doc.text('Classification: STRICTLY CONFIDENTIAL — CYBERSECURITY AUDIT', 24, 275);

  // --- PAGE 2: EXECUTIVE SUMMARY & REPOSITORY / SANDBOX (Sections 2, 3, 4, 5) ---
  doc.addPage();
  let y = 20;

  const printHeader = (title: string, sectionNum: number) => {
    doc.setFillColor(241, 245, 249);
    doc.rect(14, y - 4, 182, 8, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...primaryColor);
    doc.text(`SECTION ${sectionNum}: ${title.toUpperCase()}`, 16, y + 2);
    y += 12;
  };

  printHeader('Executive Summary', 2);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(...textColor);
  const execText = `SandTrace completed a static cybersecurity analysis of ${scan.repoName} inside an isolated Linux sandbox workspace. The scanner identified ${scan.summary.total} actionable security findings across source code, exposed credentials, vulnerable dependencies, and infrastructure files. Critical vulnerabilities require immediate revocation and code remediation before deployment.`;
  const splitExec = doc.splitTextToSize(execText, 180);
  doc.text(splitExec, 16, y);
  y += splitExec.length * 5 + 6;

  printHeader('Repository and Provider Details', 3);
  autoTable(doc, {
    startY: y,
    head: [['Attribute', 'Value', 'Attribute', 'Value']],
    body: [
      ['Repository', scan.repoName, 'Provider', scan.provider],
      ['Git URL', scan.repoUrl, 'Analyzed SHA', scan.commitHash || 'HEAD'],
      ['Files Scanned', String(scan.filesScanned || repo?.totalFiles || 0), 'Lines Analyzed', String(scan.linesAnalyzed || 0)],
      ['Contributors', String(repo?.totalContributors || 0), 'Commits', String(repo?.totalCommits || 0)],
    ],
    theme: 'grid',
    styles: { fontSize: 8.5, cellPadding: 2 },
    headStyles: { fillColor: primaryColor },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  printHeader('Sandbox & Scan Configuration', 4);
  autoTable(doc, {
    startY: y,
    head: [['Security Control', 'Enforced Policy']],
    body: [
      ['Isolation Mode', scan.sandbox.mode.toUpperCase()],
      ['Container Runtime', scan.sandbox.runtimeName],
      ['Network Boundary', 'Analysis stage network access disabled (Strict airgap)'],
      ['Privilege Enforcement', 'no-new-privileges active, capabilities dropped, non-root execution'],
      ['Resource Limits', `CPU: ${scan.sandbox.cpuLimit} | RAM: ${scan.sandbox.memoryLimit} | Disk: ${scan.sandbox.diskLimit}`],
      ['Scanner Base Image', scan.sandbox.scannerImage],
    ],
    theme: 'grid',
    styles: { fontSize: 8.5, cellPadding: 2 },
    headStyles: { fillColor: primaryColor },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  printHeader('Scan Coverage & Limitations', 5);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...mutedColor);
  const disclaimer = 'Automated static analysis evaluates source code patterns, manifest versions, and credentials, but cannot verify runtime behavior, external infrastructure, or zero-day logic flaws. Distinguish confirmed scanner evidence from manual-review flags. A clean scan does not prove an application is defect-free.';
  const splitDisc = doc.splitTextToSize(disclaimer, 180);
  doc.text(splitDisc, 16, y);
  y += splitDisc.length * 4.5 + 8;

  // --- PAGE 3: FINDINGS BREAKDOWN & SUMMARY (Sections 6, 13) ---
  doc.addPage();
  y = 20;

  printHeader('Overall Finding Summary & Risk Breakdown', 6);
  autoTable(doc, {
    startY: y,
    head: [['Severity Level', 'Count', 'Risk Weight', 'Definition']],
    body: [
      ['CRITICAL', String(scan.summary.critical), '28 pts', 'Direct remote code execution, unauthenticated root/cloud access, or live credentials'],
      ['HIGH', String(scan.summary.high), '14 pts', 'Significant injection flaw, privilege escalation, or high-confidence vulnerability'],
      ['MEDIUM', String(scan.summary.medium), '5 pts', 'Security misconfiguration, permissive CORS, weak hashing, or missing expiration'],
      ['LOW', String(scan.summary.low), '1 pt', 'Non-standard PRNG, informational hygiene, or minor deviation from best practice'],
      ['INFO', String(scan.summary.info), '0 pts', 'Contextual security metadata or manual review advisory'],
    ],
    theme: 'grid',
    styles: { fontSize: 8.5, cellPadding: 2.5 },
    headStyles: { fillColor: primaryColor },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  // Findings by Category
  autoTable(doc, {
    startY: y,
    head: [['Category', 'Count', 'Exposure Type', 'Count']],
    body: [
      ['Exposed Credentials & Secrets', String(scan.summary.secretsCount), 'Current HEAD Exposure', String(scan.summary.currentCount)],
      ['Source Code Security (SAST)', String(scan.summary.sastCount), 'Historical Git History Exposure', String(scan.summary.historicalCount)],
      ['Dependency Vulnerabilities (CVEs)', String(scan.summary.dependencyCount), 'Total Analyzed Signals', String(scan.summary.total)],
      ['Infrastructure & Configurations', String(scan.summary.configCount), 'Risk Score', `${scan.riskScore}/100 (${scan.riskRating})`],
    ],
    theme: 'grid',
    styles: { fontSize: 8.5, cellPadding: 2.5 },
    headStyles: { fillColor: primaryColor },
  });
  y = (doc as any).lastAutoTable.finalY + 12;

  // --- DETAILED EVIDENCE & FINDINGS (Sections 7, 8, 9, 10, 14) ---
  printHeader('Detailed Findings & Masked Evidence', 14);
  const findingsRows = findings.slice(0, 30).map((f, idx) => [
    String(idx + 1),
    f.severity,
    f.title,
    `${f.filePath}${f.lineNumber ? ':' + f.lineNumber : ''}`,
    f.category.toUpperCase(),
    f.exposureType,
  ]);

  autoTable(doc, {
    startY: y,
    head: [['#', 'Severity', 'Finding Title', 'Location', 'Category', 'Exposure']],
    body: findingsRows,
    theme: 'striped',
    styles: { fontSize: 8, cellPadding: 2 },
    headStyles: { fillColor: primaryColor },
    didParseCell: (data) => {
      if (data.column.index === 1) {
        const text = String(data.cell.raw);
        if (text === 'CRITICAL') data.cell.styles.textColor = [225, 29, 72];
        else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
        else if (text === 'MEDIUM') data.cell.styles.textColor = [217, 119, 6];
        else data.cell.styles.textColor = [16, 185, 129];
        data.cell.styles.fontStyle = 'bold';
      }
    },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  // --- PAGE 4: REMEDIATION ROADMAP & REFERENCES (Sections 15, 16) ---
  doc.addPage();
  y = 20;

  printHeader('Remediation Recommendations & Action Plan', 15);
  autoTable(doc, {
    startY: y,
    head: [['Priority', 'Target', 'Actionable Guidance', 'Impact']],
    body: [
      ['P1 (Immediate)', 'Secrets & Credentials', 'Revoke and rotate all detected API tokens, database URIs, and SSH keys. Transfer to environment secrets.', 'Neutralizes unauthorized cloud and database entry points.'],
      ['P2 (High)', 'Injection & SAST', 'Parameterize all dynamic SQL statements. Remove shell execution and unsafe deserialization.', 'Prevents remote code execution and data breach.'],
      ['P3 (Medium)', 'Dependencies (CVEs)', 'Upgrade outdated libraries in package manifests to fixed advisory versions.', 'Removes known public exploit vectors.'],
      ['P4 (Routine)', 'Container & IaC', 'Remove privileged mode in docker-compose. Add non-root USER instruction to Dockerfile.', 'Restricts container breakout capabilities.'],
    ],
    theme: 'grid',
    styles: { fontSize: 8.5, cellPadding: 2.5 },
    headStyles: { fillColor: primaryColor },
  });
  y = (doc as any).lastAutoTable.finalY + 12;

  printHeader('Scanner Versions & Regulatory References', 16);
  autoTable(doc, {
    startY: y,
    head: [['Engine / Tool', 'Pinned Version', 'Regulatory Standard', 'Alignment']],
    body: [
      ['SandTrace Secrets Engine', 'v8.19.1 Gitleaks rulepack', 'CWE-798', 'Hardcoded Credentials'],
      ['Semgrep Static Analysis Engine', 'v1.85.0 ruleset', 'OWASP Top 10 (2021)', 'A03 Injection / A01 Access Control'],
      ['OSV Advisory Engine', 'v1.8.4 OSV spec', 'CWE-1395', 'Known Vulnerable Dependencies'],
      ['Trivy Configuration Engine', 'v0.55.2', 'CIS Docker Benchmark', 'Container Security'],
    ],
    theme: 'grid',
    styles: { fontSize: 8.5, cellPadding: 2.5 },
    headStyles: { fillColor: primaryColor },
  });

  return doc;
}
