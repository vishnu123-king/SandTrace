import fs from 'fs';
import path from 'path';
import { SandboxManager } from '../sandbox/manager.js';
import { validateRepositoryUrl } from '../repository/validator.js';
import { SecretScanner } from './secretScanner.js';
import { SourceCodeScanner } from './sourceCodeScanner.js';
import { AuthSecurityScanner } from './authSecurityScanner.js';
import { DependencyScanner } from './dependencyScanner.js';
import { ConfigScanner } from './configScanner.js';
import { GitAnalysisEngine } from './gitAnalysis.js';
import { FindingsNormalizer } from './normalizer.js';
import { RiskScorer } from './riskScorer.js';
import { DataStore } from '../db/store.js';
import { Finding, RepositoryMetadata, ScanJob, ScanProfile, ScanStageName } from '../types.js';

function collectFilesRecursively(dir: string, baseDir: string = dir, maxFiles: number = 2000): string[] {
  let results: string[] = [];
  try {
    const list = fs.readdirSync(dir, { withFileTypes: true });
    for (const item of list) {
      if (results.length >= maxFiles) break;
      if (item.isSymbolicLink()) continue; // Skip symlinks to prevent loops
      if (
        (item.name === '.git' ||
          item.name === 'node_modules' ||
          item.name === 'vendor' ||
          item.name === 'dist' ||
          item.name === 'build' ||
          item.name === '.next' ||
          item.name === '.cache') &&
        item.isDirectory()
      ) {
        continue;
      }
      const full = path.join(dir, item.name);
      if (item.isDirectory()) {
        results = results.concat(collectFilesRecursively(full, baseDir, maxFiles - results.length));
      } else {
        results.push(path.relative(baseDir, full));
      }
    }
  } catch {}
  return results;
}

export class ScanOrchestrator {
  public static async executeScan(scanId: string, repoUrl: string, profile: ScanProfile): Promise<ScanJob> {
    const valResult = validateRepositoryUrl(repoUrl);
    if (!valResult.isValid) {
      throw new Error(valResult.error || 'Invalid repository URL');
    }

    const repoName = valResult.repoName || 'unnamed-repo';
    const provider = valResult.provider || 'Generic Git';

    const stageNames: ScanStageName[] = [
      'Sandbox initialization',
      'Repository retrieval',
      'File inventory',
      'Source-code analysis',
      'Dependency analysis',
      'Secret detection',
      'Git-history analysis',
      'Contributor analysis',
      'Finding correlation',
      'Report preparation',
    ];

    const initialScan: ScanJob = {
      id: scanId,
      repoUrl: valResult.normalizedUrl || repoUrl,
      repoName,
      provider,
      profile,
      status: 'in_progress',
      progress: 5,
      currentStage: 'Sandbox initialization',
      stages: stageNames.map((name) => ({
        name,
        status: name === 'Sandbox initialization' ? 'running' : 'pending',
      })),
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        secretsCount: 0,
        sastCount: 0,
        dependencyCount: 0,
        configCount: 0,
        authCount: 0,
        historicalCount: 0,
        currentCount: 0,
      },
      riskScore: 0,
      riskRating: 'LOW',
      sandbox: {
        mode: 'isolated_workspace',
        isolationProfile: 'SecretShield-Strict-OCI-v2',
        runtimeAvailable: true,
        runtimeName: 'Linux Rootless Container Isolation Engine',
        seccomp: true,
        networkIsolatedInAnalysis: true,
        noNewPrivileges: true,
        cpuLimit: '2 Cores (200%)',
        memoryLimit: '2048 MB',
        diskLimit: '500 MB',
        timeoutSeconds: 300,
        workspacePath: '',
        scannerImage: 'secretshield-scanner:1.4.2-pinned',
        toolVersions: {},
      },
      createdAt: new Date().toISOString(),
      startedAt: new Date().toISOString(),
      filesScanned: 0,
      linesAnalyzed: 0,
    };

    DataStore.saveScan(initialScan);

    const updateStage = (
      stageName: ScanStageName,
      status: 'running' | 'completed' | 'failed',
      durationMs?: number,
      message?: string
    ) => {
      const scan = DataStore.getScan(scanId);
      if (!scan) return;
      scan.currentStage = stageName;
      const stageIdx = scan.stages.findIndex((s) => s.name === stageName);
      if (stageIdx !== -1) {
        scan.stages[stageIdx].status = status;
        if (durationMs !== undefined) scan.stages[stageIdx].durationMs = durationMs;
        if (message) scan.stages[stageIdx].message = message;
      }
      const completedCount = scan.stages.filter((s) => s.status === 'completed').length;
      scan.progress = completedCount === stageNames.length ? 100 : Math.min(95, Math.round((completedCount / stageNames.length) * 100));
      DataStore.saveScan(scan);
    };

    // STAGE 1: Sandbox initialization
    const t0 = Date.now();
    const sandboxSession = SandboxManager.createSandbox(scanId);
    initialScan.sandbox = sandboxSession.metadata;
    DataStore.saveScan(initialScan);
    updateStage('Sandbox initialization', 'completed', Date.now() - t0, 'Workspace provisioned');

    try {
      // STAGE 2: Repository retrieval
      updateStage('Repository retrieval', 'running');
      const t1 = Date.now();
      const cloneRes = await SandboxManager.cloneRepository(
        sandboxSession,
        valResult.normalizedUrl || repoUrl,
        {
          depth: profile === 'investigation' ? 50 : 20,
          timeoutMs: 30000,
        }
      );

      if (!cloneRes.success) {
        throw new Error(cloneRes.error || 'Failed to clone repository inside isolated retrieval container.');
      }

      // Freeze snapshot for analysis phase
      SandboxManager.freezeSnapshot(sandboxSession);
      updateStage('Repository retrieval', 'completed', Date.now() - t1, `Snapshot frozen (Head: ${cloneRes.commitSha?.slice(0, 8)})`);

      // STAGE 3: File inventory
      updateStage('File inventory', 'running');
      const t2 = Date.now();
      const allFiles = collectFilesRecursively(sandboxSession.repoPath);
      let totalLines = 0;
      const languageMap: Record<string, number> = {};

      for (const rel of allFiles) {
        const ext = path.extname(rel).toLowerCase();
        languageMap[ext] = (languageMap[ext] || 0) + 1;
        try {
          const content = fs.readFileSync(path.join(sandboxSession.repoPath, rel), 'utf-8');
          totalLines += content.split('\n').length;
        } catch {}
      }

      const scanObj = DataStore.getScan(scanId)!;
      scanObj.filesScanned = allFiles.length;
      scanObj.linesAnalyzed = totalLines;
      scanObj.commitHash = cloneRes.commitSha?.slice(0, 8);
      DataStore.saveScan(scanObj);
      updateStage('File inventory', 'completed', Date.now() - t2, `Inventoried ${allFiles.length} files (${totalLines} lines)`);

      const rawFindings: Finding[] = [];

      // STAGE 4: Source-code analysis
      updateStage('Source-code analysis', 'running');
      const t3 = Date.now();
      const sastFindings = SourceCodeScanner.scanFiles(scanId, sandboxSession.repoPath, allFiles);
      const authFindings = AuthSecurityScanner.scanFiles(scanId, sandboxSession.repoPath, allFiles);
      rawFindings.push(...sastFindings, ...authFindings);
      updateStage('Source-code analysis', 'completed', Date.now() - t3, `SAST completed: ${sastFindings.length + authFindings.length} signals identified`);

      // STAGE 5: Dependency analysis
      updateStage('Dependency analysis', 'running');
      const t4 = Date.now();
      const { dependencies, findings: depFindings } = await DependencyScanner.scanDependencies(
        scanId,
        sandboxSession.repoPath,
        allFiles
      );
      rawFindings.push(...depFindings);
      updateStage('Dependency analysis', 'completed', Date.now() - t4, `Parsed ${dependencies.length} packages, ${depFindings.length} CVEs matched`);

      // STAGE 6: Secret detection (current files)
      updateStage('Secret detection', 'running');
      const t5 = Date.now();
      const currentSecretFindings = SecretScanner.scanCurrentFiles(scanId, sandboxSession.repoPath, allFiles);
      rawFindings.push(...currentSecretFindings);
      updateStage('Secret detection', 'completed', Date.now() - t5, `Detected ${currentSecretFindings.length} active credential patterns`);

      // STAGE 7: Git-history analysis (historical secrets & diff)
      updateStage('Git-history analysis', 'running');
      const t6 = Date.now();
      let historicalSecrets: Finding[] = [];
      if (profile !== 'quick') {
        historicalSecrets = await SecretScanner.scanGitHistory(scanId, sandboxSession.repoPath, currentSecretFindings);
        rawFindings.push(...historicalSecrets);
      }
      updateStage('Git-history analysis', 'completed', Date.now() - t6, `History analyzed: ${historicalSecrets.length} historical exposures found`);

      // STAGE 8: Contributor & configuration analysis
      updateStage('Contributor analysis', 'running');
      const t7 = Date.now();
      const gitMeta = await GitAnalysisEngine.analyzeRepository(sandboxSession.repoPath, rawFindings);
      const configFindings = ConfigScanner.scanFiles(scanId, sandboxSession.repoPath, allFiles);
      rawFindings.push(...configFindings);
      updateStage('Contributor analysis', 'completed', Date.now() - t7, `Analyzed ${gitMeta.contributors.length} contributors, ${gitMeta.totalCommits} commits`);

      // STAGE 9: Finding correlation & normalizer
      updateStage('Finding correlation', 'running');
      const t8 = Date.now();
      const finalFindings = FindingsNormalizer.normalizeAndDeduplicate(rawFindings);
      const summary = FindingsNormalizer.generateSummary(finalFindings);
      const risk = RiskScorer.calculate(summary);
      DataStore.saveFindings(scanId, finalFindings);
      updateStage('Finding correlation', 'completed', Date.now() - t8, `Deduplicated into ${finalFindings.length} unified findings`);

      // STAGE 10: Report preparation
      updateStage('Report preparation', 'running');
      const t9 = Date.now();

      // Update and save scan job
      const completedScan = DataStore.getScan(scanId)!;
      completedScan.status = 'completed';
      completedScan.progress = 100;
      completedScan.summary = summary;
      completedScan.riskScore = risk.score;
      completedScan.riskRating = risk.rating;
      completedScan.completedAt = new Date().toISOString();
      completedScan.durationMs = Date.now() - new Date(completedScan.startedAt!).getTime();
      completedScan.contributors = gitMeta.contributors;
      completedScan.timelineEvents = gitMeta.timelineEvents;
      completedScan.dependencies = dependencies;
      DataStore.saveScan(completedScan);

      // Save repository metadata
      const repoId = `repo-${valResult.owner}-${repoName}`;
      const existingRepo = DataStore.getRepo(repoId);
      const repoRecord: RepositoryMetadata = {
        id: repoId,
        url: valResult.normalizedUrl || repoUrl,
        name: repoName,
        owner: valResult.owner || 'Unknown',
        provider,
        defaultBranch: gitMeta.defaultBranch,
        latestCommitSha: gitMeta.latestCommitSha.slice(0, 8),
        totalCommits: gitMeta.totalCommits,
        totalContributors: gitMeta.contributors.length,
        totalFiles: allFiles.length,
        languages: languageMap,
        lastScannedAt: new Date().toISOString(),
        lastRiskScore: risk.score,
        scanCount: (existingRepo?.scanCount || 0) + 1,
      };
      DataStore.saveRepo(repoRecord);

      updateStage('Report preparation', 'completed', Date.now() - t9, 'Assessment finalized and indexed');

      // Cleanup sandbox workspace
      SandboxManager.cleanupSandbox(scanId);

      return completedScan;
    } catch (err: any) {
      console.error(`Scan ${scanId} failed:`, err);
      const failedScan = DataStore.getScan(scanId);
      if (failedScan) {
        failedScan.status = 'failed';
        failedScan.errorMessage = err.message || 'Scan process encountered an unexpected error.';
        failedScan.completedAt = new Date().toISOString();
        DataStore.saveScan(failedScan);
      }
      SandboxManager.cleanupSandbox(scanId);
      throw err;
    }
  }
}
