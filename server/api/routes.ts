import { Router } from 'express';
import crypto from 'crypto';
import { DataStore } from '../db/store.js';
import { validateRepositoryUrl } from '../repository/validator.js';
import { ScanOrchestrator } from '../analysis/orchestrator.js';
import { detectSystemCapabilities } from '../sandbox/runtime.js';
import { SandboxManager } from '../sandbox/manager.js';
import { ReportBuilder } from '../reports/reportBuilder.js';
import { FindingStatus, ScanProfile } from '../types.js';

export const apiRouter = Router();

// Health check
apiRouter.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    product: 'SandTrace',
    version: '1.4.2',
    timestamp: new Date().toISOString(),
  });
});

// Sandbox status and configuration
apiRouter.get('/sandboxes', (_req, res) => {
  const caps = detectSystemCapabilities();
  const activeSessions = SandboxManager.listSandboxes().map((s) => ({
    scanId: s.scanId,
    workspace: s.workspacePath,
    createdAt: s.createdAt,
    cleanedUp: s.cleanedUp,
  }));

  res.json({
    capabilities: caps,
    activeSessions,
    totalActive: activeSessions.filter((s) => !s.cleanedUp).length,
  });
});

// Trigger sandbox workspace cleanup
apiRouter.post('/sandboxes/cleanup', (_req, res) => {
  SandboxManager.cleanupAll();
  res.json({ success: true, message: 'All temporary sandbox workspaces pruned.' });
});

// Validate repository URL
apiRouter.post('/repositories/validate', (req, res) => {
  const { url } = req.body;
  const result = validateRepositoryUrl(url);
  res.json(result);
});

// List all repositories
apiRouter.get('/repositories', (_req, res) => {
  res.json(DataStore.getRepos());
});

// Repository details
apiRouter.get('/repositories/:id', (req, res) => {
  const repo = DataStore.getRepo(req.params.id);
  if (!repo) {
    return res.status(404).json({ error: 'Repository not found' });
  }
  res.json(repo);
});

// List all scans
apiRouter.get('/scans', (_req, res) => {
  res.json(DataStore.getAllScans());
});

// Trigger a new scan
apiRouter.post('/scans', async (req, res) => {
  const { repoUrl, profile = 'deep' } = req.body;

  if (!repoUrl) {
    return res.status(400).json({ error: 'Repository URL is required.' });
  }

  const validation = validateRepositoryUrl(repoUrl);
  if (!validation.isValid) {
    return res.status(400).json({ error: validation.error });
  }

  const scanId = `scan-${crypto.randomBytes(6).toString('hex')}`;

  // Start background scan execution
  ScanOrchestrator.executeScan(scanId, repoUrl, profile as ScanProfile).catch((err) => {
    console.error(`Background scan ${scanId} failed:`, err);
  });

  // Return immediately with queued job record
  const initialJob = DataStore.getScan(scanId);
  res.status(202).json({
    message: 'Isolated scan worker initialized.',
    scanId,
    job: initialJob,
  });
});

// Get scan details & live progress
apiRouter.get('/scans/:id', (req, res) => {
  const scan = DataStore.getScan(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Scan job not found' });
  }
  res.json(scan);
});

// Delete a scan
apiRouter.delete('/scans/:id', (req, res) => {
  DataStore.deleteScan(req.params.id);
  SandboxManager.cleanupSandbox(req.params.id);
  res.json({ success: true });
});

// Get findings for a scan with optional filters
apiRouter.get('/scans/:id/findings', (req, res) => {
  const { severity, category, status, search, exposureType } = req.query;
  let findings = DataStore.getFindings(req.params.id);

  if (severity) {
    findings = findings.filter((f) => f.severity === severity);
  }
  if (category) {
    findings = findings.filter((f) => f.category === category);
  }
  if (status) {
    findings = findings.filter((f) => f.status === status);
  }
  if (exposureType) {
    findings = findings.filter((f) => f.exposureType === exposureType);
  }
  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    findings = findings.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.filePath.toLowerCase().includes(q) ||
        f.ruleId.toLowerCase().includes(q) ||
        f.evidence.toLowerCase().includes(q)
    );
  }

  res.json(findings);
});

// Update finding status
apiRouter.patch('/scans/:id/findings/:findingId', (req, res) => {
  const { status } = req.body;
  if (!status) {
    return res.status(400).json({ error: 'Status is required' });
  }

  const updated = DataStore.updateFindingStatus(
    req.params.id,
    req.params.findingId,
    status as FindingStatus
  );

  if (!updated) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  res.json(updated);
});

// Get contributors for a scan
apiRouter.get('/scans/:id/contributors', (req, res) => {
  const scan = DataStore.getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan.contributors || []);
});

// Get timeline events for a scan
apiRouter.get('/scans/:id/timeline', (req, res) => {
  const scan = DataStore.getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan.timelineEvents || []);
});

// Get dependencies for a scan
apiRouter.get('/scans/:id/dependencies', (req, res) => {
  const scan = DataStore.getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan.dependencies || []);
});

// Get structured security report (all 16 sections)
apiRouter.get('/scans/:id/report/structured', (req, res) => {
  const scan = DataStore.getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const findings = DataStore.getFindings(req.params.id);
  const repo = DataStore.getRepos().find((r) => r.name === scan.repoName);

  const report = ReportBuilder.buildStructuredReport(scan, findings, repo);
  res.json(report);
});

// Get HTML report
apiRouter.get('/scans/:id/report/html', (req, res) => {
  const scan = DataStore.getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const findings = DataStore.getFindings(req.params.id);
  const repo = DataStore.getRepos().find((r) => r.name === scan.repoName);

  const report = ReportBuilder.buildStructuredReport(scan, findings, repo);
  const html = ReportBuilder.generateHtmlReport(report);

  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});
