import { Finding, FindingStatus, RepositoryMetadata, ScanJob, ScanProfile } from '../types';

export const api = {
  async getHealth() {
    const res = await fetch('/api/health');
    return res.json();
  },

  async getSandboxes() {
    const res = await fetch('/api/sandboxes');
    return res.json();
  },

  async cleanupSandboxes() {
    const res = await fetch('/api/sandboxes/cleanup', { method: 'POST' });
    return res.json();
  },

  async validateRepository(url: string) {
    const res = await fetch('/api/repositories/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    return res.json();
  },

  async getRepositories(): Promise<RepositoryMetadata[]> {
    const res = await fetch('/api/repositories');
    return res.json();
  },

  async getScans(): Promise<ScanJob[]> {
    const res = await fetch('/api/scans');
    return res.json();
  },

  async getScan(id: string): Promise<ScanJob> {
    const res = await fetch(`/api/scans/${id}`);
    if (!res.ok) throw new Error('Scan not found');
    return res.json();
  },

  async startScan(repoUrl: string, profile: ScanProfile = 'deep'): Promise<{ scanId: string; job: ScanJob }> {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl, profile }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to start scan');
    }
    return res.json();
  },

  async deleteScan(id: string): Promise<void> {
    await fetch(`/api/scans/${id}`, { method: 'DELETE' });
  },

  async getFindings(
    scanId: string,
    filters?: { severity?: string; category?: string; status?: string; search?: string; exposureType?: string }
  ): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filters?.severity) params.set('severity', filters.severity);
    if (filters?.category) params.set('category', filters.category);
    if (filters?.status) params.set('status', filters.status);
    if (filters?.exposureType) params.set('exposureType', filters.exposureType);
    if (filters?.search) params.set('search', filters.search);

    const res = await fetch(`/api/scans/${scanId}/findings?${params.toString()}`);
    return res.json();
  },

  async updateFindingStatus(scanId: string, findingId: string, status: FindingStatus): Promise<Finding> {
    const res = await fetch(`/api/scans/${scanId}/findings/${findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    return res.json();
  },

  async getStructuredReport(scanId: string) {
    const res = await fetch(`/api/scans/${scanId}/report/structured`);
    if (!res.ok) throw new Error('Report not found');
    return res.json();
  },

  async getContributors(scanId: string): Promise<any[]> {
    const res = await fetch(`/api/scans/${scanId}/contributors`);
    return res.json();
  },

  async getTimeline(scanId: string): Promise<any[]> {
    const res = await fetch(`/api/scans/${scanId}/timeline`);
    return res.json();
  },

  async getDependencies(scanId: string): Promise<any[]> {
    const res = await fetch(`/api/scans/${scanId}/dependencies`);
    return res.json();
  },
};
