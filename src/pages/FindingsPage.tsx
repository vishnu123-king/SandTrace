import React, { useState, useEffect } from 'react';
import { Finding, FindingCategory, FindingStatus, ScanJob, Severity } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { FindingDrawer } from '../components/FindingDrawer';
import {
  Search,
  Filter,
  AlertOctagon,
  ArrowUpDown,
  FileCode,
  ShieldAlert,
  Key,
  Layers,
  Settings,
  UserCheck,
} from 'lucide-react';

interface FindingsPageProps {
  scans: ScanJob[];
  selectedScanId?: string;
  onSelectScanId: (id: string) => void;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({
  scans,
  selectedScanId,
  onSelectScanId,
}) => {
  const currentScanId = selectedScanId || (scans[0]?.id ?? '');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [exposureFilter, setExposureFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const loadFindings = async () => {
    if (!currentScanId) return;
    setLoading(true);
    try {
      const data = await api.getFindings(currentScanId, {
        severity: severityFilter || undefined,
        category: categoryFilter || undefined,
        exposureType: exposureFilter || undefined,
        status: statusFilter || undefined,
        search: searchTerm || undefined,
      });
      setFindings(data);
    } catch (err) {
      console.error('Failed to load findings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [currentScanId, severityFilter, categoryFilter, exposureFilter, statusFilter, searchTerm]);

  const handleStatusChange = async (newStatus: FindingStatus) => {
    if (!selectedFinding || !currentScanId) return;
    try {
      const updated = await api.updateFindingStatus(currentScanId, selectedFinding.id, newStatus);
      setSelectedFinding(updated);
      setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  const currentScan = scans.find((s) => s.id === currentScanId);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <AlertOctagon className="w-6 h-6 text-sky-400" />
            Security Findings Observatory
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Normalized, correlated, and deduplicated vulnerability signals across all scanners.
          </p>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-2">
            <label className="text-xs font-mono text-slate-400">Target Audit:</label>
            <select
              value={currentScanId}
              onChange={(e) => onSelectScanId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-hidden focus:border-sky-500"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.repoName} ({s.id.slice(0, 10)}) — {s.summary.total} findings
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {/* Search Box */}
          <div className="relative md:col-span-1">
            <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Search file, rule, or title..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-hidden focus:border-sky-500"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 focus:outline-hidden focus:border-sky-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 focus:outline-hidden focus:border-sky-500"
          >
            <option value="">All Categories</option>
            <option value="secret">Secrets & Credentials</option>
            <option value="sast">Source Code (SAST)</option>
            <option value="dependency">Dependencies (CVEs)</option>
            <option value="configuration">Configuration & Containers</option>
            <option value="auth_security">Auth & Access Control</option>
          </select>

          {/* Exposure Filter */}
          <select
            value={exposureFilter}
            onChange={(e) => setExposureFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 focus:outline-hidden focus:border-sky-500"
          >
            <option value="">All Exposure Types</option>
            <option value="CURRENT">Current HEAD Only</option>
            <option value="HISTORICAL">Historical Git Commit Only</option>
          </select>
        </div>

        {/* Active Filters Pill Bar */}
        {(severityFilter || categoryFilter || exposureFilter || searchTerm) && (
          <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 text-xs text-slate-400 font-mono">
            <span>Filtered: {findings.length} matches</span>
            <button
              onClick={() => {
                setSeverityFilter('');
                setCategoryFilter('');
                setExposureFilter('');
                setSearchTerm('');
              }}
              className="text-sky-400 hover:underline cursor-pointer ml-auto"
            >
              Reset Filters
            </button>
          </div>
        )}
      </div>

      {/* Findings Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-950/80 text-xs font-mono uppercase text-slate-400 border-b border-slate-800">
            <tr>
              <th className="p-4">Severity</th>
              <th className="p-4">Finding & Classification</th>
              <th className="p-4">Location</th>
              <th className="p-4">Exposure</th>
              <th className="p-4">Status</th>
              <th className="p-4 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
            {loading ? (
              <tr>
                <td colSpan={6} className="p-8 text-center text-slate-500">
                  Loading verified findings...
                </td>
              </tr>
            ) : findings.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-12 text-center text-slate-500 space-y-2">
                  <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
                  <div>No findings matched the selected criteria.</div>
                </td>
              </tr>
            ) : (
              findings.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className="hover:bg-slate-800/40 cursor-pointer transition"
                >
                  <td className="p-4">
                    <SeverityBadge severity={f.severity} size="sm" />
                  </td>

                  <td className="p-4">
                    <div className="font-semibold text-white font-sans text-sm">{f.title}</div>
                    <div className="text-[11px] text-slate-500 flex items-center gap-2 mt-0.5">
                      <span className="uppercase text-sky-400">{f.category}</span>
                      <span>•</span>
                      <span>{f.ruleId}</span>
                    </div>
                  </td>

                  <td className="p-4 text-sky-400/90 max-w-xs truncate">
                    {f.filePath}
                    {f.lineNumber ? `:${f.lineNumber}` : ''}
                  </td>

                  <td className="p-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] ${
                        f.exposureType === 'HISTORICAL'
                          ? 'bg-purple-950/40 text-purple-300 border border-purple-800/50'
                          : 'bg-cyan-950/40 text-cyan-300 border border-cyan-800/50'
                      }`}
                    >
                      {f.exposureType}
                    </span>
                  </td>

                  <td className="p-4">
                    <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 text-[10px]">
                      {f.status}
                    </span>
                  </td>

                  <td className="p-4 text-right">
                    <span className="text-sky-400 hover:text-sky-300 text-xs underline">
                      Review →
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Slide-over Inspection Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onStatusChange={handleStatusChange}
      />
    </div>
  );
};
