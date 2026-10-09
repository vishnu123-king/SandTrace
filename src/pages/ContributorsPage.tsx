import React, { useState, useEffect } from 'react';
import { ContributorInfo, ScanJob } from '../types';
import { api } from '../services/api';
import { Users, Shield, AlertTriangle, GitCommit, FileCode, Clock, Loader2 } from 'lucide-react';

interface ContributorsPageProps {
  scans: ScanJob[];
  selectedScanId?: string;
  onSelectScanId: (id: string) => void;
}

export const ContributorsPage: React.FC<ContributorsPageProps> = ({
  scans,
  selectedScanId,
  onSelectScanId,
}) => {
  const currentScanId = selectedScanId || (scans[0]?.id ?? '');
  const currentScan = scans.find((s) => s.id === currentScanId);
  const [contributors, setContributors] = useState<ContributorInfo[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!currentScanId) return;
    const fetchContributors = async () => {
      setLoading(true);
      try {
        const list = await api.getContributors(currentScanId);
        if (Array.isArray(list) && list.length > 0) {
          setContributors(list);
        } else if (currentScan?.contributors && currentScan.contributors.length > 0) {
          setContributors(currentScan.contributors);
        } else {
          setContributors([]);
        }
      } catch {
        if (currentScan?.contributors) {
          setContributors(currentScan.contributors);
        }
      } finally {
        setLoading(false);
      }
    };
    fetchContributors();
  }, [currentScanId, currentScan]);

  const totalCommits = contributors.reduce((acc, c) => acc + c.commitCount, 0);
  const totalSensitiveTouches = contributors.reduce((acc, c) => acc + c.sensitiveFilesTouched.length, 0);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Users className="w-6 h-6 text-sky-400" />
            Contributor & Repository Activity Analysis
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real Git authorship telemetry, commit distribution, and sensitive security file touchpoints.
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
                  {s.repoName} ({s.id.slice(0, 10)})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Activity Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="text-slate-500 block uppercase">Identified Authors</span>
          <span className="text-2xl font-bold text-white mt-1 block">{contributors.length}</span>
          <span className="text-slate-400 text-[11px]">Real Git commit authors</span>
        </div>
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="text-slate-500 block uppercase">Commits Analyzed</span>
          <span className="text-2xl font-bold text-sky-400 mt-1 block">{totalCommits || '—'}</span>
          <span className="text-slate-400 text-[11px]">Repository history window</span>
        </div>
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="text-slate-500 block uppercase">Sensitive File Touches</span>
          <span className="text-2xl font-bold text-amber-400 mt-1 block">{totalSensitiveTouches}</span>
          <span className="text-slate-400 text-[11px]">Auth, configs, envs, keys</span>
        </div>
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="text-slate-500 block uppercase">Email Privacy</span>
          <span className="text-2xl font-bold text-emerald-400 mt-1 block">Protected</span>
          <span className="text-slate-400 text-[11px]">Universal email masking</span>
        </div>
      </div>

      {/* Responsible Disclosure Note */}
      <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 leading-relaxed font-mono">
        <span className="text-slate-200 font-semibold">Security Note:</span> Contributor metrics and activity signals are derived from verifiable Git metadata to assist peer review. SandTrace does not label contributors malicious or infer negative intent.
      </div>

      {/* Contributors Breakdown Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-950/80 text-xs font-mono uppercase text-slate-400 border-b border-slate-800">
            <tr>
              <th className="p-4">Contributor</th>
              <th className="p-4">Masked Email</th>
              <th className="p-4">Commits (% Share)</th>
              <th className="p-4">Sensitive Files Touched</th>
              <th className="p-4">Review Signals</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
            {loading ? (
              <tr>
                <td colSpan={5} className="p-8 text-center text-slate-500">
                  <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
                  Loading real Git contributors...
                </td>
              </tr>
            ) : contributors.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-12 text-center text-slate-500 space-y-2">
                  <Users className="w-8 h-8 text-slate-600 mx-auto" />
                  <div>No contributors cataloged for this repository scan.</div>
                </td>
              </tr>
            ) : (
              contributors.map((c, i) => (
                <tr key={i} className="hover:bg-slate-800/40 transition">
                  <td className="p-4 font-semibold text-white font-sans text-sm">{c.name}</td>
                  <td className="p-4 text-slate-400 font-mono">{c.maskedEmail}</td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-semibold">{c.commitCount}</span>
                      <span className="text-slate-500">({c.percentageOfCommits}%)</span>
                    </div>
                    <div className="w-24 h-1.5 bg-slate-800 rounded-full mt-1.5 overflow-hidden">
                      <div
                        className="h-full bg-sky-500"
                        style={{ width: `${Math.max(5, c.percentageOfCommits)}%` }}
                      />
                    </div>
                  </td>
                  <td className="p-4">
                    {c.sensitiveFilesTouched.length > 0 ? (
                      <div className="space-y-1 max-w-xs">
                        {c.sensitiveFilesTouched.map((f, fi) => (
                          <div key={fi} className="text-[11px] text-sky-400/90 truncate">
                            • {f}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-500 text-[11px]">—</span>
                    )}
                  </td>
                  <td className="p-4">
                    {c.reviewSignals.length > 0 ? (
                      <div className="space-y-1">
                        {c.reviewSignals.map((sig, si) => (
                          <div
                            key={si}
                            className="text-[11px] text-amber-300/90 flex items-center gap-1.5"
                          >
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0" />
                            {sig}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-500 text-[11px]">Normal commit activity</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
