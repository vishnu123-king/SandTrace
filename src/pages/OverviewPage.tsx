import React from 'react';
import { RepositoryMetadata, ScanJob } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskMeter } from '../components/RiskMeter';
import {
  ShieldAlert,
  FolderGit2,
  Key,
  Layers,
  ArrowRight,
  ExternalLink,
  PlusCircle,
  Clock,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';

interface OverviewPageProps {
  scans: ScanJob[];
  repos: RepositoryMetadata[];
  onSelectScan: (scanId: string) => void;
  onNewScan: () => void;
  onViewFindings: (scanId?: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  scans,
  repos,
  onSelectScan,
  onNewScan,
  onViewFindings,
}) => {
  const latestScan = scans[0];

  // Calculate aggregated stats
  const totalFindings = scans.reduce((acc, s) => acc + s.summary.total, 0);
  const totalCritical = scans.reduce((acc, s) => acc + s.summary.critical, 0);
  const totalSecrets = scans.reduce((acc, s) => acc + s.summary.secretsCount, 0);
  const totalDeps = scans.reduce((acc, s) => acc + s.summary.dependencyCount, 0);

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Security Observatory Overview</h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time defensive posture intelligence from isolated Linux sandbox audits.
          </p>
        </div>
        <button
          onClick={onNewScan}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-sm transition shadow-lg shadow-sky-500/10 cursor-pointer"
        >
          <PlusCircle className="w-4 h-4" />
          Launch New Scan
        </button>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800/80 shadow-xs">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs uppercase font-mono tracking-wider">Critical Issues</span>
            <span className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-4 h-4" />
            </span>
          </div>
          <div className="text-3xl font-bold font-mono text-white tracking-tight">{totalCritical}</div>
          <div className="text-xs text-rose-400/80 mt-1">Requires immediate revocation / triage</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800/80 shadow-xs">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs uppercase font-mono tracking-wider">Exposed Secrets</span>
            <span className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <Key className="w-4 h-4" />
            </span>
          </div>
          <div className="text-3xl font-bold font-mono text-white tracking-tight">{totalSecrets}</div>
          <div className="text-xs text-amber-400/80 mt-1">Current & historical commit exposures</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800/80 shadow-xs">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs uppercase font-mono tracking-wider">Vulnerable Deps (CVEs)</span>
            <span className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <Layers className="w-4 h-4" />
            </span>
          </div>
          <div className="text-3xl font-bold font-mono text-white tracking-tight">{totalDeps}</div>
          <div className="text-xs text-slate-400 mt-1">Matched via OSV advisory database</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800/80 shadow-xs">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs uppercase font-mono tracking-wider">Monitored Repositories</span>
            <span className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <FolderGit2 className="w-4 h-4" />
            </span>
          </div>
          <div className="text-3xl font-bold font-mono text-white tracking-tight">{repos.length}</div>
          <div className="text-xs text-slate-400 mt-1">{scans.length} total completed scan jobs</div>
        </div>
      </div>

      {/* Featured Latest Scan Banner */}
      {latestScan && (
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-6">
          <div className="space-y-3 flex-1">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/30 text-xs font-mono">
                LATEST COMPLETED AUDIT
              </span>
              <span className="text-xs text-slate-500 font-mono">{latestScan.provider}</span>
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                {latestScan.repoName}
                <span className="text-xs text-slate-400 font-normal font-mono">
                  ({latestScan.commitHash || 'HEAD'})
                </span>
              </h2>
              <div className="text-xs text-slate-400 font-mono mt-1 break-all">{latestScan.repoUrl}</div>
            </div>
            <div className="flex flex-wrap gap-4 text-xs text-slate-300 pt-2 font-mono">
              <div>Files: <span className="text-white font-semibold">{latestScan.filesScanned}</span></div>
              <div>Duration: <span className="text-white font-semibold">{Math.round((latestScan.durationMs || 0) / 1000)}s</span></div>
              <div>Profile: <span className="text-sky-400 uppercase font-semibold">{latestScan.profile}</span></div>
            </div>
          </div>

          <div className="w-full lg:w-72">
            <RiskMeter score={latestScan.riskScore} rating={latestScan.riskRating} />
          </div>

          <div className="flex flex-col sm:flex-row lg:flex-col gap-2 shrink-0">
            <button
              onClick={() => onSelectScan(latestScan.id)}
              className="px-4 py-2.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 font-medium text-xs transition flex items-center justify-center gap-1.5 cursor-pointer"
            >
              Inspect Findings ({latestScan.summary.total})
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Recent Scans Table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-semibold text-white">Recent Repository Scans</h3>
          <span className="text-xs text-slate-500 font-mono">{scans.length} total entries</span>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/80 text-xs font-mono uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-4">Repository</th>
                <th className="p-4">Provider</th>
                <th className="p-4">Profile</th>
                <th className="p-4">Findings Breakdown</th>
                <th className="p-4">Risk Score</th>
                <th className="p-4">Status</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-800/40 transition">
                  <td className="p-4">
                    <div className="font-semibold text-white">{scan.repoName}</div>
                    <div className="text-[11px] text-slate-500 truncate max-w-xs">{scan.repoUrl}</div>
                  </td>
                  <td className="p-4 text-slate-400">{scan.provider}</td>
                  <td className="p-4 uppercase text-sky-400">{scan.profile}</td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      {scan.summary.critical > 0 && (
                        <span className="text-rose-400 font-bold">{scan.summary.critical} Crit</span>
                      )}
                      {scan.summary.high > 0 && (
                        <span className="text-orange-400">{scan.summary.high} High</span>
                      )}
                      {scan.summary.secretsCount > 0 && (
                        <span className="text-amber-400">{scan.summary.secretsCount} Sec</span>
                      )}
                      {scan.summary.total === 0 && (
                        <span className="text-emerald-400">Clean</span>
                      )}
                    </div>
                  </td>
                  <td className="p-4">
                    <RiskMeter score={scan.riskScore} rating={scan.riskRating} size="sm" />
                  </td>
                  <td className="p-4">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] ${
                        scan.status === 'completed'
                          ? 'bg-emerald-950/30 text-emerald-400 border border-emerald-800/50'
                          : scan.status === 'in_progress'
                          ? 'bg-amber-950/30 text-amber-400 border border-amber-800/50 animate-pulse'
                          : 'bg-rose-950/30 text-rose-400 border border-rose-800/50'
                      }`}
                    >
                      {scan.status === 'completed' && <CheckCircle2 className="w-3 h-3" />}
                      {scan.status}
                    </span>
                  </td>
                  <td className="p-4 text-right">
                    <button
                      onClick={() => onSelectScan(scan.id)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs transition inline-flex items-center gap-1 cursor-pointer"
                    >
                      View
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
