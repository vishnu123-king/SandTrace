import React from 'react';
import { RepositoryMetadata, ScanJob } from '../types';
import { RiskMeter } from '../components/RiskMeter';
import { FolderGit2, Play, ExternalLink, Calendar, Users, FileText, ArrowRight } from 'lucide-react';

interface RepositoriesPageProps {
  repos: RepositoryMetadata[];
  scans: ScanJob[];
  onSelectScan: (scanId: string) => void;
  onNewScanForRepo: (url: string) => void;
}

export const RepositoriesPage: React.FC<RepositoriesPageProps> = ({
  repos,
  scans,
  onSelectScan,
  onNewScanForRepo,
}) => {
  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FolderGit2 className="w-6 h-6 text-sky-400" />
            Audited Git Repositories
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Repositories cataloged and analyzed within SandTrace isolated sandbox sessions.
          </p>
        </div>
      </div>

      {/* Repos Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {repos.map((repo) => {
          const repoScans = scans.filter((s) => s.repoName === repo.name);
          const latestScan = repoScans[0];

          return (
            <div
              key={repo.id}
              className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4 hover:border-slate-700 transition"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-sky-400 font-mono text-[10px] uppercase">
                      {repo.provider}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">Branch: {repo.defaultBranch}</span>
                  </div>
                  <h2 className="text-lg font-bold text-white font-mono">{repo.name}</h2>
                  <div className="text-xs text-slate-400 font-mono mt-0.5 break-all">{repo.url}</div>
                </div>

                {latestScan && (
                  <div className="shrink-0">
                    <RiskMeter score={latestScan.riskScore} rating={latestScan.riskRating} size="sm" />
                  </div>
                )}
              </div>

              {/* Stats Bar */}
              <div className="grid grid-cols-3 gap-2 p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 text-xs font-mono text-slate-300">
                <div>
                  <span className="text-[10px] text-slate-500 block uppercase">Commits</span>
                  <span className="font-semibold text-white">{repo.totalCommits || '—'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block uppercase">Contributors</span>
                  <span className="font-semibold text-white">{repo.totalContributors || '—'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block uppercase">Audits</span>
                  <span className="font-semibold text-sky-400">{repo.scanCount}</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-2">
                <button
                  onClick={() => onNewScanForRepo(repo.url)}
                  className="px-3 py-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 text-xs font-medium transition flex items-center gap-1.5 cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  Re-Scan
                </button>

                {latestScan && (
                  <button
                    onClick={() => onSelectScan(latestScan.id)}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition flex items-center gap-1 cursor-pointer"
                  >
                    View Last Assessment
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
