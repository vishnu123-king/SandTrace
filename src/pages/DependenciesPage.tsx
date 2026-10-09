import React, { useState, useEffect } from 'react';
import { DependencyItem, ScanJob } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { Package, ExternalLink, ShieldCheck, AlertTriangle, Layers, Loader2 } from 'lucide-react';

interface DependenciesPageProps {
  scans: ScanJob[];
  selectedScanId?: string;
  onSelectScanId: (id: string) => void;
}

export const DependenciesPage: React.FC<DependenciesPageProps> = ({
  scans,
  selectedScanId,
  onSelectScanId,
}) => {
  const currentScanId = selectedScanId || (scans[0]?.id ?? '');
  const currentScan = scans.find((s) => s.id === currentScanId);
  const [dependencies, setDependencies] = useState<DependencyItem[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!currentScanId) return;
    const fetchDependencies = async () => {
      setLoading(true);
      try {
        const list = await api.getDependencies(currentScanId);
        if (Array.isArray(list) && list.length > 0) {
          setDependencies(list);
        } else if (currentScan?.dependencies && currentScan.dependencies.length > 0) {
          setDependencies(currentScan.dependencies);
        } else {
          setDependencies([]);
        }
      } catch {
        if (currentScan?.dependencies) {
          setDependencies(currentScan.dependencies);
        }
      } finally {
        setLoading(false);
      }
    };
    fetchDependencies();
  }, [currentScanId, currentScan]);

  const vulnerableCount = dependencies.filter((d) => d.vulnerabilities.length > 0).length;
  const totalCves = dependencies.reduce((acc, d) => acc + d.vulnerabilities.length, 0);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Package className="w-6 h-6 text-sky-400" />
            Dependency & Supply-Chain Security
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real dependencies discovered from repository package manifests and audited against the OSV advisory database.
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

      {/* Stats Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="text-slate-500 block uppercase">Dependencies Audited</span>
          <span className="text-2xl font-bold text-white mt-1 block">{dependencies.length}</span>
          <span className="text-slate-400 text-[11px]">Parsed manifests</span>
        </div>
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="text-slate-500 block uppercase">Vulnerable Components</span>
          <span className="text-2xl font-bold text-rose-400 mt-1 block">{vulnerableCount}</span>
          <span className="text-slate-400 text-[11px]">{totalCves} total CVE advisories</span>
        </div>
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="text-slate-500 block uppercase">Clean Packages</span>
          <span className="text-2xl font-bold text-emerald-400 mt-1 block">
            {dependencies.length - vulnerableCount}
          </span>
          <span className="text-slate-400 text-[11px]">No known vulnerabilities reported</span>
        </div>
      </div>

      {/* Dependencies Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-950/80 text-xs font-mono uppercase text-slate-400 border-b border-slate-800">
            <tr>
              <th className="p-4">Package Component</th>
              <th className="p-4">Version</th>
              <th className="p-4">Ecosystem</th>
              <th className="p-4">Manifest Path</th>
              <th className="p-4">Security Advisory Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
            {loading ? (
              <tr>
                <td colSpan={5} className="p-8 text-center text-slate-500">
                  <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
                  Auditing dependencies against OSV database...
                </td>
              </tr>
            ) : dependencies.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-12 text-center text-slate-500 space-y-2">
                  <Package className="w-8 h-8 text-slate-600 mx-auto" />
                  <div>No dependency manifests detected in this repository.</div>
                </td>
              </tr>
            ) : (
              dependencies.map((dep, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition">
                  <td className="p-4 font-semibold text-white">{dep.name}</td>
                  <td className="p-4 text-sky-400">{dep.version}</td>
                  <td className="p-4 uppercase text-slate-400">{dep.ecosystem}</td>
                  <td className="p-4 text-slate-500">{dep.manifestPath}</td>
                  <td className="p-4">
                    {dep.vulnerabilities.length > 0 ? (
                      <div className="space-y-2">
                        {dep.vulnerabilities.map((v) => (
                          <div
                            key={v.id}
                            className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-900/40 space-y-1"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-rose-400 font-bold">{v.cve || v.id}</span>
                              <SeverityBadge severity={v.severity} size="sm" />
                            </div>
                            <div className="text-[11px] text-slate-300 font-sans">{v.summary}</div>
                            <div className="flex items-center justify-between pt-1 text-[11px]">
                              {v.fixedVersion && (
                                <span className="text-emerald-400 font-semibold">
                                  Fixed in: {v.fixedVersion}
                                </span>
                              )}
                              <a
                                href={v.advisoryUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-sky-400 hover:underline flex items-center gap-1 ml-auto"
                              >
                                Advisory
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 text-emerald-400">
                        <ShieldCheck className="w-4 h-4" />
                        <span>No known CVE advisories</span>
                      </div>
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
