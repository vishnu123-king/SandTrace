import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Cpu, ShieldCheck, Terminal, Trash2, CheckCircle2, AlertTriangle, Layers, HardDrive, Clock, Lock } from 'lucide-react';

export const SandboxPage: React.FC = () => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [cleaning, setCleaning] = useState(false);
  const [cleanMsg, setCleanMsg] = useState<string | null>(null);

  const loadData = async () => {
    try {
      const res = await api.getSandboxes();
      setData(res);
    } catch (err) {
      console.error('Failed to load sandbox data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCleanup = async () => {
    setCleaning(true);
    try {
      const res = await api.cleanupSandboxes();
      setCleanMsg(res.message);
      await loadData();
      setTimeout(() => setCleanMsg(null), 4000);
    } catch (err) {
      console.error('Cleanup failed:', err);
    } finally {
      setCleaning(false);
    }
  };

  if (loading || !data) {
    return (
      <div className="p-16 text-center text-slate-500 font-mono">
        Probing Linux Host Sandbox Subsystem...
      </div>
    );
  }

  const caps = data.capabilities;

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Cpu className="w-6 h-6 text-sky-400" />
            Linux Sandbox & Container Runtime Management
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Isolated execution environment configuration, resource quotas, and scanner image versions.
          </p>
        </div>

        <button
          onClick={handleCleanup}
          disabled={cleaning}
          className="px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-mono font-medium transition flex items-center gap-2 cursor-pointer border border-slate-700"
        >
          <Trash2 className="w-4 h-4 text-amber-400" />
          {cleaning ? 'Pruning Workspaces...' : 'Prune Inactive Workspaces'}
        </button>
      </div>

      {cleanMsg && (
        <div className="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded-lg text-emerald-300 text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          {cleanMsg}
        </div>
      )}

      {/* Primary Isolation Engine Status Banner */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-mono text-emerald-400 font-semibold uppercase">
              ISOLATION RUNTIME ACTIVE
            </span>
          </div>
          <h2 className="text-lg font-bold text-white font-mono">{caps.activeRuntimeDescription}</h2>
          <div className="text-xs text-slate-400 font-mono">
            Mode: {caps.preferredIsolation.toUpperCase()} | Profile: SecretShield-Strict-OCI-v2
          </div>
        </div>

        <div className="flex items-center gap-6 text-xs font-mono border-t md:border-t-0 md:border-l border-slate-800 pt-4 md:pt-0 md:pl-6">
          <div>
            <span className="text-slate-500 block uppercase">Active Workers</span>
            <span className="text-xl font-bold text-white mt-0.5 block">{data.totalActive}</span>
          </div>
          <div>
            <span className="text-slate-500 block uppercase">Base Image</span>
            <span className="text-sky-400 font-semibold mt-0.5 block">{caps.scannerImageTag}</span>
          </div>
        </div>
      </div>

      {/* Security Policies & Resource Quotas */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Resource Limits Card */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <HardDrive className="w-4 h-4 text-sky-400" />
            Enforced Sandbox Resource Quotas
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-slate-400">CPU Compute Limit:</span>
              <span className="text-white font-semibold">{caps.securityPolicies.cpuLimit}</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-slate-400">Resident Memory (RAM):</span>
              <span className="text-white font-semibold">{caps.securityPolicies.memoryLimit}</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-slate-400">Scratch Disk Quota:</span>
              <span className="text-white font-semibold">{caps.securityPolicies.diskLimit}</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-slate-400">Execution Timeout:</span>
              <span className="text-white font-semibold">{caps.securityPolicies.timeoutSeconds}s</span>
            </div>
          </div>
        </div>

        {/* Security Controls Card */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Lock className="w-4 h-4 text-emerald-400" />
            Active Linux Kernel Boundaries
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-slate-400">no-new-privileges:</span>
              <span className="text-emerald-400 font-semibold">Enforced (True)</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-slate-400">Read-Only Root Filesystem:</span>
              <span className="text-emerald-400 font-semibold">Enforced (True)</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-slate-400">Network Boundary:</span>
              <span className="text-emerald-400 font-semibold">Airgapped in Analysis Phase</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-slate-400">Seccomp Filter Status:</span>
              <span className="text-emerald-400 font-semibold">{caps.seccompSupported ? 'Active' : 'Permissive'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Pinned Security Tools Inventory */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <Layers className="w-4 h-4 text-purple-400" />
          Verified Security Scanner Adapters
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <div className="text-slate-400 font-sans font-semibold">Semgrep Core Engine</div>
            <div className="text-sky-400 mt-1">v1.85.0 (SAST)</div>
            <div className="text-[10px] text-slate-500 mt-0.5">AST & Pattern Matching</div>
          </div>
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <div className="text-slate-400 font-sans font-semibold">Gitleaks Engine</div>
            <div className="text-sky-400 mt-1">v8.19.1 (Secrets)</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Entropy & HMAC Verification</div>
          </div>
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <div className="text-slate-400 font-sans font-semibold">OSV Vulnerability DB</div>
            <div className="text-sky-400 mt-1">v1.8.4 (CVE Client)</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Live Open Source Advisories</div>
          </div>
        </div>
      </div>

      {/* Recent Sandbox Sessions Table */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
          Recent Sandbox Workspaces
        </h3>
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="bg-slate-950/80 uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3">Session Scan ID</th>
                <th className="p-3">Isolated Workspace Path</th>
                <th className="p-3">Created</th>
                <th className="p-3">Teardown Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {data.activeSessions.map((s: any, idx: number) => (
                <tr key={idx} className="hover:bg-slate-800/30">
                  <td className="p-3 font-semibold text-white">{s.scanId}</td>
                  <td className="p-3 text-slate-400">{s.workspace}</td>
                  <td className="p-3 text-slate-500">{new Date(s.createdAt).toLocaleTimeString()}</td>
                  <td className="p-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] ${
                        s.cleanedUp
                          ? 'bg-emerald-950/30 text-emerald-400 border border-emerald-800/40'
                          : 'bg-amber-950/30 text-amber-400 border border-amber-800/40'
                      }`}
                    >
                      {s.cleanedUp ? 'Destroyed & Wiped' : 'Active Workspace'}
                    </span>
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
