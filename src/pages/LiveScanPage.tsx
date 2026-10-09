import React, { useEffect, useState } from 'react';
import { ScanJob, ScanStage } from '../types';
import { api } from '../services/api';
import {
  CheckCircle2,
  Clock,
  Loader2,
  AlertCircle,
  Shield,
  ArrowRight,
  Cpu,
  Layers,
  FileCheck,
} from 'lucide-react';

interface LiveScanPageProps {
  scanId: string;
  onScanCompleted: (scanId: string) => void;
  onCancel: () => void;
}

export const LiveScanPage: React.FC<LiveScanPageProps> = ({ scanId, onScanCompleted, onCancel }) => {
  const [scan, setScan] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let interval: any;

    const poll = async () => {
      try {
        const job = await api.getScan(scanId);
        setScan(job);
        if (job.status === 'completed' || job.status === 'failed') {
          clearInterval(interval);
        }
      } catch (err: any) {
        setError(err.message || 'Failed to poll scan status');
        clearInterval(interval);
      }
    };

    poll();
    interval = setInterval(poll, 500);

    return () => clearInterval(interval);
  }, [scanId]);

  if (error) {
    return (
      <div className="p-8 max-w-3xl mx-auto text-center space-y-4">
        <AlertCircle className="w-12 h-12 text-rose-500 mx-auto" />
        <h2 className="text-xl font-bold text-white">Scan Error</h2>
        <p className="text-sm text-slate-400 font-mono">{error}</p>
        <button
          onClick={onCancel}
          className="px-4 py-2 bg-slate-800 text-slate-200 rounded-lg text-sm hover:bg-slate-700 cursor-pointer"
        >
          Return to Overview
        </button>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="p-16 text-center space-y-3">
        <Loader2 className="w-8 h-8 text-sky-400 animate-spin mx-auto" />
        <p className="text-sm font-mono text-slate-400">Connecting to SandTrace worker...</p>
      </div>
    );
  }

  const isFinished = scan.status === 'completed';
  const isFailed = scan.status === 'failed';

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      {/* Header Banner */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isFinished
                  ? 'bg-emerald-500'
                  : isFailed
                  ? 'bg-rose-500'
                  : 'bg-sky-400 animate-ping'
              }`}
            />
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              {isFinished ? 'Audit Completed' : isFailed ? 'Audit Failed' : 'Sandbox Audit in Progress'}
            </span>
          </div>
          <h1 className="text-xl font-bold text-white font-mono">{scan.repoName}</h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5 break-all">{scan.repoUrl}</p>
        </div>

        <div className="flex items-center gap-3">
          {isFinished ? (
            <button
              onClick={() => onScanCompleted(scan.id)}
              className="px-5 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm transition flex items-center gap-2 shadow-lg shadow-emerald-500/10 cursor-pointer"
            >
              <FileCheck className="w-4 h-4" />
              View Security Findings ({scan.summary.total})
              <ArrowRight className="w-4 h-4" />
            </button>
          ) : isFailed ? (
            <button
              onClick={onCancel}
              className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 text-xs hover:bg-slate-700 cursor-pointer"
            >
              Dismiss
            </button>
          ) : (
            <div className="text-right">
              <span className="text-xs font-mono text-slate-400 block">Progress</span>
              <span className="text-2xl font-bold font-mono text-sky-400">{scan.progress}%</span>
            </div>
          )}
        </div>
      </div>

      {/* Real Execution Stages Pipeline */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
            Isolated Sandbox Pipeline Stages
          </h2>
          <span className="text-xs text-slate-500 font-mono">Real Worker Telemetry</span>
        </div>

        <div className="space-y-3">
          {scan.stages.map((stage: ScanStage, idx: number) => {
            const isCurrent = stage.status === 'running';
            const isDone = stage.status === 'completed';
            const isFailedStage = stage.status === 'failed';

            return (
              <div
                key={stage.name}
                className={`p-3.5 rounded-lg border transition flex items-center justify-between ${
                  isCurrent
                    ? 'bg-sky-950/20 border-sky-500/50 shadow-xs'
                    : isDone
                    ? 'bg-slate-950/60 border-slate-800/80 text-slate-300'
                    : isFailedStage
                    ? 'bg-rose-950/20 border-rose-800/50 text-rose-300'
                    : 'bg-slate-950/30 border-slate-900 text-slate-600'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs text-slate-500 w-5">
                    {String(idx + 1).padStart(2, '0')}
                  </span>

                  <div>
                    <div className="font-medium text-sm text-slate-200 flex items-center gap-2">
                      {stage.name}
                      {isCurrent && (
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-sky-500/20 text-sky-300">
                          ACTIVE
                        </span>
                      )}
                    </div>
                    {stage.message && (
                      <div className="text-xs text-slate-400 font-mono mt-0.5">{stage.message}</div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 text-xs font-mono">
                  {stage.durationMs !== undefined && (
                    <span className="text-slate-500">
                      {stage.durationMs < 1000 ? `${stage.durationMs}ms` : `${(stage.durationMs / 1000).toFixed(1)}s`}
                    </span>
                  )}

                  {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
                  {isCurrent && <Loader2 className="w-4 h-4 text-sky-400 animate-spin shrink-0" />}
                  {isFailedStage && <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />}
                  {stage.status === 'pending' && <Clock className="w-4 h-4 text-slate-700 shrink-0" />}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Failure Banner if any */}
      {isFailed && (
        <div className="p-4 rounded-lg bg-rose-950/30 border border-rose-800/60 text-rose-300 text-sm space-y-1">
          <div className="font-semibold flex items-center gap-1.5">
            <AlertCircle className="w-4 h-4" /> Scan Execution Aborted
          </div>
          <div className="text-xs font-mono text-rose-400">
            {scan.errorMessage || 'An error occurred during sandbox isolation.'}
          </div>
        </div>
      )}

      {/* Sandbox Specs Footer */}
      <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs font-mono text-slate-500">
        <div>Runtime: {scan.sandbox.runtimeName}</div>
        <div>Limits: {scan.sandbox.cpuLimit} | {scan.sandbox.memoryLimit}</div>
        <div>Network: Airgapped in Analysis</div>
      </div>
    </div>
  );
};
