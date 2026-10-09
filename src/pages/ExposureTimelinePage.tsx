import React, { useState, useEffect } from 'react';
import { ExposureTimelineEvent, ScanJob } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { History, GitCommit, AlertOctagon, ShieldCheck, ArrowRight, Clock, Key, Loader2 } from 'lucide-react';

interface ExposureTimelinePageProps {
  scans: ScanJob[];
  selectedScanId?: string;
  onSelectScanId: (id: string) => void;
  onInspectFinding: (findingId: string) => void;
}

export const ExposureTimelinePage: React.FC<ExposureTimelinePageProps> = ({
  scans,
  selectedScanId,
  onSelectScanId,
  onInspectFinding,
}) => {
  const currentScanId = selectedScanId || (scans[0]?.id ?? '');
  const currentScan = scans.find((s) => s.id === currentScanId);
  const [timelineEvents, setTimelineEvents] = useState<ExposureTimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!currentScanId) return;
    const fetchTimeline = async () => {
      setLoading(true);
      try {
        const list = await api.getTimeline(currentScanId);
        if (Array.isArray(list) && list.length > 0) {
          setTimelineEvents(list);
        } else if (currentScan?.timelineEvents && currentScan.timelineEvents.length > 0) {
          setTimelineEvents(currentScan.timelineEvents);
        } else {
          setTimelineEvents([]);
        }
      } catch {
        if (currentScan?.timelineEvents) {
          setTimelineEvents(currentScan.timelineEvents);
        }
      } finally {
        setLoading(false);
      }
    };
    fetchTimeline();
  }, [currentScanId, currentScan]);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <History className="w-6 h-6 text-sky-400" />
            Exposure & Git History Timeline
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real chronological reconstruction of commits touching security artifacts, credentials, and architecture changes.
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

      {/* Explanatory Banner */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 leading-relaxed">
        <div className="font-semibold text-sky-400 mb-1 flex items-center gap-1.5">
          <Key className="w-4 h-4" /> Current vs. Historical Exposure Distinction
        </div>
        Deleting a secret in a subsequent commit does not revoke the credential. If a key exists anywhere in Git history, it must be considered compromised and rotated immediately in the respective cloud/service console.
      </div>

      {/* Timeline View */}
      {loading ? (
        <div className="p-16 text-center text-slate-500 font-mono">
          <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-sky-400" />
          Reconstructing real Git history timeline events...
        </div>
      ) : timelineEvents.length === 0 ? (
        <div className="p-16 text-center text-slate-500 font-mono space-y-2">
          <History className="w-8 h-8 text-slate-600 mx-auto" />
          <div>No security timeline events found for this repository.</div>
        </div>
      ) : (
        <div className="relative pl-6 space-y-8 before:absolute before:left-3 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
          {timelineEvents.map((evt) => {
            const isCrit = evt.severity === 'CRITICAL';
            const isHigh = evt.severity === 'HIGH';

            return (
              <div key={evt.id} className="relative group">
                {/* Timeline Dot */}
                <div
                  className={`absolute -left-6 top-1.5 w-3.5 h-3.5 rounded-full border-2 bg-slate-950 transition ${
                    isCrit
                      ? 'border-rose-500 ring-4 ring-rose-500/10'
                      : isHigh
                      ? 'border-orange-500 ring-4 ring-orange-500/10'
                      : 'border-sky-500 ring-4 ring-sky-500/10'
                  }`}
                />

                {/* Event Card */}
                <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      {evt.severity && <SeverityBadge severity={evt.severity} size="sm" />}
                      <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800 flex items-center gap-1">
                        <GitCommit className="w-3 h-3" />
                        {evt.commitHash}
                      </span>
                      <span className="text-xs text-slate-500 font-mono">
                        by {evt.author}
                      </span>
                    </div>

                    <span className="text-xs text-slate-500 font-mono">
                      {new Date(evt.timestamp).toLocaleDateString()}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-base font-semibold text-white">{evt.title}</h3>
                    <p className="text-xs text-slate-300 font-mono mt-1">{evt.description}</p>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs font-mono">
                    <span className="text-sky-400/90">{evt.filePath}</span>
                    {evt.findingId && (
                      <button
                        onClick={() => onInspectFinding(evt.findingId!)}
                        className="text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer"
                      >
                        Inspect Finding
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
