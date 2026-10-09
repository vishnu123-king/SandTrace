import React from 'react';
import { Finding, FindingStatus } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { X, ExternalLink, ShieldAlert, CheckCircle, Clock, AlertTriangle, FileText } from 'lucide-react';

interface FindingDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onStatusChange: (status: FindingStatus) => void;
}

export const FindingDrawer: React.FC<FindingDrawerProps> = ({ finding, onClose, onStatusChange }) => {
  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
      <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-slate-800/80 flex items-start justify-between bg-slate-950/40">
          <div className="space-y-2 pr-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {finding.category.toUpperCase()}
              </span>
              <span
                className={`font-mono text-xs px-2 py-0.5 rounded border ${
                  finding.exposureType === 'HISTORICAL'
                    ? 'bg-purple-950/40 text-purple-300 border-purple-800/50'
                    : 'bg-cyan-950/40 text-cyan-300 border-cyan-800/50'
                }`}
              >
                {finding.exposureType === 'HISTORICAL' ? 'HISTORICAL COMMIT EXPOSURE' : 'CURRENT HEAD'}
              </span>
            </div>
            <h2 className="text-lg font-semibold text-slate-100">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-md hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Finding Location Box */}
          <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800 space-y-2">
            <div className="text-xs uppercase tracking-wider font-semibold text-slate-400">
              Location & Identification
            </div>
            <div className="font-mono text-sm text-sky-400 break-all">
              {finding.filePath}
              {finding.lineNumber ? `:${finding.lineNumber}` : ''}
            </div>
            <div className="flex flex-wrap gap-4 text-xs text-slate-400 pt-2 border-t border-slate-800/60 font-mono">
              <div>Scanner: <span className="text-slate-200">{finding.scannerName}</span></div>
              <div>Rule: <span className="text-slate-200">{finding.ruleId}</span></div>
              {finding.commitHash && (
                <div>Commit: <span className="text-slate-200">{finding.commitHash}</span></div>
              )}
            </div>
          </div>

          {/* Masked Code Context */}
          {finding.maskedSnippet && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                  Sanitized Code Context
                </span>
                <span className="text-[11px] text-slate-500 font-mono">Secrets & tokens masked</span>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 overflow-x-auto">
                <pre className="font-mono text-xs text-slate-200 whitespace-pre-wrap break-all">
                  <code>{finding.maskedSnippet}</code>
                </pre>
              </div>
            </div>
          )}

          {/* Scanner Evidence */}
          <div className="space-y-2">
            <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
              Scanner Evidence & Technical Details
            </span>
            <div className="p-3.5 bg-slate-950/40 rounded-lg border border-slate-800/70 text-sm text-slate-300 leading-relaxed">
              {finding.evidence}
            </div>
          </div>

          {/* Remediation Guidance */}
          <div className="space-y-2">
            <span className="text-xs uppercase tracking-wider font-semibold text-emerald-400 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4" /> Actionable Remediation Guidance
            </span>
            <div className="p-4 bg-emerald-950/15 rounded-lg border border-emerald-900/40 text-sm text-emerald-200 leading-relaxed">
              {finding.remediation}
            </div>
          </div>

          {/* Classification & Regulatory Mapping */}
          <div className="grid grid-cols-2 gap-4">
            {finding.cweId && (
              <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800">
                <div className="text-[11px] text-slate-500 uppercase font-mono">CWE Mapping</div>
                <div className="text-xs font-mono text-slate-300 mt-1">{finding.cweId}</div>
              </div>
            )}
            {finding.owasp && (
              <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800">
                <div className="text-[11px] text-slate-500 uppercase font-mono">OWASP Category</div>
                <div className="text-xs font-mono text-slate-300 mt-1">{finding.owasp}</div>
              </div>
            )}
          </div>

          {/* Reference Links */}
          {finding.referenceUrls && finding.referenceUrls.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                External Advisories & References
              </span>
              <ul className="space-y-1.5">
                {finding.referenceUrls.map((url, i) => (
                  <li key={i}>
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1.5 break-all font-mono"
                    >
                      <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                      {url}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Status Workflow Selector */}
          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-3">
            <div className="text-xs uppercase tracking-wider font-semibold text-slate-400">
              Finding Status & Lifecycle
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {(['OPEN', 'INVESTIGATING', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED'] as FindingStatus[]).map(
                (status) => (
                  <button
                    key={status}
                    onClick={() => onStatusChange(status)}
                    className={`px-3 py-2 text-xs font-mono rounded border transition text-left ${
                      finding.status === status
                        ? 'bg-sky-500/10 border-sky-500 text-sky-300 font-semibold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                    }`}
                  >
                    {status}
                  </button>
                )
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
