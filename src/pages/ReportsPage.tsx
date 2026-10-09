import React, { useState } from 'react';
import { ScanJob } from '../types';
import { api } from '../services/api';
import { generatePdfSecurityReport } from '../utils/pdfExport';
import { FileText, Download, ExternalLink, Code2, Shield, CheckCircle2, Loader2 } from 'lucide-react';

interface ReportsPageProps {
  scans: ScanJob[];
  selectedScanId?: string;
  onSelectScanId: (id: string) => void;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({
  scans,
  selectedScanId,
  onSelectScanId,
}) => {
  const currentScanId = selectedScanId || (scans[0]?.id ?? '');
  const [generatingPdf, setGeneratingPdf] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  const currentScan = scans.find((s) => s.id === currentScanId);

  const handleDownloadPdf = async () => {
    if (!currentScan) return;
    setGeneratingPdf(true);
    try {
      const findings = await api.getFindings(currentScan.id);
      const doc = generatePdfSecurityReport(currentScan, findings);
      doc.save(`SandTrace-Assessment-${currentScan.repoName}-${currentScan.id.slice(0, 8)}.pdf`);
      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 4000);
    } catch (err) {
      console.error('Failed to generate PDF:', err);
    } finally {
      setGeneratingPdf(false);
    }
  };

  const handleDownloadJson = async () => {
    if (!currentScan) return;
    const reportData = await api.getStructuredReport(currentScan.id);
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SandTrace-Audit-${currentScan.repoName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleViewHtml = () => {
    if (!currentScan) return;
    window.open(`/api/scans/${currentScan.id}/report/html`, '_blank');
  };

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-sky-400" />
            Security Assessment Reports
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Export executive, regulatory, and technical cybersecurity reports from isolated scan evidence.
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

      {currentScan ? (
        <div className="space-y-6">
          {/* Main PDF Export Action Card */}
          <div className="p-8 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-800 shadow-xl space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-sky-400 bg-sky-500/10 px-2.5 py-1 rounded border border-sky-500/20">
                  Audit Export Package
                </span>
                <h2 className="text-xl font-bold text-white mt-2 font-mono">{currentScan.repoName}</h2>
                <div className="text-xs text-slate-400 font-mono mt-0.5">
                  Scan ID: {currentScan.id}  |  Commit: {currentScan.commitHash || 'HEAD'}  |  Profile: {currentScan.profile.toUpperCase()}
                </div>
              </div>

              <button
                onClick={handleDownloadPdf}
                disabled={generatingPdf}
                className="px-6 py-3.5 rounded-xl bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-bold text-sm transition shadow-lg shadow-sky-500/20 flex items-center gap-2.5 cursor-pointer shrink-0"
              >
                {generatingPdf ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Generating PDF Report...
                  </>
                ) : (
                  <>
                    <Download className="w-4 h-4" />
                    Generate PDF Security Report
                  </>
                )}
              </button>
            </div>

            {downloadSuccess && (
              <div className="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded-lg text-emerald-300 text-xs font-mono flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Assessment PDF downloaded successfully to local machine.
              </div>
            )}

            {/* Structured 16-Section Contents Checklist */}
            <div className="border-t border-slate-800/80 pt-5 space-y-3">
              <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                Mandatory 16-Section Specification Included:
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs font-mono text-slate-400">
                <div>✓ 1. Cover & Assessment Info</div>
                <div>✓ 2. Executive Summary</div>
                <div>✓ 3. Repository Details</div>
                <div>✓ 4. Sandbox Configuration</div>
                <div>✓ 5. Coverage & Limitations</div>
                <div>✓ 6. Overall Finding Summary</div>
                <div>✓ 7. Source-Code Findings</div>
                <div>✓ 8. Dependency CVEs</div>
                <div>✓ 9. Secret Exposure Findings</div>
                <div>✓ 10. IaC / Config Issues</div>
                <div>✓ 11. Contributor Activity</div>
                <div>✓ 12. Git History Analysis</div>
                <div>✓ 13. Severity Breakdown</div>
                <div>✓ 14. Masked Code Evidence</div>
                <div>✓ 15. Remediation Roadmap</div>
                <div>✓ 16. Tool Versions & References</div>
              </div>
            </div>
          </div>

          {/* Alternative Format Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-white font-semibold text-sm">
                <ExternalLink className="w-4 h-4 text-sky-400" />
                HTML Executive Report Preview
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Open a standalone web-rendered version of the cybersecurity assessment report in a new tab for rapid browser review or printing.
              </p>
              <button
                onClick={handleViewHtml}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition cursor-pointer flex items-center gap-1.5"
              >
                Open HTML Preview
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-white font-semibold text-sm">
                <Code2 className="w-4 h-4 text-purple-400" />
                Machine-Readable JSON Export
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Download raw structured findings conforming to SandTrace JSON schema for CI/CD ingestion, SIEM integration, or defect tracking.
              </p>
              <button
                onClick={handleDownloadJson}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition cursor-pointer flex items-center gap-1.5"
              >
                Download JSON Manifest
                <Download className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center text-slate-500 font-mono">
          No audit available. Complete a scan to generate assessment reports.
        </div>
      )}
    </div>
  );
};
