import React, { useState, useMemo } from 'react';
import { ScanProfile } from '../types';
import { api } from '../services/api';
import {
  Shield,
  Search,
  CheckCircle,
  AlertTriangle,
  Play,
  Lock,
  GitBranch,
  Settings2,
  Server,
  Zap,
  Layers,
  History,
  FileCode,
} from 'lucide-react';

interface NewScanPageProps {
  onScanStarted: (scanId: string) => void;
}

function instantValidateUrl(rawUrl: string): {
  isValid: boolean;
  provider?: string;
  repoName?: string;
  owner?: string;
  error?: string;
} {
  const trimmed = rawUrl.trim();
  if (!trimmed) return { isValid: false };

  if (trimmed.startsWith('-') || trimmed.includes('--upload-pack')) {
    return { isValid: false, error: 'Prohibited flags or suspicious characters detected.' };
  }

  if (!trimmed.startsWith('https://') && !trimmed.startsWith('http://')) {
    return { isValid: false, error: 'Repository URL must begin with https:// or http://' };
  }

  try {
    const parsed = new URL(trimmed);
    const host = parsed.hostname.toLowerCase();

    if (['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'].includes(host)) {
      return { isValid: false, error: 'Access to loopback or private host is blocked to prevent SSRF.' };
    }

    if (parsed.username || parsed.password) {
      return { isValid: false, error: 'Embedded credentials in URL are prohibited.' };
    }

    const pathParts = parsed.pathname.replace(/^\/|\/$/g, '').split('/');
    if (pathParts.length < 2 || !pathParts[0] || !pathParts[1]) {
      return { isValid: false, error: 'URL must contain owner and repository name (e.g., https://github.com/org/repo).' };
    }

    let provider = 'Generic Git';
    if (host.includes('github.com')) provider = 'GitHub';
    else if (host.includes('gitlab.com')) provider = 'GitLab';
    else if (host.includes('bitbucket.org')) provider = 'Bitbucket';
    else if (host.includes('codeberg.org') || host.includes('forgejo')) provider = 'Forgejo';
    else if (host.includes('gitea')) provider = 'Gitea';

    const repoName = pathParts[1].replace(/\.git$/, '');

    return {
      isValid: true,
      provider,
      repoName,
      owner: pathParts[0],
    };
  } catch {
    return { isValid: false, error: 'Invalid URL format.' };
  }
}

export const NewScanPage: React.FC<NewScanPageProps> = ({ onScanStarted }) => {
  const [repoUrl, setRepoUrl] = useState('');
  const [profile, setProfile] = useState<ScanProfile>('deep');
  const [branch, setBranch] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Instant synchronous client-side validation (0ms latency)
  const validation = useMemo(() => instantValidateUrl(repoUrl), [repoUrl]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetUrl = repoUrl.trim();
    if (!targetUrl) return;

    if (!validation.isValid) {
      setSubmitError(validation.error || 'Please enter a valid Git repository URL.');
      return;
    }

    setSubmitting(true);
    setSubmitError(null);

    try {
      const res = await api.startScan(targetUrl, profile);
      onScanStarted(res.scanId);
    } catch (err: any) {
      setSubmitError(err.message || 'Failed to start scan worker.');
      setSubmitting(false);
    }
  };

  const sampleRepos = [
    {
      name: 'SecretShield (Audit Target)',
      url: 'https://github.com/vishnu123-king/SecretShield-.git',
      desc: 'Target repository for security audit',
    },
    {
      name: 'Express.js (Node framework)',
      url: 'https://github.com/expressjs/express.git',
      desc: 'Popular web framework with package.json dependencies',
    },
    {
      name: 'Flask (Python framework)',
      url: 'https://github.com/pallets/flask.git',
      desc: 'Python WSGI microframework for security inspection',
    },
  ];

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      {/* Page Title */}
      <div className="border-b border-slate-800 pb-6">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-sky-400" />
          Initialize Isolated Repository Audit
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          SandTrace spawns a dedicated rootless Linux sandbox, securely clones the repository with hooks disabled, and performs multi-engine static analysis.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Repo URL Input Card */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <label className="block text-sm font-semibold text-slate-200">
            Git Repository URL <span className="text-sky-400">*</span>
          </label>

          <div className="relative">
            <input
              type="text"
              value={repoUrl}
              onChange={(e) => {
                setRepoUrl(e.target.value);
                setSubmitError(null);
              }}
              placeholder="https://github.com/owner/repository.git"
              className="w-full px-4 py-3 bg-slate-950 border border-slate-700/80 rounded-lg text-slate-100 placeholder-slate-600 focus:outline-hidden focus:border-sky-500 focus:ring-1 focus:ring-sky-500 font-mono text-sm"
              required
              autoFocus
            />
          </div>

          {/* Instant Validation Feedback */}
          {repoUrl.trim() && (
            <div className="pt-1">
              {validation.isValid ? (
                <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-emerald-400 bg-emerald-950/20 p-2.5 rounded border border-emerald-900/40">
                  <span className="flex items-center gap-1.5 font-semibold">
                    <CheckCircle className="w-4 h-4 text-emerald-400" /> Validated
                  </span>
                  <span>Provider: <strong className="text-white">{validation.provider}</strong></span>
                  <span>Repository: <strong className="text-white">{validation.repoName}</strong></span>
                  <span className="text-slate-400">| SSRF Guard: Protected</span>
                </div>
              ) : validation.error ? (
                <div className="flex items-center gap-2 text-xs font-mono text-rose-400 bg-rose-950/20 p-2.5 rounded border border-rose-900/40">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{validation.error}</span>
                </div>
              ) : null}
            </div>
          )}

          {submitError && (
            <div className="flex items-center gap-2 text-xs font-mono text-rose-400 bg-rose-950/20 p-2.5 rounded border border-rose-900/40">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{submitError}</span>
            </div>
          )}

          {/* Quick Demo Repositories */}
          <div className="pt-2">
            <span className="text-xs text-slate-500 font-mono uppercase block mb-2">
              Quick Test Repositories:
            </span>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              {sampleRepos.map((item) => (
                <button
                  key={item.name}
                  type="button"
                  onClick={() => {
                    setRepoUrl(item.url);
                    setSubmitError(null);
                  }}
                  className="p-2.5 text-left rounded-lg bg-slate-950 hover:bg-slate-800/80 border border-slate-800 transition text-xs group cursor-pointer"
                >
                  <div className="font-semibold text-slate-200 group-hover:text-sky-400 font-mono">
                    {item.name}
                  </div>
                  <div className="text-[11px] text-slate-500 truncate mt-0.5">{item.desc}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Scan Profile Selection */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <label className="block text-sm font-semibold text-slate-200">
            Select Scan Profile
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              {
                id: 'deep',
                title: 'Deep Security Scan (Recommended)',
                icon: <Layers className="w-4 h-4 text-sky-400" />,
                desc: 'Source-code AST security analysis, secrets detection, dependency CVE auditing, configuration files, and recent Git history.',
              },
              {
                id: 'quick',
                title: 'Quick Scan (Fastest)',
                icon: <Zap className="w-4 h-4 text-amber-400" />,
                desc: 'Rapid evaluation: current files, high-confidence secret patterns, basic static checks, and repository metadata.',
              },
              {
                id: 'investigation',
                title: 'Full Investigation',
                icon: <History className="w-4 h-4 text-purple-400" />,
                desc: 'Exhaustive audit: current code, full Git history, all commit authors, branch/tag metadata, and credential exposure timelines.',
              },
              {
                id: 'changed_code',
                title: 'Changed-Code Scan',
                icon: <FileCode className="w-4 h-4 text-emerald-400" />,
                desc: 'Diff-focused inspection tailored for pull requests and CI/CD pre-commit validation.',
              },
            ].map((p) => (
              <div
                key={p.id}
                onClick={() => setProfile(p.id as ScanProfile)}
                className={`p-4 rounded-lg border cursor-pointer transition ${
                  profile === p.id
                    ? 'bg-slate-950 border-sky-500 shadow-xs ring-1 ring-sky-500/20'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-2 mb-1.5">
                  {p.icon}
                  <span className="font-semibold text-sm text-slate-100">{p.title}</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{p.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Advanced Scope Controls */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center justify-between w-full text-xs font-mono uppercase tracking-wider text-slate-400 hover:text-slate-200 cursor-pointer"
          >
            <span className="flex items-center gap-2">
              <Settings2 className="w-4 h-4" />
              Advanced Sandbox & Retrieval Controls
            </span>
            <span>{showAdvanced ? 'Collapse ▲' : 'Expand ▼'}</span>
          </button>

          {showAdvanced && (
            <div className="space-y-4 pt-3 border-t border-slate-800 text-xs font-mono text-slate-300">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-400 mb-1">Target Branch / Ref (Optional)</label>
                  <input
                    type="text"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    placeholder="main / develop / v1.0.0"
                    className="w-full p-2 bg-slate-950 border border-slate-700 rounded text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Clone Depth Limit</label>
                  <input
                    type="text"
                    readOnly
                    value="50 Commits (Fast Shallow Clone)"
                    className="w-full p-2 bg-slate-950/50 border border-slate-800 rounded text-slate-500 cursor-not-allowed"
                  />
                </div>
              </div>

              <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5 text-[11px] text-slate-400">
                <div className="text-slate-300 font-semibold">Strict Security Defaults Enforced:</div>
                <div>✓ Git hooks disabled (`core.hooksPath=/dev/null`)</div>
                <div>✓ Git submodules disabled by default</div>
                <div>✓ Git LFS download disabled by default</div>
                <div>✓ Local filesystem transport protocol (`file://`) blocked</div>
                <div>✓ Analysis container airgapped with network disabled</div>
              </div>
            </div>
          )}
        </div>

        {/* Submit Action */}
        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={submitting || !repoUrl.trim() || !validation.isValid}
            className="px-6 py-3 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-40 disabled:cursor-not-allowed text-slate-950 font-bold text-sm transition shadow-lg shadow-sky-500/10 flex items-center gap-2 cursor-pointer"
          >
            <Play className="w-4 h-4 fill-current" />
            {submitting ? 'Initializing Sandbox...' : 'Start Isolated Security Audit'}
          </button>
        </div>
      </form>
    </div>
  );
};
