import React from 'react';
import {
  Shield,
  PlusCircle,
  FolderGit2,
  AlertOctagon,
  Users,
  Package,
  History,
  FileText,
  Cpu,
  Activity,
} from 'lucide-react';

export type NavTab =
  | 'overview'
  | 'new_scan'
  | 'repositories'
  | 'findings'
  | 'contributors'
  | 'dependencies'
  | 'timeline'
  | 'reports'
  | 'sandbox';

interface NavigationProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  activeScanCount?: number;
}

export const Navigation: React.FC<NavigationProps> = ({ currentTab, onSelectTab, activeScanCount = 0 }) => {
  const navItems: Array<{ id: NavTab; label: string; icon: React.ReactNode }> = [
    { id: 'overview', label: 'Overview', icon: <Activity className="w-4 h-4" /> },
    { id: 'new_scan', label: 'New Scan', icon: <PlusCircle className="w-4 h-4" /> },
    { id: 'repositories', label: 'Repositories', icon: <FolderGit2 className="w-4 h-4" /> },
    { id: 'findings', label: 'Findings', icon: <AlertOctagon className="w-4 h-4" /> },
    { id: 'contributors', label: 'Contributors', icon: <Users className="w-4 h-4" /> },
    { id: 'dependencies', label: 'Dependencies', icon: <Package className="w-4 h-4" /> },
    { id: 'timeline', label: 'Exposure Timeline', icon: <History className="w-4 h-4" /> },
    { id: 'reports', label: 'Reports', icon: <FileText className="w-4 h-4" /> },
    { id: 'sandbox', label: 'Linux Sandbox', icon: <Cpu className="w-4 h-4" /> },
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col shrink-0 select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800/80">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="font-bold tracking-tight text-white flex items-center gap-1.5 text-base">
              SandTrace
            </div>
            <div className="text-[11px] font-mono text-slate-400">Security Observatory</div>
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            Isolated Sandbox
          </span>
          <span className="font-mono text-slate-500">OCI v2</span>
        </div>
      </div>

      {/* Nav Menu */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        <div className="px-3 py-2 text-[11px] font-semibold tracking-wider uppercase text-slate-500 font-mono">
          Security Suite
        </div>
        {navItems.map((item) => {
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                isActive
                  ? 'bg-slate-900 text-sky-400 border border-slate-700/80 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <div className="flex items-center gap-3">
                <span className={isActive ? 'text-sky-400' : 'text-slate-500'}>{item.icon}</span>
                <span>{item.label}</span>
              </div>
              {item.id === 'sandbox' && activeScanCount > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  {activeScanCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/80">
        <div className="text-[11px] font-mono text-slate-500 flex items-center justify-between">
          <span>Engine v1.4.2</span>
          <span>Linux Host</span>
        </div>
        <div className="text-[10px] text-slate-500 mt-1 leading-tight">
          Isolate. Analyze. Secure.
        </div>
      </div>
    </aside>
  );
};
