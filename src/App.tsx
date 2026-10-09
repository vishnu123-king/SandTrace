import React, { useState, useEffect } from 'react';
import { Navigation, NavTab } from './components/Navigation';
import { OverviewPage } from './pages/OverviewPage';
import { NewScanPage } from './pages/NewScanPage';
import { LiveScanPage } from './pages/LiveScanPage';
import { RepositoriesPage } from './pages/RepositoriesPage';
import { FindingsPage } from './pages/FindingsPage';
import { ContributorsPage } from './pages/ContributorsPage';
import { DependenciesPage } from './pages/DependenciesPage';
import { ExposureTimelinePage } from './pages/ExposureTimelinePage';
import { ReportsPage } from './pages/ReportsPage';
import { SandboxPage } from './pages/SandboxPage';
import { api } from './services/api';
import { RepositoryMetadata, ScanJob } from './types';
import { Shield, Bell, Terminal } from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string | undefined>(undefined);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [repos, setRepos] = useState<RepositoryMetadata[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      const [scansList, reposList] = await Promise.all([
        api.getScans(),
        api.getRepositories(),
      ]);
      setScans(scansList);
      setRepos(reposList);
      if (!selectedScanId && scansList.length > 0) {
        setSelectedScanId(scansList[0].id);
      }
    } catch (err) {
      console.error('Failed to load initial data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleStartScan = (scanId: string) => {
    setActiveScanId(scanId);
    setSelectedScanId(scanId);
    loadData();
  };

  const handleScanCompleted = (scanId: string) => {
    setActiveScanId(null);
    setSelectedScanId(scanId);
    setCurrentTab('findings');
    loadData();
  };

  const handleSelectScan = (scanId: string) => {
    setSelectedScanId(scanId);
    setCurrentTab('findings');
  };

  const handleNewScanForRepo = (url: string) => {
    setCurrentTab('new_scan');
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 font-sans selection:bg-sky-500/30 selection:text-sky-200">
      {/* Navigation Sidebar */}
      <Navigation
        currentTab={currentTab}
        onSelectTab={(tab) => {
          setActiveScanId(null);
          setCurrentTab(tab);
        }}
        activeScanCount={activeScanId ? 1 : 0}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-[#090d14]">
        {/* Observatory Topbar */}
        <header className="h-14 border-b border-slate-800/80 bg-slate-950/60 backdrop-blur-md px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="text-slate-500">OPERATIONAL ENVIRONMENT:</span>
            <span className="px-2 py-0.5 rounded bg-slate-900 text-sky-400 border border-slate-800">
              Linux Host Container Sandbox (Airgapped)
            </span>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
            {scans.length > 0 && (
              <span className="hidden sm:inline">
                Indexed Scans: <strong className="text-white">{scans.length}</strong>
              </span>
            )}
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              Observatory Online
            </span>
          </div>
        </header>

        {/* Dynamic View Viewport */}
        <main className="flex-1 overflow-y-auto">
          {activeScanId ? (
            <LiveScanPage
              scanId={activeScanId}
              onScanCompleted={handleScanCompleted}
              onCancel={() => {
                setActiveScanId(null);
                setCurrentTab('overview');
              }}
            />
          ) : currentTab === 'overview' ? (
            <OverviewPage
              scans={scans}
              repos={repos}
              onSelectScan={handleSelectScan}
              onNewScan={() => setCurrentTab('new_scan')}
              onViewFindings={(id) => {
                if (id) setSelectedScanId(id);
                setCurrentTab('findings');
              }}
            />
          ) : currentTab === 'new_scan' ? (
            <NewScanPage onScanStarted={handleStartScan} />
          ) : currentTab === 'repositories' ? (
            <RepositoriesPage
              repos={repos}
              scans={scans}
              onSelectScan={handleSelectScan}
              onNewScanForRepo={handleNewScanForRepo}
            />
          ) : currentTab === 'findings' ? (
            <FindingsPage
              scans={scans}
              selectedScanId={selectedScanId}
              onSelectScanId={setSelectedScanId}
            />
          ) : currentTab === 'contributors' ? (
            <ContributorsPage
              scans={scans}
              selectedScanId={selectedScanId}
              onSelectScanId={setSelectedScanId}
            />
          ) : currentTab === 'dependencies' ? (
            <DependenciesPage
              scans={scans}
              selectedScanId={selectedScanId}
              onSelectScanId={setSelectedScanId}
            />
          ) : currentTab === 'timeline' ? (
            <ExposureTimelinePage
              scans={scans}
              selectedScanId={selectedScanId}
              onSelectScanId={setSelectedScanId}
              onInspectFinding={(fid) => {
                setCurrentTab('findings');
              }}
            />
          ) : currentTab === 'reports' ? (
            <ReportsPage
              scans={scans}
              selectedScanId={selectedScanId}
              onSelectScanId={setSelectedScanId}
            />
          ) : currentTab === 'sandbox' ? (
            <SandboxPage />
          ) : null}
        </main>
      </div>
    </div>
  );
}
