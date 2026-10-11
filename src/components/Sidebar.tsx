import React from 'react';
import {
  LayoutDashboard,
  Search,
  FileCode,
  Link2,
  FolderLock,
  FileText,
  Shield,
  Layers,
  Mail,
  Radar,
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'investigation'
  | 'gmail-monitor'
  | 'bulk-triage'
  | 'threat-hunt'
  | 'headers'
  | 'threat-intel'
  | 'graph'
  | 'campaign-dna'
  | 'timeline'
  | 'ledger'
  | 'cases'
  | 'report'
  | 'audit';

interface SidebarProps {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
  caseCount?: number;
  alertCount?: number;
  activeCaseId?: string;
  userRole?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  caseCount,
  alertCount,
  activeCaseId,
}) => {
  const coreNavItems: { id: PageId; label: string; icon: React.FC<{ className?: string }>; description: string }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, description: 'Overview & threat metrics' },
    { id: 'investigation', label: 'Analyze Email', icon: Search, description: 'Upload and inspect emails' },
    { id: 'headers', label: 'Email Headers & IP', icon: FileCode, description: 'MTA hops & real world map' },
    { id: 'gmail-monitor', label: 'Gmail Monitor', icon: Mail, description: 'Automatic inbox triage' },
    { id: 'bulk-triage', label: 'Bulk Forensic Triage', icon: Layers, description: 'Batch correlation' },
    { id: 'threat-hunt', label: 'Threat Hunting', icon: Radar, description: 'Search IOCs & campaigns' },
  ];

  const recordNavItems: { id: PageId; label: string; icon: React.FC<{ className?: string }>; badge?: number; description: string }[] = [
    { id: 'ledger', label: 'Evidence Ledger', icon: Link2, description: 'Cryptographic blockchain proof' },
    { id: 'cases', label: 'Case History', icon: FolderLock, badge: alertCount, description: 'Manage saved cases' },
    { id: 'report', label: 'Forensic Reports', icon: FileText, description: 'Exportable case dossiers' },
  ];

  return (
    <nav
      id="main-sidebar"
      className="w-64 bg-white border-r border-slate-200 flex flex-col flex-shrink-0 h-screen select-none font-sans"
    >
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-200 flex items-center gap-3">
        <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center text-white shadow-sm flex-shrink-0">
          <Shield className="w-5 h-5" />
        </div>
        <div className="min-w-0">
          <div className="font-bold text-slate-900 text-base leading-tight tracking-tight">
            CyberTrace
          </div>
          <div className="text-xs text-slate-500 font-medium">
            Email Threat Forensics
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 overflow-y-auto p-3 space-y-6">
        {/* Core Operations */}
        <div>
          <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Core Operations
          </div>
          <div className="space-y-1">
            {coreNavItems.map(item => {
              const isActive = currentPage === item.id;
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  id={`nav-item-${item.id}`}
                  onClick={() => onNavigate(item.id)}
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-left transition-all cursor-pointer ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 font-semibold shadow-xs'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 font-medium'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <Icon className={`w-5 h-5 flex-shrink-0 ${isActive ? 'text-blue-600' : 'text-slate-400'}`} />
                    <div className="truncate">
                      <div className="text-sm leading-tight">{item.label}</div>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Compliance & Records */}
        <div>
          <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Compliance & Records
          </div>
          <div className="space-y-1">
            {recordNavItems.map(item => {
              const isActive = currentPage === item.id;
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  id={`nav-item-${item.id}`}
                  onClick={() => onNavigate(item.id)}
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-left transition-all cursor-pointer ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 font-semibold shadow-xs'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 font-medium'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <Icon className={`w-5 h-5 flex-shrink-0 ${isActive ? 'text-blue-600' : 'text-slate-400'}`} />
                    <div className="truncate">
                      <div className="text-sm leading-tight">{item.label}</div>
                    </div>
                  </div>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="ml-2 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Active Case Banner */}
        {activeCaseId && (
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
            <div className="text-xs text-slate-500 font-medium">Currently Inspecting</div>
            <div className="text-sm font-semibold text-slate-800 font-mono mt-0.5 truncate">
              {activeCaseId}
            </div>
          </div>
        )}
      </div>

      {/* Footer / System Status */}
      <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-green-500"></span>
          <span className="text-xs font-medium text-slate-600">All systems online</span>
        </div>
        <button
          onClick={() => onNavigate('dashboard')}
          title="Home"
          className="text-slate-400 hover:text-slate-600 text-xs font-medium cursor-pointer"
        >
          v4.2
        </button>
      </div>
    </nav>
  );
};
