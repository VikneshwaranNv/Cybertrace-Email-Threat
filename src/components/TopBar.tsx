import React from 'react';
import {
  ChevronDown,
  BookOpen,
  Shield,
  LogOut,
} from 'lucide-react';
import { CaseRecord, InvestigationCompletePayload } from '../types/forensics';
import { UserSessionProfile } from '../services/api';

interface TopBarProps {
  activeCase: InvestigationCompletePayload | null;
  cases: CaseRecord[];
  currentUser?: UserSessionProfile | null;
  onSelectCase: (caseId: string) => void;
  onOpenIngest?: () => void;
  onOpenAuthModal?: () => void;
  onOpenGuideModal?: () => void;
  onLogout?: () => void;
  isAnalyzing?: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeCase,
  cases,
  currentUser,
  onSelectCase,
  onOpenIngest,
  onOpenAuthModal,
  onOpenGuideModal,
  onLogout,
  isAnalyzing,
}) => {
  const caseRecord = activeCase?.caseRecord;
  const initials = currentUser
    ? currentUser.name
        .split(' ')
        .map(n => n[0])
        .join('')
        .slice(0, 2)
        .toUpperCase()
    : 'AN';

  const roleBadgeStyle = (role?: string) => {
    switch (role) {
      case 'ADMIN':
        return 'bg-purple-100 text-purple-800 border-purple-200';
      case 'SENIOR_ANALYST':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'ANALYST':
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
      case 'AUDITOR':
        return 'bg-amber-100 text-amber-800 border-amber-200';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-200';
    }
  };

  return (
    <header
      id="main-topbar"
      className="h-16 border-b border-slate-200 bg-white flex items-center justify-between px-4 sm:px-8 z-10 select-none font-sans"
    >
      {/* Left: Current Active Case Indicator */}
      <div className="flex items-center gap-3 min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider hidden lg:inline">
            Active Case:
          </span>
          {caseRecord ? (
            <div className="flex items-center gap-2 min-w-0">
              <span className="px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 font-bold text-xs border border-blue-200 flex-shrink-0">
                {caseRecord.caseNumber}
              </span>
              <span className="text-xs sm:text-sm font-semibold text-slate-900 truncate max-w-[140px] sm:max-w-xs md:max-w-md">
                {caseRecord.title}
              </span>
            </div>
          ) : (
            <span className="text-xs font-medium text-slate-400">No active case selected</span>
          )}
        </div>
      </div>

      {/* Right: Actions, Case Switcher, Platform Guide & Operator Badge */}
      <div className="flex items-center gap-2 sm:gap-3 flex-shrink-0">
        {/* Switch Case dropdown */}
        {cases.length > 0 && (
          <div className="relative hidden md:block">
            <select
              id="case-switcher-dropdown"
              value={caseRecord?.caseId || ''}
              onChange={e => onSelectCase(e.target.value)}
              className="appearance-none bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-lg px-3 py-2 pr-8 text-xs font-medium text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 cursor-pointer max-w-[200px] truncate"
            >
              {cases.map(c => (
                <option key={c.caseId} value={c.caseId}>
                  {c.caseNumber} – {c.title.substring(0, 24)} ({c.severity})
                </option>
              ))}
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-slate-500 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
        )}

        {/* Platform Guide & Architecture Button */}
        {onOpenGuideModal && (
          <button
            id="btn-platform-guide"
            onClick={onOpenGuideModal}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-blue-200 bg-blue-50/60 hover:bg-blue-100 text-blue-700 text-xs font-bold transition-all cursor-pointer shadow-2xs"
            title="Architecture, 5-Stage Pipeline & Security Glossary"
          >
            <BookOpen className="w-4 h-4 text-blue-600 flex-shrink-0" />
            <span className="hidden sm:inline">Platform Guide</span>
          </button>
        )}

        {/* Operator Profile & Role Switcher */}
        {onOpenAuthModal && (
          <button
            id="btn-operator-auth"
            onClick={onOpenAuthModal}
            className="flex items-center gap-2 px-2.5 sm:px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 hover:border-slate-300 transition-colors text-left cursor-pointer"
            title="Switch User Role or Sign In"
          >
            <div className={`w-7 h-7 rounded-full ${currentUser ? 'bg-blue-600 text-white' : 'bg-slate-200 text-slate-600'} flex items-center justify-center text-xs font-bold flex-shrink-0`}>
              {currentUser ? initials : 'OP'}
            </div>
            <div className="hidden lg:block min-w-0">
              <div className="text-xs font-bold text-slate-800 leading-tight truncate max-w-[130px]">
                {currentUser?.name || 'Sign In'}
              </div>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded border ${roleBadgeStyle(currentUser?.role)}`}>
                  {currentUser?.role || 'GUEST'}
                </span>
              </div>
            </div>
          </button>
        )}

        {/* Sign Out Action */}
        {currentUser && onLogout && (
          <button
            id="btn-operator-logout"
            onClick={onLogout}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50/60 hover:bg-red-100 text-red-700 text-xs font-semibold transition-all cursor-pointer shadow-2xs"
            title="Sign out of SOC session"
          >
            <LogOut className="w-3.5 h-3.5 text-red-600 flex-shrink-0" />
            <span className="hidden sm:inline">Sign Out</span>
          </button>
        )}
      </div>
    </header>
  );
};
