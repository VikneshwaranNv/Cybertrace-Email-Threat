import React, { useState, useEffect } from 'react';
import {
  FolderLock,
  Search,
  Filter,
  ShieldAlert,
  AlertTriangle,
  FileCheck2,
  ExternalLink,
  ChevronRight,
  User,
  Clock,
  Tag,
  MessageSquare,
  History,
  Plus,
  CheckCircle2,
  X,
  FileText,
  Layers,
  ShieldCheck,
  AlertCircle,
} from 'lucide-react';
import { CaseRecord, CaseStatus, CasePriority } from '../types/forensics';
import { PageId } from '../components/Sidebar';
import {
  updateCaseStatus as apiUpdateCaseStatus,
  updateCasePriority as apiUpdateCasePriority,
  updateCaseAssignment as apiUpdateCaseAssignment,
  addCaseNote,
  fetchAssignableAnalysts,
  fetchCasePayload,
  getStoredUser,
} from '../services/api';

interface CaseHistoryPageProps {
  cases: CaseRecord[];
  onSelectCase: (caseId: string) => void;
  onUpdateStatus: (caseId: string, status: CaseRecord['status']) => void;
  onNavigate: (page: PageId) => void;
}

interface AssignableAnalyst {
  id: string;
  name: string;
  email: string;
  role: string;
}

export const CaseHistoryPage: React.FC<CaseHistoryPageProps> = ({
  cases,
  onSelectCase,
  onUpdateStatus,
  onNavigate,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');

  // Assignable analysts for assignment dropdown
  const [assignableAnalysts, setAssignableAnalysts] = useState<AssignableAnalyst[]>([]);

  // Active drawer for Notes & History
  const [activeCaseDetails, setActiveCaseDetails] = useState<CaseRecord | null>(null);
  const [newNote, setNewNote] = useState('');
  const [submittingNote, setSubmittingNote] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Current authenticated user profile
  const currentUser = getStoredUser();
  const isAuditor = currentUser?.role === 'AUDITOR';

  useEffect(() => {
    fetchAssignableAnalysts()
      .then(analysts => setAssignableAnalysts(analysts))
      .catch(err => console.warn('Could not load assignable analysts', err));
  }, []);

  const filteredCases = cases.filter(c => {
    if (severityFilter !== 'ALL' && c.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && c.status !== statusFilter) return false;
    if (priorityFilter !== 'ALL' && c.priority !== priorityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        c.caseId.toLowerCase().includes(q) ||
        c.caseNumber.toLowerCase().includes(q) ||
        c.title.toLowerCase().includes(q) ||
        c.classification.toLowerCase().includes(q) ||
        (c.assignedTo && c.assignedTo.toLowerCase().includes(q)) ||
        (c.analyst && c.analyst.toLowerCase().includes(q)) ||
        (c.tags && c.tags.some(t => t.toLowerCase().includes(q)))
      );
    }
    return true;
  });

  const getPriorityBadge = (p?: CasePriority) => {
    switch (p) {
      case 'CRITICAL':
        return 'text-red-700 bg-red-50 border-red-200';
      case 'HIGH':
        return 'text-amber-700 bg-amber-50 border-amber-200';
      case 'MEDIUM':
        return 'text-blue-700 bg-blue-50 border-blue-200';
      case 'LOW':
        return 'text-emerald-700 bg-emerald-50 border-emerald-200';
      default:
        return 'text-slate-600 bg-slate-100 border-slate-200';
    }
  };

  const getSeverityBadge = (s?: string) => {
    switch (s) {
      case 'CRITICAL':
        return 'text-rose-700 bg-rose-50 border-rose-200';
      case 'HIGH':
        return 'text-orange-700 bg-orange-50 border-orange-200';
      case 'MEDIUM':
        return 'text-amber-700 bg-amber-50 border-amber-200';
      case 'LOW':
        return 'text-emerald-700 bg-emerald-50 border-emerald-200';
      default:
        return 'text-slate-600 bg-slate-100 border-slate-200';
    }
  };

  const handleOpenDrawer = async (c: CaseRecord) => {
    setActiveCaseDetails(c);
    setActionError(null);
    try {
      const full = await fetchCasePayload(c.caseId);
      if (full && full.caseRecord) {
        setActiveCaseDetails(full.caseRecord);
      }
    } catch {
      // Fall back to current case record
    }
  };

  const handleStatusChange = async (caseId: string, status: CaseStatus) => {
    if (isAuditor) return;
    setActionError(null);
    try {
      const updated = await apiUpdateCaseStatus(caseId, status);
      onUpdateStatus(caseId, status);
      if (activeCaseDetails && activeCaseDetails.caseId === caseId) {
        setActiveCaseDetails(updated);
      }
    } catch (e: any) {
      console.error('Failed to update status', e);
      setActionError(e?.message || 'Failed to update case status');
    }
  };

  const handlePriorityChange = async (caseId: string, priority: CasePriority) => {
    if (isAuditor) return;
    setActionError(null);
    try {
      const updated = await apiUpdateCasePriority(caseId, priority);
      if (activeCaseDetails && activeCaseDetails.caseId === caseId) {
        setActiveCaseDetails(updated);
      }
    } catch (e: any) {
      console.error('Failed to update priority', e);
      setActionError(e?.message || 'Failed to update case priority');
    }
  };

  const handleAssignmentChange = async (caseId: string, analystId: string) => {
    if (isAuditor) return;
    setActionError(null);
    try {
      const updated = await apiUpdateCaseAssignment(caseId, analystId);
      if (activeCaseDetails && activeCaseDetails.caseId === caseId) {
        setActiveCaseDetails(updated);
      }
    } catch (e: any) {
      console.error('Failed to update assignment', e);
      setActionError(e?.message || 'Failed to update case assignment');
    }
  };

  const handleAddNote = async () => {
    if (!activeCaseDetails || !newNote.trim() || isAuditor) return;
    setSubmittingNote(true);
    setActionError(null);
    try {
      const updated = await addCaseNote(activeCaseDetails.caseId, {
        note: newNote.trim(),
        author: currentUser?.name || 'Analyst',
      });
      setActiveCaseDetails(updated);
      setNewNote('');
    } catch (e: any) {
      console.error('Failed to add note', e);
      setActionError(e?.message || 'Failed to record analyst note');
    } finally {
      setSubmittingNote(false);
    }
  };

  return (
    <div id="case-history-view" className="space-y-6 pb-12 font-sans">
      {/* Top Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center flex-shrink-0">
            <FolderLock className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900">
              SOC Case Management & Investigation History
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Decoupled forensic risk detection & analyst operational priority, RBAC custody transitions, and chronological audit ledger.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {isAuditor && (
            <span className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-amber-50 text-amber-800 border border-amber-200 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-amber-600" />
              Auditor Mode (Read-Only)
            </span>
          )}
          <span className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-blue-50 text-blue-700 border border-blue-200">
            Total Cases: {cases.length}
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-2.5 flex-1 min-w-[260px]">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search by Case ID, subject, classification, tags, or assignee..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3.5 py-2 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white transition-colors"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-500 font-medium">Status:</span>
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-xs text-slate-700 font-medium focus:outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">OPEN</option>
              <option value="IN_PROGRESS">IN_PROGRESS</option>
              <option value="ESCALATED">ESCALATED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-500 font-medium">Priority:</span>
            <select
              value={priorityFilter}
              onChange={e => setPriorityFilter(e.target.value)}
              className="bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-xs text-slate-700 font-medium focus:outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="ALL">All Priorities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-500 font-medium">Forensic Risk:</span>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-xs text-slate-700 font-medium focus:outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="ALL">All Risks</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Case Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 font-semibold text-xs border-b border-slate-200">
              <tr>
                <th className="py-3.5 px-4">CASE ID</th>
                <th className="py-3.5 px-4">TITLE & CLASSIFICATION</th>
                <th className="py-3.5 px-4">FORENSIC RISK</th>
                <th className="py-3.5 px-4">OPERATIONAL PRIORITY</th>
                <th className="py-3.5 px-4">LIFECYCLE STATUS</th>
                <th className="py-3.5 px-4">ASSIGNEE</th>
                <th className="py-3.5 px-4 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {filteredCases.map(c => (
                <tr key={c.caseId} className="hover:bg-slate-50/70 transition-colors">
                  <td className="py-3.5 px-4 font-bold text-blue-700 font-mono">
                    <div>{c.caseNumber}</div>
                    <div className="text-[10px] text-slate-400 font-normal">{c.caseId}</div>
                  </td>
                  <td className="py-3.5 px-4 font-medium text-slate-900 max-w-xs">
                    <div className="truncate font-semibold">{c.title}</div>
                    <div className="text-[11px] text-slate-500 flex items-center gap-1.5 mt-0.5">
                      <span className="font-medium text-slate-600">{c.classification.replace(/_/g, ' ')}</span>
                      {c.tags && c.tags.length > 0 && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 text-slate-500 border border-slate-200">
                          #{c.tags[0]}
                        </span>
                      )}
                    </div>
                  </td>
                  {/* Forensic Detection Risk */}
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-1.5">
                      <span className={`px-2 py-0.5 rounded-md font-bold text-[11px] border ${getSeverityBadge(c.severity)}`}>
                        {c.severity}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">({c.riskScore ?? '—'}/100)</span>
                    </div>
                  </td>
                  {/* Analyst Operational Priority */}
                  <td className="py-3.5 px-4">
                    <select
                      value={c.priority || 'MEDIUM'}
                      disabled={isAuditor}
                      onChange={e => handlePriorityChange(c.caseId, e.target.value as CasePriority)}
                      className={`border rounded-lg px-2.5 py-1 text-xs font-semibold focus:outline-none cursor-pointer ${getPriorityBadge(
                        c.priority
                      )} disabled:opacity-60 disabled:cursor-not-allowed`}
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </td>
                  {/* Operational Status */}
                  <td className="py-3.5 px-4">
                    <select
                      value={c.status}
                      disabled={isAuditor}
                      onChange={e => handleStatusChange(c.caseId, e.target.value as CaseStatus)}
                      className="bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs text-slate-800 font-semibold focus:outline-none focus:border-blue-500 cursor-pointer shadow-2xs disabled:opacity-60 disabled:cursor-not-allowed"
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="IN_PROGRESS">IN_PROGRESS</option>
                      <option value="ESCALATED">ESCALATED</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                    </select>
                  </td>
                  {/* Assignee */}
                  <td className="py-3.5 px-4 text-slate-600 text-xs truncate max-w-[140px]">
                    <div className="font-medium text-slate-900 truncate">
                      {c.assignedTo || c.assignedAnalystName || c.analyst.split(' ')[0]}
                    </div>
                    {c.lastUpdatedBy && (
                      <div className="text-[10px] text-slate-400 truncate">
                        by {c.lastUpdatedBy}
                      </div>
                    )}
                  </td>
                  {/* Actions */}
                  <td className="py-3.5 px-4 text-right space-x-2">
                    <button
                      onClick={() => handleOpenDrawer(c)}
                      className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold border border-slate-200 inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                      title="View notes, assignment, and audit history"
                    >
                      <History className="w-3.5 h-3.5 text-slate-500" />
                      <span>Audit & Notes</span>
                    </button>
                    <button
                      onClick={() => {
                        onSelectCase(c.caseId);
                        onNavigate('investigation');
                      }}
                      className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-over Drawer for Case Management Details: Notes, Assignment & Audit History */}
      {activeCaseDetails && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs flex justify-end z-50 animate-in fade-in duration-200">
          <div className="w-full max-w-xl bg-white border-l border-slate-200 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-100">
              <div>
                <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 uppercase tracking-wider">
                  Case Record Dossier
                </span>
                <h3 className="text-base font-bold text-slate-900 mt-2">
                  {activeCaseDetails.caseNumber}: {activeCaseDetails.title}
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  ID: <span className="font-mono">{activeCaseDetails.caseId}</span>
                </p>
              </div>
              <button
                onClick={() => {
                  setActiveCaseDetails(null);
                  setActionError(null);
                }}
                className="p-1.5 rounded-lg bg-slate-100 text-slate-500 hover:text-slate-800 hover:bg-slate-200 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Error Notification inside drawer */}
            {actionError && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{actionError}</span>
              </div>
            )}

            {/* Auditor notice */}
            {isAuditor && (
              <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-800 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-amber-600 flex-shrink-0" />
                <span>Auditor Mode: Read-Only Oversight. Case mutations, notes, and reassignment are disabled.</span>
              </div>
            )}

            {/* Decoupled Forensic Risk vs Operational Priority */}
            <div className="grid grid-cols-2 gap-3">
              {/* Automated Forensic Detection */}
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-bold text-slate-600 uppercase tracking-wider">
                    Forensic Risk
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">Detection Result</span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getSeverityBadge(activeCaseDetails.severity)}`}>
                    {activeCaseDetails.severity}
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-700">
                    {activeCaseDetails.riskScore}/100
                  </span>
                </div>
                <p className="text-[10px] text-slate-500 mt-1.5">
                  Automated deterministic engine risk calculation (immutable forensic detection result).
                </p>
              </div>

              {/* Analyst Operational Priority */}
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-bold text-slate-600 uppercase tracking-wider">
                    Operational Priority
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">Workflow Urgency</span>
                </div>
                <div>
                  <select
                    value={activeCaseDetails.priority || 'MEDIUM'}
                    disabled={isAuditor}
                    onChange={e => handlePriorityChange(activeCaseDetails.caseId, e.target.value as CasePriority)}
                    className={`w-full border rounded-lg px-2.5 py-1 text-xs font-semibold focus:outline-none cursor-pointer ${getPriorityBadge(
                      activeCaseDetails.priority
                    )} disabled:opacity-60 disabled:cursor-not-allowed`}
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
                <p className="text-[10px] text-slate-500 mt-1.5">
                  Analyst-assigned response priority. Decoupled from forensic risk score.
                </p>
              </div>
            </div>

            {/* Case Operational Status & Assignment */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                {/* Lifecycle Status */}
                <div>
                  <label className="text-[11px] text-slate-500 font-semibold uppercase block mb-1">
                    Lifecycle Status
                  </label>
                  <select
                    value={activeCaseDetails.status}
                    disabled={isAuditor}
                    onChange={e => handleStatusChange(activeCaseDetails.caseId, e.target.value as CaseStatus)}
                    className="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 text-xs text-slate-800 font-semibold focus:outline-none focus:border-blue-500 cursor-pointer disabled:opacity-60"
                  >
                    <option value="OPEN">OPEN</option>
                    <option value="IN_PROGRESS">IN_PROGRESS</option>
                    <option value="ESCALATED">ESCALATED</option>
                    <option value="RESOLVED">RESOLVED</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                  </select>
                </div>

                {/* Assigned Analyst */}
                <div>
                  <label className="text-[11px] text-slate-500 font-semibold uppercase block mb-1">
                    Assigned Analyst
                  </label>
                  <select
                    value={activeCaseDetails.assignedAnalystId || ''}
                    disabled={isAuditor || assignableAnalysts.length === 0}
                    onChange={e => handleAssignmentChange(activeCaseDetails.caseId, e.target.value)}
                    className="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 text-xs text-slate-800 font-semibold focus:outline-none focus:border-blue-500 cursor-pointer disabled:opacity-60"
                  >
                    <option value="" disabled>
                      {activeCaseDetails.assignedTo || 'Select an Analyst...'}
                    </option>
                    {assignableAnalysts.map(a => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.role})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-200/60 text-[11px] text-slate-500">
                <div>
                  <span className="block text-slate-400">Last Modified By</span>
                  <span className="font-semibold text-slate-700">
                    {activeCaseDetails.lastUpdatedBy || activeCaseDetails.analyst || 'System'}
                  </span>
                </div>
                <div>
                  <span className="block text-slate-400">Last Updated</span>
                  <span className="font-mono text-[10px] text-slate-600">
                    {(activeCaseDetails.updatedAt || activeCaseDetails.createdAt).replace('T', ' ').substring(0, 19)}
                  </span>
                </div>
              </div>
            </div>

            {/* Quick Cross-Navigation Links */}
            <div className="space-y-2">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                Direct DFIR Workspace Navigation
              </span>
              <div className="grid grid-cols-3 gap-2">
                <button
                  onClick={() => {
                    onSelectCase(activeCaseDetails.caseId);
                    onNavigate('investigation');
                    setActiveCaseDetails(null);
                  }}
                  className="px-3 py-2 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Investigation</span>
                </button>
                <button
                  onClick={() => {
                    onSelectCase(activeCaseDetails.caseId);
                    onNavigate('ledger');
                    setActiveCaseDetails(null);
                  }}
                  className="px-3 py-2 rounded-lg bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>Evidence Ledger</span>
                </button>
                <button
                  onClick={() => {
                    onSelectCase(activeCaseDetails.caseId);
                    onNavigate('report');
                    setActiveCaseDetails(null);
                  }}
                  className="px-3 py-2 rounded-lg bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <FileCheck2 className="w-3.5 h-3.5" />
                  <span>DFIR Report</span>
                </button>
              </div>
            </div>

            {/* Analyst Notes Section */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wide flex items-center gap-1.5">
                  <MessageSquare className="w-4 h-4 text-blue-600" /> Analyst Operational Notes ({(activeCaseDetails.notes || []).length})
                </h4>
              </div>

              {/* Add Note Input with character counter & max 5000 enforcement */}
              {!isAuditor && (
                <div className="space-y-1.5">
                  <textarea
                    rows={3}
                    maxLength={5000}
                    placeholder="Record detailed analyst observations, containment actions, or threat indicators (up to 5,000 characters)..."
                    value={newNote}
                    onChange={e => setNewNote(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white resize-none"
                  />
                  <div className="flex items-center justify-between text-[11px] text-slate-500">
                    <span>Author: <strong className="text-slate-700">{currentUser?.name || 'Authenticated Analyst'}</strong> (server-derived)</span>
                    <div className="flex items-center gap-2">
                      <span className={newNote.length > 4500 ? 'text-amber-600 font-semibold' : 'text-slate-400'}>
                        {newNote.length} / 5000 chars
                      </span>
                      <button
                        onClick={handleAddNote}
                        disabled={submittingNote || !newNote.trim()}
                        className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs transition-colors cursor-pointer disabled:opacity-50"
                      >
                        {submittingNote ? 'Recording...' : 'Add Note'}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Notes List */}
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {activeCaseDetails.notes && activeCaseDetails.notes.length > 0 ? (
                  activeCaseDetails.notes.map(n => (
                    <div
                      key={n.id}
                      className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-1"
                    >
                      <div className="flex justify-between text-[11px] text-slate-500">
                        <span className="font-bold text-blue-700">{n.author}</span>
                        <span className="font-mono text-[10px]">{n.timestamp.replace('T', ' ').substring(0, 19)}</span>
                      </div>
                      <p className="text-slate-800 text-xs whitespace-pre-wrap leading-relaxed">{n.content}</p>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-slate-400 italic p-4 text-center border border-dashed border-slate-200 rounded-xl">
                    No notes recorded yet. Add the first analyst entry above.
                  </div>
                )}
              </div>
            </div>

            {/* Investigation History Audit Trail */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wide flex items-center gap-1.5">
                <History className="w-4 h-4 text-purple-600" /> Case Operational Audit History ({(activeCaseDetails.history || []).length})
              </h4>

              <div className="space-y-2 max-h-52 overflow-y-auto">
                {activeCaseDetails.history && activeCaseDetails.history.length > 0 ? (
                  activeCaseDetails.history.map(h => (
                    <div
                      key={h.id}
                      className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs flex items-start justify-between gap-3"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-purple-700">{h.action}</span>
                          {h.previousValue && h.newValue && (
                            <span className="text-[10px] font-mono bg-purple-50 text-purple-600 px-1.5 py-0.2 rounded border border-purple-200">
                              {h.previousValue} → {h.newValue}
                            </span>
                          )}
                        </div>
                        <span className="text-slate-600 text-xs block">{h.details}</span>
                      </div>
                      <div className="text-right text-[11px] text-slate-500 flex-shrink-0 font-medium">
                        <div className="text-slate-700 font-semibold">{h.actor}</div>
                        <div className="font-mono text-[10px] text-slate-400">
                          {h.timestamp.replace('T', ' ').substring(0, 19)}
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-slate-400 italic p-4 text-center border border-dashed border-slate-200 rounded-xl">
                    Initial case creation logged in ledger.
                  </div>
                )}
              </div>
            </div>

            {/* Bottom Close Bar */}
            <div className="pt-4 border-t border-slate-100 flex justify-end">
              <button
                onClick={() => {
                  setActiveCaseDetails(null);
                  setActionError(null);
                }}
                className="px-4 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-colors cursor-pointer"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
