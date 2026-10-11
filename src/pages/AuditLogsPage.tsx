import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Clock,
  User,
  Key,
  ShieldAlert,
} from 'lucide-react';
import { SecurityAuditLog, fetchAuditLogs } from '../services/api';

interface AuditLogsPageProps {
  currentUserRole?: string;
  onSwitchToAdmin?: () => void;
}

export const AuditLogsPage: React.FC<AuditLogsPageProps> = ({ currentUserRole, onSwitchToAdmin }) => {
  const [logs, setLogs] = useState<SecurityAuditLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'SUCCESS' | 'DENIED' | 'FAILURE'>('ALL');

  const loadLogs = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchAuditLogs();
      setLogs(data);
    } catch (err: any) {
      console.warn('Audit logs fetch notice:', err?.message || err);
      setError(err?.message || 'Access Denied: Authentication or privileges required to inspect SOC audit trails.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, []);

  const filteredLogs = logs.filter(log => {
    const matchesSearch =
      searchTerm === '' ||
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (log.actorEmail && log.actorEmail.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (log.details && log.details.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (log.resourceId && log.resourceId.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus = statusFilter === 'ALL' || log.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const deniedCount = logs.filter(l => l.status === 'DENIED').length;
  const failureCount = logs.filter(l => l.status === 'FAILURE').length;
  const successCount = logs.filter(l => l.status === 'SUCCESS').length;

  return (
    <div id="soc-audit-logs-view" className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center flex-shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-900">
                  Security Governance & Immutable Audit Trail
                </h2>
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                  RBAC PROTECTED // {currentUserRole ? `${currentUserRole} ACCESS` : 'SECURE AUDIT TRAIL'}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Tamper-evident log of authentication decisions, cross-case access attempts, role authorizations, and evidence actions.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={loadLogs}
              disabled={loading}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer shadow-xs"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh Trail</span>
            </button>
          </div>
        </div>

        {/* Telemetry Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
            <div className="text-[11px] text-slate-500 font-semibold uppercase tracking-wider">Total Recorded Events</div>
            <div className="text-xl font-bold text-slate-900 mt-1 font-mono">{logs.length}</div>
          </div>
          <div className="p-4 bg-emerald-50/50 border border-emerald-200 rounded-xl">
            <div className="text-[11px] text-emerald-700 font-semibold uppercase tracking-wider">Authorized Executions</div>
            <div className="text-xl font-bold text-emerald-700 mt-1 font-mono">{successCount}</div>
          </div>
          <div className="p-4 bg-amber-50/50 border border-amber-200 rounded-xl">
            <div className="text-[11px] text-amber-700 font-semibold uppercase tracking-wider">Access Violations Blocked</div>
            <div className="text-xl font-bold text-amber-700 mt-1 font-mono">{deniedCount}</div>
          </div>
          <div className="p-4 bg-red-50/50 border border-red-200 rounded-xl">
            <div className="text-[11px] text-red-700 font-semibold uppercase tracking-wider">Authentication Failures</div>
            <div className="text-xl font-bold text-red-700 mt-1 font-mono">{failureCount}</div>
          </div>
        </div>
      </div>

      {/* Error / Unauthorized Warning */}
      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 flex items-start gap-3 text-red-900 shadow-sm">
          <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div className="text-xs space-y-1">
            <div className="font-bold text-red-800 uppercase tracking-wide">Authorization Notice:</div>
            <div className="text-red-700">{error}</div>
            <div className="text-[11px] text-slate-500 pt-1 font-medium flex items-center gap-1.5 flex-wrap">
              <span>Tip: Switch profiles using the operator badge or</span>
              {onSwitchToAdmin && (
                <button
                  onClick={onSwitchToAdmin}
                  className="text-blue-700 underline font-semibold hover:text-blue-800 cursor-pointer"
                >
                  open the Identity & RBAC switcher
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white border border-slate-200 p-4 rounded-xl shadow-sm">
        <div className="flex items-center gap-2.5 flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search action, actor email, details, or case ID..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3.5 py-2 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white transition-colors"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-xs text-slate-500 font-medium">Filter:</span>
          {(['ALL', 'SUCCESS', 'DENIED', 'FAILURE'] as const).map(status => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase transition-colors cursor-pointer ${
                statusFilter === status
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'bg-slate-100 text-slate-600 hover:text-slate-900 hover:bg-slate-200'
              }`}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 uppercase text-[11px] font-semibold tracking-wider">
              <tr>
                <th className="py-3.5 px-4 font-mono">Timestamp (UTC)</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Security Action</th>
                <th className="py-3.5 px-4">Actor & Role</th>
                <th className="py-3.5 px-4">Target Resource</th>
                <th className="py-3.5 px-4">Audit Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    {loading ? 'Retrieving cryptographic audit trail...' : 'No audit events matching criteria.'}
                  </td>
                </tr>
              ) : (
                filteredLogs.map(log => {
                  const isDenied = log.status === 'DENIED';
                  const isFailure = log.status === 'FAILURE';
                  const isSuccess = log.status === 'SUCCESS';

                  return (
                    <tr
                      key={log.id}
                      className={`hover:bg-slate-50/80 transition-colors ${
                        isDenied ? 'bg-amber-50/40' : isFailure ? 'bg-red-50/40' : ''
                      }`}
                    >
                      <td className="py-3.5 px-4 whitespace-nowrap text-xs text-slate-500 font-mono">
                        {log.timestamp.replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                            isSuccess
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : isDenied
                              ? 'bg-amber-50 text-amber-700 border border-amber-200'
                              : 'bg-red-50 text-red-700 border border-red-200'
                          }`}
                        >
                          {isSuccess && <CheckCircle2 className="w-3.5 h-3.5" />}
                          {isDenied && <ShieldAlert className="w-3.5 h-3.5" />}
                          {isFailure && <XCircle className="w-3.5 h-3.5" />}
                          {log.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-bold text-slate-900 font-mono">
                        <span className="text-blue-700">{log.action}</span>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="flex flex-col">
                          <span className="text-slate-900 font-semibold text-xs">{log.actorEmail || 'Anonymous'}</span>
                          <span className="text-[11px] text-slate-500 font-mono">
                            {log.actorRole || 'UNKNOWN'} {log.ip ? `• ${log.ip}` : ''}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {log.resourceId ? (
                          <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 text-slate-700 text-[11px] font-mono font-medium">
                            {log.resourceId}
                          </span>
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-slate-600 text-xs max-w-md truncate" title={log.details}>
                        {log.details || '—'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
