import React, { useState, useEffect, useRef } from 'react';
import {
  Layers,
  UploadCloud,
  Search,
  Filter,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ArrowRight,
  ExternalLink,
  RefreshCw,
  Globe,
  Server,
  Hash,
  FileCode,
  Play,
  Sparkles,
  Building,
  User,
  Mail,
  Ban,
  ChevronRight,
  X,
  Clock,
  Radio,
  Copy,
  Check,
} from 'lucide-react';
import {
  BulkTriageSession,
  BulkTriageItem,
  BulkCampaignCluster,
  BulkIndicatorItem,
  MailType,
  RiskLevel,
} from '../types/forensics';
import {
  loadBulkTriageDemo,
  createBulkTriageSession,
  uploadBulkTriageBatch,
  fetchBulkTriageStatus,
  cancelBulkTriage,
  fetchBulkTriageEmails,
  fetchBulkTriageEmailDetail,
  fetchBulkTriageCampaigns,
  fetchBulkTriageIndicators,
  promoteBulkTriageItem,
  requestBulkTriageAiDeepDive,
} from '../services/api';

interface BulkTriagePageProps {
  onSelectCase?: (caseId: string) => void;
  onNavigate?: (page: any) => void;
  onShowNotification?: (msg: string, type?: 'success' | 'info' | 'error') => void;
}

export const BulkTriagePage: React.FC<BulkTriagePageProps> = ({
  onSelectCase,
  onNavigate,
  onShowNotification,
}) => {
  const [session, setSession] = useState<BulkTriageSession | null>(null);
  const [emails, setEmails] = useState<BulkTriageItem[]>([]);
  const [campaigns, setCampaigns] = useState<BulkCampaignCluster[]>([]);
  const [indicators, setIndicators] = useState<BulkIndicatorItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingDemo, setLoadingDemo] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  // Pagination & Filtering
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [mailTypeFilter, setMailTypeFilter] = useState<string>('ALL');
  const [riskLevelFilter, setRiskLevelFilter] = useState<string>('ALL');
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>('ALL');
  const [activeViewTab, setActiveViewTab] = useState<'queue' | 'campaigns' | 'indicators'>('queue');

  // Drawer for inspecting email detail
  const [activeItem, setActiveItem] = useState<BulkTriageItem | null>(null);
  const [activeRawSource, setActiveRawSource] = useState<string | null>(null);
  const [activeDetailTab, setActiveDetailTab] = useState<'overview' | 'raw' | 'ai'>('overview');
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [promotingId, setPromotingId] = useState<string | null>(null);
  const [runningAiId, setRunningAiId] = useState<string | null>(null);
  const [copiedRaw, setCopiedRaw] = useState(false);

  // File Upload Reference
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const zipInputRef = useRef<HTMLInputElement | null>(null);

  const notify = (msg: string, type: 'success' | 'info' | 'error' = 'info') => {
    if (onShowNotification) onShowNotification(msg, type);
  };

  // Poll active session progress if processing
  useEffect(() => {
    if (!session || session.status !== 'PROCESSING') return;

    const interval = setInterval(async () => {
      try {
        const updated = await fetchBulkTriageStatus(session.sessionId);
        setSession(updated);
        if (updated.status === 'COMPLETED' || updated.status === 'CANCELLED') {
          loadSessionData(updated.sessionId);
        }
      } catch (err) {
        console.warn('Status poll warning:', err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [session?.status, session?.sessionId]);

  // Load paginated emails when filters or page change
  useEffect(() => {
    if (!session) return;
    loadEmails(session.sessionId, page);
  }, [session?.sessionId, page, mailTypeFilter, riskLevelFilter, selectedCampaignId, searchQuery]);

  const loadEmails = async (sessionId: string, targetPage: number) => {
    setLoading(true);
    try {
      const data = await fetchBulkTriageEmails(sessionId, {
        page: targetPage,
        limit: 50,
        mailType: mailTypeFilter,
        riskLevel: riskLevelFilter,
        campaignId: selectedCampaignId,
        search: searchQuery,
      });
      setEmails(data.items);
      setTotalCount(data.totalCount);
      setTotalPages(data.totalPages);
      setPage(data.page);
    } catch (err: any) {
      notify(err.message || 'Failed to load triaged emails', 'error');
    } finally {
      setLoading(false);
    }
  };

  const loadSessionData = async (sessionId: string) => {
    try {
      const [campRes, indRes] = await Promise.all([
        fetchBulkTriageCampaigns(sessionId),
        fetchBulkTriageIndicators(sessionId),
      ]);
      setCampaigns(campRes.campaigns);
      setIndicators(indRes.indicators);
      loadEmails(sessionId, 1);
    } catch (err: any) {
      console.error('Failed to load session clusters/indicators:', err);
    }
  };

  // 1-Click Load 6,000+ Simulated Demo Batch
  const handleLoadDemo = async () => {
    setLoadingDemo(true);
    try {
      const s = await loadBulkTriageDemo();
      setSession(s);
      notify(`Loaded 6,250 simulated triage emails across ${s.metrics.campaignClustersCount} coordinated campaigns!`, 'success');
      await loadSessionData(s.sessionId);
    } catch (err: any) {
      notify(err.message || 'Failed to load demo batch', 'error');
    } finally {
      setLoadingDemo(false);
    }
  };

  // Upload EML Files
  const handleUploadFiles = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setLoading(true);
    try {
      let activeSessionId = session?.sessionId;
      if (!activeSessionId || session.status === 'COMPLETED' || session.status === 'CANCELLED') {
        const newSession = await createBulkTriageSession();
        activeSessionId = newSession.sessionId;
        setSession(newSession);
      }

      const fileEntries: Array<{ filename: string; content: string }> = [];
      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const text = await file.text();
        fileEntries.push({ filename: file.name, content: text });
      }

      await uploadBulkTriageBatch(activeSessionId, fileEntries);
      notify(`Queued ${fileEntries.length} EMLs for controlled parallel triage.`, 'info');
      const updated = await fetchBulkTriageStatus(activeSessionId);
      setSession(updated);
    } catch (err: any) {
      notify(err.message || 'Batch upload failed', 'error');
    } finally {
      setLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // Cancel Ingestion
  const handleCancelSession = async () => {
    if (!session) return;
    setCancelling(true);
    try {
      await cancelBulkTriage(session.sessionId);
      notify('Triage queue processing cancelled by investigator.', 'info');
      const updated = await fetchBulkTriageStatus(session.sessionId);
      setSession(updated);
    } catch (err: any) {
      notify(err.message || 'Failed to cancel session', 'error');
    } finally {
      setCancelling(false);
    }
  };

  // Inspect Single Email Detail
  const handleInspectEmail = async (item: BulkTriageItem) => {
    setActiveItem(item);
    setActiveDetailTab('overview');
    setLoadingDetail(true);
    try {
      if (session) {
        const detail = await fetchBulkTriageEmailDetail(session.sessionId, item.triageId);
        setActiveItem(detail.item || item);
        setActiveRawSource(detail.rawSource || null);
      }
    } catch (err) {
      console.warn('Failed to load full MIME detail:', err);
    } finally {
      setLoadingDetail(false);
    }
  };

  // Promote Item to Full Formal Investigation Case
  const handlePromoteItem = async (triageId: string) => {
    if (!session) return;
    setPromotingId(triageId);
    try {
      const res = await promoteBulkTriageItem(session.sessionId, triageId);
      notify(`Promoted to formal Case ${res.caseId} (Sealed in Evidence Ledger Block #${res.payload.evidenceBlock.blockIndex})`, 'success');

      // Update local state
      setEmails(prev =>
        prev.map(i => (i.triageId === triageId ? { ...i, isPromoted: true, promotedCaseId: res.caseId } : i))
      );
      if (activeItem?.triageId === triageId) {
        setActiveItem(prev => (prev ? { ...prev, isPromoted: true, promotedCaseId: res.caseId } : null));
      }

      // Prompt to navigate or open case
      if (onSelectCase) {
        onSelectCase(res.caseId);
      }
    } catch (err: any) {
      notify(err.message || 'Promotion failed', 'error');
    } finally {
      setPromotingId(null);
    }
  };

  // Run On-Demand Gemini Deep-Dive
  const handleRunAiDeepDive = async (triageId: string) => {
    if (!session) return;
    setRunningAiId(triageId);
    try {
      const res = await requestBulkTriageAiDeepDive(session.sessionId, triageId);
      notify('Gemini 3.8 Flash deep analysis completed.', 'success');
      setActiveItem(res.item);
      setEmails(prev => prev.map(i => (i.triageId === triageId ? res.item : i)));
      setActiveDetailTab('ai');
    } catch (err: any) {
      notify(err.message || 'AI deep-dive failed or quota cooling down', 'error');
    } finally {
      setRunningAiId(null);
    }
  };

  // Helper Badge Renderers
  const getMailTypeBadge = (mailType: MailType) => {
    switch (mailType) {
      case 'COMPANY':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-blue-50 text-blue-700 border border-blue-200">
            <Building className="w-3 h-3 text-blue-600" />
            COMPANY
          </span>
        );
      case 'PERSONAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <User className="w-3 h-3 text-emerald-600" />
            PERSONAL
          </span>
        );
      case 'SPAM':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-amber-50 text-amber-800 border border-amber-200">
            <Ban className="w-3 h-3 text-amber-600" />
            SPAM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-slate-100 text-slate-700 border border-slate-200">
            <HelpCircle className="w-3 h-3 text-slate-400" />
            UNKNOWN
          </span>
        );
    }
  };

  const getRiskLevelBadge = (level: RiskLevel, score: number) => {
    switch (level) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[11px] font-bold bg-red-100 text-red-800 border border-red-200">
            <ShieldAlert className="w-3 h-3 text-red-700" />
            CRITICAL ({score})
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[11px] font-bold bg-amber-100 text-amber-800 border border-amber-200">
            <AlertTriangle className="w-3 h-3 text-amber-700" />
            HIGH ({score})
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[11px] font-bold bg-blue-100 text-blue-800 border border-blue-200">
            MEDIUM ({score})
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[11px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
            LOW ({score})
          </span>
        );
    }
  };

  const metrics = session?.metrics || {
    totalEmails: 0,
    mailTypes: { PERSONAL: 0, COMPANY: 0, SPAM: 0, UNKNOWN: 0 },
    riskLevels: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    campaignClustersCount: 0,
    uniquePublicIpsCount: 0,
    uniqueDomainsCount: 0,
    promotedCount: 0,
  };

  return (
    <div id="bulk-triage-view" className="space-y-6 pb-16 font-sans">
      {/* Demo / Mode Notice Banner */}
      {session?.isDemo && (
        <div className="px-4 py-2.5 rounded-xl bg-amber-500/10 border border-amber-300 text-amber-900 text-xs flex items-center justify-between shadow-xs">
          <div className="flex items-center gap-2 font-semibold">
            <Radio className="w-4 h-4 text-amber-600 animate-pulse" />
            <span>
              <strong>DEMO / SIMULATED DATA:</strong> 6,250 synthetic forensic EML models populated with 5 coordinated attack campaigns and 173 deduplicated public IPs.
            </span>
          </div>
          <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-amber-200/80 text-amber-900 font-bold">
            PROTOTYPE VALIDATION MODE
          </span>
        </div>
      )}

      {/* Top Banner & Control Deck */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-xs">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900">
                Large-Scale Bulk Forensic Triage & Campaign Correlation
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                High-throughput streaming ingestion, RFC-822 mail-type classification, indicator deduplication, and explainable clustering (6,000+ Target)
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <input
            type="file"
            multiple
            accept=".eml,message/rfc822"
            ref={fileInputRef}
            onChange={handleUploadFiles}
            className="hidden"
          />

          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={loading || session?.status === 'PROCESSING'}
            className="px-3.5 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-300 shadow-xs disabled:opacity-50"
          >
            <UploadCloud className="w-4 h-4 text-slate-500" />
            <span>Upload Multiple EMLs</span>
          </button>

          <button
            onClick={handleLoadDemo}
            disabled={loadingDemo || session?.status === 'PROCESSING'}
            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-xs disabled:opacity-50"
          >
            {loadingDemo ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Generating 6,000+ Batch...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Load 6,000+ Demo Batch</span>
              </>
            )}
          </button>

          {session?.status === 'PROCESSING' && (
            <button
              onClick={handleCancelSession}
              disabled={cancelling}
              className="px-3 py-2 rounded-lg bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <XCircle className="w-4 h-4 text-red-600" />
              <span>{cancelling ? 'Cancelling...' : 'Cancel Triage'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Processing Progress Bar (when active) */}
      {session?.status === 'PROCESSING' && (
        <div className="bg-white border border-blue-200 rounded-xl p-4 shadow-xs space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-700 flex items-center gap-1.5">
              <RefreshCw className="w-3.5 h-3.5 text-blue-600 animate-spin" />
              Processing Ingestion Queue: {session.processedCount} of {session.totalCount} emails triaged...
            </span>
            <span className="font-mono font-bold text-blue-700">{session.progressPercent}%</span>
          </div>
          <div className="w-full h-2 rounded-full bg-slate-100 overflow-hidden">
            <div
              className="h-full bg-blue-600 transition-all duration-300 ease-out"
              style={{ width: `${session.progressPercent}%` }}
            />
          </div>
        </div>
      )}

      {/* Primary Telemetry Metrics Deck (14 required metrics) */}
      {session && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
          {/* Total Ingested */}
          <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs">
            <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider mb-1">
              Total Ingested
            </span>
            <span className="font-mono text-xl font-bold text-slate-900">{metrics.totalEmails.toLocaleString()}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">MIME byte streams</span>
          </div>

          {/* Company Mail */}
          <div className="bg-white border border-blue-100 rounded-xl p-3.5 shadow-xs">
            <span className="text-blue-600 block text-[10px] uppercase font-bold tracking-wider mb-1">
              Company Mail
            </span>
            <span className="font-mono text-xl font-bold text-blue-700">{metrics.mailTypes.COMPANY.toLocaleString()}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Enterprise traffic</span>
          </div>

          {/* Personal Mail */}
          <div className="bg-white border border-emerald-100 rounded-xl p-3.5 shadow-xs">
            <span className="text-emerald-600 block text-[10px] uppercase font-bold tracking-wider mb-1">
              Personal Mail
            </span>
            <span className="font-mono text-xl font-bold text-emerald-700">{metrics.mailTypes.PERSONAL.toLocaleString()}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">1-to-1 conversations</span>
          </div>

          {/* Spam / Marketing */}
          <div className="bg-white border border-amber-100 rounded-xl p-3.5 shadow-xs">
            <span className="text-amber-600 block text-[10px] uppercase font-bold tracking-wider mb-1">
              Spam / Bulk
            </span>
            <span className="font-mono text-xl font-bold text-amber-700">{metrics.mailTypes.SPAM.toLocaleString()}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Marketing & newsletters</span>
          </div>

          {/* Unknown / Anomalous */}
          <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs">
            <span className="text-slate-500 block text-[10px] uppercase font-bold tracking-wider mb-1">
              Unknown Mail
            </span>
            <span className="font-mono text-xl font-bold text-slate-700">{metrics.mailTypes.UNKNOWN.toLocaleString()}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Truncated / Ambiguous</span>
          </div>

          {/* Coordinated Campaigns */}
          <div className="bg-white border border-purple-100 rounded-xl p-3.5 shadow-xs">
            <span className="text-purple-600 block text-[10px] uppercase font-bold tracking-wider mb-1">
              Campaigns
            </span>
            <span className="font-mono text-xl font-bold text-purple-700">{metrics.campaignClustersCount}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Correlated clusters</span>
          </div>

          {/* Deduplicated IPs / Domains */}
          <div className="bg-white border border-indigo-100 rounded-xl p-3.5 shadow-xs">
            <span className="text-indigo-600 block text-[10px] uppercase font-bold tracking-wider mb-1">
              Unique Public IPs
            </span>
            <span className="font-mono text-xl font-bold text-indigo-700">{metrics.uniquePublicIpsCount}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">{metrics.uniqueDomainsCount} unique domains</span>
          </div>
        </div>
      )}

      {/* Severity Distribution Strip */}
      {session && (
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-700">Threat Severity Spectrum:</span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-red-50 border border-red-200">
              <span className="w-2 h-2 rounded-full bg-red-600" />
              <span className="font-bold text-red-900">Critical:</span>
              <span className="font-mono font-bold text-red-700">{metrics.riskLevels.CRITICAL.toLocaleString()}</span>
            </div>

            <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-amber-50 border border-amber-200">
              <span className="w-2 h-2 rounded-full bg-amber-600" />
              <span className="font-bold text-amber-900">High:</span>
              <span className="font-mono font-bold text-amber-700">{metrics.riskLevels.HIGH.toLocaleString()}</span>
            </div>

            <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-blue-50 border border-blue-200">
              <span className="w-2 h-2 rounded-full bg-blue-600" />
              <span className="font-bold text-blue-900">Medium (Elevated):</span>
              <span className="font-mono font-bold text-blue-700">{metrics.riskLevels.MEDIUM.toLocaleString()}</span>
            </div>

            <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-emerald-50 border border-emerald-200">
              <span className="w-2 h-2 rounded-full bg-emerald-600" />
              <span className="font-bold text-emerald-900">Low (Benign):</span>
              <span className="font-mono font-bold text-emerald-700">{metrics.riskLevels.LOW.toLocaleString()}</span>
            </div>
          </div>
        </div>
      )}

      {/* Sub-view Navigation Tabs */}
      {session && (
        <div className="flex items-center justify-between border-b border-slate-200 pb-2">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveViewTab('queue')}
              className={`px-3.5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2 ${
                activeViewTab === 'queue'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              <span>Priority Investigation Queue ({totalCount.toLocaleString()})</span>
            </button>

            <button
              onClick={() => setActiveViewTab('campaigns')}
              className={`px-3.5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2 ${
                activeViewTab === 'campaigns'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Correlated Campaigns ({campaigns.length})</span>
            </button>

            <button
              onClick={() => setActiveViewTab('indicators')}
              className={`px-3.5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2 ${
                activeViewTab === 'indicators'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Hash className="w-4 h-4" />
              <span>Deduplicated IOCs ({indicators.length})</span>
            </button>
          </div>

          <span className="text-xs text-slate-500 font-medium">
            Session ID: <span className="font-mono text-slate-700 font-semibold">{session.sessionId}</span>
          </span>
        </div>
      )}

      {/* Empty State before Loading anything */}
      {!session && (
        <div className="p-12 text-center bg-white border border-slate-200 rounded-xl shadow-xs space-y-4">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-blue-50 border border-blue-200 text-blue-600 flex items-center justify-center">
            <Layers className="w-8 h-8" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900">No Active Bulk Forensic Session</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto leading-relaxed">
              Upload multiple raw EML message files for bounded batch analysis, or load the deterministic 6,000+ demonstration batch to inspect cross-tenant campaigns and mail types.
            </p>
          </div>
          <div className="pt-2 flex flex-wrap items-center justify-center gap-3">
            <button
              onClick={handleLoadDemo}
              disabled={loadingDemo}
              className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-xs"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>Load 6,000+ Simulated Demo Batch</span>
            </button>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="px-4 py-2.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-300"
            >
              <UploadCloud className="w-4 h-4 text-slate-500" />
              <span>Upload EML Archive</span>
            </button>
          </div>
        </div>
      )}

      {/* VIEW 1: Priority Investigation Queue */}
      {session && activeViewTab === 'queue' && (
        <div className="space-y-4">
          {/* Filter and Search Bar */}
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs flex flex-wrap items-center justify-between gap-3">
            {/* Search Input */}
            <div className="relative flex-1 min-w-[260px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search triage queue by subject, sender, IP, domain, or campaign..."
                value={searchQuery}
                onChange={e => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                className="w-full pl-9 pr-3 py-2 text-xs border border-slate-200 rounded-lg bg-slate-50 focus:bg-white focus:outline-hidden focus:ring-1 focus:ring-blue-500 font-sans"
              />
            </div>

            {/* Filter Pills */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              {/* Mail Type Filter */}
              <select
                value={mailTypeFilter}
                onChange={e => {
                  setMailTypeFilter(e.target.value);
                  setPage(1);
                }}
                className="px-2.5 py-1.5 rounded-lg bg-slate-50 border border-slate-200 font-semibold text-slate-700 cursor-pointer focus:outline-hidden"
              >
                <option value="ALL">All Mail Types</option>
                <option value="COMPANY">Company Only</option>
                <option value="PERSONAL">Personal Only</option>
                <option value="SPAM">Spam / Bulk</option>
                <option value="UNKNOWN">Unknown Only</option>
              </select>

              {/* Risk Level Filter */}
              <select
                value={riskLevelFilter}
                onChange={e => {
                  setRiskLevelFilter(e.target.value);
                  setPage(1);
                }}
                className="px-2.5 py-1.5 rounded-lg bg-slate-50 border border-slate-200 font-semibold text-slate-700 cursor-pointer focus:outline-hidden"
              >
                <option value="ALL">All Threat Levels</option>
                <option value="CRITICAL">Critical Threats Only</option>
                <option value="HIGH">High Threats Only</option>
                <option value="MEDIUM">Medium / Elevated Only</option>
                <option value="LOW">Low / Benign Only</option>
              </select>

              {/* Campaign Filter */}
              {campaigns.length > 0 && (
                <select
                  value={selectedCampaignId}
                  onChange={e => {
                    setSelectedCampaignId(e.target.value);
                    setPage(1);
                  }}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-50 border border-slate-200 font-semibold text-slate-700 cursor-pointer focus:outline-hidden max-w-[200px] truncate"
                >
                  <option value="ALL">All Campaigns ({campaigns.length})</option>
                  {campaigns.map(c => (
                    <option key={c.campaignId} value={c.campaignId}>
                      {c.campaignCode} - {c.campaignName.slice(0, 25)}...
                    </option>
                  ))}
                </select>
              )}
            </div>
          </div>

          {/* Queue Data Table */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="p-4 border-b border-slate-100 flex items-center justify-between">
              <span className="text-xs font-bold text-slate-800">
                Displaying {emails.length} of {totalCount.toLocaleString()} Triaged Messages (Page {page} of {totalPages})
              </span>
              <span className="text-[11px] text-slate-500">
                Sorted by Explainable Risk Score (Highest Threat First)
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase font-semibold text-[10px] tracking-wider">
                    <th className="p-3">Mail Type</th>
                    <th className="p-3">Threat Severity</th>
                    <th className="p-3">Subject & Sender</th>
                    <th className="p-3">Originating Infrastructure</th>
                    <th className="p-3">Campaign Cluster</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {emails.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-8 text-center text-slate-500">
                        {loading ? 'Loading triaged messages...' : 'No triaged emails match the selected filters.'}
                      </td>
                    </tr>
                  ) : (
                    emails.map(item => (
                      <tr
                        key={item.triageId}
                        onClick={() => handleInspectEmail(item)}
                        className={`transition-colors cursor-pointer hover:bg-slate-50/80 ${
                          activeItem?.triageId === item.triageId ? 'bg-blue-50/40' : ''
                        }`}
                      >
                        {/* Mail Type */}
                        <td className="p-3 whitespace-nowrap">
                          {getMailTypeBadge(item.mailClassification.mailType)}
                        </td>

                        {/* Threat Severity */}
                        <td className="p-3 whitespace-nowrap">
                          {getRiskLevelBadge(item.riskLevel, item.riskScore)}
                        </td>

                        {/* Subject & Sender */}
                        <td className="p-3 max-w-xs sm:max-w-md">
                          <div className="font-bold text-slate-900 truncate">{item.emailSubject}</div>
                          <div className="text-[11px] text-slate-500 truncate flex items-center gap-1.5 mt-0.5">
                            <span className="font-mono">{item.fromAddress}</span>
                            {item.hasAttachments && (
                              <span className="px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 text-[10px] font-semibold">
                                📎 {item.attachmentNames.length} att
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Origin Infrastructure */}
                        <td className="p-3 whitespace-nowrap">
                          <div className="font-mono text-blue-700 font-bold">{item.originatingIp || 'Internal / N/A'}</div>
                          <div className="text-[10px] text-slate-500 truncate max-w-[140px]">
                            {item.originatingCountry ? `${item.originatingCountry} (${item.originatingAsn || 'AS-UNKNOWN'})` : 'Routable Transit'}
                          </div>
                        </td>

                        {/* Campaign Cluster */}
                        <td className="p-3 whitespace-nowrap">
                          {item.campaignCode ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-purple-50 text-purple-800 border border-purple-200">
                              {item.campaignCode}
                            </span>
                          ) : (
                            <span className="text-slate-400 text-[11px] italic">Isolated Activity</span>
                          )}
                        </td>

                        {/* Actions */}
                        <td className="p-3 whitespace-nowrap text-right" onClick={e => e.stopPropagation()}>
                          {item.isPromoted ? (
                            <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-700 bg-emerald-50 px-2 py-1 rounded border border-emerald-200">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                              Case {item.promotedCaseId}
                            </span>
                          ) : (
                            <button
                              onClick={() => handlePromoteItem(item.triageId)}
                              disabled={promotingId === item.triageId}
                              className="px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-[11px] font-bold transition-colors cursor-pointer shadow-xs disabled:opacity-50"
                            >
                              {promotingId === item.triageId ? 'Promoting...' : 'Promote to Case'}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="p-4 border-t border-slate-100 flex items-center justify-between text-xs">
                <span className="text-slate-500">
                  Page {page} of {totalPages}
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page <= 1}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold disabled:opacity-50 cursor-pointer"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page >= totalPages}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold disabled:opacity-50 cursor-pointer"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* VIEW 2: Correlated Campaigns Overview */}
      {session && activeViewTab === 'campaigns' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {campaigns.map(camp => (
            <div key={camp.campaignId} className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-1 rounded-lg bg-purple-50 text-purple-800 border border-purple-200 font-mono text-xs font-bold">
                    {camp.campaignCode}
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    camp.threatLevel === 'CRITICAL' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800'
                  }`}>
                    {camp.threatLevel}
                  </span>
                </div>
                <span className="text-xs font-bold text-slate-800 bg-slate-100 px-2.5 py-1 rounded-full">
                  {camp.totalEmails.toLocaleString()} emails in cluster
                </span>
              </div>

              <div>
                <h4 className="text-sm font-bold text-slate-900">{camp.campaignName}</h4>
                <div className="text-xs text-purple-700 font-semibold mt-0.5">{camp.attackTechnique}</div>
              </div>

              {/* Rationale & Indicators */}
              <div className="space-y-1.5 text-xs text-slate-600 bg-slate-50 p-3 rounded-lg border border-slate-200">
                <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
                  Cluster Forensic Rationale
                </span>
                {camp.clusterRationale.map((r, i) => (
                  <div key={i} className="text-[11px] leading-relaxed">
                    • {r}
                  </div>
                ))}
              </div>

              <div className="text-xs space-y-1">
                <div className="text-slate-500 font-medium">Sample Lure Subjects:</div>
                <div className="text-slate-800 italic text-[11px] space-y-0.5">
                  {camp.sampleSubjects.slice(0, 2).map((s, i) => (
                    <div key={i} className="truncate">"{s}"</div>
                  ))}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
                <span className="text-[11px] text-slate-500">
                  Infrastructure: <span className="font-mono text-slate-800 font-semibold">{camp.originatingIps.join(', ') || 'Various'}</span>
                </span>
                <button
                  onClick={() => {
                    setSelectedCampaignId(camp.campaignId);
                    setActiveViewTab('queue');
                  }}
                  className="text-xs text-blue-600 hover:text-blue-800 font-bold flex items-center gap-1 cursor-pointer"
                >
                  <span>Filter Queue to this Campaign</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* VIEW 3: Deduplicated Indicators Registry */}
      {session && activeViewTab === 'indicators' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
          <div className="p-4 border-b border-slate-100 flex items-center justify-between">
            <span className="text-xs font-bold text-slate-900">
              Deduplicated Infrastructure & Threat Indicators ({indicators.length} unique nodes across {metrics.totalEmails.toLocaleString()} emails)
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase font-semibold text-[10px] tracking-wider">
                  <th className="p-3">Type</th>
                  <th className="p-3">Indicator Value</th>
                  <th className="p-3">Observed Ingestion Frequency</th>
                  <th className="p-3">Autonomous System / Location</th>
                  <th className="p-3">Associated Campaigns</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {indicators.slice(0, 100).map((ind, idx) => (
                  <tr key={idx} className="hover:bg-slate-50">
                    <td className="p-3">
                      <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700 uppercase">
                        {ind.type}
                      </span>
                    </td>
                    <td className="p-3 font-mono font-bold text-slate-900">{ind.indicator}</td>
                    <td className="p-3">
                      <span className="font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                        {ind.frequency.toLocaleString()} emails
                      </span>
                    </td>
                    <td className="p-3 text-slate-600">
                      {ind.asn || ind.country ? `${ind.country || ''} (${ind.asn || ''})` : 'Direct Target Domain'}
                    </td>
                    <td className="p-3">
                      {ind.associatedCampaigns.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {ind.associatedCampaigns.map(c => (
                            <span key={c} className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200">
                              {c}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-slate-400 italic">General Mail Stream</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Slide-out Drawer: Email Detail Inspection */}
      {activeItem && (
        <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-white border-l border-slate-200 shadow-2xl z-50 flex flex-col font-sans">
          {/* Drawer Header */}
          <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-xs text-slate-800">{activeItem.triageId}</span>
              {getMailTypeBadge(activeItem.mailClassification.mailType)}
              {getRiskLevelBadge(activeItem.riskLevel, activeItem.riskScore)}
            </div>
            <button
              onClick={() => setActiveItem(null)}
              className="p-1.5 rounded-lg hover:bg-slate-200 text-slate-500 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Drawer Tabs */}
          <div className="flex border-b border-slate-200 px-4 bg-white text-xs">
            <button
              onClick={() => setActiveDetailTab('overview')}
              className={`py-2.5 px-3 font-bold border-b-2 transition-all cursor-pointer ${
                activeDetailTab === 'overview'
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              Forensic Overview
            </button>
            <button
              onClick={() => setActiveDetailTab('raw')}
              className={`py-2.5 px-3 font-bold border-b-2 transition-all cursor-pointer ${
                activeDetailTab === 'raw'
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              Raw MIME Preview
            </button>
            <button
              onClick={() => setActiveDetailTab('ai')}
              className={`py-2.5 px-3 font-bold border-b-2 transition-all cursor-pointer flex items-center gap-1.5 ${
                activeDetailTab === 'ai'
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-600" />
              <span>Gemini AI Deep-Dive</span>
            </button>
          </div>

          {/* Drawer Content Body */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
            {activeDetailTab === 'overview' && (
              <>
                <div>
                  <h3 className="text-sm font-bold text-slate-900">{activeItem.emailSubject}</h3>
                  <div className="text-slate-500 font-mono mt-1">From: {activeItem.fromAddress}</div>
                  <div className="text-slate-500 font-mono">To: {activeItem.toAddresses.join(', ')}</div>
                  <div className="text-slate-400 mt-1">Date: {activeItem.date}</div>
                </div>

                {/* Mail Type Classification Justification */}
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-800 uppercase tracking-wider text-[10px]">
                      Mail-Type Classification Confidence
                    </span>
                    <span className="font-bold text-blue-700">{activeItem.mailClassification.mailTypeConfidence}%</span>
                  </div>
                  <div className="text-slate-600 space-y-1 pt-1 border-t border-slate-200 text-[11px]">
                    {activeItem.mailClassification.mailTypeReasons.map((r, i) => (
                      <div key={i}>• {r}</div>
                    ))}
                  </div>
                </div>

                {/* Threat Scoring Breakdown */}
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-800 uppercase tracking-wider text-[10px]">
                      Deterministic Risk Reasons
                    </span>
                    <span className="font-bold text-red-700">Score: {activeItem.riskScore}/100</span>
                  </div>
                  <div className="text-slate-600 space-y-1 pt-1 border-t border-slate-200 text-[11px]">
                    {activeItem.riskReasons.map((r, i) => (
                      <div key={i}>• {r}</div>
                    ))}
                  </div>
                </div>

                {/* Origin Infrastructure */}
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                  <span className="font-bold text-slate-800 uppercase tracking-wider text-[10px] block mb-1">
                    Observed Originating Relay
                  </span>
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-slate-900">{activeItem.originatingIp || 'Internal / Not Observed'}</span>
                    <span className="text-slate-600">{activeItem.originatingCountry || 'Public Transit'}</span>
                  </div>
                  {activeItem.originatingAsn && (
                    <div className="text-[11px] text-slate-500 font-mono">{activeItem.originatingAsn}</div>
                  )}
                </div>

                {/* Extracted IOCs */}
                {(activeItem.extractedDomains.length > 0 || activeItem.extractedUrls.length > 0) && (
                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                    <span className="font-bold text-slate-800 uppercase tracking-wider text-[10px] block mb-1">
                      Extracted Destination IOCs
                    </span>
                    {activeItem.extractedDomains.map((d, i) => (
                      <div key={i} className="font-mono text-purple-700 font-semibold text-[11px]">
                        Domain: {d}
                      </div>
                    ))}
                    {activeItem.extractedUrls.map((u, i) => (
                      <div key={i} className="font-mono text-blue-700 truncate text-[11px]">
                        URL: {u}
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}

            {activeDetailTab === 'raw' && (
              <div className="bg-slate-900 text-slate-100 rounded-xl p-3 font-mono text-[11px] max-h-[500px] overflow-auto leading-relaxed border border-slate-800">
                <pre className="whitespace-pre-wrap select-text">
                  {activeRawSource || `SHA-256 Digest: ${activeItem.rawSha256}\r\n\r\nSubject: ${activeItem.emailSubject}\r\nFrom: ${activeItem.fromAddress}\r\nDate: ${activeItem.date}`}
                </pre>
              </div>
            )}

            {activeDetailTab === 'ai' && (
              <div className="space-y-3">
                {activeItem.aiDeepAnalysis ? (
                  <div className="space-y-3">
                    <div className="p-3 rounded-xl bg-blue-50 border border-blue-200 text-xs">
                      <span className="font-bold text-blue-900 block mb-1">
                        Gemini 3.8 Flash Analysis Report ({activeItem.aiDeepAnalysis.assessment.classification})
                      </span>
                      <p className="text-slate-700 leading-relaxed">
                        {activeItem.aiDeepAnalysis.assessment.executiveSummary || activeItem.aiDeepAnalysis.assessment.reasons.join('. ')}
                      </p>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-1">
                      <span className="font-bold text-slate-800 uppercase tracking-wider text-[10px] block">
                        Directly Observed Evidence vs AI Inference
                      </span>
                      <div className="space-y-1 pt-1 border-t border-slate-200 text-[11px]">
                        {activeItem.aiDeepAnalysis.assessment.observedEvidence?.slice(0, 3).map((e, i) => (
                          <div key={i} className="text-slate-700 font-semibold">• [Observed] {e}</div>
                        ))}
                        {activeItem.aiDeepAnalysis.assessment.aiInference?.slice(0, 3).map((inf, i) => (
                          <div key={i} className="text-purple-700 italic">• [Inference] {inf}</div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-6 text-center space-y-3 bg-slate-50 rounded-xl border border-slate-200">
                    <Sparkles className="w-8 h-8 text-blue-600 mx-auto" />
                    <div>
                      <h4 className="font-bold text-slate-900">Optional AI Deep Analysis</h4>
                      <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                        Execute on-demand Gemini 3.8 Flash multi-modal reasoning to evaluate complex social engineering and linguistic lures.
                      </p>
                    </div>
                    <button
                      onClick={() => handleRunAiDeepDive(activeItem.triageId)}
                      disabled={runningAiId === activeItem.triageId}
                      className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition-all cursor-pointer shadow-xs disabled:opacity-50"
                    >
                      {runningAiId === activeItem.triageId ? 'Executing Analysis...' : 'Run Gemini 3.8 Flash Deep-Dive'}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Drawer Footer Actions */}
          <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
            {activeItem.isPromoted ? (
              <span className="text-emerald-700 font-bold text-xs flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                Case Registered ({activeItem.promotedCaseId})
              </span>
            ) : (
              <button
                onClick={() => handlePromoteItem(activeItem.triageId)}
                disabled={promotingId === activeItem.triageId}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition-colors cursor-pointer shadow-xs disabled:opacity-50 flex items-center gap-1.5"
              >
                <span>Promote to Formal Investigation</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}

            {activeItem.promotedCaseId && onSelectCase && (
              <button
                onClick={() => {
                  onSelectCase(activeItem.promotedCaseId!);
                  if (onNavigate) onNavigate('investigation');
                }}
                className="text-xs font-bold text-blue-600 hover:text-blue-800 flex items-center gap-1 cursor-pointer"
              >
                <span>Open in Investigation Tab</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
