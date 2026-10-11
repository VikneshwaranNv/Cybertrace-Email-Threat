import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Mail,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Search,
  Filter,
  FileCode,
  Copy,
  Check,
  X,
  Radio,
  Clock,
  User,
  Inbox,
  ArrowRight,
  ChevronRight,
  AlertCircle,
  Hash,
  Paperclip,
  Globe,
  Lock,
  LogOut,
  SlidersHorizontal,
  FolderPlus,
  Network,
  Layers,
  Eye,
  Activity,
  Sparkles,
  HelpCircle,
  Info,
  Terminal,
} from 'lucide-react';
import {
  SafeGmailStatus,
  GmailMessageSummaryItem,
  GmailTriageRecord,
  GmailRawMessagePayload,
  GmailSyncStatusState,
  RiskLevel,
  GmailPromotionResponse,
  GmailCampaignSummary,
  GmailNormalizedIOC,
  IOCReputation,
} from '../types/forensics';
import {
  fetchGmailStatus,
  fetchGmailAuthUrl,
  connectGmailDemo,
  disconnectGmail,
  fetchGmailMessages,
  fetchRawGmailMessage,
  triageGmailMessage,
  triageGmailBatch,
  triggerGmailSync,
  fetchGmailSyncStatus,
  promoteGmailMessage,
  fetchGmailCampaigns,
  fetchGmailCampaignDetail,
  fetchGmailIocs,
} from '../services/api';

interface GmailMonitorPageProps {
  onShowNotification?: (msg: string, type?: 'success' | 'info' | 'error') => void;
  onNavigate?: (pageId: any) => void;
  onSelectCase?: (caseId: string) => void;
}

export const GmailMonitorPage: React.FC<GmailMonitorPageProps> = ({
  onShowNotification,
  onNavigate,
  onSelectCase,
}) => {
  // --- Connection & Sync Status ---
  const [connection, setConnection] = useState<SafeGmailStatus | null>(null);
  const [syncState, setSyncState] = useState<GmailSyncStatusState | null>(null);
  const [messages, setMessages] = useState<GmailMessageSummaryItem[]>([]);
  const [triageMap, setTriageMap] = useState<Record<string, GmailTriageRecord>>({});

  // --- Loading States ---
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [triagingId, setTriagingId] = useState<string | null>(null);
  const [batchTriaging, setBatchTriaging] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);

  // --- Filtering & Search ---
  const [searchQuery, setSearchQuery] = useState('');
  const [filterTriage, setFilterTriage] = useState<'ALL' | 'TRIAGED' | 'UNTRIAGED'>('ALL');
  const [filterRisk, setFilterRisk] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [filterMailType, setFilterMailType] = useState<'ALL' | 'COMPANY' | 'PERSONAL' | 'SPAM' | 'UNKNOWN'>('ALL');

  // --- Slide-out Inspection Drawer ---
  const [activeMessageId, setActiveMessageId] = useState<string | null>(null);
  const [activeRawPayload, setActiveRawPayload] = useState<GmailRawMessagePayload | null>(null);
  const [loadingRaw, setLoadingRaw] = useState(false);
  const [activeDetailTab, setActiveDetailTab] = useState<'overview' | 'raw'>('overview');
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // --- Formal DFIR Case Promotion States ---
  const [promotedMap, setPromotedMap] = useState<Record<string, GmailPromotionResponse>>({});
  const [promotingId, setPromotingId] = useState<string | null>(null);
  const [confirmPromoteId, setConfirmPromoteId] = useState<string | null>(null);

  // --- Threat Intelligence & Campaign Correlation States (Phase 7) ---
  const [campaigns, setCampaigns] = useState<GmailCampaignSummary[]>([]);
  const [campaignIocs, setCampaignIocs] = useState<GmailNormalizedIOC[]>([]);
  const [loadingCampaigns, setLoadingCampaigns] = useState(false);
  const [selectedCampaign, setSelectedCampaign] = useState<GmailCampaignSummary | null>(null);
  const [campaignModalOpen, setCampaignModalOpen] = useState(false);
  const [activeViewTab, setActiveViewTab] = useState<'inbox' | 'campaigns' | 'iocs'>('inbox');
  const [selectedIocFilter, setSelectedIocFilter] = useState<string | null>(null);

  // --- Error State Banner ---
  const [errorBanner, setErrorBanner] = useState<{ message: string; code?: string } | null>(null);
  const [showOauthSetupModal, setShowOauthSetupModal] = useState(false);
  const [connectingDemo, setConnectingDemo] = useState(false);
  const [copiedOauthUri, setCopiedOauthUri] = useState(false);
  const [copiedEnvSnippet, setCopiedEnvSnippet] = useState(false);

  const notify = useCallback(
    (msg: string, type: 'success' | 'info' | 'error' = 'info') => {
      if (onShowNotification) onShowNotification(msg, type);
    },
    [onShowNotification]
  );

  // Load Correlated Campaigns and Enriched IOCs
  const loadCampaigns = useCallback(async () => {
    try {
      setLoadingCampaigns(true);
      const res = await fetchGmailCampaigns();
      setCampaigns(res.campaigns || []);
      setCampaignIocs(res.iocs || []);
    } catch (err: any) {
      console.warn('[Gmail Monitor] Could not load campaigns:', err?.message);
    } finally {
      setLoadingCampaigns(false);
    }
  }, []);

  // 1. Load Initial Connection & Sync Status
  const loadStatusAndData = useCallback(async () => {
    setLoadingStatus(true);
    setErrorBanner(null);
    try {
      const statusRes = await fetchGmailStatus();
      setConnection(statusRes);

      if (statusRes.connected) {
        // Fetch Sync Status
        try {
          const syncRes = await fetchGmailSyncStatus();
          setSyncState(syncRes);
        } catch (err: any) {
          console.warn('[Gmail Monitor] Could not load sync status:', err?.message);
        }

        // Fetch recent messages
        setLoadingMessages(true);
        try {
          const msgRes = await fetchGmailMessages({ maxResults: 50 });
          setMessages(msgRes.messages || []);
        } catch (err: any) {
          console.warn('[Gmail Monitor] Could not load messages:', err?.message);
          setErrorBanner({
            message: err?.message || 'Failed to load mailbox messages.',
            code: err?.code,
          });
        } finally {
          setLoadingMessages(false);
        }

        // Load campaigns and IOCs
        loadCampaigns();
      }
    } catch (err: any) {
      console.error('[Gmail Monitor] Failed to load status:', err);
      setErrorBanner({ message: 'Unable to reach backend Gmail service.', code: 'NETWORK_ERROR' });
    } finally {
      setLoadingStatus(false);
    }
  }, [loadCampaigns]);

  useEffect(() => {
    loadStatusAndData();

    // Listen for OAuth callback postMessage if authorization occurred in a popup
    const handleMessage = (event: MessageEvent) => {
      if (event.data?.type === 'GMAIL_CONNECTED') {
        notify(`Gmail connected successfully: ${event.data.email}`, 'success');
        loadStatusAndData();
      }
    };
    window.addEventListener('message', handleMessage);

    // Check URL parameters for ?gmail_connected=true
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('gmail_connected') === 'true') {
      notify('Gmail connected successfully!', 'success');
      window.history.replaceState({}, document.title, window.location.pathname);
      loadStatusAndData();
    }

    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, [loadStatusAndData, notify]);

  // 2a. Connect Simulated Demo Mailbox (Offline SIH Evaluation Mode)
  const handleConnectDemo = async () => {
    setConnectingDemo(true);
    setErrorBanner(null);
    try {
      const res = await connectGmailDemo();
      notify(`Simulated Demo Mailbox linked: ${res.gmailEmail}`, 'success');
      setShowOauthSetupModal(false);

      // Reload status and mailbox messages
      const [statusRes, msgRes] = await Promise.all([
        fetchGmailStatus(),
        fetchGmailMessages({ maxResults: 50 }),
      ]);
      setConnection(statusRes);
      const msgs = msgRes.messages || [];
      setMessages(msgs);

      // Auto-triage demo messages immediately for a seamless judging/evaluation experience
      if (msgs.length > 0) {
        try {
          const batchRes = await triageGmailBatch(msgs.map(m => m.id));
          const newMap: Record<string, GmailTriageRecord> = {};
          for (const item of batchRes.results) {
            if (item.success && item.data) {
              newMap[item.messageId] = item.data;
            }
          }
          setTriageMap(newMap);
        } catch (tErr) {
          console.warn('[Gmail Monitor] Auto-triage demo notice:', tErr);
        }
      }

      const syncRes = await fetchGmailSyncStatus().catch(() => null);
      if (syncRes) setSyncState(syncRes);
      loadCampaigns();
    } catch (err: any) {
      notify(err?.message || 'Failed to connect simulated demo mailbox.', 'error');
    } finally {
      setConnectingDemo(false);
    }
  };

  // 2b. Connect Gmail Action (Redirect to Google OAuth)
  const handleConnectGmail = async () => {
    try {
      const { url } = await fetchGmailAuthUrl();
      if (url) {
        window.location.href = url;
      }
    } catch (err: any) {
      const msg = err?.message || '';
      if (
        msg.includes('OAuth is not configured') ||
        msg.includes('GOOGLE_CLIENT_ID') ||
        msg.includes('GOOGLE_CLIENT_SECRET') ||
        err?.code === 'GMAIL_OAUTH_NOT_CONFIGURED'
      ) {
        setShowOauthSetupModal(true);
      } else {
        notify(msg || 'Failed to initiate Google OAuth flow.', 'error');
      }
    }
  };

  // 3. Disconnect Gmail Action
  const handleDisconnectGmail = async () => {
    if (!window.confirm('Are you sure you want to disconnect this Gmail account from CyberTrace?')) {
      return;
    }
    setDisconnecting(true);
    try {
      await disconnectGmail();
      setConnection({ connected: false });
      setSyncState(null);
      setMessages([]);
      setTriageMap({});
      setActiveMessageId(null);
      notify('Gmail account disconnected successfully.', 'info');
    } catch (err: any) {
      notify(err?.message || 'Failed to disconnect Gmail account.', 'error');
    } finally {
      setDisconnecting(false);
    }
  };

  // 4. Trigger Incremental Synchronization
  const handleSyncNow = async () => {
    if (syncing) return;
    setSyncing(true);
    setErrorBanner(null);
    try {
      const syncResult = await triggerGmailSync();
      notify(
        `Sync completed: ${syncResult.messagesDiscovered} discovered, ${syncResult.messagesTriaged} triaged`,
        'success'
      );

      // Refresh sync state and message list
      const [newSyncState, newMessages] = await Promise.all([
        fetchGmailSyncStatus().catch(() => null),
        fetchGmailMessages({ maxResults: 50 }).catch(() => null),
      ]);

      if (newSyncState) setSyncState(newSyncState);
      if (newMessages?.messages) setMessages(newMessages.messages);
      loadCampaigns();
    } catch (err: any) {
      let message = err?.message || 'Synchronization failed.';
      if (err?.statusCode === 409 || err?.code === 'GMAIL_SYNC_IN_PROGRESS') {
        message = 'A mailbox synchronization is already actively running for this account.';
      } else if (err?.statusCode === 429 || err?.code === 'GMAIL_RATE_LIMIT') {
        message = 'Gmail rate limit reached. Upstream API requested a cooldown.';
      } else if (err?.statusCode === 401 || err?.code === 'GMAIL_AUTH_ERROR') {
        message = 'Gmail authorization token expired or revoked. Please reconnect.';
      }
      setErrorBanner({ message, code: err?.code });
      notify(message, 'error');
    } finally {
      setSyncing(false);
    }
  };

  // 5. Triage Single Message
  const handleTriageSingle = async (messageId: string) => {
    setTriagingId(messageId);
    try {
      const record = await triageGmailMessage(messageId);
      setTriageMap(prev => ({ ...prev, [messageId]: record }));
      loadCampaigns();
      notify(
        `Message ${messageId} triaged: ${record.riskLevel} risk (${record.riskScore}/100, ${record.mailClassification.mailType})`,
        record.riskLevel === 'CRITICAL' || record.riskLevel === 'HIGH' ? 'error' : 'success'
      );
    } catch (err: any) {
      notify(err?.message || `Failed to triage message ${messageId}`, 'error');
    } finally {
      setTriagingId(null);
    }
  };

  // 6. Batch Triage All Untriaged Messages in View
  const handleBatchTriage = async () => {
    const untriagedIds = messages
      .map(m => m.id)
      .filter(id => !triageMap[id]);

    if (untriagedIds.length === 0) {
      notify('All messages in the current view have already been triaged.', 'info');
      return;
    }

    setBatchTriaging(true);
    try {
      const batchRes = await triageGmailBatch(untriagedIds);
      const newMap = { ...triageMap };

      for (const item of batchRes.results) {
        if (item.success && item.data) {
          newMap[item.messageId] = item.data;
        }
      }
      setTriageMap(newMap);
      loadCampaigns();
      notify(
        `Batch triage complete: ${batchRes.succeeded} analyzed, ${batchRes.failed} failed`,
        batchRes.failed > 0 ? 'info' : 'success'
      );
    } catch (err: any) {
      notify(err?.message || 'Batch triage failed', 'error');
    } finally {
      setBatchTriaging(false);
    }
  };

  // 7. Open Forensic Detail Drawer
  const handleInspect = async (messageId: string) => {
    setActiveMessageId(messageId);
    setActiveRawPayload(null);
    setActiveDetailTab('overview');

    // If message is not yet triaged, triage it on demand
    if (!triageMap[messageId]) {
      setTriagingId(messageId);
      try {
        const record = await triageGmailMessage(messageId);
        setTriageMap(prev => ({ ...prev, [messageId]: record }));
      } catch (err: any) {
        notify(err?.message || 'Could not triage message for inspection', 'error');
      } finally {
        setTriagingId(null);
      }
    }
  };

  // 8. Fetch Raw RFC-822 On Demand (strictly never pre-fetched)
  const handleLoadRawPayload = async (messageId: string) => {
    setLoadingRaw(true);
    try {
      const rawRes = await fetchRawGmailMessage(messageId);
      setActiveRawPayload(rawRes);
    } catch (err: any) {
      notify(err?.message || 'Failed to fetch raw RFC-822 message', 'error');
    } finally {
      setLoadingRaw(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // 9. Promote Triaged Threat to Formal DFIR Case
  const handleConfirmPromotion = async () => {
    if (!confirmPromoteId) return;
    const messageId = confirmPromoteId;
    setConfirmPromoteId(null);
    setPromotingId(messageId);
    try {
      const res = await promoteGmailMessage(messageId);
      setPromotedMap(prev => ({ ...prev, [messageId]: res }));
      notify(
        res.alreadyPromoted
          ? `Threat was previously promoted to ${res.caseNumber} (${res.caseId})`
          : `Successfully promoted to formal Case ${res.caseNumber} (${res.caseId})`,
        'success'
      );
    } catch (err: any) {
      notify(err?.message || `Failed to promote message ${messageId} to formal case`, 'error');
    } finally {
      setPromotingId(null);
    }
  };

  const handleOpenCase = (caseId: string) => {
    if (onSelectCase) {
      onSelectCase(caseId);
    }
    if (onNavigate) {
      onNavigate('investigation');
    }
  };

  // --- Filtered Messages ---
  const filteredMessages = useMemo(() => {
    return messages.filter(m => {
      const record = triageMap[m.id];

      // Triage status filter
      if (filterTriage === 'TRIAGED' && !record) return false;
      if (filterTriage === 'UNTRIAGED' && record) return false;

      // Risk level filter
      if (filterRisk !== 'ALL') {
        if (!record || record.riskLevel !== filterRisk) return false;
      }

      // Mail type filter
      if (filterMailType !== 'ALL') {
        if (!record || record.mailClassification.mailType !== filterMailType) return false;
      }

      // Free text search (ID, sender, subject)
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const idMatch = m.id.toLowerCase().includes(q) || m.threadId.toLowerCase().includes(q);
        const subjMatch = record ? record.subject.toLowerCase().includes(q) : false;
        const senderMatch = record ? record.sender.raw.toLowerCase().includes(q) : false;
        if (!idMatch && !subjMatch && !senderMatch) return false;
      }

      return true;
    });
  }, [messages, triageMap, filterTriage, filterRisk, filterMailType, searchQuery]);

  // --- Metrics Summary ---
  const metrics = useMemo(() => {
    const total = messages.length;
    const triagedCount = Object.keys(triageMap).length;
    const untriagedCount = Math.max(0, total - triagedCount);

    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const rec of Object.values(triageMap) as GmailTriageRecord[]) {
      if (rec.riskLevel === 'CRITICAL') criticalCount++;
      else if (rec.riskLevel === 'HIGH') highCount++;
      else if (rec.riskLevel === 'MEDIUM') mediumCount++;
      else if (rec.riskLevel === 'LOW') lowCount++;
    }

    return {
      total,
      triagedCount,
      untriagedCount,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      threatCount: criticalCount + highCount,
      campaignsCount: campaigns.length,
      iocsCount: campaignIocs.length,
    };
  }, [messages, triageMap, campaigns, campaignIocs]);

  const activeRecord = activeMessageId ? triageMap[activeMessageId] : null;

  // Map each message to its correlated campaign (if any)
  const messageCampaignMap = useMemo(() => {
    const map = new Map<string, GmailCampaignSummary>();
    for (const c of campaigns) {
      for (const msgId of c.relatedMessageIds) {
        map.set(msgId, c);
      }
    }
    return map;
  }, [campaigns]);

  // Render Threat Intel Reputation Badge
  const renderReputationBadge = (reputation?: IOCReputation) => {
    switch (reputation) {
      case 'MALICIOUS':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-50 text-red-700 border border-red-200">
            <ShieldAlert className="w-3 h-3" />
            <span>MALICIOUS</span>
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-200">
            <AlertTriangle className="w-3 h-3" />
            <span>SUSPICIOUS</span>
          </span>
        );
      case 'BENIGN':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <ShieldCheck className="w-3 h-3" />
            <span>BENIGN</span>
          </span>
        );
      case 'UNKNOWN':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
            <span>UNAVAILABLE</span>
          </span>
        );
    }
  };

  // Render Risk Badge
  const renderRiskBadge = (level?: RiskLevel, score?: number) => {
    if (!level) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-slate-100 text-slate-500 border border-slate-200">
          UNTRIAGED
        </span>
      );
    }
    const colorMap: Record<RiskLevel, string> = {
      CRITICAL: 'bg-red-50 text-red-700 border-red-200',
      HIGH: 'bg-amber-50 text-amber-700 border-amber-200',
      MEDIUM: 'bg-yellow-50 text-yellow-700 border-yellow-200',
      LOW: 'bg-green-50 text-green-700 border-green-200',
    };
    return (
      <span
        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-bold border ${
          colorMap[level] || 'bg-slate-100 text-slate-700 border-slate-200'
        }`}
      >
        <span>{level}</span>
        {typeof score === 'number' && <span className="opacity-75">({score})</span>}
      </span>
    );
  };

  // Render Mail Type Badge
  const renderMailTypeBadge = (mailType?: string) => {
    if (!mailType) return <span className="text-slate-400 text-xs">-</span>;
    const badgeColors: Record<string, string> = {
      COMPANY: 'bg-blue-50 text-blue-700 border-blue-200',
      PERSONAL: 'bg-purple-50 text-purple-700 border-purple-200',
      SPAM: 'bg-slate-100 text-slate-700 border-slate-300',
      UNKNOWN: 'bg-gray-100 text-gray-600 border-gray-200',
    };
    return (
      <span
        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${
          badgeColors[mailType] || 'bg-slate-100 text-slate-600 border-slate-200'
        }`}
      >
        {mailType}
      </span>
    );
  };

  // Render Auth Result Pill
  const renderAuthPill = (name: string, status?: string) => {
    const isPass = status === 'PASS' || status === 'pass';
    const isFail = status === 'FAIL' || status === 'fail';
    return (
      <span
        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold border ${
          isPass
            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
            : isFail
            ? 'bg-rose-50 text-rose-700 border-rose-200'
            : 'bg-slate-100 text-slate-600 border-slate-200'
        }`}
      >
        <span>{name}:</span>
        <span>{status || 'NONE'}</span>
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Primary SOC Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white p-5 rounded-2xl border border-slate-200 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-md flex-shrink-0">
            <Mail className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">Gmail Threat Monitor</h1>
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                Phase 5 SOC Interface
              </span>
              {connection?.connected && connection.gmailEmail?.includes('demo') && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 animate-pulse">
                  <Sparkles className="w-3 h-3 text-emerald-600" />
                  Offline SIH Demo Mailbox
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Continuous mailbox monitoring, incremental history sync, and deterministic threat triage
            </p>
          </div>
        </div>

        {/* Global Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {connection?.connected ? (
            <>
              <button
                onClick={handleSyncNow}
                disabled={syncing}
                className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold text-white shadow-sm transition-all ${
                  syncing
                    ? 'bg-blue-400 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700 active:scale-95'
                }`}
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
                <span>{syncing ? 'Syncing Mailbox...' : 'Sync Now'}</span>
              </button>

              <button
                onClick={() => loadStatusAndData()}
                disabled={loadingMessages}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 transition-colors"
                title="Reload message queue from Gmail"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-slate-500 ${loadingMessages ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>

              <button
                onClick={handleDisconnectGmail}
                disabled={disconnecting}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 border border-red-200 transition-colors"
                title="Disconnect this Gmail account"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Disconnect</span>
              </button>
            </>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={handleConnectDemo}
                disabled={connectingDemo}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-300 shadow-xs transition-all active:scale-95"
                title="Instant 1-Click: Test full forensic pipeline with pre-staged realistic attack scenarios (no Google credentials needed)"
              >
                <Sparkles className={`w-3.5 h-3.5 text-emerald-600 ${connectingDemo ? 'animate-spin' : ''}`} />
                <span>{connectingDemo ? 'Loading...' : '⚡ Demo Mailbox (Offline SIH Mode)'}</span>
              </button>
              <button
                onClick={handleConnectGmail}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-xs transition-all active:scale-95"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Connect Google Account</span>
              </button>
              <button
                onClick={() => setShowOauthSetupModal(true)}
                className="p-2 rounded-xl text-slate-500 hover:text-slate-700 hover:bg-slate-100 border border-slate-200 transition-colors"
                title="Google OAuth Setup Guide (.env configuration)"
              >
                <HelpCircle className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* 2. Error Banner (if any) */}
      {errorBanner && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1 text-xs text-red-800">
            <span className="font-bold">Operational Notice: </span>
            <span>{errorBanner.message}</span>
            {errorBanner.code && (
              <span className="ml-2 font-mono bg-red-100 px-1.5 py-0.5 rounded text-[10px]">
                {errorBanner.code}
              </span>
            )}
          </div>
          <button
            onClick={() => setErrorBanner(null)}
            className="text-red-400 hover:text-red-600"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* 3. Status Overview Deck */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Connection Tile */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">
              Connection
            </span>
            <div
              className={`w-2.5 h-2.5 rounded-full ${
                connection?.connected ? 'bg-emerald-500 animate-pulse' : 'bg-slate-300'
              }`}
            />
          </div>
          <div className="mt-2 flex items-center gap-2">
            {connection?.connected ? (
              <ShieldCheck className="w-5 h-5 text-emerald-600 flex-shrink-0" />
            ) : (
              <AlertCircle className="w-5 h-5 text-slate-400 flex-shrink-0" />
            )}
            <div className="min-w-0">
              <div className="text-sm font-bold text-slate-900 truncate">
                {connection?.connected
                  ? connection.gmailEmail?.includes('demo')
                    ? 'Simulated Mailbox Active'
                    : 'Authorized & Active'
                  : 'Disconnected'}
              </div>
              <div className="text-xs text-slate-500 truncate">
                {connection?.gmailEmail
                  ? connection.gmailEmail.includes('demo')
                    ? 'soc.demo@cybertrace-defense.internal (SIH Mode)'
                    : connection.gmailEmail
                  : 'No account linked'}
              </div>
            </div>
          </div>
        </div>

        {/* Sync Status Tile */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">
              Sync State
            </span>
            <span
              className={`text-[11px] font-mono px-2 py-0.5 rounded font-bold border ${
                syncState?.status === 'COMPLETED'
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : syncState?.status === 'SYNCING' || syncing
                  ? 'bg-blue-50 text-blue-700 border-blue-200 animate-pulse'
                  : syncState?.status === 'FAILED'
                  ? 'bg-red-50 text-red-700 border-red-200'
                  : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}
            >
              {syncing ? 'SYNCING' : syncState?.status || 'IDLE'}
            </span>
          </div>
          <div className="mt-2">
            <div className="text-sm font-bold text-slate-900">
              {syncState?.historyId ? `History #${syncState.historyId}` : 'Initial check pending'}
            </div>
            <div className="text-xs text-slate-500 truncate flex items-center gap-1 mt-0.5">
              <Clock className="w-3 h-3" />
              <span>
                {syncState?.lastSyncCompletedAt
                  ? new Date(syncState.lastSyncCompletedAt).toLocaleTimeString()
                  : 'Never synced'}
              </span>
            </div>
          </div>
        </div>

        {/* Ingested Volume */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">
              Mailbox Ingested
            </span>
            <Inbox className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <div className="text-2xl font-black text-slate-900">{metrics.total}</div>
            <div className="text-xs text-slate-500">
              ({metrics.triagedCount} triaged, {metrics.untriagedCount} pending)
            </div>
          </div>
        </div>

        {/* Threat Detection Count */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">
              Identified Threats
            </span>
            <ShieldAlert className="w-4 h-4 text-red-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <div className="text-2xl font-black text-red-600">{metrics.threatCount}</div>
            <div className="text-xs text-slate-500">
              ({metrics.criticalCount} Critical, {metrics.highCount} High)
            </div>
          </div>
        </div>

        {/* Correlated Campaigns & Enriched IOCs */}
        <div
          onClick={() => setActiveViewTab('campaigns')}
          className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm cursor-pointer hover:border-indigo-300 transition-colors"
          title="Click to view correlated threat campaigns"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">
              Campaign Intel
            </span>
            <Network className="w-4 h-4 text-indigo-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <div className="text-2xl font-black text-indigo-600">{campaigns.length}</div>
            <div className="text-xs text-slate-500">
              Active ({campaignIocs.length} IOCs)
            </div>
          </div>
        </div>
      </div>

      {/* 4. When Not Connected: Dual Option Call to Action Banner */}
      {!connection?.connected && !loadingStatus && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Card 1: Instant Simulated Demo Mailbox (Offline SIH Mode) */}
            <div className="relative overflow-hidden bg-gradient-to-br from-emerald-50/80 via-white to-teal-50/60 border-2 border-emerald-300 rounded-2xl p-6 shadow-sm flex flex-col justify-between hover:shadow-md transition-shadow">
              <div className="absolute top-3 right-3">
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                  <Sparkles className="w-3 h-3 text-emerald-600" />
                  Recommended for Evaluation & Judging
                </span>
              </div>
              <div>
                <div className="w-12 h-12 bg-emerald-600 text-white rounded-xl flex items-center justify-center shadow-md mb-4">
                  <Sparkles className="w-6 h-6" />
                </div>
                <h3 className="text-base font-bold text-slate-900">
                  ⚡ Load Simulated Demo Mailbox (Offline SIH Mode)
                </h3>
                <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                  Test the complete end-to-end Gmail Threat Monitor instantly without needing Google Cloud credentials or API keys.
                </p>
                <div className="mt-4 space-y-2 text-xs text-slate-700 bg-white/80 rounded-xl p-3 border border-emerald-100">
                  <div className="font-semibold text-emerald-900 text-[11px] uppercase tracking-wider">
                    Included Pre-Staged Attack Scenarios:
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-red-500"></span>
                    <span><strong>Executive BEC Wire Fraud:</strong> Urgent CFO spoofing & gift card wire request</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                    <span><strong>M365 Phishing:</strong> Password expiration lure with credential harvest link</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-red-600"></span>
                    <span><strong>Malware Delivery:</strong> Overdue invoice with disguised executable payload</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                    <span><strong>Clean IT Notice:</strong> Routine VPN maintenance communication</span>
                  </div>
                </div>
              </div>
              <div className="mt-5 pt-4 border-t border-emerald-100">
                <button
                  onClick={handleConnectDemo}
                  disabled={connectingDemo}
                  className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-700 shadow-sm transition-all active:scale-[0.98]"
                >
                  <Sparkles className={`w-4 h-4 ${connectingDemo ? 'animate-spin' : ''}`} />
                  <span>{connectingDemo ? 'Connecting Demo Mailbox...' : '⚡ Load Simulated Demo Mailbox (Instant 1-Click)'}</span>
                </button>
                <div className="text-[10px] text-slate-400 text-center mt-2">
                  Zero setup required • Runs 100% locally with deterministic triage
                </div>
              </div>
            </div>

            {/* Card 2: Live Google Workspace OAuth Connection */}
            <div className="bg-gradient-to-br from-blue-50/70 via-white to-indigo-50/50 border border-slate-200 rounded-2xl p-6 shadow-sm flex flex-col justify-between hover:shadow-md transition-shadow">
              <div>
                <div className="w-12 h-12 bg-blue-600 text-white rounded-xl flex items-center justify-center shadow-md mb-4">
                  <Lock className="w-6 h-6" />
                </div>
                <h3 className="text-base font-bold text-slate-900">
                  Connect Live Google Workspace Account
                </h3>
                <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                  Connect your real Gmail or Google Workspace inbox via official Google OAuth 2.0 with read-only scopes.
                </p>
                <div className="mt-4 space-y-2 text-xs text-slate-700 bg-white/80 rounded-xl p-3 border border-blue-100">
                  <div className="font-semibold text-blue-900 text-[11px] uppercase tracking-wider">
                    Enterprise Security Architecture:
                  </div>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-blue-600" />
                    <span>Strict <code>gmail.readonly</code> scope isolation</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-blue-600" />
                    <span>Cryptographic 256-bit entropy CSRF state validation</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-blue-600" />
                    <span>Raw RFC-822 parsed strictly on backend (zero credential leakage)</span>
                  </div>
                </div>
              </div>
              <div className="mt-5 pt-4 border-t border-slate-100 space-y-2">
                <button
                  onClick={handleConnectGmail}
                  className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-sm transition-all active:scale-[0.98]"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Connect Google Account via OAuth 2.0</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowOauthSetupModal(true)}
                  className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 transition-colors"
                >
                  <HelpCircle className="w-3.5 h-3.5 text-slate-500" />
                  <span>Google Cloud OAuth Setup Guide (.env Configuration)</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. Connected Mailbox Queue, Threat Campaigns & Enriched IOCs */}
      {connection?.connected && (
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
          {/* View Mode Tabs */}
          <div className="flex items-center gap-1 border-b border-slate-200 px-4 pt-3 bg-slate-50/50">
            <button
              onClick={() => setActiveViewTab('inbox')}
              className={`pb-3 px-3.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                activeViewTab === 'inbox'
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Monitored Mailbox ({messages.length})</span>
            </button>
            <button
              onClick={() => setActiveViewTab('campaigns')}
              className={`pb-3 px-3.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                activeViewTab === 'campaigns'
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Correlated Campaigns ({campaigns.length})</span>
            </button>
            <button
              onClick={() => setActiveViewTab('iocs')}
              className={`pb-3 px-3.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                activeViewTab === 'iocs'
                  ? 'border-purple-600 text-purple-600'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Threat Intelligence IOCs ({campaignIocs.length})</span>
            </button>
          </div>

          {/* TAB 1: MONITORED MAILBOX INBOX */}
          {activeViewTab === 'inbox' && (
            <>
              {/* Controls Bar */}
              <div className="p-4 border-b border-slate-200 bg-slate-50/50 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                {/* Search Input */}
                <div className="relative flex-1 max-w-md">
                  <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Search by subject, sender domain, or message ID..."
                    className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                {/* Filter Dropdowns */}
                <div className="flex flex-wrap items-center gap-2">
                  {/* Triage Filter */}
                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase">Triage:</span>
                    <select
                      value={filterTriage}
                      onChange={e => setFilterTriage(e.target.value as any)}
                      className="text-xs bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500 font-medium text-slate-700"
                    >
                      <option value="ALL">All ({messages.length})</option>
                      <option value="UNTRIAGED">Untriaged ({metrics.untriagedCount})</option>
                      <option value="TRIAGED">Triaged ({metrics.triagedCount})</option>
                    </select>
                  </div>

                  {/* Risk Level Filter */}
                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase">Risk:</span>
                    <select
                      value={filterRisk}
                      onChange={e => setFilterRisk(e.target.value as any)}
                      className="text-xs bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500 font-medium text-slate-700"
                    >
                      <option value="ALL">All Levels</option>
                      <option value="CRITICAL">Critical ({metrics.criticalCount})</option>
                      <option value="HIGH">High ({metrics.highCount})</option>
                      <option value="MEDIUM">Medium ({metrics.mediumCount})</option>
                      <option value="LOW">Low ({metrics.lowCount})</option>
                    </select>
                  </div>

                  {/* Mail Type Filter */}
                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase">Type:</span>
                    <select
                      value={filterMailType}
                      onChange={e => setFilterMailType(e.target.value as any)}
                      className="text-xs bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500 font-medium text-slate-700"
                    >
                      <option value="ALL">All Types</option>
                      <option value="COMPANY">Company</option>
                      <option value="PERSONAL">Personal</option>
                      <option value="SPAM">Spam</option>
                      <option value="UNKNOWN">Unknown</option>
                    </select>
                  </div>

                  {/* Batch Triage Button */}
                  {metrics.untriagedCount > 0 && (
                    <button
                      onClick={handleBatchTriage}
                      disabled={batchTriaging}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-slate-800 hover:bg-slate-900 transition-colors shadow-sm ml-auto"
                    >
                      <Radio className={`w-3.5 h-3.5 ${batchTriaging ? 'animate-spin' : ''}`} />
                      <span>{batchTriaging ? 'Triaging Batch...' : `Triage Untriaged (${metrics.untriagedCount})`}</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Messages Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-700">
                  <thead className="bg-slate-50 text-slate-400 text-[11px] uppercase tracking-wider font-semibold border-b border-slate-200">
                    <tr>
                      <th className="py-3 px-4">Threat Assessment</th>
                      <th className="py-3 px-4">Subject & Message ID</th>
                      <th className="py-3 px-4">Classification</th>
                      <th className="py-3 px-4">Campaign</th>
                      <th className="py-3 px-4">Sender / Origin</th>
                      <th className="py-3 px-4 text-right">Forensic Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-normal">
                    {loadingMessages ? (
                      <tr>
                        <td colSpan={6} className="py-12 text-center text-slate-400">
                          <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-500 mb-2" />
                          <div>Retrieving mailbox messages via Gmail API...</div>
                        </td>
                      </tr>
                    ) : filteredMessages.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-12 text-center text-slate-400">
                          <Inbox className="w-8 h-8 mx-auto text-slate-300 mb-2" />
                          <div>No messages found matching active filter criteria.</div>
                        </td>
                      </tr>
                    ) : (
                      filteredMessages.map(msg => {
                        const record = triageMap[msg.id];
                        const isTriaging = triagingId === msg.id;
                        const campaign = messageCampaignMap.get(msg.id);

                        return (
                          <tr
                            key={msg.id}
                            className={`hover:bg-slate-50/80 transition-colors cursor-pointer ${
                              activeMessageId === msg.id ? 'bg-blue-50/50' : ''
                            }`}
                            onClick={() => handleInspect(msg.id)}
                          >
                            {/* Threat Assessment / Risk */}
                            <td className="py-3.5 px-4 whitespace-nowrap">
                              {record ? (
                                <div className="flex items-center gap-2">
                                  {renderRiskBadge(record.riskLevel, record.riskScore)}
                                </div>
                              ) : (
                                <div className="flex items-center gap-1.5 text-slate-400">
                                  <span className="w-2 h-2 rounded-full bg-slate-300" />
                                  <span className="text-[11px] font-medium">Pending Triage</span>
                                </div>
                              )}
                            </td>

                            {/* Subject & ID */}
                            <td className="py-3.5 px-4 max-w-xs">
                              <div className="font-semibold text-slate-900 truncate">
                                {record ? record.subject : `Gmail Message ${msg.id}`}
                              </div>
                              <div className="flex items-center gap-2 mt-0.5 text-[11px] text-slate-400 font-mono">
                                <span>ID: {msg.id.slice(0, 16)}...</span>
                                {msg.threadId && <span className="opacity-75">Th: {msg.threadId.slice(0, 10)}</span>}
                              </div>
                            </td>

                            {/* Classification */}
                            <td className="py-3.5 px-4 whitespace-nowrap">
                              {renderMailTypeBadge(record?.mailClassification.mailType)}
                            </td>

                            {/* Correlated Campaign */}
                            <td className="py-3.5 px-4 whitespace-nowrap">
                              {campaign ? (
                                <button
                                  type="button"
                                  onClick={e => {
                                    e.stopPropagation();
                                    setSelectedCampaign(campaign);
                                    setCampaignModalOpen(true);
                                  }}
                                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-bold bg-indigo-50 text-indigo-700 hover:bg-indigo-100 border border-indigo-200 transition-colors"
                                  title={`Inspect ${campaign.campaignName}`}
                                >
                                  <Network className="w-3 h-3 text-indigo-600" />
                                  <span>{campaign.campaignCode}</span>
                                </button>
                              ) : (
                                <span className="text-slate-300 text-xs italic">—</span>
                              )}
                            </td>

                            {/* Sender */}
                            <td className="py-3.5 px-4 max-w-xs">
                              {record ? (
                                <div>
                                  <div className="text-xs text-slate-800 font-medium truncate">
                                    {record.sender.fromAddress}
                                  </div>
                                  <div className="text-[11px] text-slate-400 truncate">
                                    {record.sender.fromDomain}
                                  </div>
                                </div>
                              ) : (
                                <span className="text-slate-400 text-xs italic">Awaiting analysis</span>
                              )}
                            </td>

                            {/* Actions */}
                            <td className="py-3.5 px-4 text-right whitespace-nowrap">
                              <div className="flex items-center justify-end gap-1.5" onClick={e => e.stopPropagation()}>
                                {record ? (
                                  <>
                                    {promotedMap[msg.id] ? (
                                      <button
                                        onClick={() => handleOpenCase(promotedMap[msg.id].caseId)}
                                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-semibold text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 transition-colors"
                                        title={`Open Case ${promotedMap[msg.id].caseNumber}`}
                                      >
                                        <FolderPlus className="w-3 h-3" />
                                        <span>Case {promotedMap[msg.id].caseNumber}</span>
                                        <ExternalLink className="w-3 h-3" />
                                      </button>
                                    ) : (
                                      <button
                                        onClick={() => setConfirmPromoteId(msg.id)}
                                        disabled={promotingId === msg.id}
                                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-semibold text-purple-700 bg-purple-50 hover:bg-purple-100 border border-purple-200 transition-colors"
                                        title="Promote triaged email to a formal DFIR case"
                                      >
                                        <FolderPlus className={`w-3 h-3 ${promotingId === msg.id ? 'animate-spin' : ''}`} />
                                        <span>{promotingId === msg.id ? 'Promoting...' : 'Promote'}</span>
                                      </button>
                                    )}
                                    <button
                                      onClick={() => handleInspect(msg.id)}
                                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 transition-colors"
                                    >
                                      <span>Inspect</span>
                                      <ChevronRight className="w-3 h-3" />
                                    </button>
                                  </>
                                ) : (
                                  <button
                                    onClick={() => handleTriageSingle(msg.id)}
                                    disabled={isTriaging}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 active:scale-95 transition-all shadow-xs"
                                  >
                                    <Radio className={`w-3 h-3 ${isTriaging ? 'animate-spin' : ''}`} />
                                    <span>{isTriaging ? 'Analyzing...' : 'Triage'}</span>
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* TAB 2: CORRELATED THREAT CAMPAIGNS */}
          {activeViewTab === 'campaigns' && (
            <div className="p-6 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
                <div>
                  <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                    <Network className="w-5 h-5 text-indigo-600" />
                    <span>Multi-Signal Threat Campaign Correlation</span>
                  </h3>
                  <p className="text-xs text-slate-500 mt-1">
                    Deterministic graph correlation connecting Gmail threats sharing originating IPs, phishing domains, URLs, and attachment SHA-256 hashes (0 Gemini calls).
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => loadCampaigns()}
                    disabled={loadingCampaigns}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 transition-colors"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${loadingCampaigns ? 'animate-spin' : ''}`} />
                    <span>Refresh Campaigns</span>
                  </button>
                </div>
              </div>

              {campaigns.length === 0 ? (
                <div className="py-16 text-center text-slate-400 bg-slate-50/50 rounded-2xl border border-slate-200">
                  <Network className="w-10 h-10 mx-auto text-slate-300 mb-3" />
                  <div className="text-sm font-semibold text-slate-700">No Correlated Threat Campaigns Detected Yet</div>
                  <div className="text-xs text-slate-500 max-w-md mx-auto mt-1">
                    Campaign correlation automatically clusters messages when 2 or more triaged emails share common attack infrastructure (IPs, destination domains, URLs, or attachment signatures).
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  {campaigns.map(camp => (
                    <div
                      key={camp.campaignId}
                      className="bg-white rounded-2xl border border-slate-200 hover:border-indigo-300 p-5 shadow-xs hover:shadow-md transition-all space-y-4 flex flex-col justify-between"
                    >
                      <div className="space-y-3">
                        {/* Header */}
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200">
                                {camp.campaignCode}
                              </span>
                              <span className="font-mono text-xs text-slate-400">({camp.campaignId})</span>
                            </div>
                            <h4 className="text-sm font-bold text-slate-900 mt-1">{camp.campaignName}</h4>
                          </div>
                          <div className="flex items-center gap-1.5">
                            {renderRiskBadge(camp.campaignRiskLevel, camp.campaignRiskScore)}
                          </div>
                        </div>

                        {/* Metrics */}
                        <div className="grid grid-cols-3 gap-2 bg-slate-50 p-3 rounded-xl border border-slate-100 text-center">
                          <div>
                            <div className="text-[10px] font-semibold text-slate-400 uppercase">Messages</div>
                            <div className="text-sm font-bold text-slate-800">{camp.totalMessages}</div>
                          </div>
                          <div>
                            <div className="text-[10px] font-semibold text-slate-400 uppercase">Peak Risk</div>
                            <div className="text-sm font-bold text-red-600">{camp.highestMessageRisk}/100</div>
                          </div>
                          <div>
                            <div className="text-[10px] font-semibold text-slate-400 uppercase">Shared IOCs</div>
                            <div className="text-sm font-bold text-indigo-600">{camp.sharedIocs.length}</div>
                          </div>
                        </div>

                        {/* Correlation Evidence */}
                        <div className="space-y-1.5">
                          <div className="text-[11px] font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                            <Layers className="w-3 h-3 text-indigo-500" />
                            <span>Correlation Evidence</span>
                          </div>
                          <ul className="space-y-1 text-xs text-slate-600 bg-indigo-50/40 p-2.5 rounded-xl border border-indigo-100">
                            {camp.correlationReasons.map((reason, idx) => (
                              <li key={idx} className="flex items-start gap-1.5">
                                <span className="text-indigo-500 font-bold">•</span>
                                <span className="font-medium text-slate-800">{reason}</span>
                              </li>
                            ))}
                          </ul>
                        </div>

                        {/* Threat Intel Findings */}
                        <div className="space-y-1.5">
                          <div className="text-[11px] font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                            <ShieldAlert className="w-3 h-3 text-red-500" />
                            <span>Threat Intelligence Findings</span>
                          </div>
                          <div className="space-y-1">
                            {camp.threatIntelFindings.map((finding, idx) => (
                              <div key={idx} className="text-xs text-slate-700 bg-slate-50 p-2 rounded-lg border border-slate-200">
                                {finding}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => {
                          setSelectedCampaign(camp);
                          setCampaignModalOpen(true);
                        }}
                        className="w-full mt-2 inline-flex items-center justify-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 shadow-xs transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Inspect Campaign Details ({camp.totalMessages} Messages)</span>
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: EXTRACTED & ENRICHED IOCs */}
          {activeViewTab === 'iocs' && (
            <div className="p-6 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
                <div>
                  <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                    <Activity className="w-5 h-5 text-purple-600" />
                    <span>Extracted Indicators of Compromise & Threat Intelligence</span>
                  </h3>
                  <p className="text-xs text-slate-500 mt-1">
                    Normalized indicators enriched via AbuseIPDB, AlienVault OTX, and VirusTotal providers. Defanged to prevent inadvertent analyst execution.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => loadCampaigns()}
                    disabled={loadingCampaigns}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 transition-colors"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${loadingCampaigns ? 'animate-spin' : ''}`} />
                    <span>Refresh IOCs</span>
                  </button>
                </div>
              </div>

              {campaignIocs.length === 0 ? (
                <div className="py-16 text-center text-slate-400 bg-slate-50/50 rounded-2xl border border-slate-200">
                  <Activity className="w-10 h-10 mx-auto text-slate-300 mb-3" />
                  <div className="text-sm font-semibold text-slate-700">No Indicators Extracted Yet</div>
                  <div className="text-xs text-slate-500 max-w-md mx-auto mt-1">
                    Triage mailbox messages to extract IPs, domains, URLs, and attachment file hashes.
                  </div>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-700">
                    <thead className="bg-slate-50 text-slate-400 text-[11px] uppercase tracking-wider font-semibold border-b border-slate-200">
                      <tr>
                        <th className="py-3 px-4">IOC Type</th>
                        <th className="py-3 px-4">Defanged Value</th>
                        <th className="py-3 px-4">Threat Intelligence</th>
                        <th className="py-3 px-4">Provider Source</th>
                        <th className="py-3 px-4 text-center">Occurrences</th>
                        <th className="py-3 px-4 text-right">Related Messages</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-normal">
                      {campaignIocs.map(ioc => (
                        <tr key={ioc.id} className="hover:bg-slate-50/80 transition-colors">
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 uppercase">
                              {ioc.type}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 max-w-md">
                            <div className="font-mono text-xs text-slate-900 break-all select-all font-semibold">
                              {ioc.defangedValue}
                            </div>
                            {ioc.threatIntel?.maliciousCategory && (
                              <div className="text-[11px] text-red-600 mt-0.5 font-sans">
                                Category: {ioc.threatIntel.maliciousCategory}
                              </div>
                            )}
                          </td>
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            {renderReputationBadge(ioc.threatIntel?.reputation)}
                          </td>
                          <td className="py-3.5 px-4 whitespace-nowrap text-slate-600">
                            <div className="text-xs font-medium">{ioc.threatIntel?.source || 'THREAT INTELLIGENCE UNAVAILABLE'}</div>
                            {ioc.threatIntel?.reputationScore ? (
                              <div className="text-[10px] text-slate-400 font-mono">
                                Score: {ioc.threatIntel.reputationScore}/100
                              </div>
                            ) : null}
                          </td>
                          <td className="py-3.5 px-4 whitespace-nowrap text-center font-bold text-slate-900">
                            {ioc.occurrenceCount}
                          </td>
                          <td className="py-3.5 px-4 whitespace-nowrap text-right text-slate-500 font-mono text-[11px]">
                            {ioc.sourceMessageIds.length} message(s)
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 6. Slide-out Forensic Inspection Drawer / Modal */}
      {activeMessageId && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-slate-900/40 backdrop-blur-xs flex justify-end">
          <div className="w-full max-w-2xl bg-white h-full shadow-2xl flex flex-col border-l border-slate-200 animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="p-5 border-b border-slate-200 flex items-center justify-between bg-slate-50/70">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-9 h-9 rounded-xl bg-blue-600 text-white flex items-center justify-center flex-shrink-0">
                  <Shield className="w-5 h-5" />
                </div>
                <div className="min-w-0">
                  <h3 className="font-bold text-slate-900 text-sm truncate">
                    {activeRecord ? activeRecord.subject : `Inspecting Message ${activeMessageId}`}
                  </h3>
                  <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                    Gmail ID: {activeMessageId}
                  </div>
                </div>
              </div>
              <button
                onClick={() => {
                  setActiveMessageId(null);
                  setActiveRawPayload(null);
                }}
                className="w-8 h-8 rounded-lg hover:bg-slate-200 flex items-center justify-center text-slate-500 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Tab Navigation */}
            <div className="flex border-b border-slate-200 px-5 bg-white">
              <button
                onClick={() => setActiveDetailTab('overview')}
                className={`py-2.5 px-3 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
                  activeDetailTab === 'overview'
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                }`}
              >
                <Shield className="w-3.5 h-3.5" />
                <span>Forensic Overview</span>
              </button>
              <button
                onClick={() => {
                  setActiveDetailTab('raw');
                  if (!activeRawPayload && activeMessageId) {
                    handleLoadRawPayload(activeMessageId);
                  }
                }}
                className={`py-2.5 px-3 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
                  activeDetailTab === 'raw'
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>Raw RFC-822 MIME</span>
              </button>
            </div>

            {/* Drawer Body */}
            <div className="flex-1 overflow-y-auto p-5 space-y-6">
              {triagingId === activeMessageId ? (
                <div className="py-16 text-center text-slate-400">
                  <RefreshCw className="w-8 h-8 animate-spin mx-auto text-blue-600 mb-2" />
                  <div className="text-sm font-semibold text-slate-800">
                    Executing Deterministic Forensic Analysis...
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Headers &rarr; Mail Classification &rarr; Heuristics &rarr; Explainable Risk Score
                  </div>
                </div>
              ) : activeDetailTab === 'overview' && activeRecord ? (
                <>
                  {/* Formal DFIR Case Promotion Status Banner */}
                  {promotedMap[activeMessageId!] ? (
                    <div className="p-3.5 rounded-xl border border-emerald-200 bg-emerald-50/70 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className="w-8 h-8 rounded-lg bg-emerald-600 text-white flex items-center justify-center flex-shrink-0">
                          <FolderPlus className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-emerald-900">
                            Formal DFIR Case Active: {promotedMap[activeMessageId!].caseNumber}
                          </div>
                          <div className="text-[11px] text-emerald-700 font-mono truncate">
                            ID: {promotedMap[activeMessageId!].caseId} • Cryptographically sealed in Evidence Ledger
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => handleOpenCase(promotedMap[activeMessageId!].caseId)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-emerald-700 hover:bg-emerald-800 transition-colors shadow-xs flex-shrink-0"
                      >
                        <span>Open Investigation</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>
                  ) : (
                    <div className="p-3.5 rounded-xl border border-purple-200 bg-purple-50/60 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className="w-8 h-8 rounded-lg bg-purple-600 text-white flex items-center justify-center flex-shrink-0">
                          <FolderPlus className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-purple-900">
                            Promote to Formal DFIR Case
                          </div>
                          <div className="text-[11px] text-purple-700">
                            Transition this threat into a formal case with ledger evidence, timeline, and graph.
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => setConfirmPromoteId(activeMessageId)}
                        disabled={promotingId === activeMessageId}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-purple-600 hover:bg-purple-700 transition-colors shadow-xs flex-shrink-0"
                      >
                        <FolderPlus className={`w-3.5 h-3.5 ${promotingId === activeMessageId ? 'animate-spin' : ''}`} />
                        <span>{promotingId === activeMessageId ? 'Promoting...' : 'Promote to Case'}</span>
                      </button>
                    </div>
                  )}

                  {/* Risk & Classification Banner */}
                  <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 flex flex-wrap items-center justify-between gap-3">
                    <div className="space-y-1">
                      <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                        Threat Determination
                      </span>
                      <div className="flex items-center gap-2">
                        {renderRiskBadge(activeRecord.riskLevel, activeRecord.riskScore)}
                        <span className="text-xs font-bold text-slate-700">
                          {activeRecord.threatClassification}
                        </span>
                      </div>
                    </div>

                    <div className="space-y-1 text-right">
                      <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                        Mail Type Classification
                      </span>
                      <div>{renderMailTypeBadge(activeRecord.mailClassification.mailType)}</div>
                    </div>
                  </div>

                  {/* Mail Classification Reasons */}
                  {activeRecord.mailClassification.reasons.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                        Classification Evidence
                      </h4>
                      <ul className="space-y-1 bg-slate-50 p-3 rounded-xl border border-slate-200 text-xs text-slate-700">
                        {activeRecord.mailClassification.reasons.map((r, i) => (
                          <li key={i} className="flex items-start gap-2">
                            <span className="text-blue-500">•</span>
                            <span>{r}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Header & Sender Metadata */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                      Message Transport Metadata
                    </h4>
                    <div className="grid grid-cols-1 gap-2 bg-slate-50 p-3.5 rounded-xl border border-slate-200 text-xs font-mono">
                      <div>
                        <span className="text-slate-400">From: </span>
                        <span className="text-slate-900 font-semibold">{activeRecord.sender.raw}</span>
                      </div>
                      <div>
                        <span className="text-slate-400">To: </span>
                        <span className="text-slate-800">{activeRecord.recipients.join(', ') || '(empty)'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400">Originating IP: </span>
                        <span className="text-slate-900 font-bold">
                          {activeRecord.originatingIp || 'None detected in received headers'}
                        </span>
                      </div>
                      {activeRecord.receivedAt && (
                        <div>
                          <span className="text-slate-400">Timestamp: </span>
                          <span className="text-slate-700">{activeRecord.receivedAt}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Authentication Envelope (SPF, DKIM, DMARC) */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                      Email Authentication Status
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {renderAuthPill('SPF', activeRecord.authStatus.spf)}
                      {renderAuthPill('DKIM', activeRecord.authStatus.dkim)}
                      {renderAuthPill('DMARC', activeRecord.authStatus.dmarc)}
                    </div>
                  </div>

                  {/* Threat Factors & Indicators */}
                  {activeRecord.threatIndicators.reasons.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                        Threat Indicators & Risk Factors
                      </h4>
                      <ul className="space-y-1.5 bg-amber-50/60 p-3 rounded-xl border border-amber-200 text-xs text-amber-900">
                        {activeRecord.threatIndicators.reasons.map((reason, i) => (
                          <li key={i} className="flex items-start gap-2">
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-600 flex-shrink-0 mt-0.5" />
                            <span>{reason}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Extracted Hyperlinks (Strictly non-clickable text for SOC security) */}
                  {activeRecord.extractedUrls.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center justify-between">
                        <span>Extracted Hyperlinks ({activeRecord.extractedUrls.length})</span>
                        <span className="text-[10px] text-slate-400 normal-case">
                          * Rendered as plain text to prevent navigation
                        </span>
                      </h4>
                      <div className="space-y-1.5 max-h-40 overflow-y-auto">
                        {activeRecord.extractedUrls.map((url, i) => (
                          <div
                            key={i}
                            className="bg-slate-100 text-slate-800 px-3 py-1.5 rounded-lg text-xs font-mono break-all flex items-center justify-between gap-2 select-all"
                          >
                            <span className="truncate">{url}</span>
                            <button
                              onClick={() => copyToClipboard(url, `url-${i}`)}
                              className="text-slate-400 hover:text-slate-600 flex-shrink-0"
                              title="Copy URL"
                            >
                              {copiedText === `url-${i}` ? (
                                <Check className="w-3.5 h-3.5 text-green-600" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Extracted Attachments */}
                  {activeRecord.attachments.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                        Attachments ({activeRecord.attachments.length})
                      </h4>
                      <div className="space-y-2">
                        {activeRecord.attachments.map((att, i) => (
                          <div
                            key={i}
                            className={`p-3 rounded-xl border text-xs ${
                              att.isSuspicious
                                ? 'bg-red-50/70 border-red-200'
                                : 'bg-slate-50 border-slate-200'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2 font-semibold text-slate-900">
                                <Paperclip className="w-3.5 h-3.5" />
                                <span>{att.filename}</span>
                              </div>
                              <span className="text-slate-500 font-mono text-[11px]">
                                {(att.sizeBytes / 1024).toFixed(1)} KB
                              </span>
                            </div>
                            <div className="mt-1 text-[11px] text-slate-500 font-mono truncate">
                              SHA-256: {att.sha256}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Cryptographic Hashes */}
                  <div className="space-y-2 pt-2 border-t border-slate-200">
                    <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                      Cryptographic Evidence Hashes
                    </h4>
                    <div className="space-y-1.5 font-mono text-[11px]">
                      <div className="bg-slate-100 p-2 rounded-lg flex items-center justify-between text-slate-700">
                        <span className="truncate">SHA-256: {activeRecord.forensicSha256}</span>
                        <button
                          onClick={() => copyToClipboard(activeRecord.forensicSha256, 'sha256')}
                          className="text-slate-400 hover:text-slate-600 ml-2"
                        >
                          {copiedText === 'sha256' ? (
                            <Check className="w-3 h-3 text-green-600" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                      <div className="bg-slate-100 p-2 rounded-lg flex items-center justify-between text-slate-700">
                        <span className="truncate">MD5: {activeRecord.forensicMd5}</span>
                        <button
                          onClick={() => copyToClipboard(activeRecord.forensicMd5, 'md5')}
                          className="text-slate-400 hover:text-slate-600 ml-2"
                        >
                          {copiedText === 'md5' ? (
                            <Check className="w-3 h-3 text-green-600" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </>
              ) : activeDetailTab === 'raw' ? (
                /* Raw RFC-822 Escaped Monospace Viewer */
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                      Unaltered RFC-822 Content
                    </div>
                    {activeRawPayload?.rawEml && (
                      <button
                        onClick={() => copyToClipboard(activeRawPayload.rawEml, 'rawEml')}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 transition-colors"
                      >
                        {copiedText === 'rawEml' ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-green-600" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Raw</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>

                  {loadingRaw ? (
                    <div className="py-16 text-center text-slate-400">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-600 mb-2" />
                      <div>Downloading format=raw RFC-822 representation from Gmail API...</div>
                    </div>
                  ) : activeRawPayload?.rawEml ? (
                    <pre className="p-4 bg-slate-900 text-slate-100 rounded-xl font-mono text-[11px] overflow-x-auto max-h-[500px] leading-relaxed select-all whitespace-pre-wrap">
                      {activeRawPayload.rawEml}
                    </pre>
                  ) : (
                    <div className="text-center py-12 text-slate-400">
                      <FileCode className="w-8 h-8 mx-auto text-slate-300 mb-2" />
                      <div>Raw email content could not be retrieved.</div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-12 text-center text-slate-400">
                  <AlertCircle className="w-8 h-8 mx-auto text-slate-300 mb-2" />
                  <div>Select a message from the queue to inspect forensic results.</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 7. Formal DFIR Case Promotion Confirmation Modal */}
      {confirmPromoteId && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-200 flex items-center justify-between bg-slate-50/60">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-purple-600 text-white flex items-center justify-center flex-shrink-0">
                  <FolderPlus className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 text-sm">
                    Promote Threat to Formal DFIR Case
                  </h3>
                  <div className="text-[11px] text-slate-500">
                    Analyst-Initiated Investigation Promotion
                  </div>
                </div>
              </div>
              <button
                onClick={() => setConfirmPromoteId(null)}
                className="w-8 h-8 rounded-lg hover:bg-slate-200 flex items-center justify-center text-slate-500 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-4">
              <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 text-xs space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400 font-medium">Gmail Message ID:</span>
                  <span className="font-mono font-semibold text-slate-800">{confirmPromoteId}</span>
                </div>
                {triageMap[confirmPromoteId] && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-slate-400 font-medium">Subject:</span>
                      <span className="font-semibold text-slate-900 truncate max-w-xs">
                        {triageMap[confirmPromoteId].subject}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400 font-medium">Determined Threat:</span>
                      <div className="flex items-center gap-1.5">
                        {renderRiskBadge(
                          triageMap[confirmPromoteId].riskLevel,
                          triageMap[confirmPromoteId].riskScore
                        )}
                        <span className="font-bold text-slate-800">
                          {triageMap[confirmPromoteId].threatClassification}
                        </span>
                      </div>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400 font-medium">Sender:</span>
                      <span className="text-slate-800 truncate max-w-xs">
                        {triageMap[confirmPromoteId].sender.fromAddress}
                      </span>
                    </div>
                  </>
                )}
              </div>

              <div className="text-xs text-slate-600 leading-relaxed space-y-2">
                <p>
                  <strong>What happens during case promotion:</strong>
                </p>
                <ul className="list-disc list-inside space-y-1 text-slate-500 text-[11px]">
                  <li>Retrieves the unaltered RFC-822 raw email MIME directly from the Gmail API.</li>
                  <li>Processes email through full CyberTrace forensic pipeline (RFC-822 parsing, IOC extraction, MITRE ATT&CK mapping, infrastructure graph).</li>
                  <li>Appends and cryptographically seals a tamper-evident evidence block in the blockchain ledger.</li>
                  <li>Assigns a formal sequential Case ID and opens full DFIR incident workflow.</li>
                </ul>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-end gap-2.5">
              <button
                type="button"
                onClick={() => setConfirmPromoteId(null)}
                disabled={promotingId === confirmPromoteId}
                className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800 hover:bg-slate-200/60 rounded-xl transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmPromotion}
                disabled={promotingId === confirmPromoteId}
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-purple-600 hover:bg-purple-700 active:scale-95 rounded-xl transition-all shadow-md"
              >
                <FolderPlus className={`w-4 h-4 ${promotingId === confirmPromoteId ? 'animate-spin' : ''}`} />
                <span>{promotingId === confirmPromoteId ? 'Promoting to Case...' : 'Confirm & Promote to Case'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 8. Campaign Detail Modal */}
      {campaignModalOpen && selectedCampaign && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white w-full max-w-3xl rounded-2xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[85vh]">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-indigo-600 text-white flex items-center justify-center shadow-md">
                  <Network className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-indigo-100 text-indigo-800 border border-indigo-200">
                      {selectedCampaign.campaignCode}
                    </span>
                    <h3 className="text-base font-bold text-slate-900">{selectedCampaign.campaignName}</h3>
                  </div>
                  <div className="text-xs text-slate-500 mt-0.5 flex items-center gap-2">
                    <span>Threat Category: <strong className="text-slate-700">{selectedCampaign.threatCategory}</strong></span>
                    <span>•</span>
                    <span>{selectedCampaign.totalMessages} Correlated Messages</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {renderRiskBadge(selectedCampaign.campaignRiskLevel, selectedCampaign.campaignRiskScore)}
                <button
                  type="button"
                  onClick={() => setCampaignModalOpen(false)}
                  className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-200/60 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6">
              {/* Evidence Correlation */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-indigo-600" />
                  <span>Correlation Rationale & Shared Evidence</span>
                </h4>
                <ul className="space-y-1.5 bg-indigo-50/50 p-3.5 rounded-xl border border-indigo-100 text-xs text-slate-700">
                  {selectedCampaign.correlationReasons.map((r, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-indigo-600 flex-shrink-0 mt-0.5" />
                      <span className="font-medium text-slate-800">{r}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Correlated Gmail Messages */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                  <Mail className="w-3.5 h-3.5 text-slate-600" />
                  <span>Correlated Gmail Messages ({selectedCampaign.relatedMessageIds.length})</span>
                </h4>
                <div className="border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-100 text-xs">
                  {selectedCampaign.relatedMessageIds.map(msgId => {
                    const rec = triageMap[msgId];
                    return (
                      <div key={msgId} className="p-3 bg-white flex items-center justify-between gap-3 hover:bg-slate-50">
                        <div className="min-w-0 flex-1">
                          <div className="font-semibold text-slate-900 truncate">
                            {rec ? rec.subject : `Message ${msgId}`}
                          </div>
                          <div className="text-[11px] text-slate-500 truncate flex items-center gap-2 mt-0.5">
                            <span>From: {rec?.sender?.fromAddress || 'Pending'}</span>
                            <span>•</span>
                            <span className="font-mono">ID: {msgId.slice(0, 16)}...</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {renderRiskBadge(rec?.riskLevel, rec?.riskScore)}
                          <button
                            type="button"
                            onClick={() => {
                              setCampaignModalOpen(false);
                              handleInspect(msgId);
                            }}
                            className="px-2.5 py-1 rounded text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200"
                          >
                            Inspect
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Shared Indicators & Threat Intel */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
                  <span>Shared Indicators & Threat Intelligence ({selectedCampaign.sharedIocs.length})</span>
                </h4>
                <div className="border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-100 text-xs">
                  {selectedCampaign.sharedIocs.map(ioc => (
                    <div key={ioc.id} className="p-3 bg-white flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 uppercase">
                            {ioc.type}
                          </span>
                          <span className="font-mono font-semibold text-slate-900 select-all">{ioc.defangedValue}</span>
                        </div>
                        <div className="text-[11px] text-slate-500 mt-0.5">
                          Source: {ioc.threatIntel?.source || 'THREAT INTELLIGENCE UNAVAILABLE'}
                          {ioc.threatIntel?.maliciousCategory ? ` • ${ioc.threatIntel.maliciousCategory}` : ''}
                        </div>
                      </div>
                      <div>{renderReputationBadge(ioc.threatIntel?.reputation)}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-end">
              <button
                type="button"
                onClick={() => setCampaignModalOpen(false)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 shadow-xs transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 8. Google OAuth Setup Guidance Modal */}
      {showOauthSetupModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-xl w-full overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-200 bg-gradient-to-r from-blue-50 to-indigo-50 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-md">
                  <Lock className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-900">Google Cloud OAuth 2.0 Setup Guide</h3>
                  <p className="text-[11px] text-slate-500">Configure credentials to connect live Gmail inboxes</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowOauthSetupModal(false)}
                className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-4 max-h-[75vh] overflow-y-auto text-xs text-slate-700">
              <div className="bg-amber-50 border border-amber-200 rounded-xl p-3.5 flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="font-bold text-amber-900">Why are you seeing this?</div>
                  <div className="text-amber-800 text-[11px] leading-relaxed">
                    Google requires an OAuth 2.0 Client ID and Client Secret registered in Google Cloud Console before allowing third-party applications to request user mailbox access.
                  </div>
                </div>
              </div>

              {/* Step by Step */}
              <div className="space-y-3">
                <h4 className="font-bold text-slate-900 uppercase text-[10px] tracking-wider text-slate-500">
                  Step-by-Step Instructions:
                </h4>

                <div className="space-y-3">
                  <div className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="w-5 h-5 rounded-full bg-blue-600 text-white font-bold text-[10px] flex items-center justify-center flex-shrink-0 mt-0.5">
                      1
                    </div>
                    <div className="space-y-1 flex-1">
                      <div className="font-semibold text-slate-900">Create Google Cloud OAuth Credentials</div>
                      <div className="text-[11px] text-slate-500">
                        Go to <strong>Google Cloud Console</strong> &rarr; <strong>APIs & Services</strong> &rarr; <strong>Credentials</strong> &rarr; <strong>Create Credentials</strong> &rarr; <strong>OAuth client ID</strong>.
                        Select Application type: <strong>Web application</strong>.
                      </div>
                    </div>
                  </div>

                  <div className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="w-5 h-5 rounded-full bg-blue-600 text-white font-bold text-[10px] flex items-center justify-center flex-shrink-0 mt-0.5">
                      2
                    </div>
                    <div className="space-y-1.5 flex-1">
                      <div className="font-semibold text-slate-900">Add Authorized Redirect URI</div>
                      <div className="text-[11px] text-slate-500">
                        In the OAuth Client configuration under <strong>Authorized redirect URIs</strong>, paste the exact callback URI:
                      </div>
                      <div className="flex items-center gap-2 bg-white border border-slate-200 rounded-lg p-2 font-mono text-[11px] text-slate-800">
                        <span className="flex-1 select-all break-all">http://localhost:3000/api/gmail/oauth/callback</span>
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText('http://localhost:3000/api/gmail/oauth/callback');
                            setCopiedOauthUri(true);
                            setTimeout(() => setCopiedOauthUri(false), 2000);
                          }}
                          className="px-2 py-1 bg-slate-100 hover:bg-slate-200 rounded text-slate-700 font-sans font-medium text-[10px] flex items-center gap-1 transition-colors"
                        >
                          {copiedOauthUri ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedOauthUri ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="w-5 h-5 rounded-full bg-blue-600 text-white font-bold text-[10px] flex items-center justify-center flex-shrink-0 mt-0.5">
                      3
                    </div>
                    <div className="space-y-1.5 flex-1">
                      <div className="font-semibold text-slate-900">Add to your project <code>.env</code> file</div>
                      <div className="text-[11px] text-slate-500">
                        Add your Client ID and Client Secret to the project root <code>.env</code> file:
                      </div>
                      <div className="relative bg-slate-900 text-slate-200 rounded-lg p-3 font-mono text-[11px] leading-relaxed">
                        <pre className="overflow-x-auto whitespace-pre">
{`GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-secret-key
GOOGLE_REDIRECT_URI=http://localhost:3000/api/gmail/oauth/callback`}
                        </pre>
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText(`GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com\nGOOGLE_CLIENT_SECRET=GOCSPX-your-secret-key\nGOOGLE_REDIRECT_URI=http://localhost:3000/api/gmail/oauth/callback`);
                            setCopiedEnvSnippet(true);
                            setTimeout(() => setCopiedEnvSnippet(false), 2000);
                          }}
                          className="absolute top-2 right-2 px-2 py-1 bg-slate-800 hover:bg-slate-700 rounded text-slate-300 text-[10px] font-sans font-medium flex items-center gap-1"
                        >
                          {copiedEnvSnippet ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedEnvSnippet ? 'Copied' : 'Copy Template'}</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Instant Alternative: Demo Mailbox */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-emerald-50 to-teal-50 border border-emerald-200 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="font-bold text-emerald-900 flex items-center gap-1.5">
                    <Sparkles className="w-4 h-4 text-emerald-600" />
                    <span>No Google Cloud credentials right now?</span>
                  </div>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded-full">
                    Instant SIH Mode
                  </span>
                </div>
                <p className="text-[11px] text-emerald-800 leading-relaxed">
                  You can immediately test the entire Gmail Threat Monitor, including RFC-822 forensics, heuristic triage, threat campaigns, and 1-click case promotion using the pre-loaded offline demo mailbox.
                </p>
                <button
                  type="button"
                  onClick={handleConnectDemo}
                  disabled={connectingDemo}
                  className="mt-1 w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-700 shadow-xs transition-all"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${connectingDemo ? 'animate-spin' : ''}`} />
                  <span>{connectingDemo ? 'Loading...' : '⚡ Load Simulated Demo Mailbox Now (1-Click)'}</span>
                </button>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-end">
              <button
                type="button"
                onClick={() => setShowOauthSetupModal(false)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 shadow-xs transition-colors"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

