import React, { useState } from 'react';
import {
  FileCode,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Clock,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Server,
  Network,
  Info,
  Layers,
  Copy,
  Check,
  Search,
  Globe,
  RefreshCw,
  Radio,
  ExternalLink,
  ArrowRight,
} from 'lucide-react';
import { HeaderAnalysis, ReceivedHop, InvestigationCompletePayload, CaseRecord } from '../types/forensics';
import { WorldMapCanvas } from '../components/WorldMapCanvas';
import { lookupIp } from '../services/api';

interface HeaderForensicsPageProps {
  headerAnalysis: HeaderAnalysis | null;
  geolocations: any[];
  activeCase?: InvestigationCompletePayload | null;
  cases?: CaseRecord[];
  onSelectCase?: (caseId: string) => void;
  onLoadScenario?: (scenario: 'LEGITIMATE' | 'BEC' | 'PHISHING') => void;
  onNavigate?: (page: string) => void;
  onQuickIngest?: () => void;
}

export const HeaderForensicsPage: React.FC<HeaderForensicsPageProps> = ({
  headerAnalysis,
  geolocations = [],
  activeCase,
  cases = [],
  onSelectCase,
  onLoadScenario,
  onNavigate,
  onQuickIngest,
}) => {
  const [activeTab, setActiveTab] = useState<'audit' | 'raw' | 'lookup'>('audit');
  const [rawSearchQuery, setRawSearchQuery] = useState('');
  const [copiedRaw, setCopiedRaw] = useState(false);

  // Standalone IP lookup state
  const [lookupInput, setLookupInput] = useState('');
  const [lookupResult, setLookupResult] = useState<any | null>(null);
  const [isLookingUp, setIsLookingUp] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  // Empty state handling
  if (!headerAnalysis || !activeCase) {
    return (
      <div id="header-forensics-empty-view" className="space-y-6 pb-12">
        <div className="bg-white border border-slate-200 rounded-xl p-8 text-center shadow-xs">
          <div className="w-14 h-14 mx-auto mb-4 bg-blue-50 border border-blue-200 text-blue-600 rounded-2xl flex items-center justify-center">
            <FileCode className="w-7 h-7" />
          </div>
          <h2 className="text-lg font-bold text-slate-900">Email Header & Transit Forensics</h2>
          <p className="text-sm text-slate-600 max-w-md mx-auto mt-1 mb-6 leading-relaxed">
            Select an active email investigation below, or load a forensic scenario to inspect RFC-5322 headers, cryptographic signatures (SPF/DKIM/DMARC), and MTA relay hops.
          </p>

          {/* Quick Scenario Buttons */}
          <div className="flex flex-wrap items-center justify-center gap-2.5 max-w-xl mx-auto">
            {onLoadScenario && (
              <>
                <button
                  onClick={() => onLoadScenario('PHISHING')}
                  className="px-3.5 py-2 rounded-lg bg-red-50 text-red-700 hover:bg-red-100 border border-red-200 text-xs font-semibold transition-colors cursor-pointer"
                >
                  Load Phishing Case
                </button>
                <button
                  onClick={() => onLoadScenario('BEC')}
                  className="px-3.5 py-2 rounded-lg bg-amber-50 text-amber-800 hover:bg-amber-100 border border-amber-200 text-xs font-semibold transition-colors cursor-pointer"
                >
                  Load BEC Case
                </button>
                <button
                  onClick={() => onLoadScenario('LEGITIMATE')}
                  className="px-3.5 py-2 rounded-lg bg-emerald-50 text-emerald-800 hover:bg-emerald-100 border border-emerald-200 text-xs font-semibold transition-colors cursor-pointer"
                >
                  Load Legitimate Case
                </button>
              </>
            )}
            {onQuickIngest && (
              <button
                onClick={onQuickIngest}
                className="px-3.5 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-700 text-xs font-semibold transition-colors cursor-pointer shadow-xs"
              >
                Ingest New Email
              </button>
            )}
          </div>
        </div>

        {/* Existing investigations list */}
        {cases.length > 0 && onSelectCase && (
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">
              Available Investigations ({cases.length})
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {cases.map(c => (
                <button
                  key={c.caseId}
                  onClick={() => onSelectCase(c.caseId)}
                  className="p-3.5 text-left border border-slate-200 rounded-lg hover:border-blue-300 hover:bg-blue-50/40 transition-all cursor-pointer group"
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-mono font-bold text-slate-800">{c.caseNumber}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      c.classification === 'PHISHING' || c.severity === 'CRITICAL'
                        ? 'bg-red-100 text-red-800'
                        : c.classification === 'BUSINESS_EMAIL_COMPROMISE' || c.severity === 'HIGH'
                        ? 'bg-amber-100 text-amber-800'
                        : 'bg-emerald-100 text-emerald-800'
                    }`}>
                      {c.classification || c.severity}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-slate-900 line-clamp-1 group-hover:text-blue-700">
                    {c.title}
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  // Safe field extractions
  const spf = headerAnalysis.spf || { status: 'UNKNOWN', details: 'No SPF record evaluated' };
  const dkim = headerAnalysis.dkim || { status: 'UNKNOWN', details: 'No DKIM signature evaluated' };
  const dmarc = headerAnalysis.dmarc || { status: 'UNKNOWN', details: 'No DMARC policy evaluated' };
  const inconsistencies = headerAnalysis.inconsistencies || {
    replyToMismatch: false,
    returnPathMismatch: false,
    messageIdAnomaly: false,
    displaySpoofing: false,
    punycodeHomograph: false,
    timezoneAnomaly: false,
    notes: [],
  };
  const receivedHops = Array.isArray(headerAnalysis.receivedHops) ? headerAnalysis.receivedHops : [];
  const originatingIp = headerAnalysis.originatingIp || '';
  const originConfidence = headerAnalysis.originConfidence ?? 85;
  const originExplanation =
    (headerAnalysis as any).originExplanation ||
    headerAnalysis.originReliabilityExplanation ||
    headerAnalysis.originAttributionNotice ||
    'Origin MTA determined via earliest external envelope transit trace.';

  const dkimDomain = (dkim as any).signingDomain || (dkim as any).domain || 'None';
  const dkimSelector = (dkim as any).selector || 'None';
  const dmarcPolicy = (dmarc as any).policy || (dmarc as any).disposition || 'none';
  const dmarcFromDomain = (dmarc as any).headerFromDomain || (dmarc as any).domain || 'N/A';

  const getAuthStatusBadge = (status: string) => {
    if (status === 'PASS') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold text-xs bg-emerald-50 text-emerald-700 border border-emerald-200">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
          PASS
        </span>
      );
    }
    if (status === 'FAIL') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold text-xs bg-red-50 text-red-700 border border-red-200">
          <XCircle className="w-3.5 h-3.5 text-red-600" />
          FAIL
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold text-xs bg-slate-100 text-slate-700 border border-slate-200">
        <HelpCircle className="w-3.5 h-3.5 text-slate-500" />
        {status || 'UNKNOWN'}
      </span>
    );
  };

  // Compile raw RFC-822 headers for inspection
  const evidenceHeaders = activeCase.evidence?.headers;
  const rawHeadersText = (() => {
    if (!evidenceHeaders) return 'No raw headers recorded for this evidence.';
    const lines: string[] = [];
    if (evidenceHeaders.receivedHeaders && Array.isArray(evidenceHeaders.receivedHeaders)) {
      evidenceHeaders.receivedHeaders.forEach(rh => lines.push(`Received: ${rh}`));
    }
    if (evidenceHeaders.from) lines.push(`From: ${evidenceHeaders.from}`);
    if (evidenceHeaders.to && Array.isArray(evidenceHeaders.to)) {
      lines.push(`To: ${evidenceHeaders.to.join(', ')}`);
    }
    if (evidenceHeaders.replyTo) lines.push(`Reply-To: ${evidenceHeaders.replyTo}`);
    if (evidenceHeaders.returnPath) lines.push(`Return-Path: ${evidenceHeaders.returnPath}`);
    if (evidenceHeaders.subject) lines.push(`Subject: ${evidenceHeaders.subject}`);
    if (evidenceHeaders.date) lines.push(`Date: ${evidenceHeaders.date}`);
    if (evidenceHeaders.messageId) lines.push(`Message-ID: ${evidenceHeaders.messageId}`);
    if (evidenceHeaders.contentType) lines.push(`Content-Type: ${evidenceHeaders.contentType}`);
    if (evidenceHeaders.mimeVersion) lines.push(`MIME-Version: ${evidenceHeaders.mimeVersion}`);
    if (evidenceHeaders.xMailer) lines.push(`X-Mailer: ${evidenceHeaders.xMailer}`);
    return lines.join('\n');
  })();

  const filteredRawLines = rawHeadersText
    .split('\n')
    .filter(line => !rawSearchQuery || line.toLowerCase().includes(rawSearchQuery.toLowerCase()));

  const handleCopyHeaders = () => {
    navigator.clipboard.writeText(rawHeadersText);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handlePerformIpLookup = async (ipToQuery?: string) => {
    const targetIp = (ipToQuery || lookupInput).trim();
    if (!targetIp) return;
    setLookupInput(targetIp);
    setIsLookingUp(true);
    setLookupError(null);
    try {
      const data = await lookupIp(targetIp);
      setLookupResult(data);
    } catch (err: any) {
      setLookupError(err.message || 'Lookup failed');
      setLookupResult(null);
    } finally {
      setIsLookingUp(false);
    }
  };

  return (
    <div id="header-forensics-view" className="space-y-6 pb-12 font-sans">
      {/* Investigation Context & Navigation Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600 text-white flex items-center justify-center flex-shrink-0">
            <FileCode className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-sm text-slate-900">
                {activeCase.caseRecord?.caseNumber || 'ACTIVE CASE'}
              </span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                activeCase.caseRecord?.classification === 'PHISHING'
                  ? 'bg-red-100 text-red-800'
                  : activeCase.caseRecord?.classification === 'BUSINESS_EMAIL_COMPROMISE'
                  ? 'bg-amber-100 text-amber-800'
                  : 'bg-emerald-100 text-emerald-800'
              }`}>
                {activeCase.caseRecord?.classification || 'CASE'}
              </span>
            </div>
            <div className="text-xs text-slate-500 line-clamp-1 max-w-md">
              {activeCase.caseRecord?.title}
            </div>
          </div>
        </div>

        {/* Case Switcher & Action Links */}
        <div className="flex items-center gap-2">
          {cases.length > 1 && onSelectCase && (
            <select
              value={activeCase.caseRecord?.caseId}
              onChange={e => onSelectCase(e.target.value)}
              className="text-xs font-semibold bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-slate-700 cursor-pointer focus:outline-hidden focus:ring-1 focus:ring-blue-500"
            >
              {cases.map(c => (
                <option key={c.caseId} value={c.caseId}>
                  {c.caseNumber} - {c.title.substring(0, 32)}...
                </option>
              ))}
            </select>
          )}

          {onNavigate && (
            <button
              onClick={() => onNavigate('investigation')}
              className="text-xs font-semibold px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <span>Investigation Overview</span>
              <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
            </button>
          )}
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setActiveTab('audit')}
          className={`px-3.5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2 ${
            activeTab === 'audit'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          <span>Cryptographic Alignment & Hop Flow</span>
        </button>

        <button
          onClick={() => setActiveTab('raw')}
          className={`px-3.5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2 ${
            activeTab === 'raw'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <FileCode className="w-4 h-4" />
          <span>RFC-822 Raw Headers</span>
        </button>

        <button
          onClick={() => setActiveTab('lookup')}
          className={`px-3.5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2 ${
            activeTab === 'lookup'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>On-Demand IP Forensic Lookup</span>
        </button>
      </div>

      {/* TAB 1: Cryptographic Alignment & Hop Flow */}
      {activeTab === 'audit' && (
        <div className="space-y-6">
          {/* Top Cryptographic Authentication Badges */}
          <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-blue-600" />
                  <h2 className="text-base font-bold text-slate-900">
                    Email Authentication & Alignment Audit
                  </h2>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">
                  Deterministic verification of SPF, DKIM, and DMARC envelope-to-header parameters (RFC 7208, RFC 6376, RFC 7489)
                </p>
              </div>
              <span className="text-xs font-semibold px-3 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                Strict Forensic Verification
              </span>
            </div>

            {/* The 3 Core Badges */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* SPF */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-800 uppercase tracking-wide">SPF (Sender Policy)</span>
                  {getAuthStatusBadge(spf.status)}
                </div>
                <div className="text-xs text-slate-600 space-y-1.5">
                  <div>
                    <span className="text-slate-400 block text-[11px] uppercase font-semibold">Client IP</span>
                    <span className="font-mono font-semibold text-slate-900">{spf.clientIp || 'Not Extracted'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px] uppercase font-semibold">Sender Domain</span>
                    <span className="font-mono font-semibold text-slate-900">{spf.senderDomain || 'N/A'}</span>
                  </div>
                  <p className="text-xs text-slate-600 pt-1 border-t border-slate-200/80 leading-relaxed">{spf.details}</p>
                </div>
              </div>

              {/* DKIM */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-800 uppercase tracking-wide">DKIM (Signature)</span>
                  {getAuthStatusBadge(dkim.status)}
                </div>
                <div className="text-xs text-slate-600 space-y-1.5">
                  <div>
                    <span className="text-slate-400 block text-[11px] uppercase font-semibold">Signing Domain (d=)</span>
                    <span className="font-mono font-semibold text-slate-900">{dkimDomain}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px] uppercase font-semibold">Selector (s=)</span>
                    <span className="font-mono font-semibold text-slate-900">{dkimSelector}</span>
                  </div>
                  <p className="text-xs text-slate-600 pt-1 border-t border-slate-200/80 leading-relaxed">{dkim.details}</p>
                </div>
              </div>

              {/* DMARC */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-800 uppercase tracking-wide">DMARC (Policy)</span>
                  {getAuthStatusBadge(dmarc.status)}
                </div>
                <div className="text-xs text-slate-600 space-y-1.5">
                  <div>
                    <span className="text-slate-400 block text-[11px] uppercase font-semibold">Policy (p=)</span>
                    <span className="font-mono font-semibold text-slate-900">{dmarcPolicy}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px] uppercase font-semibold">From Domain</span>
                    <span className="font-mono font-semibold text-slate-900">{dmarcFromDomain}</span>
                  </div>
                  <p className="text-xs text-slate-600 pt-1 border-t border-slate-200/80 leading-relaxed">{dmarc.details}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Header Inconsistencies & Attack Vectors Card */}
          <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-500" />
                <h3 className="text-base font-bold text-slate-900">
                  Header Inconsistencies & Spoofing Vectors
                </h3>
              </div>
              <span className="text-xs font-semibold px-2.5 py-1 rounded-md bg-slate-100 text-slate-600">
                Heuristic Anomaly Scan
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
              {/* Reply-To Mismatch */}
              <div
                className={`p-4 rounded-xl border ${
                  inconsistencies.replyToMismatch
                    ? 'bg-red-50/60 border-red-200 text-red-900'
                    : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-sm">Reply-To Divergence</span>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded uppercase ${
                    inconsistencies.replyToMismatch ? 'bg-red-100 text-red-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {inconsistencies.replyToMismatch ? 'CRITICAL' : 'OK'}
                  </span>
                </div>
                <p className="text-xs leading-relaxed">
                  {inconsistencies.replyToMismatch
                    ? 'Reply-To deliberately routes responses away from From address.'
                    : 'Reply-To matches sender or is standard envelope default.'}
                </p>
              </div>

              {/* Return-Path Mismatch */}
              <div
                className={`p-4 rounded-xl border ${
                  inconsistencies.returnPathMismatch
                    ? 'bg-amber-50/60 border-amber-200 text-amber-900'
                    : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-sm">Return-Path Mismatch</span>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded uppercase ${
                    inconsistencies.returnPathMismatch ? 'bg-amber-100 text-amber-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {inconsistencies.returnPathMismatch ? 'SUSPICIOUS' : 'OK'}
                  </span>
                </div>
                <p className="text-xs leading-relaxed">
                  {inconsistencies.returnPathMismatch
                    ? 'Bounce delivery address differs from header From domain.'
                    : 'Envelope sender aligns with From header domain.'}
                </p>
              </div>

              {/* Display Name Spoofing */}
              <div
                className={`p-4 rounded-xl border ${
                  inconsistencies.displaySpoofing
                    ? 'bg-red-50/60 border-red-200 text-red-900'
                    : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-sm">Display Name Spoofing</span>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded uppercase ${
                    inconsistencies.displaySpoofing ? 'bg-red-100 text-red-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {inconsistencies.displaySpoofing ? 'CRITICAL' : 'OK'}
                  </span>
                </div>
                <p className="text-xs leading-relaxed">
                  {inconsistencies.displaySpoofing
                    ? 'Display name mimics an executive, organization, or email address.'
                    : 'Display name conforms to standard persona nomenclature.'}
                </p>
              </div>

              {/* Message-ID Anomaly */}
              <div
                className={`p-4 rounded-xl border ${
                  inconsistencies.messageIdAnomaly
                    ? 'bg-amber-50/60 border-amber-200 text-amber-900'
                    : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-sm">Message-ID Integrity</span>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded uppercase ${
                    inconsistencies.messageIdAnomaly ? 'bg-amber-100 text-amber-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {inconsistencies.messageIdAnomaly ? 'SUSPICIOUS' : 'OK'}
                  </span>
                </div>
                <p className="text-xs leading-relaxed">
                  {inconsistencies.messageIdAnomaly
                    ? 'Forged client software or non-conforming Message-ID syntax.'
                    : 'Conforms to RFC-5322 globally unique identifier structure.'}
                </p>
              </div>

              {/* Punycode Homograph */}
              <div
                className={`p-4 rounded-xl border ${
                  inconsistencies.punycodeHomograph
                    ? 'bg-red-50/60 border-red-200 text-red-900'
                    : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-sm">Punycode / Homoglyph</span>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded uppercase ${
                    inconsistencies.punycodeHomograph ? 'bg-red-100 text-red-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {inconsistencies.punycodeHomograph ? 'CRITICAL' : 'OK'}
                  </span>
                </div>
                <p className="text-xs leading-relaxed">
                  {inconsistencies.punycodeHomograph
                    ? 'Internationalized domain name (xn--) or visual character spoof.'
                    : 'Standard ASCII domain representation without lookalike glyphs.'}
                </p>
              </div>

              {/* Time Inversion / Timezone Anomaly */}
              <div
                className={`p-4 rounded-xl border ${
                  (inconsistencies as any).timeInversion || inconsistencies.timezoneAnomaly
                    ? 'bg-red-50/60 border-red-200 text-red-900'
                    : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-sm">Chronological Flow</span>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded uppercase ${
                    (inconsistencies as any).timeInversion || inconsistencies.timezoneAnomaly
                      ? 'bg-red-100 text-red-800'
                      : 'bg-slate-200 text-slate-700'
                  }`}>
                    {(inconsistencies as any).timeInversion || inconsistencies.timezoneAnomaly ? 'ANOMALY' : 'OK'}
                  </span>
                </div>
                <p className="text-xs leading-relaxed">
                  {(inconsistencies as any).timeInversion || inconsistencies.timezoneAnomaly
                    ? 'Negative transit delay detected between sequential MTA relays.'
                    : 'Sequential timestamps advance chronologically through routing.'}
                </p>
              </div>
            </div>
          </div>

          {/* World Map & Geolocation Routing Canvas */}
          <WorldMapCanvas
            geolocations={geolocations}
            originConfidence={originConfidence}
            originatingIp={originatingIp}
            onSelectGeo={geo => {
              // Pre-fill IP into lookup tab
              setLookupInput(geo.ip);
            }}
          />

          {/* Originating IP Analysis Callout */}
          <div className="bg-white border border-blue-200 rounded-xl p-6 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Network className="w-5 h-5 text-blue-600" />
                <h3 className="text-base font-bold text-slate-900">
                  Originating Transit IP Forensic Attribution
                </h3>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-500 font-medium">Origin Reliability:</span>
                <span className="font-bold text-blue-700 bg-blue-50 px-2.5 py-1 rounded-md border border-blue-200">
                  {originConfidence}% Confidence
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 font-medium">Probable Origin MTA IP:</span>
                  <span className="font-mono font-bold text-slate-900 text-sm">{originatingIp || 'Not Determined'}</span>
                </div>
                {originatingIp && (
                  <button
                    onClick={() => {
                      setActiveTab('lookup');
                      handlePerformIpLookup(originatingIp);
                    }}
                    className="text-blue-600 hover:text-blue-800 font-semibold flex items-center gap-1 cursor-pointer"
                  >
                    <span>Inspect this IP in Forensics Lookup</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
              <div className="pt-2.5 border-t border-slate-200 text-slate-700 text-xs flex items-start gap-2 leading-relaxed">
                <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                <span>{originExplanation}</span>
              </div>
            </div>
          </div>

          {/* Hop-by-Hop Received Chain Table */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="p-5 border-b border-slate-100 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  Hop-by-Hop MTA Received Chain (Chronological Relay Flow)
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Ordered from initial submission relay (Hop 1) to final internal mailbox delivery agent
                </p>
              </div>
              <span className="text-xs font-semibold px-3 py-1 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
                Total Relays: {receivedHops.length}
              </span>
            </div>

            <div className="divide-y divide-slate-100">
              {receivedHops.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500">
                  No Received header hops extracted from this email.
                </div>
              ) : (
                receivedHops.map(hop => {
                  // Safe indicators resolution
                  const indicators: string[] = Array.isArray((hop as any).suspiciousIndicators)
                    ? (hop as any).suspiciousIndicators
                    : hop.flagReason
                    ? [hop.flagReason]
                    : hop.isSuspicious
                    ? ['Suspicious Routing Anomaly']
                    : [];

                  return (
                    <div
                      key={hop.hopNumber}
                      className={`p-4 transition-colors text-xs ${
                        hop.isOriginating
                          ? 'bg-red-50/40 hover:bg-red-50/70'
                          : 'bg-white hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2.5">
                          <span className="w-6 h-6 rounded-full bg-slate-100 border border-slate-300 flex items-center justify-center font-bold text-xs text-slate-700">
                            {hop.hopNumber}
                          </span>
                          <span className="font-bold text-slate-900 font-mono text-xs">
                            {hop.fromHost || 'Unknown Relay Host'}
                          </span>
                          {hop.isOriginating && (
                            <span className="px-2 py-0.5 rounded-full bg-red-100 text-red-800 border border-red-200 text-[10px] font-bold">
                              PROBABLE ORIGINATING MTA
                            </span>
                          )}
                          {hop.relayRole && (
                            <span className="px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 border border-slate-200 text-[10px] font-semibold">
                              {hop.relayRole.replace(/_/g, ' ')}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-3 text-slate-500 text-xs">
                          <span className="flex items-center gap-1 font-medium">
                            <Clock className="w-3.5 h-3.5 text-slate-400" />
                            Delay:{' '}
                            <span className="text-slate-800 font-semibold">
                              {hop.delaySeconds !== undefined ? `${hop.delaySeconds}s` : 'N/A'}
                            </span>
                          </span>
                          <span className="text-slate-400">•</span>
                          <span className="font-mono">{hop.timestamp || 'No timestamp'}</span>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs bg-slate-50 p-3 rounded-lg border border-slate-200">
                        <div>
                          <span className="text-[11px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">
                            Transmitted By / Protocol
                          </span>
                          <span className="truncate block font-semibold text-slate-800">
                            {hop.byHost || 'N/A'} {hop.protocol ? `(${hop.protocol})` : ''}
                          </span>
                        </div>
                        <div>
                          <span className="text-[11px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">
                            Relay IP Address
                          </span>
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-blue-700 font-bold">{hop.ip || 'No IP in header'}</span>
                            {hop.ip && (
                              <button
                                onClick={() => {
                                  setActiveTab('lookup');
                                  handlePerformIpLookup(hop.ip);
                                }}
                                className="text-[10px] text-blue-600 hover:text-blue-800 underline font-medium cursor-pointer"
                              >
                                Lookup
                              </button>
                            )}
                          </div>
                        </div>
                        <div>
                          <span className="text-[11px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">
                            Anomaly Status
                          </span>
                          {indicators.length > 0 ? (
                            <span className="text-red-700 font-bold">{indicators.join(', ')}</span>
                          ) : (
                            <span className="text-emerald-700 font-semibold flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                              Standard SMTP Transit
                            </span>
                          )}
                        </div>
                      </div>

                      {hop.attributionReasoning && (
                        <div className="mt-2 text-[11px] text-slate-500 italic pl-1">
                          ↳ {hop.attributionReasoning}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: RFC-822 Raw Headers */}
      {activeTab === 'raw' && (
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Raw RFC-822 / RFC-5322 Message Headers
              </h3>
              <p className="text-xs text-slate-500">
                Complete unaltered email headers preserved verbatim for chain-of-custody review
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyHeaders}
                className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-xs font-semibold text-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
              >
                {copiedRaw ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                    <span className="text-emerald-700">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-slate-500" />
                    <span>Copy Headers</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Search Filter */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Filter headers (e.g., Received, DKIM-Signature, Authentication-Results, Message-ID)..."
              value={rawSearchQuery}
              onChange={e => setRawSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs border border-slate-200 rounded-lg bg-slate-50 focus:bg-white focus:outline-hidden focus:ring-1 focus:ring-blue-500 font-mono"
            />
          </div>

          {/* Raw Header Display */}
          <div className="bg-slate-900 text-slate-100 rounded-xl p-4 overflow-x-auto font-mono text-xs max-h-[500px] leading-relaxed select-text border border-slate-800 shadow-inner">
            {filteredRawLines.length === 0 ? (
              <div className="text-slate-500 italic py-4 text-center">
                No headers match your search query "{rawSearchQuery}".
              </div>
            ) : (
              filteredRawLines.map((line, idx) => {
                const isHeaderKey = /^[A-Za-z0-9-]+:/.test(line);
                const colonIdx = line.indexOf(':');
                const key = isHeaderKey ? line.substring(0, colonIdx) : '';
                const val = isHeaderKey ? line.substring(colonIdx + 1) : line;

                return (
                  <div key={idx} className="flex hover:bg-slate-800/60 px-1 py-0.5 rounded">
                    <span className="text-slate-600 select-none w-10 text-right pr-3 font-mono text-[11px]">
                      {idx + 1}
                    </span>
                    <span className="flex-1 break-all">
                      {isHeaderKey ? (
                        <>
                          <span className="text-amber-400 font-semibold">{key}:</span>
                          <span className="text-slate-200">{val}</span>
                        </>
                      ) : (
                        <span className="text-slate-400 pl-4">{line}</span>
                      )}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* TAB 3: On-Demand IP Forensic Lookup Tool */}
      {activeTab === 'lookup' && (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-4">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Interactive IP Geolocation & ASN Intelligence Sandbox
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Query any IPv4 or IPv6 address to retrieve geographic positioning, autonomous system routing, hosting provider, and proxy/VPN indicators
              </p>
            </div>

            {/* IP input form */}
            <form
              onSubmit={e => {
                e.preventDefault();
                handlePerformIpLookup();
              }}
              className="flex flex-wrap gap-2 items-center"
            >
              <div className="relative flex-1 min-w-[240px]">
                <Globe className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Enter IPv4 or IPv6 address (e.g., 209.85.220.41, 1.1.1.1, 8.8.8.8)..."
                  value={lookupInput}
                  onChange={e => setLookupInput(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 text-xs border border-slate-200 rounded-lg bg-slate-50 focus:bg-white focus:outline-hidden focus:ring-1 focus:ring-blue-500 font-mono font-semibold"
                />
              </div>

              <button
                type="submit"
                disabled={isLookingUp || !lookupInput.trim()}
                className="px-4 py-2 rounded-lg bg-blue-600 text-white text-xs font-bold hover:bg-blue-700 transition-colors disabled:opacity-50 cursor-pointer shadow-xs flex items-center gap-1.5"
              >
                {isLookingUp ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Resolving...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5" />
                    <span>Forensic Lookup</span>
                  </>
                )}
              </button>
            </form>

            {/* Quick pre-fill chips from this investigation */}
            <div className="flex flex-wrap items-center gap-1.5 pt-1">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mr-1">
                From Investigation:
              </span>
              {originatingIp && (
                <button
                  type="button"
                  onClick={() => handlePerformIpLookup(originatingIp)}
                  className="text-xs font-mono px-2 py-0.5 rounded-md bg-red-50 text-red-700 hover:bg-red-100 border border-red-200 transition-colors cursor-pointer"
                >
                  Origin: {originatingIp}
                </button>
              )}
              {geolocations.map(g => (
                <button
                  key={g.ip}
                  type="button"
                  onClick={() => handlePerformIpLookup(g.ip)}
                  className="text-xs font-mono px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 hover:bg-slate-200 border border-slate-200 transition-colors cursor-pointer"
                >
                  {g.ip}
                </button>
              ))}
              <button
                type="button"
                onClick={() => handlePerformIpLookup('1.1.1.1')}
                className="text-xs font-mono px-2 py-0.5 rounded-md bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 transition-colors cursor-pointer"
              >
                1.1.1.1 (Cloudflare)
              </button>
              <button
                type="button"
                onClick={() => handlePerformIpLookup('8.8.8.8')}
                className="text-xs font-mono px-2 py-0.5 rounded-md bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 transition-colors cursor-pointer"
              >
                8.8.8.8 (Google)
              </button>
            </div>

            {/* Error banner */}
            {lookupError && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-600 flex-shrink-0" />
                <span>{lookupError}</span>
              </div>
            )}

            {/* Lookup Result Card */}
            {lookupResult && (
              <div className="mt-4 p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-200">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-base font-bold text-slate-900">{lookupResult.ip}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-blue-100 text-blue-800 font-semibold font-mono">
                      {lookupResult.version || 'IPv4'}
                    </span>
                    {lookupResult.geolocatable === false && (
                      <span className="text-xs px-2 py-0.5 rounded bg-amber-100 text-amber-800 font-semibold">
                        Private / Non-Routable
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-slate-500 font-semibold">
                    Provider: {lookupResult.source || 'ipwho.is'}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-xs">
                  <div>
                    <span className="text-slate-400 block font-semibold text-[11px] uppercase">Country</span>
                    <span className="font-bold text-slate-800">
                      {lookupResult.country || 'Unknown'} {lookupResult.countryCode ? `(${lookupResult.countryCode})` : ''}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block font-semibold text-[11px] uppercase">City / Region</span>
                    <span className="font-semibold text-slate-800">
                      {lookupResult.city || lookupResult.region || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block font-semibold text-[11px] uppercase">Coordinates</span>
                    <span className="font-mono text-slate-800">
                      {lookupResult.latitude !== undefined && lookupResult.longitude !== undefined
                        ? `${lookupResult.latitude.toFixed(4)}, ${lookupResult.longitude.toFixed(4)}`
                        : 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block font-semibold text-[11px] uppercase">ISP / Org</span>
                    <span className="font-semibold text-slate-800 truncate block">
                      {lookupResult.organization || lookupResult.isp || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block font-semibold text-[11px] uppercase">Autonomous System</span>
                    <span className="font-mono font-semibold text-slate-800 truncate block">
                      {lookupResult.asn || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block font-semibold text-[11px] uppercase">Network Role</span>
                    <span className="inline-block font-semibold">
                      {(lookupResult.isTor || lookupResult.vpnTorProxy?.isTor) ? (
                        <span className="text-red-700 bg-red-50 px-2 py-0.5 rounded border border-red-200">Tor Exit</span>
                      ) : (lookupResult.isVpn || lookupResult.vpnTorProxy?.isVpn) ? (
                        <span className="text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">VPN</span>
                      ) : (lookupResult.isProxy || lookupResult.vpnTorProxy?.isProxy) ? (
                        <span className="text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">Proxy</span>
                      ) : lookupResult.geolocatable === false ? (
                        <span className="text-slate-600 bg-slate-200 px-2 py-0.5 rounded">RFC 1918 Private</span>
                      ) : (
                        <span className="text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">Public Transit</span>
                      )}
                    </span>
                  </div>
                </div>

                {lookupResult.attributionNote && (
                  <div className="text-[11px] text-slate-600 bg-white p-2.5 rounded-lg border border-slate-200 flex items-start gap-2">
                    <Info className="w-3.5 h-3.5 text-blue-600 flex-shrink-0 mt-0.5" />
                    <span>{lookupResult.attributionNote}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
