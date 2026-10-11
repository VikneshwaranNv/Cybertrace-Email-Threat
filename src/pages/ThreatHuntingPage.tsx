import React, { useState, useEffect } from 'react';
import {
  Search,
  Crosshair,
  ShieldAlert,
  Flame,
  Filter,
  CheckCircle2,
  ExternalLink,
  Tag,
  Clock,
  Layers,
  Fingerprint,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import {
  CaseRecord,
  HuntResult,
  IOCHit,
  CampaignLink,
  RiskLevel,
  ThreatClassification,
} from '../types/forensics';
import { huntThreats } from '../services/api';

interface ThreatHuntingPageProps {
  onSelectCase: (caseId: string) => void;
  onNavigate: (page: any) => void;
}

export const ThreatHuntingPage: React.FC<ThreatHuntingPageProps> = ({
  onSelectCase,
  onNavigate,
}) => {
  const [query, setQuery] = useState('');
  const [selectedRiskLevels, setSelectedRiskLevels] = useState<RiskLevel[]>([]);
  const [selectedThreatType, setSelectedThreatType] = useState<string>('ALL');
  const [minScore, setMinScore] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<'cases' | 'iocs' | 'campaigns'>('cases');

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<HuntResult | null>(null);

  // Detect if query is in defanged format
  const isDefanged =
    query.includes('[.]') ||
    query.includes('hxxp') ||
    query.includes('[@]') ||
    query.includes('[:]');

  const executeSearch = async () => {
    setLoading(true);
    try {
      const data = await huntThreats({
        q: query.trim() || undefined,
        riskLevels: selectedRiskLevels.length > 0 ? selectedRiskLevels : undefined,
        threatTypes:
          selectedThreatType !== 'ALL'
            ? [selectedThreatType as ThreatClassification]
            : undefined,
        minRiskScore: minScore > 0 ? minScore : undefined,
        limit: 50,
      });
      setResult(data);
    } catch (err) {
      console.error('Threat hunt failed:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    executeSearch();
  }, []);

  const toggleRiskLevel = (lvl: RiskLevel) => {
    setSelectedRiskLevels((prev) =>
      prev.includes(lvl) ? prev.filter((x) => x !== lvl) : [...prev, lvl]
    );
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      executeSearch();
    }
  };

  const threatTypeOptions = [
    'ALL',
    'PHISHING',
    'BUSINESS_EMAIL_COMPROMISE',
    'EXECUTIVE_IMPERSONATION',
    'CREDENTIAL_HARVESTING',
    'MALICIOUS_LINK',
    'SUSPICIOUS_ATTACHMENT',
    'SPOOFING',
    'LEGITIMATE',
  ];

  return (
    <div id="threat-hunting-view" className="space-y-6 max-w-7xl mx-auto font-sans pb-12">
      {/* Header Banner */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-blue-600 text-white flex items-center justify-center flex-shrink-0 shadow-sm">
              <Crosshair className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
                Threat Hunting & Correlation Engine
              </h1>
              <p className="text-xs sm:text-sm text-slate-500 mt-1">
                Fast, deterministic cross-case indicator hunting, domain correlation & campaign telemetry.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-3 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-semibold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Deterministic Engine
            </span>
          </div>
        </div>

        {/* Search Bar */}
        <div className="mt-6 space-y-2">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="w-5 h-5 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Hunt across IOCs, domains, hashes, senders, subject lines, or case IDs (e.g. hxxp://evil[.]com, 192.168.1.1)..."
                className="w-full pl-11 pr-4 py-3 bg-slate-50 border border-slate-300 rounded-xl text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-all font-mono"
              />
            </div>
            <button
              onClick={executeSearch}
              disabled={loading}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white text-sm font-semibold rounded-xl flex items-center gap-2 transition-colors cursor-pointer shadow-xs disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              <span>Hunt</span>
            </button>
          </div>

          {/* Defang Normalization Indicator */}
          {isDefanged && (
            <div className="text-xs text-blue-700 bg-blue-50 border border-blue-200 rounded-lg px-3 py-1.5 flex items-center gap-2 font-mono">
              <Sparkles className="w-3.5 h-3.5 text-blue-600" />
              <span>Defanged indicator format detected — automatically refanged and normalized for cross-evidence search.</span>
            </div>
          )}
        </div>

        {/* Filter Controls */}
        <div className="mt-5 pt-4 border-t border-slate-100 flex flex-wrap items-center justify-between gap-4 text-xs">
          {/* Risk Level Pills */}
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-600">Risk Filter:</span>
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as RiskLevel[]).map((lvl) => {
              const active = selectedRiskLevels.includes(lvl);
              return (
                <button
                  key={lvl}
                  onClick={() => toggleRiskLevel(lvl)}
                  className={`px-2.5 py-1 rounded-lg border font-bold text-[11px] transition-colors cursor-pointer ${
                    active
                      ? lvl === 'CRITICAL'
                        ? 'bg-red-600 text-white border-red-600'
                        : lvl === 'HIGH'
                        ? 'bg-amber-500 text-white border-amber-500'
                        : 'bg-blue-600 text-white border-blue-600'
                      : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {lvl}
                </button>
              );
            })}
          </div>

          {/* Threat Type Selector */}
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-600">Threat Type:</span>
            <select
              value={selectedThreatType}
              onChange={(e) => setSelectedThreatType(e.target.value)}
              className="bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1 text-xs text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer"
            >
              {threatTypeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </div>

          {/* Score Slider */}
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-600">Min Risk:</span>
            <input
              type="range"
              min="0"
              max="90"
              step="10"
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              className="w-24 accent-blue-600 cursor-pointer"
            />
            <span className="font-mono text-slate-700 w-8 text-right">{minScore}+</span>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      {result && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs text-slate-500 font-medium">Matching Cases</div>
            <div className="text-2xl font-bold text-slate-900 mt-1">{result.totalMatches}</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs text-slate-500 font-medium">Correlated Indicators</div>
            <div className="text-2xl font-bold text-blue-600 mt-1">{result.iocHits.length}</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs text-slate-500 font-medium">Campaign Links</div>
            <div className="text-2xl font-bold text-purple-600 mt-1">{result.campaignLinks.length}</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs text-slate-500 font-medium">Query Latency</div>
            <div className="text-2xl font-bold text-emerald-600 mt-1">{result.durationMs} ms</div>
          </div>
        </div>
      )}

      {/* Tabs Header */}
      <div className="flex border-b border-slate-200 gap-4 text-sm font-semibold">
        <button
          onClick={() => setActiveTab('cases')}
          className={`pb-3 flex items-center gap-2 cursor-pointer border-b-2 transition-colors ${
            activeTab === 'cases'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Cases ({result?.cases.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('iocs')}
          className={`pb-3 flex items-center gap-2 cursor-pointer border-b-2 transition-colors ${
            activeTab === 'iocs'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Crosshair className="w-4 h-4" />
          <span>IOC Hits ({result?.iocHits.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('campaigns')}
          className={`pb-3 flex items-center gap-2 cursor-pointer border-b-2 transition-colors ${
            activeTab === 'campaigns'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Fingerprint className="w-4 h-4" />
          <span>Campaigns ({result?.campaignLinks.length || 0})</span>
        </button>
      </div>

      {/* Tab Content: Cases */}
      {activeTab === 'cases' && (
        <div className="space-y-3">
          {result && result.cases.length > 0 ? (
            result.cases.map((c) => (
              <div
                key={c.caseId}
                className="bg-white border border-slate-200 rounded-xl p-4 sm:p-5 flex flex-wrap items-center justify-between gap-4 shadow-xs hover:border-blue-300 transition-all"
              >
                <div className="space-y-1.5 min-w-0">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2.5 py-0.5 rounded-md bg-blue-50 text-blue-700 font-mono text-xs font-bold border border-blue-200">
                      {c.caseNumber}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        c.severity === 'CRITICAL'
                          ? 'bg-red-100 text-red-800'
                          : c.severity === 'HIGH'
                          ? 'bg-amber-100 text-amber-800'
                          : 'bg-blue-100 text-blue-800'
                      }`}
                    >
                      {c.severity}
                    </span>
                    <span className="text-xs text-slate-500 font-medium">
                      Risk: {c.riskScore}/100
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 truncate">
                    {c.title}
                  </h3>
                  <div className="flex items-center gap-4 text-xs text-slate-500">
                    <span>Classification: <strong className="text-slate-700">{c.classification}</strong></span>
                    <span>Status: <strong className="text-slate-700">{c.status}</strong></span>
                    <span>Analyst: <strong className="text-slate-700">{c.assignedTo}</strong></span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      onSelectCase(c.caseId);
                      onNavigate('investigation');
                    }}
                    className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <span>Investigate</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))
          ) : (
            <div className="p-12 text-center text-slate-500 bg-white border border-slate-200 rounded-xl shadow-xs">
              No matching cases found. Adjust your search query or broaden filter parameters.
            </div>
          )}
        </div>
      )}

      {/* Tab Content: IOC Hits */}
      {activeTab === 'iocs' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
          {result && result.iocHits.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase">
                  <tr>
                    <th className="py-3 px-4">Defanged Indicator</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Reputation</th>
                    <th className="py-3 px-4">Case Frequency</th>
                    <th className="py-3 px-4">Referenced In</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono">
                  {result.iocHits.map((ioc, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80">
                      <td className="py-3 px-4 font-bold text-slate-900">{ioc.defangedValue}</td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px]">
                          {ioc.type}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            ioc.reputation === 'MALICIOUS'
                              ? 'bg-red-100 text-red-800'
                              : ioc.reputation === 'SUSPICIOUS'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-slate-100 text-slate-700'
                          }`}
                        >
                          {ioc.reputation}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-bold text-blue-600">{ioc.caseCount} case(s)</td>
                      <td className="py-3 px-4 text-slate-500 text-[11px]">
                        {ioc.caseIds.join(', ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-12 text-center text-slate-500">
              No matching indicators identified.
            </div>
          )}
        </div>
      )}

      {/* Tab Content: Campaigns */}
      {activeTab === 'campaigns' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
          {result && result.campaignLinks.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase">
                  <tr>
                    <th className="py-3 px-4">Campaign Name</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Risk Score</th>
                    <th className="py-3 px-4">Associated Cases</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono">
                  {result.campaignLinks.map((cmp) => (
                    <tr key={cmp.campaignId} className="hover:bg-slate-50/80">
                      <td className="py-3 px-4 font-bold text-slate-900">{cmp.name}</td>
                      <td className="py-3 px-4 text-slate-600">{cmp.threatCategory}</td>
                      <td className="py-3 px-4 font-bold text-purple-700">{cmp.riskScore} / 100</td>
                      <td className="py-3 px-4 text-slate-500 text-[11px]">
                        {cmp.caseIds.join(', ')} ({cmp.caseCount} total)
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-12 text-center text-slate-500">
              No active threat campaigns linked to current search results.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
