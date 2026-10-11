import React, { useState } from 'react';
import {
  Crosshair,
  Search,
  Filter,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Radio,
  ExternalLink,
  Layers,
  Database,
  Info,
  Copy,
  Hash,
  Clock,
  ShieldX,
  RefreshCw,
} from 'lucide-react';
import { NormalizedIOC } from '../types/forensics';

interface ThreatIntelligencePageProps {
  iocs: NormalizedIOC[];
}

export const ThreatIntelligencePage: React.FC<ThreatIntelligencePageProps> = ({ iocs }) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [filterReputation, setFilterReputation] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredIocs = iocs.filter(ioc => {
    if (filterType !== 'ALL' && ioc.type !== filterType) return false;
    if (filterReputation !== 'ALL' && ioc.reputation !== filterReputation) return false;
    if (filterStatus !== 'ALL' && ioc.enrichmentStatus !== filterStatus) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        ioc.value.toLowerCase().includes(q) ||
        ioc.type.toLowerCase().includes(q) ||
        ioc.source.toLowerCase().includes(q) ||
        (ioc.relatedThreats && ioc.relatedThreats.some(t => t.toLowerCase().includes(q)))
      );
    }
    return true;
  });

  const getReputationBadge = (rep: NormalizedIOC['reputation']) => {
    switch (rep) {
      case 'MALICIOUS':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
            MALICIOUS
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
            SUSPICIOUS
          </span>
        );
      case 'BENIGN':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            BENIGN
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
            UNKNOWN
          </span>
        );
    }
  };

  const getStatusBadge = (status: NormalizedIOC['enrichmentStatus']) => {
    if (status === 'ENRICHED') {
      return (
        <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
          <CheckCircle2 className="w-3 h-3 text-emerald-600" /> ENRICHED
        </span>
      );
    }
    if (status === 'THREAT INTELLIGENCE UNAVAILABLE') {
      return (
        <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-red-50 text-red-700 border border-red-200 flex items-center gap-1">
          <ShieldX className="w-3 h-3 text-red-600" /> FEED OFFLINE
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-slate-100 text-slate-600 border border-slate-200 flex items-center gap-1">
        <Clock className="w-3 h-3 text-slate-500" /> {status}
      </span>
    );
  };

  const copyVal = (val: string, id: string) => {
    navigator.clipboard.writeText(val);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const enrichedCount = iocs.filter(i => i.enrichmentStatus === 'ENRICHED').length;
  const unavailableCount = iocs.filter(i => i.enrichmentStatus === 'THREAT INTELLIGENCE UNAVAILABLE').length;
  const maliciousCount = iocs.filter(i => i.reputation === 'MALICIOUS').length;

  return (
    <div id="threat-intel-view" className="space-y-6 pb-12">
      {/* Top Banner with Provider Telemetry */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center flex-shrink-0">
              <Crosshair className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Threat Intelligence & Normalized IOC Engine
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Multi-provider telemetry supporting IPv4/IPv6, Domains, URLs, File Hashes, and Email Identifiers
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-700 flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-blue-600" />
              AbuseIPDB • AlienVault OTX • VirusTotal
            </span>
          </div>
        </div>

        {/* Status Indicators Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Total Extracted IOCs</span>
            <span className="text-2xl font-bold text-slate-900">{iocs.length}</span>
          </div>
          <div className="p-4 rounded-xl bg-emerald-50/50 border border-emerald-200">
            <span className="text-xs font-semibold text-emerald-800 uppercase tracking-wider block mb-1">Enriched Telemetry</span>
            <span className="text-2xl font-bold text-emerald-700">{enrichedCount}</span>
          </div>
          <div className="p-4 rounded-xl bg-red-50/50 border border-red-200">
            <span className="text-xs font-semibold text-red-800 uppercase tracking-wider block mb-1">Malicious Detections</span>
            <span className="text-2xl font-bold text-red-700">{maliciousCount}</span>
          </div>
          <div className="p-4 rounded-xl bg-amber-50/50 border border-amber-200">
            <span className="text-xs font-semibold text-amber-800 uppercase tracking-wider block mb-1">Feeds Unavailable</span>
            <span className="text-2xl font-bold text-amber-700">{unavailableCount}</span>
          </div>
        </div>

        {/* Transparency Disclaimer */}
        <div className="p-3.5 rounded-xl bg-blue-50/60 border border-blue-200 text-xs text-blue-900 flex items-start gap-2.5">
          <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
          <div className="leading-relaxed">
            <strong>Evidence Transparency Notice:</strong> Threat intelligence provides historical and external behavioral telemetry. If live external API keys are offline, results are strictly labeled <span className="font-semibold text-red-700">FEED OFFLINE</span> or grounded in deterministic offline hash and domain reputation records.
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2.5 flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search indicators by value, type, source, or threat..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-600"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-xs font-medium text-slate-500">Type:</span>
            <select
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
              className="bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs text-slate-800 font-medium focus:outline-none focus:border-blue-600"
            >
              <option value="ALL">All Types</option>
              <option value="ipv4">IPv4</option>
              <option value="ipv6">IPv6</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash_sha256">SHA-256</option>
              <option value="hash_md5">MD5</option>
              <option value="email">Email</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs font-medium text-slate-500">Reputation:</span>
            <select
              value={filterReputation}
              onChange={e => setFilterReputation(e.target.value)}
              className="bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs text-slate-800 font-medium focus:outline-none focus:border-blue-600"
            >
              <option value="ALL">All Reputations</option>
              <option value="MALICIOUS">Malicious</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="BENIGN">Benign</option>
              <option value="UNKNOWN">Unknown</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs font-medium text-slate-500">Enrichment:</span>
            <select
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value)}
              className="bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs text-slate-800 font-medium focus:outline-none focus:border-blue-600"
            >
              <option value="ALL">All Statuses</option>
              <option value="ENRICHED">Enriched</option>
              <option value="THREAT INTELLIGENCE UNAVAILABLE">Unavailable</option>
              <option value="PENDING">Pending</option>
            </select>
          </div>
        </div>
      </div>

      {/* Normalized IOC Cards */}
      <div className="space-y-3">
        {filteredIocs.length === 0 ? (
          <div className="p-12 text-center bg-white border border-slate-200 rounded-xl shadow-sm">
            <Crosshair className="w-10 h-10 text-slate-300 mx-auto mb-2" />
            <p className="text-sm font-semibold text-slate-700">No indicators match the selected filters</p>
            <p className="text-xs text-slate-400 mt-1">Try resetting the filter criteria or searching for another term.</p>
          </div>
        ) : (
          filteredIocs.map(ioc => (
            <div
              key={ioc.id}
              className={`p-5 rounded-xl border transition-all shadow-xs ${
                ioc.reputation === 'MALICIOUS'
                  ? 'bg-white border-red-200 hover:border-red-300'
                  : ioc.reputation === 'SUSPICIOUS'
                  ? 'bg-white border-amber-200 hover:border-amber-300'
                  : 'bg-white border-slate-200 hover:border-slate-300'
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-2 max-w-3xl">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded-md bg-slate-100 text-slate-700 text-xs font-semibold uppercase">
                      {ioc.type.replace('_', ' ')}
                    </span>
                    {getReputationBadge(ioc.reputation)}
                    {getStatusBadge(ioc.enrichmentStatus)}
                    {ioc.isSimulated ? (
                      <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-purple-50 text-purple-700 border border-purple-200">
                        TRAINING CASE DATA
                      </span>
                    ) : (
                      <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                        OBSERVED EVIDENCE
                      </span>
                    )}
                    <span className="text-slate-500 text-xs">
                      Provider: <strong className="text-slate-800">{ioc.source}</strong>
                    </span>
                  </div>

                  {/* IOC Value */}
                  <div className="flex items-center gap-2 pt-1">
                    <span className="text-sm font-bold text-slate-900 font-mono break-all select-all">
                      {ioc.value}
                    </span>
                    <button
                      onClick={() => copyVal(ioc.value, ioc.id)}
                      className="p-1 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 flex-shrink-0 transition-colors cursor-pointer"
                      title="Copy indicator"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                    {copiedId === ioc.id && (
                      <span className="text-xs text-emerald-600 font-medium">Copied!</span>
                    )}
                  </div>
                </div>

                {/* Score & Confidence */}
                <div className="text-right flex flex-col items-end">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Confidence</span>
                  <div className="text-xl font-extrabold font-mono">
                    <span
                      className={
                        ioc.reputation === 'MALICIOUS'
                          ? 'text-red-600'
                          : ioc.reputation === 'SUSPICIOUS'
                          ? 'text-amber-600'
                          : 'text-emerald-600'
                      }
                    >
                      {ioc.confidence}%
                    </span>
                  </div>
                  <span className="text-xs text-slate-400 mt-0.5">
                    {ioc.timestamp ? ioc.timestamp.substring(0, 10) : '2026-09'}
                  </span>
                </div>
              </div>

              {/* Normalized Details: First Seen, Last Seen, Related Threats */}
              <div className="mt-4 pt-3.5 border-t border-slate-100 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div>
                  <span className="text-slate-400 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Temporal History</span>
                  <span className="text-slate-700">
                    First: {ioc.firstSeen || 'Not indexed'} • Last: {ioc.lastSeen || 'Recent'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Related Threats / Vectors</span>
                  <span className="text-slate-900 font-medium">
                    {ioc.relatedThreats && ioc.relatedThreats.length > 0
                      ? ioc.relatedThreats.join(', ')
                      : 'None identified'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Evidence Reference</span>
                  <span className="text-blue-700 font-mono">
                    {ioc.evidenceReferences && ioc.evidenceReferences.length > 0
                      ? ioc.evidenceReferences.join('; ')
                      : 'Parsed from RFC-822 message envelope'}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
