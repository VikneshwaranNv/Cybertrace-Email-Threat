import React, { useState } from 'react';
import {
  Fingerprint,
  ShieldAlert,
  AlertTriangle,
  Layers,
  Info,
  ExternalLink,
  CheckCircle2,
  HelpCircle,
  Database,
  ArrowRight,
  TrendingUp,
  Cpu,
  Search,
  Calendar,
  Network,
} from 'lucide-react';
import { CampaignMatch } from '../types/forensics';

interface CampaignDnaPageProps {
  campaignMatches: CampaignMatch[];
  onSelectCase?: (caseId: string) => void;
}

export const CampaignDnaPage: React.FC<CampaignDnaPageProps> = ({
  campaignMatches = [],
  onSelectCase,
}) => {
  const safeMatches = Array.isArray(campaignMatches) ? campaignMatches : [];
  const [selectedCampaign, setSelectedCampaign] = useState<CampaignMatch | null>(
    safeMatches[0] || null
  );

  return (
    <div id="campaign-dna-view" className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-purple-50 text-purple-600 flex items-center justify-center flex-shrink-0">
              <Fingerprint className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Campaign Intelligence & Cross-Case Correlation Engine
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Multi-dimensional correlation with strict separation of factual observed evidence vs probabilistic AI inferences
              </p>
            </div>
          </div>

          <span className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-purple-50 text-purple-700 border border-purple-200">
            APT Fingerprint Correlation
          </span>
        </div>

        {/* Evidence Separation Notice */}
        <div className="p-3.5 rounded-xl bg-purple-50/50 border border-purple-200 text-xs text-purple-900 flex items-start gap-2.5">
          <Info className="w-4 h-4 text-purple-600 mt-0.5 flex-shrink-0" />
          <div className="leading-relaxed">
            <strong>Evidence Reliability Mandate:</strong> Campaign matches strictly delineate <span className="text-blue-700 font-bold">Observed Correlation</span> (reproducible mathematical facts such as shared CIDRs, domains, or hashes) from <span className="text-purple-700 font-bold">AI Inference</span> (probabilistic behavioral hypotheses). AI inferences are non-definitive.
          </div>
        </div>
      </div>

      {safeMatches.length === 0 ? (
        <div className="p-12 text-center bg-white border border-slate-200 rounded-xl shadow-sm space-y-3">
          <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-slate-900">No Known Campaign Correlated</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            This communication does not exhibit structural or infrastructure signatures matching registered high-risk cybercrime syndicates.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Matched Campaigns List */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
              Correlated Threat Syndicates ({safeMatches.length})
            </h3>

            {safeMatches.map(camp => {
              const isSelected = selectedCampaign?.campaignId === camp.campaignId;
              return (
                <button
                  key={camp.campaignId}
                  onClick={() => setSelectedCampaign(camp)}
                  className={`w-full text-left p-4 rounded-xl border transition-all cursor-pointer shadow-xs ${
                    isSelected
                      ? 'bg-purple-50/60 border-purple-400 ring-1 ring-purple-300'
                      : 'bg-white border-slate-200 hover:border-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-900 font-mono">{camp.campaignCode}</span>
                    <span
                      className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${
                        camp.severity === 'CRITICAL'
                          ? 'bg-red-50 text-red-700 border-red-200'
                          : 'bg-amber-50 text-amber-700 border-amber-200'
                      }`}
                    >
                      {camp.severity}
                    </span>
                  </div>

                  <p className="text-xs text-slate-700 mb-2.5 font-semibold">{camp.name}</p>

                  <div className="flex items-center justify-between pt-2.5 border-t border-slate-100 text-xs">
                    <span className="text-slate-500">Similarity Score:</span>
                    <span className="font-bold text-purple-700 text-sm font-mono">
                      {camp.similarityScore}% Match
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Right: Detailed Comparison with Strict Evidence Separation */}
          {selectedCampaign && (
            <div className="lg:col-span-2 space-y-5">
              {/* Main Match Header Card */}
              <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-100">
                  <div>
                    <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200 uppercase font-mono">
                      Campaign ID: {selectedCampaign.campaignId}
                    </span>
                    <h3 className="text-lg font-bold text-slate-900 mt-2">
                      {selectedCampaign.campaignCode}: {selectedCampaign.name}
                    </h3>
                  </div>

                  <div className="text-right">
                    <div className="text-3xl font-extrabold text-purple-600 font-mono">
                      {selectedCampaign.similarityScore}%
                    </div>
                    <div className="text-xs text-slate-500 font-medium">
                      Confidence: <strong>{selectedCampaign.confidence}</strong>
                    </div>
                  </div>
                </div>

                <p className="text-sm text-slate-600 leading-relaxed">
                  {selectedCampaign.description}
                </p>

                {/* Campaign Metadata Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs bg-slate-50 p-3.5 rounded-xl border border-slate-200">
                  <div>
                    <span className="text-[11px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">Threat Group</span>
                    <span className="font-bold text-slate-900 truncate block">{selectedCampaign.threatActorGroup}</span>
                  </div>
                  <div>
                    <span className="text-[11px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">First Observed</span>
                    <span className="text-slate-800 font-medium">{selectedCampaign.firstSeen || 'Historical'}</span>
                  </div>
                  <div>
                    <span className="text-[11px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">Last Observed</span>
                    <span className="text-slate-800 font-medium">{selectedCampaign.lastSeen || 'Active'}</span>
                  </div>
                  <div>
                    <span className="text-[11px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">Confidence</span>
                    <span className="text-blue-700 font-bold">{selectedCampaign.confidence}</span>
                  </div>
                </div>
              </div>

              {/* CRITICAL: STRICT EVIDENCE SEPARATION (OBSERVED CORRELATION vs AI INFERENCE) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* 1. OBSERVED CORRELATION (Factual / Reproducible) */}
                <div className="bg-white border border-blue-200 rounded-xl p-5 space-y-3 shadow-xs">
                  <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                    <Search className="w-4 h-4 text-blue-600" />
                    <div>
                      <h4 className="text-xs font-bold text-blue-900 uppercase tracking-wide">
                        Observed Correlation
                      </h4>
                      <span className="text-[11px] text-slate-500">Factual, reproducible evidence links</span>
                    </div>
                  </div>

                  <div className="space-y-2 text-xs">
                    {(selectedCampaign.observedCorrelation || []).length > 0 ? (
                      (selectedCampaign.observedCorrelation || []).map((obs, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-lg bg-blue-50/50 border border-blue-100 text-slate-800 flex items-start gap-2 font-mono text-[11px]"
                        >
                          <span className="text-blue-600 font-bold">✓</span>
                          <span>{obs}</span>
                        </div>
                      ))
                    ) : (
                      <div className="p-3 text-slate-400 text-xs italic">
                        No direct cryptographic or infrastructure overlap observed.
                      </div>
                    )}
                  </div>
                </div>

                {/* 2. AI INFERENCE (Probabilistic / Behavioral) */}
                <div className="bg-white border border-purple-200 rounded-xl p-5 space-y-3 shadow-xs">
                  <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                    <Cpu className="w-4 h-4 text-purple-600" />
                    <div>
                      <h4 className="text-xs font-bold text-purple-900 uppercase tracking-wide">
                        AI Inference
                      </h4>
                      <span className="text-[11px] text-slate-500">Probabilistic behavioral hypothesis</span>
                    </div>
                  </div>

                  <div className="space-y-2 text-xs">
                    {(selectedCampaign.aiInference || []).length > 0 ? (
                      (selectedCampaign.aiInference || []).map((inf, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-lg bg-purple-50/50 border border-purple-100 text-purple-950 flex items-start gap-2 font-mono text-[11px]"
                        >
                          <span className="text-purple-600 font-bold">~</span>
                          <span>{inf}</span>
                        </div>
                      ))
                    ) : (
                      <div className="p-3 text-slate-400 text-xs italic">
                        No AI inference generated for this cluster.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Shared Infrastructure & Shared IOCs */}
              <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
                <div className="border-b border-slate-100 pb-3 flex items-center justify-between">
                  <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <Network className="w-4 h-4 text-blue-600" /> Shared Infrastructure & Correlated Indicators
                  </h4>
                  <span className="text-xs font-medium text-slate-500">Cluster Telemetry</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                    <span className="text-[11px] text-slate-500 uppercase font-semibold block">Shared Infrastructure</span>
                    {(selectedCampaign.sharedInfrastructure || []).length > 0 ? (
                      (selectedCampaign.sharedInfrastructure || []).map((infra, i) => (
                        <div key={i} className="text-blue-700 font-bold font-mono">• {infra}</div>
                      ))
                    ) : (
                      <span className="text-slate-400 italic">No shared IP relays</span>
                    )}
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                    <span className="text-[11px] text-slate-500 uppercase font-semibold block">Shared IOCs</span>
                    {(selectedCampaign.sharedIOCs || []).length > 0 ? (
                      (selectedCampaign.sharedIOCs || []).map((ioc, i) => (
                        <div key={i} className="text-purple-700 font-bold font-mono">• {ioc}</div>
                      ))
                    ) : (
                      <span className="text-slate-400 italic">No direct IOC indicator matches</span>
                    )}
                  </div>
                </div>

                {/* Related Investigations */}
                <div className="pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3">
                  <span className="text-xs text-slate-600 font-medium">
                    Related Investigations in Forensic Corpus:
                  </span>
                  <div className="flex gap-2">
                    {(selectedCampaign.relatedInvestigations || []).map(caseNum => (
                      <button
                        key={caseNum}
                        onClick={() => onSelectCase && onSelectCase(caseNum)}
                        className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 text-blue-700 border border-slate-200 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                      >
                        <span>{caseNum}</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    ))}
                  </div>
                </div>

                {/* Non-Definitive Attribution Notice */}
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
                  <strong className="text-slate-800">Attribution Notice:</strong> {selectedCampaign.attributionNotice}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
