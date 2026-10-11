import React, { useState } from 'react';
import { ShieldAlert, Info, AlertTriangle, CheckCircle2, ChevronRight } from 'lucide-react';
import { RiskComponent, RiskScore } from '../types/forensics';
import { RiskExplanationModal } from './RiskExplanationModal';

interface RiskMeterProps {
  riskScore: RiskScore;
  compact?: boolean;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ riskScore, compact = false }) => {
  const [selectedComponent, setSelectedComponent] = useState<RiskComponent | null>(null);

  const getScoreBadge = (score: number) => {
    if (score >= 75) return { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', dot: 'bg-red-600' };
    if (score >= 50) return { bg: 'bg-amber-50', text: 'text-amber-800', border: 'border-amber-200', dot: 'bg-amber-500' };
    if (score >= 25) return { bg: 'bg-yellow-50', text: 'text-yellow-800', border: 'border-yellow-200', dot: 'bg-yellow-500' };
    return { bg: 'bg-emerald-50', text: 'text-emerald-700', border: 'border-emerald-200', dot: 'bg-emerald-600' };
  };

  const getBarColor = (score: number) => {
    if (score >= 75) return 'bg-red-600';
    if (score >= 50) return 'bg-amber-500';
    if (score >= 25) return 'bg-yellow-500';
    return 'bg-emerald-600';
  };

  const badge = getScoreBadge(riskScore.totalScore);

  const components = [
    riskScore.components.aiNlpPhishing,
    riskScore.components.urlDomainIntel,
    riskScore.components.emailAuthentication,
    riskScore.components.ipIntelligence,
    riskScore.components.attachmentAnalysis,
    riskScore.components.socialEngineering,
  ];

  if (compact) {
    return (
      <div className="flex items-center gap-3">
        <div
          className={`w-14 h-14 rounded-xl border flex flex-col items-center justify-center font-mono ${badge.bg} ${badge.border} ${badge.text}`}
        >
          <span className="text-xl font-bold leading-none">{riskScore.totalScore}</span>
          <span className="text-[10px] font-semibold uppercase">{riskScore.level}</span>
        </div>
        <div className="flex-1">
          <div className="flex justify-between text-xs font-medium mb-1">
            <span className="text-slate-600">Composite Threat Score</span>
            <span className={`font-semibold ${badge.text}`}>
              {riskScore.totalScore} / 100 ({riskScore.level})
            </span>
          </div>
          <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden border border-slate-200">
            <div
              className={`h-full transition-all duration-500 ${getBarColor(riskScore.totalScore)}`}
              style={{ width: `${riskScore.totalScore}%` }}
            />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div id="risk-engine-panel" className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-100">
        <div className="flex items-start gap-3.5">
          <div className={`p-2.5 rounded-xl border ${badge.bg} ${badge.border} ${badge.text} flex-shrink-0`}>
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-slate-900">
                Threat Risk Score Breakdown
              </h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200 font-medium">
                0-100 Scale
              </span>
            </div>
            <p className="text-sm text-slate-500 mt-0.5">
              Calculated automatically from authentication headers, sender reputation, attachments, and URL analysis.
            </p>
          </div>
        </div>

        {/* Big Score Card */}
        <div className={`px-5 py-3 rounded-xl border flex items-center gap-3.5 self-start sm:self-auto ${badge.bg} ${badge.border}`}>
          <div>
            <div className="text-xs font-medium text-slate-600 uppercase tracking-wider">Overall Risk</div>
            <div className="flex items-baseline gap-1.5">
              <span className={`text-3xl font-extrabold ${badge.text}`}>{riskScore.totalScore}</span>
              <span className="text-xs font-semibold text-slate-500">/ 100</span>
            </div>
            <div className={`text-xs font-bold uppercase tracking-wide mt-0.5 ${badge.text}`}>
              {riskScore.level} RISK
            </div>
          </div>
          {riskScore.totalScore >= 50 ? (
            <AlertTriangle className={`w-7 h-7 ${badge.text}`} />
          ) : (
            <CheckCircle2 className={`w-7 h-7 ${badge.text}`} />
          )}
        </div>
      </div>

      {/* Summary reason */}
      <div className="mt-4 p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-sm text-slate-700 flex items-start gap-2.5">
        <Info className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
        <div className="flex-1 leading-relaxed">
          <span className="font-semibold text-slate-900">Executive Summary: </span>
          {riskScore.summaryReason}
        </div>
      </div>

      {/* 6 Explainable Component Bars */}
      <div className="mt-5">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
            Contributing Risk Factors (Click any card for full calculation audit)
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {components.map(comp => (
            <button
              key={comp.name}
              id={`risk-component-${comp.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}
              onClick={() => setSelectedComponent(comp)}
              className="group text-left p-4 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 hover:border-blue-300 transition-all cursor-pointer flex flex-col justify-between shadow-xs hover:shadow-sm"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-sm font-semibold text-slate-900 group-hover:text-blue-600 transition-colors">
                    {comp.name}
                  </span>
                  <span className="text-xs font-medium text-slate-400">
                    {comp.weightPercent}% weight
                  </span>
                </div>
                <div className="flex items-baseline justify-between text-xs mb-2">
                  <span className="text-slate-500">Raw: {comp.rawScore} / 100</span>
                  <span className="font-semibold text-slate-800">
                    +{comp.weightedScore} pts added
                  </span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden border border-slate-100">
                  <div
                    className={`h-full ${getBarColor(comp.rawScore)}`}
                    style={{ width: `${comp.rawScore}%` }}
                  />
                </div>
              </div>

              <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 group-hover:text-blue-600">
                <span className="truncate max-w-[200px]">{comp.supportingIndicators[0] || 'View Audit Details'}</span>
                <ChevronRight className="w-4 h-4 flex-shrink-0 text-slate-400 group-hover:text-blue-600 transition-transform group-hover:translate-x-0.5" />
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Drill-down Modal */}
      {selectedComponent && (
        <RiskExplanationModal
          component={selectedComponent}
          totalScore={riskScore.totalScore}
          onClose={() => setSelectedComponent(null)}
        />
      )}
    </div>
  );
};
