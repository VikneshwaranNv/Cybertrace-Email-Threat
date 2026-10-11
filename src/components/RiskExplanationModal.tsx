import React from 'react';
import { X, Calculator, ShieldCheck, AlertCircle, FileSearch, CheckCircle } from 'lucide-react';
import { RiskComponent } from '../types/forensics';

interface RiskExplanationModalProps {
  component: RiskComponent;
  totalScore: number;
  onClose: () => void;
}

export const RiskExplanationModal: React.FC<RiskExplanationModalProps> = ({
  component,
  totalScore,
  onClose,
}) => {
  return (
    <div
      id="risk-explanation-modal"
      className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4"
      onClick={e => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-white border border-slate-200 rounded-xl max-w-xl w-full p-6 shadow-xl space-y-5">
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-slate-100">
          <div>
            <span className="inline-block text-xs font-semibold px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-100 uppercase tracking-wide">
              Component Audit • {component.weightPercent}% Weight
            </span>
            <h2 className="text-xl font-bold text-slate-900 mt-1">{component.name}</h2>
          </div>
          <button
            id="close-modal-btn"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Mathematical Formula Card */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-100 text-blue-700">
              <Calculator className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Calculation Formula</div>
              <div className="text-sm font-semibold text-slate-900">{component.calculation}</div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Impact on Total</div>
            <div className="text-base font-bold text-blue-600">
              +{component.weightedScore} <span className="text-xs text-slate-400 font-normal">/ {totalScore} pts</span>
            </div>
          </div>
        </div>

        {/* Contributing Evidence */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 uppercase tracking-wider">
            <FileSearch className="w-4 h-4 text-emerald-600" />
            <span>Contributing Forensic Evidence</span>
          </div>
          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {component.evidence.map((item, idx) => (
              <div
                key={idx}
                className="text-xs p-3 rounded-lg bg-slate-50 border border-slate-200 text-slate-700 flex items-start gap-2.5"
              >
                <CheckCircle className="w-4 h-4 text-emerald-600 mt-0.5 flex-shrink-0" />
                <span className="leading-relaxed">{item}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Supporting Indicators */}
        {component.supportingIndicators.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 uppercase tracking-wider">
              <AlertCircle className="w-4 h-4 text-amber-600" />
              <span>Supporting Indicators & Signals</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {component.supportingIndicators.map((ind, idx) => (
                <span
                  key={idx}
                  className="text-xs font-medium px-3 py-1 rounded-md bg-amber-50 text-amber-800 border border-amber-200"
                >
                  {ind}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="pt-3 border-t border-slate-100 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2.5 rounded-lg text-sm font-semibold bg-slate-900 hover:bg-slate-800 text-white transition-colors cursor-pointer"
          >
            Close Breakdown
          </button>
        </div>
      </div>
    </div>
  );
};
