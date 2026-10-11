import React, { useState } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  ShieldAlert,
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  RefreshCw,
  Cpu,
  Fingerprint,
  Info,
  ChevronRight,
  Layers,
  ArrowRight,
} from 'lucide-react';
import {
  InvestigationCompletePayload,
  CopilotQueryResponse,
  CopilotEvidenceReference,
} from '../types/forensics';
import { askInvestigationCopilot } from '../services/api';

interface InvestigationCopilotProps {
  payload: InvestigationCompletePayload | null;
  onNavigateSection?: (section: string, targetId?: string) => void;
}

const SUGGESTED_QUESTIONS = [
  'Why was this email classified as high risk?',
  'What evidence supports the phishing classification?',
  'Which indicators contributed most to the risk score?',
  'Is the sender identity suspicious?',
  'What does the Received header chain indicate?',
  'Which infrastructure is connected to this email?',
  'Is this case related to a previous campaign?',
  'Summarize this investigation for an analyst.',
];

export const InvestigationCopilot: React.FC<InvestigationCopilotProps> = ({
  payload,
  onNavigateSection,
}) => {
  const [question, setQuestion] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeResponse, setActiveResponse] = useState<CopilotQueryResponse | null>(null);
  const [history, setHistory] = useState<Array<{ q: string; a: CopilotQueryResponse }>>([]);
  const [highlightedRef, setHighlightedRef] = useState<string | null>(null);

  const handleAsk = async (queryText?: string) => {
    const targetQ = queryText || question;
    if (!targetQ.trim() || !payload || isLoading) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await askInvestigationCopilot(
        targetQ.trim(),
        payload.caseRecord.caseId,
        payload
      );
      setActiveResponse(response);
      setHistory(prev => [{ q: targetQ.trim(), a: response }, ...prev.slice(0, 9)]);
      setQuestion('');
    } catch (err: any) {
      console.error('Failed to query copilot:', err);
      setError(err.message || 'Failed to query investigation copilot. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRefClick = (ref: CopilotEvidenceReference) => {
    setHighlightedRef(ref.refId);
    setTimeout(() => setHighlightedRef(null), 3000);

    if (onNavigateSection) {
      onNavigateSection(ref.targetSection, ref.targetId);
    } else {
      const el =
        document.getElementById(`evidence-${ref.targetSection}`) ||
        document.getElementById(ref.targetId || '') ||
        document.getElementById('email-investigation-view');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  };

  return (
    <div
      id="investigation-copilot-panel"
      className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm"
    >
      {/* Copilot Header */}
      <div className="p-5 bg-slate-50/80 border-b border-slate-200 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-blue-100 border border-blue-200 flex items-center justify-center text-blue-700">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-900">
                Investigation AI Assistant
              </h3>
              <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-200">
                Evidence-Grounded
              </span>
            </div>
            <p className="text-sm text-slate-500">
              Ask natural questions about this email's headers, suspicious links, attachments, or sender reputation.
            </p>
          </div>
        </div>

        {/* Security & Integrity Indicators */}
        <div className="flex items-center gap-2 text-xs">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white border border-slate-200 text-slate-600 font-medium shadow-xs">
            <Fingerprint className="w-3.5 h-3.5 text-blue-600" />
            SHA-256 Verified
          </span>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-medium">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            Prompt Guard Active
          </span>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Suggested Quick Inquiries */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 uppercase tracking-wider">
              <Sparkles className="w-4 h-4 text-blue-600" />
              Suggested Questions
            </span>
            <span className="text-xs text-slate-400">Click any question to ask instantly</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {SUGGESTED_QUESTIONS.map((q, idx) => (
              <button
                key={idx}
                disabled={isLoading || !payload}
                onClick={() => {
                  setQuestion(q);
                  handleAsk(q);
                }}
                className="px-3 py-2.5 rounded-lg text-xs font-medium text-slate-700 bg-slate-50 hover:bg-blue-50 hover:text-blue-700 border border-slate-200 hover:border-blue-200 transition-all text-left flex items-center justify-between disabled:opacity-50 disabled:cursor-not-allowed group cursor-pointer"
              >
                <span className="line-clamp-2">{q}</span>
                <ChevronRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-blue-600 flex-shrink-0 ml-1.5 transition-transform group-hover:translate-x-0.5" />
              </button>
            ))}
          </div>
        </div>

        {/* Input Bar */}
        <form
          onSubmit={e => {
            e.preventDefault();
            handleAsk();
          }}
          className="flex items-center gap-3"
        >
          <div className="relative flex-1">
            <input
              type="text"
              value={question}
              disabled={isLoading || !payload}
              onChange={e => setQuestion(e.target.value)}
              placeholder={
                payload
                  ? 'Ask a question about this email (e.g. "What makes the Received chain suspicious?")...'
                  : 'Select or load an investigation to enable Copilot analysis...'
              }
              className="w-full bg-white border border-slate-300 focus:border-blue-600 rounded-lg pl-4 pr-10 py-3 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-100 transition-all disabled:opacity-50"
            />
            {question && (
              <button
                type="button"
                onClick={() => setQuestion('')}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-sm"
              >
                ✕
              </button>
            )}
          </div>

          <button
            type="submit"
            disabled={!question.trim() || isLoading || !payload}
            className="px-5 py-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold flex items-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm flex-shrink-0 cursor-pointer"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                <span>Ask Question</span>
              </>
            )}
          </button>
        </form>

        {/* Loading State Animation */}
        {isLoading && (
          <div className="p-5 rounded-xl bg-blue-50/50 border border-blue-200 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-blue-100 border border-blue-200 flex items-center justify-center flex-shrink-0">
              <Cpu className="w-5 h-5 text-blue-700 animate-pulse" />
            </div>
            <div className="space-y-1">
              <div className="text-sm font-bold text-slate-900 flex items-center gap-2">
                Examining Evidence & Headers
                <span className="inline-block w-2 h-2 rounded-full bg-blue-600 animate-ping" />
              </div>
              <p className="text-xs text-slate-600">
                Cross-referencing RFC-822 headers, verifiable IOCs, and threat intelligence to formulate an evidence-backed answer.
              </p>
            </div>
          </div>
        )}

        {/* Error Notification */}
        {error && (
          <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
            <div className="flex-1 space-y-1">
              <div className="font-semibold">Unable to Complete Request</div>
              <div className="text-xs text-red-700">{error}</div>
            </div>
            <button
              onClick={() => handleAsk()}
              className="px-3 py-1 rounded-md bg-white hover:bg-red-100 text-xs font-semibold text-red-800 border border-red-200 cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        {/* Active Response Display */}
        {activeResponse && !isLoading && (
          <div className="space-y-5 rounded-xl bg-slate-50/50 border border-slate-200 p-6">
            {/* Answer Meta Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-200 text-xs">
              <div className="flex items-center gap-2 text-slate-500">
                <span className="px-2.5 py-1 rounded-md bg-white border border-slate-200 font-medium text-slate-700">
                  Model: {activeResponse.modelUsed}
                </span>
                <span>
                  Query at {new Date(activeResponse.queryTimestamp).toLocaleTimeString()}
                </span>
              </div>

              {/* Confidence Pill */}
              <div className="flex items-center gap-2">
                <span className="text-slate-500 font-medium">Confidence:</span>
                <span
                  className={`px-3 py-1 rounded-full text-xs font-semibold ${
                    activeResponse.confidence === 'High'
                      ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                      : activeResponse.confidence === 'Medium'
                      ? 'bg-amber-100 text-amber-800 border border-amber-200'
                      : 'bg-red-100 text-red-800 border border-red-200'
                  }`}
                >
                  {activeResponse.confidence} Confidence
                </span>
              </div>
            </div>

            {/* 1. CONCLUSION */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-blue-600" />
                Conclusion & Verdict
              </span>
              <div
                className={`p-4 rounded-xl text-sm leading-relaxed ${
                  activeResponse.conclusion.includes('Insufficient evidence')
                    ? 'bg-amber-50 border border-amber-200 text-amber-900'
                    : 'bg-white border border-slate-200 text-slate-900 shadow-xs'
                }`}
              >
                {activeResponse.conclusion}
              </div>
            </div>

            {/* 2. KEY EVIDENCE */}
            <div className="space-y-2.5">
              <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                <Layers className="w-4 h-4 text-blue-600" />
                Key Supporting Evidence
              </span>
              <ul className="space-y-2">
                {activeResponse.keyEvidence.map((item, idx) => {
                  const isObserved = item.includes('[OBSERVED EVIDENCE]');
                  const isAi = item.includes('[AI INFERENCE]');
                  const isThreat = item.includes('[THREAT INTELLIGENCE]');
                  const isDemo = item.includes('[DEMO/SIMULATED DATA]');

                  return (
                    <li
                      key={idx}
                      className="p-3.5 rounded-xl bg-white border border-slate-200 text-xs text-slate-800 flex items-start gap-3 shadow-xs"
                    >
                      <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-600 flex items-center justify-center text-xs font-bold flex-shrink-0 mt-0.5 border border-slate-200">
                        {idx + 1}
                      </span>
                      <div className="flex-1 space-y-1.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {isObserved && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200 uppercase">
                              OBSERVED EVIDENCE
                            </span>
                          )}
                          {isAi && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200 uppercase">
                              AI INFERENCE
                            </span>
                          )}
                          {isThreat && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200 uppercase">
                              THREAT INTELLIGENCE
                            </span>
                          )}
                          {isDemo && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 border border-slate-200 uppercase">
                              DEMO DATA
                            </span>
                          )}
                        </div>
                        <div className="text-sm leading-relaxed text-slate-800">
                          {item
                            .replace(/\[OBSERVED EVIDENCE\]/g, '')
                            .replace(/\[AI INFERENCE\]/g, '')
                            .replace(/\[THREAT INTELLIGENCE\]/g, '')
                            .replace(/\[DEMO\/SIMULATED DATA\]/g, '')
                            .trim()}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>

            {/* 3. RISK IMPACT */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-amber-600" />
                Risk & Security Impact
              </span>
              <div className="p-4 rounded-xl bg-white border border-slate-200 text-sm text-slate-700 leading-relaxed shadow-xs">
                {activeResponse.riskImpact}
              </div>
            </div>

            {/* 4. LIMITATIONS & FORENSIC SAFEGUARDS */}
            {activeResponse.limitations.length > 0 && (
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                  <Info className="w-4 h-4 text-slate-400" />
                  Forensic Scope & Safeguards
                </span>
                <div className="p-3.5 rounded-xl bg-white border border-slate-200 text-xs text-slate-600 space-y-1.5 shadow-xs">
                  {activeResponse.limitations.map((lim, lIdx) => (
                    <div key={lIdx} className="flex items-start gap-2">
                      <span className="text-slate-400 font-bold">•</span>
                      <span>{lim}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 5. INTERACTIVE EVIDENCE CITATIONS */}
            {activeResponse.evidenceReferences.length > 0 && (
              <div className="pt-3 border-t border-slate-200 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                    <Fingerprint className="w-4 h-4 text-blue-600" />
                    Verified Evidence Citations (Click to jump to evidence)
                  </span>
                </div>

                <div className="flex flex-wrap gap-2">
                  {activeResponse.evidenceReferences.map((ref, rIdx) => {
                    const isHighlighted = highlightedRef === ref.refId;

                    return (
                      <button
                        key={rIdx}
                        onClick={() => handleRefClick(ref)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all text-left flex items-center gap-2 cursor-pointer ${
                          isHighlighted
                            ? 'bg-blue-600 border-blue-600 text-white shadow-sm'
                            : 'bg-white border-slate-200 hover:border-blue-400 text-blue-700 hover:bg-blue-50 shadow-xs'
                        }`}
                        title={ref.description}
                      >
                        <span>{ref.label}</span>
                        <ArrowRight className="w-3.5 h-3.5 text-blue-500" />
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Empty State when no question asked yet */}
        {!activeResponse && !isLoading && (
          <div className="p-8 rounded-xl bg-slate-50 border border-dashed border-slate-200 text-center space-y-2">
            <Bot className="w-8 h-8 text-blue-600 mx-auto" />
            <h4 className="text-sm font-semibold text-slate-800">
              Assistant Ready for Questions
            </h4>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Select any suggested question above or type your own question to receive an evidence-backed explanation.
            </p>
          </div>
        )}

        {/* Prior Questions Accordion / History */}
        {history.length > 1 && (
          <div className="space-y-2 pt-2 border-t border-slate-200">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
              Previous Questions ({history.length - 1})
            </span>
            <div className="space-y-2">
              {history.slice(1, 4).map((h, hIdx) => (
                <button
                  key={hIdx}
                  onClick={() => setActiveResponse(h.a)}
                  className="w-full p-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-left transition-colors flex items-center justify-between text-xs text-slate-700 cursor-pointer shadow-xs"
                >
                  <span className="truncate pr-3 font-medium text-slate-800">
                    "{h.q}"
                  </span>
                  <span className="text-xs font-semibold text-blue-600 flex-shrink-0">
                    {h.a.confidence} Confidence • View Answer
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Copilot Footer Disclaimers */}
      <div className="p-3.5 bg-slate-50 border-t border-slate-200 text-xs text-slate-500 flex flex-wrap items-center justify-between gap-2">
        <span>
          SOC Integrity: Responses are strictly verified against captured RFC-822 headers and evidence hashes.
        </span>
        <span className="text-slate-400">
          No external assumptions • Evidence-grounded only
        </span>
      </div>
    </div>
  );
};
