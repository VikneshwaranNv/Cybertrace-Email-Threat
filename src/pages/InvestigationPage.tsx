import React, { useState } from 'react';
import {
  UploadCloud,
  FileText,
  Hash,
  Paperclip,
  ExternalLink,
  Code,
  Eye,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Layers,
  Sparkles,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { InvestigationCompletePayload } from '../types/forensics';
import { RiskMeter } from '../components/RiskMeter';
import { InvestigationCopilot } from '../components/InvestigationCopilot';

interface InvestigationPageProps {
  payload?: InvestigationCompletePayload | null;
  activeCase?: InvestigationCompletePayload | null;
  onAnalyzeEmail?: (rawEmail: string, title?: string) => Promise<void>;
  onIngestRaw?: (rawEmail: string, title?: string) => Promise<void>;
  onLoadDemoCase?: (caseId: string) => void;
  onLoadScenario?: (scenario: 'LEGITIMATE' | 'BEC' | 'PHISHING') => void;
  onSelectCase?: (caseId: string) => void;
  onNavigate?: (pageId: any) => void;
  isAnalyzing: boolean;
}

export const InvestigationPage: React.FC<InvestigationPageProps> = ({
  payload,
  activeCase,
  onAnalyzeEmail,
  onIngestRaw,
  onLoadDemoCase,
  onLoadScenario,
  onSelectCase,
  onNavigate,
  isAnalyzing,
}) => {
  const currentPayload = payload ?? activeCase ?? null;
  const triggerAnalyze = onAnalyzeEmail ?? onIngestRaw ?? (async () => {});
  const triggerLoadDemo = (caseId: string) => {
    if (onLoadDemoCase) {
      onLoadDemoCase(caseId);
    } else if (onSelectCase) {
      onSelectCase(caseId);
    } else if (onLoadScenario) {
      if (caseId === 'CASE-2026-001') onLoadScenario('LEGITIMATE');
      else if (caseId === 'CASE-2026-002') onLoadScenario('BEC');
      else if (caseId === 'CASE-2026-003') onLoadScenario('PHISHING');
    }
  };

  const handleCopilotNavigate = (section: string, targetId?: string) => {
    if (section === 'headers' && onNavigate) {
      onNavigate('headers');
    } else if (section === 'iocs' && onNavigate) {
      onNavigate('threat-intel');
    } else if (section === 'campaign' && onNavigate) {
      onNavigate('campaign-dna');
    } else if (section === 'ledger' && onNavigate) {
      onNavigate('ledger');
    } else if (section === 'timeline' && onNavigate) {
      onNavigate('timeline');
    } else {
      const el = document.getElementById(`evidence-${section}`);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  };

  const [activeBodyTab, setActiveBodyTab] = useState<'plaintext' | 'sanitized' | 'raw'>('plaintext');
  const [pasteContent, setPasteContent] = useState('');
  const [pasteTitle, setPasteTitle] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [showIngestZone, setShowIngestZone] = useState(true);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async event => {
      const content = event.target?.result as string;
      if (content) {
        await triggerAnalyze(content, file.name.replace(/\.eml$/i, ''));
      }
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async event => {
      const content = event.target?.result as string;
      if (content) {
        await triggerAnalyze(content, file.name.replace(/\.eml$/i, ''));
      }
    };
    reader.readAsText(file);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div id="email-investigation-view" className="space-y-6 pb-12">
      {/* Top Ingestion Panel: Both Upload File and Paste Raw Text directly visible */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <div>
            <div className="flex items-center gap-2">
              <UploadCloud className="w-5 h-5 text-blue-600" />
              <h2 className="text-base font-bold text-slate-900">
                Email Evidence Ingestion
              </h2>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Choose an ingestion method: upload an RFC-822 (.eml) file, paste raw headers/text, or load a pre-configured scenario.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider mr-1 hidden md:inline">Demo Scenarios:</span>
            <button
              onClick={() => triggerLoadDemo('CASE-2026-001')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-200 transition-colors cursor-pointer"
            >
              Benign (Case 001)
            </button>
            <button
              onClick={() => triggerLoadDemo('CASE-2026-002')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 transition-colors cursor-pointer"
            >
              Wire Fraud (Case 002)
            </button>
            <button
              onClick={() => triggerLoadDemo('CASE-2026-003')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-red-50 hover:bg-red-100 text-red-800 border border-red-200 transition-colors cursor-pointer"
            >
              Phishing (Case 003)
            </button>
            {currentPayload && (
              <button
                onClick={() => setShowIngestZone(prev => !prev)}
                className="ml-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 transition-colors cursor-pointer flex items-center gap-1"
                title={showIngestZone ? 'Collapse ingestion panel' : 'Expand ingestion panel'}
              >
                {showIngestZone ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                <span>{showIngestZone ? 'Collapse' : 'Ingest New'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Both Ingestion Options Directly Rendered Side-by-Side */}
        {showIngestZone && (
          <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* OPTION 1: Upload a File (.eml) */}
            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-6 h-6 rounded-lg bg-blue-100 text-blue-700 flex items-center justify-center font-bold text-xs">
                    1
                  </div>
                  <div>
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Upload Email File (.eml)
                    </h3>
                    <p className="text-[11px] text-slate-500">
                      Standard RFC-822 email file (.eml, .txt)
                    </p>
                  </div>
                </div>

                <div
                  onDragOver={e => e.preventDefault()}
                  onDrop={handleDrop}
                  className="mt-3 border-2 border-dashed border-slate-300 hover:border-blue-500 bg-white rounded-xl p-5 text-center transition-all flex flex-col items-center justify-center gap-2 min-h-[145px]"
                >
                  <div className="w-10 h-10 rounded-full bg-blue-50 text-blue-600 flex items-center justify-center">
                    <UploadCloud className="w-5 h-5" />
                  </div>
                  <div className="text-xs font-semibold text-slate-700">
                    Drag and drop an <span className="font-mono text-blue-600">.eml</span> file here
                  </div>
                  <p className="text-[11px] text-slate-400">or click to browse from your device</p>
                  <label
                    htmlFor="eml-file-input"
                    className="mt-1 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold cursor-pointer transition-colors shadow-xs"
                  >
                    Browse Local File
                  </label>
                  <input
                    id="eml-file-input"
                    type="file"
                    accept=".eml,message/rfc822,text/plain"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </div>
              </div>
            </div>

            {/* OPTION 2: Paste Raw Text */}
            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-6 h-6 rounded-lg bg-emerald-100 text-emerald-700 flex items-center justify-center font-bold text-xs">
                    2
                  </div>
                  <div>
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Paste Raw Headers & Body Text
                    </h3>
                    <p className="text-[11px] text-slate-500">
                      Directly paste raw RFC-822 source text
                    </p>
                  </div>
                </div>

                <input
                  type="text"
                  placeholder="Investigation Title (Optional, e.g. Suspicious Wire Transfer)"
                  value={pasteTitle}
                  onChange={e => setPasteTitle(e.target.value)}
                  className="w-full bg-white border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />

                <textarea
                  rows={4}
                  placeholder="Received: from mail.example.com ...&#10;From: attacker@fake-bank.com&#10;To: employee@company.com&#10;Subject: Action Required: Urgent Payment&#10;&#10;Please review and authorize immediately..."
                  value={pasteContent}
                  onChange={e => setPasteContent(e.target.value)}
                  className="w-full bg-white border border-slate-300 rounded-lg p-2.5 text-xs font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-none leading-relaxed"
                />
              </div>

              <div className="mt-3 flex items-center justify-between">
                <span className="text-[11px] text-slate-400">
                  {pasteContent.length > 0 ? `${pasteContent.length} chars entered` : 'Ready to parse'}
                </span>
                <button
                  disabled={!pasteContent.trim() || isAnalyzing}
                  onClick={async () => {
                    await triggerAnalyze(pasteContent, pasteTitle || undefined);
                    setPasteContent('');
                    setPasteTitle('');
                  }}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 transition-colors shadow-xs cursor-pointer"
                >
                  {isAnalyzing ? 'Analyzing...' : 'Analyze Pasted Email'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Loading state indicator */}
      {isAnalyzing && (
        <div className="p-8 bg-white border border-blue-200 rounded-xl text-center space-y-3 shadow-sm">
          <div className="w-10 h-10 border-3 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto" />
          <h3 className="text-base font-bold text-slate-900">
            Analyzing Email Evidence...
          </h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Parsing headers, extracting indicators of compromise (IOCs), validating cryptographic hashes, and generating risk assessments.
          </p>
        </div>
      )}

      {/* Active Evidence Data View */}
      {currentPayload && !isAnalyzing && (
        <>
          {/* Explainable Risk Overview */}
          <div id="evidence-risk">
            <RiskMeter riskScore={currentPayload.riskScore} />
          </div>

          {/* EVIDENCE-BASED INVESTIGATION COPILOT */}
          <InvestigationCopilot
            payload={currentPayload}
            onNavigateSection={handleCopilotNavigate}
          />

          {/* Primary Evidence Metadata Card */}
          <div id="evidence-headers" className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-5">
            <div className="flex flex-wrap items-center justify-between pb-4 border-b border-slate-100 gap-3">
              <div className="flex items-center gap-2.5">
                <FileText className="w-5 h-5 text-blue-600" />
                <h3 className="text-base font-bold text-slate-900">
                  Envelope Headers & Identity
                </h3>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="px-2.5 py-1 rounded-md bg-slate-100 text-slate-700 border border-slate-200 font-medium">
                  Size: {Math.round(currentPayload.evidence.sizeBytes / 1024)} KB
                </span>
                <span className="px-2.5 py-1 rounded-md bg-slate-100 text-slate-700 border border-slate-200 font-medium">
                  {currentPayload.evidence.headers.receivedHeaders.length} Server Hops
                </span>
                <span className="px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 border border-blue-200 font-medium">
                  MIME: {currentPayload.evidence.mimeType}
                </span>
              </div>
            </div>

            {/* Grid of Key Headers */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">From Header</span>
                <span className="text-sm font-semibold text-slate-900 truncate block" title={currentPayload.evidence.headers.from}>
                  {currentPayload.evidence.headers.from}
                </span>
                <span className="text-xs text-slate-500 mt-1 block">Address: {currentPayload.evidence.headers.fromAddress}</span>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Recipient (To)</span>
                <span className="text-sm font-semibold text-slate-900 truncate block" title={currentPayload.evidence.headers.to}>
                  {currentPayload.evidence.headers.to}
                </span>
                {currentPayload.evidence.headers.cc && (
                  <span className="text-xs text-slate-500 mt-1 block">CC: {currentPayload.evidence.headers.cc}</span>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Subject</span>
                <span className="text-sm font-semibold text-slate-900 truncate block" title={currentPayload.evidence.headers.subject}>
                  {currentPayload.evidence.headers.subject}
                </span>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Reply-To Header</span>
                <span
                  className={`text-sm truncate block ${
                    currentPayload.headerAnalysis.inconsistencies.replyToMismatch
                      ? 'text-red-600 font-bold'
                      : 'text-slate-800 font-medium'
                  }`}
                >
                  {currentPayload.evidence.headers.replyTo || '(Not Specified / Defaults to From)'}
                </span>
                {currentPayload.headerAnalysis.inconsistencies.replyToMismatch && (
                  <span className="text-xs font-semibold text-red-600 mt-1 inline-flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> Address mismatch detected
                  </span>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Return-Path</span>
                <span
                  className={`text-sm truncate block ${
                    currentPayload.headerAnalysis.inconsistencies.returnPathMismatch
                      ? 'text-amber-600 font-semibold'
                      : 'text-slate-800 font-medium'
                  }`}
                >
                  {currentPayload.evidence.headers.returnPath || '(Not Specified)'}
                </span>
                {currentPayload.headerAnalysis.inconsistencies.returnPathMismatch && (
                  <span className="text-xs font-semibold text-amber-600 mt-1 block">
                    Domain differs from sender
                  </span>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Date Sent</span>
                <span className="text-sm text-slate-800 font-medium truncate block">
                  {currentPayload.evidence.headers.date || currentPayload.evidence.ingestedAt}
                </span>
              </div>
            </div>

            {/* Cryptographic Hashes Row */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
                <span className="flex items-center gap-1.5 uppercase tracking-wider">
                  <Hash className="w-4 h-4 text-blue-600" />
                  Cryptographic Integrity Hashes
                </span>
                <span className="text-emerald-700 font-medium">Tamper-Proof Evidence Seal</span>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-white p-3 rounded-lg border border-slate-200 shadow-xs">
                <div className="truncate">
                  <span className="text-xs font-semibold text-slate-500 uppercase mr-2">SHA-256:</span>
                  <span className="font-mono text-xs text-slate-900 select-all font-semibold">{currentPayload.evidence.sha256}</span>
                </div>
                <button
                  onClick={() => copyToClipboard(currentPayload.evidence.sha256, 'sha256')}
                  className="px-3 py-1 rounded-md text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 flex items-center gap-1.5 flex-shrink-0 cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                  <span>{copiedHash === 'sha256' ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-white p-3 rounded-lg border border-slate-200 shadow-xs">
                <div className="truncate">
                  <span className="text-xs font-semibold text-slate-500 uppercase mr-2">MD5:</span>
                  <span className="font-mono text-xs text-slate-900 select-all font-semibold">{currentPayload.evidence.md5}</span>
                </div>
                <button
                  onClick={() => copyToClipboard(currentPayload.evidence.md5, 'md5')}
                  className="px-3 py-1 rounded-md text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 flex items-center gap-1.5 flex-shrink-0 cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                  <span>{copiedHash === 'md5' ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Email Body Viewer with Tabs */}
          <div id="evidence-body" className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 bg-slate-50/80 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveBodyTab('plaintext')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                    activeBodyTab === 'plaintext'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Plain Text</span>
                </button>
                <button
                  onClick={() => setActiveBodyTab('sanitized')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                    activeBodyTab === 'sanitized'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>Sanitized Preview</span>
                </button>
                <button
                  onClick={() => setActiveBodyTab('raw')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                    activeBodyTab === 'raw'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  <Code className="w-3.5 h-3.5" />
                  <span>Raw RFC-822</span>
                </button>
              </div>

              <span className="text-xs text-slate-500 font-medium">
                Length: {currentPayload.evidence.body.text.length} characters
              </span>
            </div>

            <div className="p-5">
              {activeBodyTab === 'plaintext' && (
                <pre className="text-xs font-mono text-slate-800 whitespace-pre-wrap max-h-96 overflow-y-auto leading-relaxed bg-slate-50 p-4 rounded-xl border border-slate-200">
                  {currentPayload.evidence.body.text || '(Empty text body)'}
                </pre>
              )}

              {activeBodyTab === 'sanitized' && (
                <div className="max-h-96 overflow-y-auto bg-white text-slate-900 p-4 rounded-xl border border-slate-200 text-sm leading-relaxed">
                  {(currentPayload.evidence.body.sanitizedHtml || currentPayload.evidence.body.html) ? (
                    <div
                      dangerouslySetInnerHTML={{ __html: currentPayload.evidence.body.sanitizedHtml || currentPayload.evidence.body.html || '' }}
                    />
                  ) : (
                    <div className="text-slate-500 italic">No HTML content present in message.</div>
                  )}
                </div>
              )}

              {activeBodyTab === 'raw' && (
                <pre className="text-xs font-mono text-slate-800 whitespace-pre max-h-96 overflow-y-auto bg-slate-900 text-slate-100 p-4 rounded-xl">
                  {currentPayload.evidence.rawSource}
                </pre>
              )}
            </div>
          </div>

          {/* Attachments Forensics Card */}
          <div id="evidence-attachments" className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2.5">
                <Paperclip className="w-5 h-5 text-blue-600" />
                <h3 className="text-base font-bold text-slate-900">
                  Attachment Forensics & Risk ({currentPayload.evidence.attachments.length})
                </h3>
              </div>
              <span className="text-xs font-medium text-slate-500">
                Static MIME & Signature Checks
              </span>
            </div>

            {currentPayload.evidence.attachments.length === 0 ? (
              <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 text-center text-sm text-slate-500">
                No binary or archive attachments detected in this message envelope.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {currentPayload.evidence.attachments.map((att, idx) => (
                  <div
                    key={idx}
                    className={`p-4 rounded-xl border text-xs space-y-2.5 ${
                      att.isSuspicious
                        ? 'bg-red-50/60 border-red-200 text-red-900'
                        : 'bg-slate-50 border-slate-200 text-slate-800'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className="font-bold text-sm text-slate-900 block truncate">{att.filename}</span>
                        <span className="text-xs text-slate-500 block mt-0.5">{att.contentType || (att as any).mimeType || 'application/octet-stream'} • {Math.round(att.sizeBytes / 1024)} KB</span>
                      </div>
                      <span
                        className={`text-xs font-semibold px-2.5 py-1 rounded-full uppercase flex-shrink-0 ${
                          att.isSuspicious
                            ? 'bg-red-100 text-red-800 border border-red-200'
                            : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                        }`}
                      >
                        {att.isSuspicious ? 'High Risk' : 'Benign'}
                      </span>
                    </div>

                    <div className="text-xs space-y-1 pt-2 border-t border-slate-200/60">
                      <div className="text-slate-600 truncate font-mono">
                        SHA-256: <span className="text-slate-900 font-semibold">{att.sha256}</span>
                      </div>
                      {att.threatDetails && (
                        <div className="text-red-700 font-semibold mt-1">
                          Security Flag: {att.threatDetails}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* MITRE ATT&CK Mappings */}
          <div id="evidence-mitre" className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex flex-wrap items-center justify-between pb-3 border-b border-slate-100 gap-3">
              <div className="flex items-center gap-2.5">
                <Layers className="w-5 h-5 text-purple-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    MITRE ATT&CK Observed Techniques
                  </h3>
                  <p className="text-xs text-slate-500">
                    Mapped strictly from verifiable email headers and content without speculative extrapolation.
                  </p>
                </div>
              </div>
              <span className="text-xs font-semibold px-3 py-1 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
                {currentPayload.mitreMappings ? currentPayload.mitreMappings.length : 0} Techniques Observed
              </span>
            </div>

            {(!currentPayload.mitreMappings || currentPayload.mitreMappings.length === 0) ? (
              <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 text-center text-sm text-slate-500">
                No adversarial MITRE ATT&CK techniques identified in this communication.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {currentPayload.mitreMappings.map(m => (
                  <div
                    key={m.techniqueId}
                    className="p-4 rounded-xl bg-white border border-slate-200 hover:border-purple-300 transition-colors space-y-2.5 shadow-xs"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className="text-purple-700 font-bold text-sm">{m.techniqueId}: {m.techniqueName}</span>
                        <span className="text-xs text-slate-500 block">Tactic: {m.tactic}</span>
                      </div>
                      <span className="px-2.5 py-0.5 rounded-full bg-slate-100 text-xs text-slate-700 font-semibold border border-slate-200">
                        {m.confidence}% Conf
                      </span>
                    </div>

                    <div className="text-xs p-3 rounded-lg bg-slate-50 text-slate-700 border border-slate-200">
                      <strong className="text-slate-500 text-[11px] uppercase tracking-wider block mb-0.5">Observed Evidence:</strong>
                      {m.evidenceFound}
                    </div>

                    <div className="flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-100">
                      <span>Ref: {m.evidenceReferences.join(', ')}</span>
                      <a
                        href={`https://attack.mitre.org/techniques/${m.techniqueId.replace('.', '/')}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-600 hover:text-blue-700 font-medium flex items-center gap-1"
                      >
                        MITRE Matrix <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};
