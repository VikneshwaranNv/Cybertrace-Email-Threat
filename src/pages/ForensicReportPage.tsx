import React, { useState, useEffect } from 'react';
import {
  FileText,
  Printer,
  Download,
  Copy,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { ForensicReportData } from '../types/forensics';
import { fetchCaseReport } from '../services/api';

interface ForensicReportPageProps {
  caseId: string;
}

export const ForensicReportPage: React.FC<ForensicReportPageProps> = ({ caseId }) => {
  const [report, setReport] = useState<ForensicReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let isMounted = true;
    const load = async () => {
      setLoading(true);
      try {
        const data = await fetchCaseReport(caseId);
        if (isMounted) setReport(data);
      } catch (err) {
        console.error('Failed to load forensic report:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };
    load();
    return () => {
      isMounted = false;
    };
  }, [caseId]);

  const handlePrint = () => {
    window.print();
  };

  const handleCopyMarkdown = () => {
    if (!report) return;
    const sectionsText = report.structuredSections && report.structuredSections.length > 0
      ? report.structuredSections
          .map(
            s => `### ${s.sectionNumber}. ${s.title}${s.isAiGenerated ? ' [AI-GENERATED CONCLUSION]' : ''}\n${s.content}\n`
          )
          .join('\n')
      : '';

    const text = `
# OFFICIAL DIGITAL FORENSICS INVESTIGATION REPORT
Report ID: ${report.reportId}
Generated At: ${report.generatedAt}
Investigator: ${report.analyst}
Organization: ${report.organization}
Classification: ${report.threatAssessment.classification}
Risk Score: ${report.riskScore.totalScore}/100 [${report.riskScore.level}]

---
${sectionsText}
---
LEGAL DISCLAIMER:
${report.legalDisclaimer}
    `.trim();

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    if (!report) return;
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(report, null, 2))}`;
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', jsonString);
    downloadAnchor.setAttribute('download', `${report.reportId}_Forensic_Report.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  if (loading) {
    return (
      <div className="p-12 text-center text-slate-500 bg-white border border-slate-200 rounded-xl space-y-3 font-sans shadow-sm">
        <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-xs text-slate-600 font-medium">Generating Comprehensive 18-Section Forensic Dossier...</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-12 text-center text-slate-500 bg-white border border-slate-200 rounded-xl shadow-sm">
        Failed to load report data.
      </div>
    );
  }

  const INSUFFICIENT = 'Insufficient evidence available to answer this question.';

  return (
    <div id="forensic-report-view" className="space-y-6 pb-16 max-w-5xl mx-auto font-sans">
      {/* Top Action Bar (hidden when printed) */}
      <div className="print:hidden bg-white border border-slate-200 rounded-xl p-4 sm:p-5 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center flex-shrink-0">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-900">
              Official Forensic Investigation Dossier (18 Formatted Sections)
            </h2>
            <span className="text-xs text-slate-500 font-mono">
              Report Ref: {report.reportId}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleCopyMarkdown}
            className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Copy className="w-3.5 h-3.5" />
            <span>{copied ? 'Copied Markdown' : 'Copy Text'}</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download JSON</span>
          </button>

          <button
            onClick={handlePrint}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-1.5 transition-colors shadow-xs cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save as PDF</span>
          </button>
        </div>
      </div>

      {/* The Printable 18-Section Forensic Document */}
      <div className="bg-white border border-slate-200 rounded-xl p-8 sm:p-12 space-y-8 text-slate-800 print:bg-white print:text-black print:border-none print:p-0 shadow-sm">
        {/* Document Header & Seal */}
        <div className="border-b border-slate-200 pb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="text-xs font-semibold tracking-wider text-blue-600 uppercase">
              SMART INDIA HACKATHON 2026 // PROBLEM STATEMENT 26106
            </div>
            <h1 className="text-2xl font-bold text-slate-900 tracking-tight mt-1.5">
              DIGITAL FORENSICS & EMAIL THREAT EXAMINATION REPORT
            </h1>
            <p className="text-xs text-slate-500 mt-1">
              Professional SOC Incident Response & Evidentiary Chain-of-Custody Record
            </p>
          </div>

          <div className="text-right text-xs space-y-1">
            <div className="text-blue-700 font-bold font-mono text-sm">{report.reportId}</div>
            <div className="text-slate-500 text-xs">Generated: {report.generatedAt}</div>
            <div className="text-emerald-700 font-semibold flex items-center gap-1 justify-end text-xs">
              <ShieldCheck className="w-4 h-4 text-emerald-600" /> ISO/IEC 27037 Compliant
            </div>
          </div>
        </div>

        {/* Render the 18 Distinct Forensic Sections */}
        <div className="space-y-6">
          {report.structuredSections && report.structuredSections.length > 0 ? (
            report.structuredSections.map(sec => {
              const isAi = sec.isAiGenerated;
              return (
                <section
                  key={sec.sectionNumber}
                  className={`p-5 rounded-xl border text-xs space-y-3 transition-all ${
                    isAi
                      ? 'bg-purple-50/40 border-purple-200'
                      : 'bg-slate-50/60 border-slate-200'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/80 pb-2.5">
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded-md bg-blue-50 text-blue-700 border border-blue-200 text-[11px] font-mono font-bold">
                        Section {String(sec.sectionNumber).padStart(2, '0')}
                      </span>
                      <span>{sec.title}</span>
                    </h3>

                    {isAi ? (
                      <span className="px-2.5 py-0.5 rounded-full bg-purple-100 text-purple-800 border border-purple-200 text-[10px] font-bold flex items-center gap-1">
                        <Sparkles className="w-3 h-3 text-purple-600" /> AI-GENERATED CONCLUSION
                      </span>
                    ) : (
                      <span className="px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200 text-[10px] font-semibold">
                        FORENSICALLY GROUNDED
                      </span>
                    )}
                  </div>

                  <div className="text-slate-700 leading-relaxed font-sans text-xs whitespace-pre-wrap">
                    {sec.content || INSUFFICIENT}
                  </div>
                </section>
              );
            })
          ) : (
            <div className="text-xs text-slate-400 italic">Report sections rendering...</div>
          )}
        </div>

        {/* Legal Disclaimer and Limitations Footer */}
        <div className="pt-6 border-t border-slate-200 text-xs text-slate-500 space-y-2">
          <div>
            <strong className="text-slate-800 font-semibold">Forensic Rule of Non-Fabrication:</strong> Whenever required evidence does not exist in the evidentiary artifact, the platform strictly records: <span className="font-mono text-blue-700 font-semibold">"Insufficient evidence available to answer this question."</span>
          </div>
          <div>
            <strong className="text-slate-800 font-semibold">Legal Disclaimer:</strong> {report.legalDisclaimer}
          </div>
        </div>
      </div>
    </div>
  );
};
