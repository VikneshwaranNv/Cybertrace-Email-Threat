import React, { useState } from 'react';
import {
  Clock,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  FileSearch,
  Link2,
  ChevronDown,
  ChevronUp,
  Radio,
  Server,
  Fingerprint,
  Cpu,
  Layers,
} from 'lucide-react';
import { TimelineEvent } from '../types/forensics';

interface AttackTimelinePageProps {
  timeline: TimelineEvent[];
}

export const AttackTimelinePage: React.FC<AttackTimelinePageProps> = ({ timeline }) => {
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({
    'TL-STEP-1': true,
    'TL-STEP-7': true,
    'TL-STEP-9': true,
  });

  const toggleExpand = (id: string) => {
    setExpandedEvents(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const getPhaseIcon = (phase: TimelineEvent['phase']) => {
    switch (phase) {
      case 'EMAIL_RECEIVED':
        return <FileSearch className="w-4 h-4 text-blue-600" />;
      case 'SENDER_ANALYZED':
        return <Server className="w-4 h-4 text-slate-700" />;
      case 'AUTH_CHECKED':
        return <CheckCircle2 className="w-4 h-4 text-emerald-600" />;
      case 'SUSPICIOUS_INDICATOR_DETECTED':
        return <AlertTriangle className="w-4 h-4 text-amber-600" />;
      case 'INFRASTRUCTURE_ENRICHED':
        return <Radio className="w-4 h-4 text-blue-600" />;
      case 'CAMPAIGN_CORRELATED':
        return <Fingerprint className="w-4 h-4 text-purple-600" />;
      case 'AI_CLASSIFIED':
        return <Cpu className="w-4 h-4 text-indigo-600" />;
      case 'RISK_CALCULATED':
        return <ShieldAlert className="w-4 h-4 text-red-600" />;
      case 'EVIDENCE_SEALED':
        return <Link2 className="w-4 h-4 text-emerald-600" />;
      default:
        return <Clock className="w-4 h-4 text-slate-500" />;
    }
  };

  const getSeverityPill = (severity: TimelineEvent['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'WARNING':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'SUCCESS':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <div id="attack-timeline-view" className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center flex-shrink-0">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900">
              Attack Reconstruction & Chronological Forensic Narrative
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Automated step-by-step investigation narrative tracing initial RFC-822 ingress to cryptographic ledger sealing
            </p>
          </div>
        </div>

        <span className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-blue-50 text-blue-700 border border-blue-200">
          9-Phase Audit Trail
        </span>
      </div>

      {/* Sequential Timeline Component */}
      <div className="relative pl-6 sm:pl-8 space-y-4 before:absolute before:left-3 sm:before:left-4 before:top-4 before:bottom-4 before:w-0.5 before:bg-slate-200">
        {timeline.map((event, idx) => {
          const isExpanded = Boolean(expandedEvents[event.id]);

          return (
            <div key={event.id} className="relative group">
              {/* Timeline Step Dot */}
              <div className="absolute -left-6 sm:-left-8 top-3 w-6 h-6 rounded-full bg-white border-2 border-blue-600 flex items-center justify-center text-[10px] font-bold text-blue-600 shadow-sm">
                {event.stepNumber}
              </div>

              {/* Event Card */}
              <div className="bg-white border border-slate-200 hover:border-slate-300 rounded-xl overflow-hidden transition-all shadow-xs">
                {/* Header */}
                <div
                  onClick={() => toggleExpand(event.id)}
                  className="p-4 cursor-pointer flex flex-wrap items-center justify-between gap-3 hover:bg-slate-50/70 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 flex-shrink-0">
                      {getPhaseIcon(event.phase)}
                    </div>
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-bold text-slate-900">{event.title}</span>
                        <span className={`text-[11px] px-2.5 py-0.5 rounded-full border uppercase font-bold ${getSeverityPill(event.severity)}`}>
                          {event.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {event.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 text-xs text-slate-500">
                    <span className="text-xs font-semibold text-blue-600 bg-blue-50 px-2 py-0.5 rounded-md border border-blue-100">
                      {event.timeDelta}
                    </span>
                    <span className="hidden md:inline text-slate-400 font-mono text-[11px]">{event.timestamp}</span>
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Collapsible Detail Section */}
                {isExpanded && (
                  <div className="p-5 bg-slate-50/60 border-t border-slate-100 text-xs space-y-4">
                    {/* Observed Evidence */}
                    <div className="space-y-1.5">
                      <span className="text-xs font-bold text-slate-600 uppercase tracking-wider block">
                        Forensic Telemetry Observed
                      </span>
                      <div className="space-y-1.5">
                        {event.observedEvidence.map((obs, i) => (
                          <div
                            key={i}
                            className="p-3 rounded-lg bg-white border border-slate-200 text-slate-800 text-xs flex items-start gap-2.5 font-mono shadow-xs"
                          >
                            <span className="text-blue-600 font-bold">›</span>
                            <span className="break-all">{obs}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Action Taken */}
                    <div className="p-3.5 rounded-xl bg-white border border-slate-200 text-xs text-slate-700 flex flex-wrap items-center justify-between gap-2 shadow-xs">
                      <div>
                        <span className="text-[11px] text-slate-400 uppercase tracking-wider block font-semibold">Analyst / System Action</span>
                        <span className="font-bold text-slate-900 mt-0.5 block">{event.actionTaken}</span>
                      </div>
                      <span className="text-xs font-medium px-2.5 py-1 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200">
                        ISO/IEC 27037 Verified
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
