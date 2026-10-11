import React, { useState } from 'react';
import {
  X,
  Shield,
  Layers,
  BookOpen,
  Users,
  CheckCircle2,
  Activity,
  Link2,
  Fingerprint,
  Info,
  Sparkles,
} from 'lucide-react';
import { UserSessionProfile, loginUser } from '../services/api';

interface PlatformGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser?: UserSessionProfile | null;
  onSessionChange?: (user: UserSessionProfile | null) => void;
  onSelectScenario?: (scenario: 'LEGITIMATE' | 'BEC' | 'PHISHING') => void;
}

type GuideTab = 'overview' | 'pipeline' | 'glossary' | 'roles';

interface RoleInfo {
  role: string;
  email: string;
  password: string;
  name: string;
  badgeColor: string;
  description: string;
  permissions: string[];
}

const ROLES_INFO: RoleInfo[] = [
  {
    role: 'ADMIN',
    email: 'admin@soc.internal',
    password: 'Admin@SOC2026!',
    name: 'Chief SOC Security Admin',
    badgeColor: 'bg-purple-100 text-purple-800 border-purple-300',
    description: 'Full supervisory authority across all tenant cases, immutable audit logs, and ledger integrity verification.',
    permissions: ['View all tenant cases', 'Manage threat campaigns', 'Review system audit trail', 'Sealed ledger inspection'],
  },
  {
    role: 'SENIOR_ANALYST',
    email: 'senior@soc.internal',
    password: 'Senior@SOC2026!',
    name: 'Aditi Rao (Senior SOC Analyst)',
    badgeColor: 'bg-blue-100 text-blue-800 border-blue-300',
    description: 'Lead Incident Responder. Authority to assign analysts, adjust operational priorities, and collaborate on dossiers.',
    permissions: ['Triage & ingest emails', 'Assign analysts to cases', 'Adjust operational priority', 'Add collaborative notes'],
  },
  {
    role: 'ANALYST',
    email: 'analyst@soc.internal',
    password: 'Analyst@SOC2026!',
    name: 'SOC Analyst',
    badgeColor: 'bg-emerald-100 text-emerald-800 border-emerald-300',
    description: 'Frontline SOC forensic investigator. Analyzes headers, examines IOCs, and submits investigation findings.',
    permissions: ['Triage & ingest emails', 'Examine IOC threat intelligence', 'Submit case notes', 'Export forensic PDF reports'],
  },
  {
    role: 'AUDITOR',
    email: 'auditor@soc.internal',
    password: 'Auditor@SOC2026!',
    name: 'Rohan Gupta (Compliance Auditor)',
    badgeColor: 'bg-amber-100 text-amber-800 border-amber-300',
    description: 'Strictly read-only compliance inspector. Validates chain-of-custody without modifying case data.',
    permissions: ['Inspect forensic dossiers', 'Verify SHA-256 ledger proofs', 'Export court-admissible PDFs', 'All mutations blocked (HTTP 403)'],
  },
];

interface GlossaryItem {
  term: string;
  badge: string;
  color: string;
  explanation: string;
  example: string;
}

const GLOSSARY_ITEMS: GlossaryItem[] = [
  {
    term: 'SPF (Sender Policy Framework)',
    badge: 'Email Authentication',
    color: 'border-blue-200 bg-blue-50 text-blue-800',
    explanation: 'A DNS-based protocol that specifies which IP addresses are authorized to send emails on behalf of a domain. If an email originates from an unauthorized server, SPF fails.',
    example: 'v=spf1 include:_spf.google.com ~all',
  },
  {
    term: 'DKIM (DomainKeys Identified Mail)',
    badge: 'Cryptographic Integrity',
    color: 'border-indigo-200 bg-indigo-50 text-indigo-800',
    explanation: 'Adds a cryptographic digital signature to the email header. Recipient mail servers verify this signature against the sender DNS public key to confirm the email was not modified in transit.',
    example: 'd=company.com; s=2026; b=K3j9F... [SHA-256 RSA]',
  },
  {
    term: 'DMARC',
    badge: 'Policy Enforcement',
    color: 'border-purple-200 bg-purple-50 text-purple-800',
    explanation: 'Domain-based Message Authentication, Reporting, and Conformance. Dictates how recipient servers handle authentication failures (none/monitor, quarantine, or strict reject).',
    example: 'v=DMARC1; p=reject; rua=mailto:dmarc@company.com',
  },
  {
    term: 'IOC (Indicator of Compromise)',
    badge: 'Threat Intelligence',
    color: 'border-red-200 bg-red-50 text-red-800',
    explanation: 'Digital forensic artifacts discovered in an email attack, such as malicious IP addresses, domain names, file hashes, and URLs linked to cybercrime actors.',
    example: '198.51.100.23, login-micros0ft.com, sha256:e3b0c44...',
  },
  {
    term: 'Defanging (hxxp:// & [.] )',
    badge: 'Analyst Safety',
    color: 'border-amber-200 bg-amber-50 text-amber-800',
    explanation: 'Neutralizing active links and domain names so analysts do not accidentally click or trigger malware during forensic analysis.',
    example: 'https://evil.com/login -> hxxps://evil[.]com/login',
  },
  {
    term: 'Cryptographic Evidence Ledger',
    badge: 'Chain of Custody',
    color: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    explanation: 'An immutable SHA-256 blockchain data structure where every email case is cryptographically linked to the preceding block. Guaranteed tamper-proof for court admissibility.',
    example: 'Block #4: hash=8f1c... prevHash=3e2a... [VALID]',
  },
  {
    term: 'BEC (Business Email Compromise)',
    badge: 'Attack Vector',
    color: 'border-rose-200 bg-rose-50 text-rose-800',
    explanation: 'A targeted social engineering attack where cybercriminals impersonate corporate executives or vendors to deceive employees into wiring funds or divulging sensitive credentials.',
    example: 'Display name "CEO", Reply-To mismatched to attacker inbox',
  },
];

export const PlatformGuideModal: React.FC<PlatformGuideModalProps> = ({
  isOpen,
  onClose,
  currentUser,
  onSessionChange,
  onSelectScenario,
}) => {
  const [activeTab, setActiveTab] = useState<GuideTab>('overview');
  const [switchingRole, setSwitchingRole] = useState<string | null>(null);
  const [switchFeedback, setSwitchFeedback] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleRoleSwitch = async (roleInfo: RoleInfo) => {
    try {
      setSwitchingRole(roleInfo.role);
      setSwitchFeedback(null);
      const { user } = await loginUser(roleInfo.email, roleInfo.password);
      if (onSessionChange) {
        onSessionChange(user);
      }
      setSwitchFeedback(`Switched to ${user.name} (${user.role})`);
      setTimeout(() => setSwitchFeedback(null), 3500);
    } catch (err: any) {
      setSwitchFeedback(`Switch failed: ${err?.message || 'Error'}`);
    } finally {
      setSwitchingRole(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 select-none font-sans animate-in fade-in duration-200">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
        {/* Modal Header */}
        <div className="px-6 py-5 border-b border-slate-200 flex items-center justify-between bg-gradient-to-r from-slate-900 via-blue-950 to-slate-900 text-white">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center shadow-md">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-tight">
                  CyberTrace Architecture & Platform Guide
                </h2>
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-blue-500/30 text-blue-200 font-semibold border border-blue-400/40">
                  SIH 2026 Problem 26106
                </span>
              </div>
              <p className="text-xs text-blue-200/80 mt-0.5">
                Autonomous AI Email Threat Forensics, Deterministic Verification & Evidence Ledger
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-300 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
            title="Close Guide"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="px-6 border-b border-slate-200 bg-slate-50 flex items-center gap-2 overflow-x-auto">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'overview'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <BookOpen className="w-4 h-4" />
            <span>Platform Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('pipeline')}
            className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'pipeline'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>5-Stage Forensic Pipeline</span>
          </button>

          <button
            onClick={() => setActiveTab('glossary')}
            className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'glossary'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Info className="w-4 h-4" />
            <span>Security Glossary</span>
          </button>

          <button
            onClick={() => setActiveTab('roles')}
            className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'roles'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Users className="w-4 h-4" />
            <span>Roles & 1-Click Switcher</span>
          </button>
        </div>

        {/* Tab Content Container */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Executive Summary Card */}
              <div className="bg-gradient-to-br from-blue-50 via-slate-50 to-indigo-50 border border-blue-200/80 rounded-2xl p-6">
                <div className="flex items-center gap-2 text-blue-700 font-semibold text-xs uppercase tracking-wider">
                  <Sparkles className="w-4 h-4" />
                  <span>Problem Statement Overview</span>
                </div>
                <h3 className="text-xl font-bold text-slate-900 mt-2">
                  Autonomous AI-Powered Email Threat Forensics & SOC Operations
                </h3>
                <p className="text-sm text-slate-600 mt-2 leading-relaxed">
                  CyberTrace addresses <strong>SIH 2026 Problem Statement 26106</strong> by delivering an enterprise-grade Digital Forensics and Incident Response (DFIR) platform capable of detecting sophisticated email attacks (BEC, phishing, spoofing, malware droppers) without relying on external cloud LLMs for mission-critical triage. It couples <strong>deterministic RFC-822 header analysis</strong> with an <strong>immutable cryptographic evidence ledger</strong> to provide court-admissible forensic artifacts.
                </p>

                {/* Quick Scenario Launcher Box */}
                {onSelectScenario && (
                  <div className="mt-5 pt-4 border-t border-blue-200/60">
                    <span className="text-xs font-semibold text-slate-700 uppercase tracking-wider block mb-2">
                      Try 1-Click Live Test Scenarios:
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <button
                        onClick={() => {
                          onSelectScenario('BEC');
                          onClose();
                        }}
                        className="p-3 bg-white hover:bg-amber-50 border border-amber-200 hover:border-amber-400 rounded-xl text-left transition-all cursor-pointer group shadow-xs"
                      >
                        <div className="text-xs font-bold text-amber-800 group-hover:text-amber-900">
                          🔴 Executive BEC Scam
                        </div>
                        <div className="text-[11px] text-slate-500 mt-1">
                          CEO wire fraud with mismatched reply-to headers.
                        </div>
                      </button>

                      <button
                        onClick={() => {
                          onSelectScenario('PHISHING');
                          onClose();
                        }}
                        className="p-3 bg-white hover:bg-red-50 border border-red-200 hover:border-red-400 rounded-xl text-left transition-all cursor-pointer group shadow-xs"
                      >
                        <div className="text-xs font-bold text-red-800 group-hover:text-red-900">
                          🟠 Credential Phishing
                        </div>
                        <div className="text-[11px] text-slate-500 mt-1">
                          Fake Microsoft 365 login harvester with obfuscated URLs.
                        </div>
                      </button>

                      <button
                        onClick={() => {
                          onSelectScenario('LEGITIMATE');
                          onClose();
                        }}
                        className="p-3 bg-white hover:bg-emerald-50 border border-emerald-200 hover:border-emerald-400 rounded-xl text-left transition-all cursor-pointer group shadow-xs"
                      >
                        <div className="text-xs font-bold text-emerald-800 group-hover:text-emerald-900">
                          🟢 Clean Corporate Email
                        </div>
                        <div className="text-[11px] text-slate-500 mt-1">
                          Authentic corporate memo passing all SPF/DKIM/DMARC checks.
                        </div>
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* 4 Core Pillars */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl border border-slate-200 bg-white shadow-xs">
                  <div className="flex items-center gap-2 text-blue-600 font-semibold text-sm">
                    <Activity className="w-4 h-4" />
                    <span>Deterministic Triage Engine</span>
                  </div>
                  <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                    Zero-Gemini offline fallback engine parses RFC-822 headers, inspects Received hop latency, verifies SPF/DKIM/DMARC alignment, and scores threat risk deterministically.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-slate-200 bg-white shadow-xs">
                  <div className="flex items-center gap-2 text-purple-600 font-semibold text-sm">
                    <Fingerprint className="w-4 h-4" />
                    <span>IOC Threat Intelligence</span>
                  </div>
                  <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                    Automated indicator extraction and defanging (hxxp://, evil[.]com). Correlates threat indicators with MITRE ATT&CK tactics and known cybercrime campaigns.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-slate-200 bg-white shadow-xs">
                  <div className="flex items-center gap-2 text-emerald-600 font-semibold text-sm">
                    <Link2 className="w-4 h-4" />
                    <span>Cryptographic Evidence Ledger</span>
                  </div>
                  <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                    Every analyzed email is sealed into an immutable SHA-256 blockchain block with Merkle verification. Guarantees chain of custody and court admissibility.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-slate-200 bg-white shadow-xs">
                  <div className="flex items-center gap-2 text-amber-600 font-semibold text-sm">
                    <Users className="w-4 h-4" />
                    <span>Multi-Tenant SOC Workflow</span>
                  </div>
                  <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                    Decoupled operational priority, assignable analyst collaboration, server-enforced note limits, live SSE threat alerting, and court-grade A4 PDF export.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: 5-STAGE PIPELINE */}
          {activeTab === 'pipeline' && (
            <div className="space-y-4">
              <div className="text-xs text-slate-500 font-medium">
                Every email entering CyberTrace undergoes a structured 5-stage automated investigation pipeline:
              </div>

              <div className="space-y-3">
                {/* Stage 1 */}
                <div className="p-4 rounded-xl border border-blue-200 bg-blue-50/40 flex items-start gap-4">
                  <div className="w-8 h-8 rounded-lg bg-blue-600 text-white font-bold text-sm flex items-center justify-center flex-shrink-0">
                    1
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-slate-900">
                        Multi-Source Ingestion & Parsing
                      </h4>
                      <span className="text-[11px] font-semibold text-blue-700 bg-blue-100 px-2 py-0.5 rounded-full">
                        RFC-822 / Gmail / EML
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                      Accepts raw RFC-822 MIME emails, automated Gmail inbox monitoring via OAuth2, or bulk batches (up to 6,000+ messages). Normalizes headers, decodes base64/quoted-printable payloads, and isolates attachments.
                    </p>
                  </div>
                </div>

                {/* Stage 2 */}
                <div className="p-4 rounded-xl border border-indigo-200 bg-indigo-50/40 flex items-start gap-4">
                  <div className="w-8 h-8 rounded-lg bg-indigo-600 text-white font-bold text-sm flex items-center justify-center flex-shrink-0">
                    2
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-slate-900">
                        Header Forensics & Authentication Verification
                      </h4>
                      <span className="text-[11px] font-semibold text-indigo-700 bg-indigo-100 px-2 py-0.5 rounded-full">
                        SPF / DKIM / DMARC / GeoIP
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                      Evaluates SPF validation, DKIM cryptographic signatures, and DMARC alignment. Reconstructs Received header hop chains with hop-by-hop latency and GeoIP reverse lookup.
                    </p>
                  </div>
                </div>

                {/* Stage 3 */}
                <div className="p-4 rounded-xl border border-purple-200 bg-purple-50/40 flex items-start gap-4">
                  <div className="w-8 h-8 rounded-lg bg-purple-600 text-white font-bold text-sm flex items-center justify-center flex-shrink-0">
                    3
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-slate-900">
                        Threat Intelligence & Safe Defanging
                      </h4>
                      <span className="text-[11px] font-semibold text-purple-700 bg-purple-100 px-2 py-0.5 rounded-full">
                        IOCs / MITRE ATT&CK
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                      Extracts URLs, domains, IP addresses, and attachment hashes. Automatically defangs indicators to prevent accidental detonation. Correlates indicators with active campaigns and MITRE ATT&CK technique IDs.
                    </p>
                  </div>
                </div>

                {/* Stage 4 */}
                <div className="p-4 rounded-xl border border-emerald-200 bg-emerald-50/40 flex items-start gap-4">
                  <div className="w-8 h-8 rounded-lg bg-emerald-600 text-white font-bold text-sm flex items-center justify-center flex-shrink-0">
                    4
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-slate-900">
                        Cryptographic Evidence Ledger Sealing
                      </h4>
                      <span className="text-[11px] font-semibold text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded-full">
                        SHA-256 Merkle Chain
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                      Seals investigation results into a cryptographically linked block. The block contains raw header hashes, payload digest, timestamp, and previous block hash. Tampering with any byte invalidates the ledger chain.
                    </p>
                  </div>
                </div>

                {/* Stage 5 */}
                <div className="p-4 rounded-xl border border-amber-200 bg-amber-50/40 flex items-start gap-4">
                  <div className="w-8 h-8 rounded-lg bg-amber-600 text-white font-bold text-sm flex items-center justify-center flex-shrink-0">
                    5
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-slate-900">
                        SOC Incident Response & Court-Admissible Export
                      </h4>
                      <span className="text-[11px] font-semibold text-amber-700 bg-amber-100 px-2 py-0.5 rounded-full">
                        SSE Alert / PDF Dossier
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                      Triggers real-time SSE alerts to analysts. Enables case prioritization, analyst assignment, collaborative note audit trails, threat hunting indicator search, and 1-click court-admissible A4 PDF generation.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: GLOSSARY */}
          {activeTab === 'glossary' && (
            <div className="space-y-4">
              <div className="text-xs text-slate-500 font-medium">
                Plain-language explanations of essential cybersecurity and email forensics terminology:
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {GLOSSARY_ITEMS.map((item, idx) => (
                  <div key={idx} className="p-4 rounded-xl border border-slate-200 bg-white shadow-xs flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <h4 className="text-sm font-bold text-slate-900">{item.term}</h4>
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${item.color}`}>
                          {item.badge}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 mt-2 leading-relaxed">
                        {item.explanation}
                      </p>
                    </div>
                    <div className="mt-3 pt-2 border-t border-slate-100">
                      <span className="text-[10px] font-mono text-slate-500 bg-slate-50 px-2 py-1 rounded block truncate">
                        {item.example}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: ROLES & SWITCHER */}
          {activeTab === 'roles' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="text-xs text-slate-500 font-medium">
                  Click any role below to instantly switch sessions and test role-based access control (RBAC):
                </div>
                {switchFeedback && (
                  <span className="text-xs font-semibold text-emerald-700 bg-emerald-50 px-3 py-1 rounded-lg border border-emerald-200 animate-in fade-in">
                    {switchFeedback}
                  </span>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {ROLES_INFO.map((r, idx) => {
                  const isCurrent = currentUser?.role === r.role;
                  return (
                    <div
                      key={idx}
                      className={`p-5 rounded-2xl border transition-all ${
                        isCurrent
                          ? 'border-blue-500 bg-blue-50/20 shadow-md ring-2 ring-blue-500/20'
                          : 'border-slate-200 bg-white hover:border-slate-300 shadow-xs'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`text-xs font-bold px-2.5 py-1 rounded-lg border ${r.badgeColor}`}>
                          {r.role}
                        </span>
                        {isCurrent ? (
                          <span className="flex items-center gap-1.5 text-xs font-semibold text-blue-700 bg-blue-100 px-2.5 py-1 rounded-md">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Active Session
                          </span>
                        ) : (
                          <button
                            onClick={() => handleRoleSwitch(r)}
                            disabled={switchingRole === r.role}
                            className="text-xs font-semibold text-blue-600 hover:text-blue-800 bg-blue-50 hover:bg-blue-100 px-3 py-1 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                          >
                            {switchingRole === r.role ? 'Switching...' : 'Switch to Role'}
                          </button>
                        )}
                      </div>

                      <div className="mt-3">
                        <div className="text-sm font-bold text-slate-900">{r.name}</div>
                        <div className="text-xs font-mono text-slate-400 mt-0.5">{r.email}</div>
                        <p className="text-xs text-slate-600 mt-2 leading-relaxed">
                          {r.description}
                        </p>
                      </div>

                      <div className="mt-3 pt-3 border-t border-slate-100">
                        <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                          Role Privileges:
                        </span>
                        <ul className="space-y-1">
                          {r.permissions.map((p, pIdx) => (
                            <li key={pIdx} className="text-xs text-slate-600 flex items-center gap-1.5">
                              <span className="w-1.5 h-1.5 rounded-full bg-blue-500 flex-shrink-0" />
                              <span>{p}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Shield className="w-4 h-4 text-blue-600" />
            <span>CyberTrace Defense Architecture — 100% Deterministic & Air-Gappable</span>
          </div>
          <button
            onClick={onClose}
            className="px-5 py-2 bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold rounded-xl transition-colors cursor-pointer shadow-xs"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
