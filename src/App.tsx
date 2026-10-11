import React, { useState, useEffect } from 'react';
import { Sidebar, PageId } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { AuthModal } from './components/AuthModal';
import { DashboardPage } from './pages/DashboardPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { HeaderForensicsPage } from './pages/HeaderForensicsPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { InfrastructureGraphPage } from './pages/InfrastructureGraphPage';
import { CampaignDnaPage } from './pages/CampaignDnaPage';
import { AttackTimelinePage } from './pages/AttackTimelinePage';
import { LedgerPage } from './pages/LedgerPage';
import { CaseHistoryPage } from './pages/CaseHistoryPage';
import { ForensicReportPage } from './pages/ForensicReportPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { BulkTriagePage } from './pages/BulkTriagePage';
import { GmailMonitorPage } from './pages/GmailMonitorPage';
import { ThreatHuntingPage } from './pages/ThreatHuntingPage';
import { AlertNotificationCenter } from './components/AlertNotificationCenter';
import { PlatformGuideModal } from './components/PlatformGuideModal';
import { AuthPage } from './pages/AuthPage';
import {
  fetchCases,
  fetchCaseById,
  ingestRawEmail,
  loadDemoScenario,
  updateCaseStatus,
  UserSessionProfile,
  getStoredUser,
  verifyCurrentSession,
  logoutUser,
  clearSession,
} from './services/api';
import { CaseRecord, InvestigationCompletePayload } from './types/forensics';
import { AlertCircle, Terminal, X, UploadCloud, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [currentPage, setCurrentPage] = useState<PageId>('dashboard');
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [activeCase, setActiveCase] = useState<InvestigationCompletePayload | null>(null);
  const [currentUser, setCurrentUser] = useState<UserSessionProfile | null>(getStoredUser());
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [isGuideModalOpen, setIsGuideModalOpen] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isIngestModalOpen, setIsIngestModalOpen] = useState(false);
  const [rawInput, setRawInput] = useState('');
  const [modalScenario, setModalScenario] = useState<string>('CUSTOM');
  const [notification, setNotification] = useState<{ message: string; type: 'success' | 'info' | 'error' } | null>(null);

  // Initial session & data bootstrap
  useEffect(() => {
    let isMounted = true;
    const initializeSessionAndData = async () => {
      try {
        const user = await verifyCurrentSession();
        if (isMounted) {
          setCurrentUser(user);
          if (user) {
            await loadAllCasesAndDefault();
          }
        }
      } catch (err) {
        console.warn('Session verification notice:', err);
        if (isMounted) {
          setCurrentUser(null);
        }
      } finally {
        if (isMounted) {
          setIsCheckingAuth(false);
        }
      }
    };
    initializeSessionAndData();
    return () => {
      isMounted = false;
    };
  }, []);

  const handleLogout = async () => {
    try {
      await logoutUser();
    } catch (err) {
      console.warn('Logout network notice:', err);
    } finally {
      clearSession();
      setCurrentUser(null);
      setActiveCase(null);
      setCases([]);
      showNotification('Logged out of SOC Platform', 'info');
    }
  };

  const showNotification = (message: string, type: 'success' | 'info' | 'error' = 'info') => {
    setNotification({ message, type });
    setTimeout(() => {
      setNotification(null);
    }, 4000);
  };

  const loadAllCasesAndDefault = async () => {
    try {
      const caseList = await fetchCases();
      setCases(caseList);

      if (caseList.length > 0) {
        // Find highest severity or first case
        const target = caseList.find(c => c.severity === 'CRITICAL') || caseList[0];
        const fullCase = await fetchCaseById(target.caseId);
        setActiveCase(fullCase);
      }
    } catch (err: any) {
      console.error('Failed to load initial cases:', err);
      showNotification(err?.message || 'Failed to load initial investigations', 'error');
    }
  };

  const handleSelectCase = async (caseId: string) => {
    try {
      setIsAnalyzing(true);
      const fullCase = await fetchCaseById(caseId);
      setActiveCase(fullCase);
      showNotification(`Switched active investigation to ${fullCase.caseRecord.caseNumber}`, 'info');
    } catch (err) {
      console.error('Failed to select case:', err);
      showNotification('Error loading case record', 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleIngestRaw = async (raw: string, scenario?: string) => {
    try {
      setIsAnalyzing(true);
      const result = await ingestRawEmail(raw, scenario);
      setActiveCase(result);
      const updatedCases = await fetchCases();
      setCases(updatedCases);
      setIsIngestModalOpen(false);
      setRawInput('');
      setCurrentPage('investigation');
      showNotification(`Ingestion complete: Sealed as Block in Ledger (${result.caseRecord.caseNumber})`, 'success');
    } catch (err: any) {
      console.error('Failed to ingest raw email:', err);
      showNotification(err.message || 'Forensic parsing failed', 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleLoadScenario = async (type: 'LEGITIMATE' | 'BEC' | 'PHISHING') => {
    try {
      setIsAnalyzing(true);
      const result = await loadDemoScenario(type);
      setActiveCase(result);
      const updatedCases = await fetchCases();
      setCases(updatedCases);
      setIsIngestModalOpen(false);
      setCurrentPage('investigation');
      showNotification(`Scenario loaded: ${result.caseRecord.title}`, 'success');
    } catch (err: any) {
      console.error('Failed to load demo scenario:', err);
      showNotification('Error loading demo scenario', 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleUpdateStatus = async (caseId: string, status: CaseRecord['status']) => {
    try {
      const updated = await updateCaseStatus(caseId, status);
      setCases(prev => prev.map(c => (c.caseId === caseId ? updated : c)));
      if (activeCase && activeCase.caseRecord.caseId === caseId) {
        setActiveCase({
          ...activeCase,
          caseRecord: updated,
        });
      }
      showNotification(`Case ${updated.caseNumber} updated to ${status}`, 'info');
    } catch (err) {
      console.error('Failed to update case status:', err);
    }
  };

  const criticalAlertCount = cases.filter(c => c.severity === 'CRITICAL' && c.status !== 'CLOSED').length;

  if (isCheckingAuth) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-white font-sans">
        <div className="w-12 h-12 border-3 border-blue-500 border-t-transparent rounded-full animate-spin mb-4" />
        <div className="text-sm font-semibold tracking-wider text-slate-300 uppercase">
          Verifying SOC Credentials...
        </div>
      </div>
    );
  }

  if (!currentUser) {
    return (
      <AuthPage
        onAuthenticated={user => {
          setCurrentUser(user);
          loadAllCasesAndDefault();
          showNotification(`Authenticated as ${user.name} (${user.role})`, 'success');
        }}
      />
    );
  }

  return (
    <div className="flex h-screen bg-slate-50 text-slate-900 font-sans antialiased overflow-hidden select-none">
      {/* Sidebar Navigation */}
      <Sidebar
        currentPage={currentPage}
        onNavigate={setCurrentPage}
        caseCount={cases.length}
        alertCount={criticalAlertCount}
        activeCaseId={activeCase?.caseRecord.caseNumber || 'CASE-2026-001'}
        userRole={currentUser?.role}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* TopBar */}
        <TopBar
          activeCase={activeCase}
          cases={cases}
          currentUser={currentUser}
          onSelectCase={handleSelectCase}
          onOpenIngest={() => setIsIngestModalOpen(true)}
          onOpenAuthModal={() => setIsAuthModalOpen(true)}
          onOpenGuideModal={() => setIsGuideModalOpen(true)}
          onLogout={handleLogout}
          isAnalyzing={isAnalyzing}
        />

        {/* Real-time Threat Alert Notification Center (Phase 11) */}
        <AlertNotificationCenter
          onNavigate={setCurrentPage}
          onSelectCase={handleSelectCase}
        />

        {/* Global Toast Notification */}
        {notification && (
          <div
            className={`fixed top-4 right-6 z-50 px-4 py-3 rounded-xl border text-sm font-medium shadow-lg flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-200 bg-white ${
              notification.type === 'success'
                ? 'border-green-200 text-slate-900'
                : notification.type === 'error'
                ? 'border-red-200 text-slate-900'
                : 'border-blue-200 text-slate-900'
            }`}
          >
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-green-600 flex-shrink-0" />
            ) : notification.type === 'error' ? (
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
            ) : (
              <Terminal className="w-5 h-5 text-blue-600 flex-shrink-0" />
            )}
            <span>{notification.message}</span>
          </div>
        )}

        {/* Scrollable View Container */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-slate-50">
          <div className="max-w-7xl mx-auto">
            {currentPage === 'dashboard' && (
              <DashboardPage
                cases={cases}
                activeCase={activeCase}
                onSelectCase={handleSelectCase}
                onNavigate={setCurrentPage}
                onQuickIngest={() => setIsIngestModalOpen(true)}
                onLoadScenario={handleLoadScenario}
                onOpenGuide={() => setIsGuideModalOpen(true)}
              />
            )}

            {currentPage === 'investigation' && (
              <InvestigationPage
                activeCase={activeCase}
                onIngestRaw={handleIngestRaw}
                onLoadScenario={handleLoadScenario}
                onSelectCase={handleSelectCase}
                isAnalyzing={isAnalyzing}
                onNavigate={setCurrentPage}
              />
            )}

            {currentPage === 'gmail-monitor' && (
              <GmailMonitorPage
                onShowNotification={showNotification}
                onNavigate={setCurrentPage}
                onSelectCase={handleSelectCase}
              />
            )}

            {currentPage === 'bulk-triage' && (
              <BulkTriagePage
                onSelectCase={handleSelectCase}
                onNavigate={setCurrentPage}
                onShowNotification={showNotification}
              />
            )}

            {currentPage === 'threat-hunt' && (
              <ThreatHuntingPage
                onSelectCase={handleSelectCase}
                onNavigate={setCurrentPage}
              />
            )}

            {currentPage === 'headers' && (
              <HeaderForensicsPage
                headerAnalysis={activeCase ? activeCase.headerAnalysis : null}
                geolocations={activeCase ? activeCase.geolocations : []}
                activeCase={activeCase}
                cases={cases}
                onSelectCase={handleSelectCase}
                onLoadScenario={handleLoadScenario}
                onNavigate={setCurrentPage}
                onQuickIngest={() => setIsIngestModalOpen(true)}
              />
            )}

            {currentPage === 'threat-intel' && (
              <ThreatIntelligencePage
                iocs={activeCase ? activeCase.iocs : []}
              />
            )}

            {currentPage === 'graph' && (
              <InfrastructureGraphPage
                graphData={activeCase ? (activeCase.graphData || (activeCase as any).investigationGraph || null) : null}
                onSelectCase={handleSelectCase}
              />
            )}

            {currentPage === 'campaign-dna' && (
              <CampaignDnaPage
                campaignMatches={activeCase ? activeCase.campaignMatches : []}
                onSelectCase={handleSelectCase}
              />
            )}

            {currentPage === 'timeline' && (
              <AttackTimelinePage
                timeline={activeCase ? activeCase.attackTimeline : []}
              />
            )}

            {currentPage === 'ledger' && <LedgerPage />}

            {currentPage === 'cases' && (
              <CaseHistoryPage
                cases={cases}
                onSelectCase={handleSelectCase}
                onUpdateStatus={handleUpdateStatus}
                onNavigate={setCurrentPage}
              />
            )}

            {currentPage === 'report' && (
              <ForensicReportPage
                caseId={activeCase ? activeCase.caseRecord.caseId : cases[0]?.caseId || 'CASE-2026-001'}
              />
            )}

            {currentPage === 'audit' && (
              <AuditLogsPage
                currentUserRole={currentUser?.role}
                onSwitchToAdmin={() => setIsAuthModalOpen(true)}
              />
            )}
          </div>
        </main>
      </div>

      {/* Global Quick Ingestion Modal */}
      {isIngestModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl space-y-0">
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-200 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold text-slate-900">
                  Analyze New Email
                </h3>
                <p className="text-sm text-slate-500 mt-0.5">
                  Choose a pre-configured sample email or paste your own raw email headers and text.
                </p>
              </div>
              <button
                onClick={() => setIsIngestModalOpen(false)}
                className="p-2 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
                title="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Demo Scenarios Selection */}
            <div className="p-6 bg-slate-50 border-b border-slate-200 space-y-3">
              <label className="text-xs font-semibold text-slate-600 uppercase tracking-wider block">
                Option 1: Load a Sample Email Scenario
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => handleLoadScenario('LEGITIMATE')}
                  className="p-3.5 rounded-xl border border-slate-200 bg-white hover:border-green-500 hover:shadow-xs text-left transition-all cursor-pointer group"
                >
                  <div className="text-sm font-semibold text-slate-900 group-hover:text-green-700">
                    Safe Email
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Normal IT support notice. All checks pass.
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => handleLoadScenario('BEC')}
                  className="p-3.5 rounded-xl border border-slate-200 bg-white hover:border-amber-500 hover:shadow-xs text-left transition-all cursor-pointer group"
                >
                  <div className="text-sm font-semibold text-slate-900 group-hover:text-amber-700">
                    Executive Impersonation
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Urgent wire transfer scam with forged reply address.
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => handleLoadScenario('PHISHING')}
                  className="p-3.5 rounded-xl border border-slate-200 bg-white hover:border-red-500 hover:shadow-xs text-left transition-all cursor-pointer group"
                >
                  <div className="text-sm font-semibold text-slate-900 group-hover:text-red-700">
                    Credential Theft
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Fake password reset link leading to credential harvester.
                  </div>
                </button>
              </div>
            </div>

            {/* Raw Input Area */}
            <div className="p-6 space-y-2">
              <label htmlFor="raw-email-input" className="text-xs font-semibold text-slate-600 uppercase tracking-wider block">
                Option 2: Paste Raw Email Headers & Body (.eml)
              </label>
              <textarea
                id="raw-email-input"
                value={rawInput}
                onChange={e => setRawInput(e.target.value)}
                placeholder="From: security-alert@suspicious-domain.com&#10;To: employee@company.com&#10;Subject: Action Required: Reset Password&#10;&#10;Please click the link below to verify your account..."
                rows={6}
                className="w-full p-3.5 rounded-xl bg-white border border-slate-300 text-sm font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-none"
              />
              <p className="text-xs text-slate-500">
                The platform will automatically extract headers, check authentication (SPF/DKIM/DMARC), analyze IP hops, and identify security threats.
              </p>
            </div>

            {/* Modal Footer */}
            <div className="p-6 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
              <span className="text-xs text-slate-500 font-medium">
                Analysis completes in seconds
              </span>
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setIsIngestModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-sm font-medium text-slate-700 hover:bg-slate-200 transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={!rawInput.trim() || isAnalyzing}
                  onClick={() => handleIngestRaw(rawInput)}
                  className="px-5 py-2 rounded-lg text-sm font-semibold bg-blue-600 hover:bg-blue-700 text-white transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-xs"
                >
                  {isAnalyzing ? 'Analyzing Email...' : 'Start Analysis'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Operator Identity & RBAC Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        currentUser={currentUser}
        onSessionChange={setCurrentUser}
      />

      {/* Platform Architecture & Educational Guide Modal */}
      <PlatformGuideModal
        isOpen={isGuideModalOpen}
        onClose={() => setIsGuideModalOpen(false)}
        currentUser={currentUser}
        onSessionChange={setCurrentUser}
        onSelectScenario={handleLoadScenario}
      />
    </div>
  );
}
