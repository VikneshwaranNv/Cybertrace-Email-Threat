import {
  CaseRecord,
  CaseHistoryItem,
  EvidenceBlock,
  ForensicReportData,
  InvestigationCompletePayload,
  LedgerVerificationResult,
  CopilotQueryResponse,
  BulkTriageSession,
  BulkTriageItem,
  BulkCampaignCluster,
  BulkIndicatorItem,
  SafeGmailStatus,
  GmailMessageSummaryItem,
  GmailTriageRecord,
  GmailRawMessagePayload,
  GmailSyncResult,
  GmailSyncStatusState,
  GmailPromotionResponse,
  GmailCampaignSummary,
  GmailCampaignDetailResponse,
  GmailNormalizedIOC,
  SocDashboardSummaryResponse,
  AlertEvent,
  HuntQuery,
  HuntResult,
  IOCHit,
} from '../types/forensics';
import { supabase, isSupabaseConfigured } from './supabase';

export interface SystemHealth {
  status: string;
  platform: string;
  timestamp: string;
  geminiConfigured: boolean;
  totalInvestigations: number;
  totalEvidenceBlocks: number;
  engineVersion: string;
  authConfigured?: boolean;
}

export interface UserSessionProfile {
  userId: string;
  email: string;
  name: string;
  role: 'ANALYST' | 'ADMIN' | 'SENIOR_ANALYST' | 'AUDITOR';
  organization: string;
  badgeNumber: string;
}

export interface SecurityAuditLog {
  id: string;
  timestamp: string;
  action: string;
  actorId?: string;
  actorEmail?: string;
  actorRole?: string;
  ip?: string;
  status: 'SUCCESS' | 'FAILURE' | 'DENIED';
  resourceId?: string;
  resourceType?: string;
  details?: string;
}

const TOKEN_STORAGE_KEY = 'soc_auth_token';
const USER_STORAGE_KEY = 'soc_auth_user';

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY) || sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function getStoredUser(): UserSessionProfile | null {
  try {
    const raw = localStorage.getItem(USER_STORAGE_KEY) || sessionStorage.getItem(USER_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function saveSession(token: string, user: UserSessionProfile, rememberMe = true) {
  try {
    if (rememberMe) {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
      sessionStorage.removeItem(USER_STORAGE_KEY);
    } else {
      sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
      sessionStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      localStorage.removeItem(USER_STORAGE_KEY);
    }
  } catch (e) {
    console.warn('Storage unavailable', e);
  }
}

export function clearSession() {
  try {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    localStorage.removeItem(USER_STORAGE_KEY);
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    sessionStorage.removeItem(USER_STORAGE_KEY);
  } catch (e) {
    console.warn('Storage unavailable', e);
  }
}

function getAuthHeaders(): HeadersInit {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

let activeBootstrapPromise: Promise<string | null> | null = null;

export async function ensureActiveSession(): Promise<UserSessionProfile> {
  const token = getStoredToken();
  if (token) {
    const verified = await verifyCurrentSession();
    if (verified) return verified;
  }

  if (!activeBootstrapPromise) {
    activeBootstrapPromise = (async () => {
      try {
        const res = await fetch('/api/auth/bootstrap', { method: 'POST' });
        if (res.ok) {
          const data = await res.json();
          saveSession(data.token, data.user);
          return data.token;
        }
      } catch (err) {
        console.warn('Bootstrap endpoint unavailable, attempting direct login:', err);
      }
      try {
        const loginData = await loginUser('analyst@soc.internal', 'Analyst@SOC2026!');
        return loginData.token;
      } catch (loginErr) {
        console.error('Auto-login failed:', loginErr);
        return null;
      } finally {
        activeBootstrapPromise = null;
      }
    })();
  }

  await activeBootstrapPromise;
  const user = getStoredUser();
  if (!user) {
    throw new Error('Unable to establish authenticated analyst session');
  }
  return user;
}

export async function authedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  let token = getStoredToken();
  if (!token) {
    try {
      await ensureActiveSession();
      token = getStoredToken();
    } catch {
      // Proceed; server will respond with 401 if unauthenticated
    }
  }

  const headers = new Headers(init?.headers || {});
  if (!headers.has('Content-Type') && !(init?.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  let res = await fetch(input, { ...init, headers });

  // If token was rejected (expired or server restarted), automatically re-authenticate and retry once
  if (res.status === 401 && token) {
    try {
      clearSession();
      await ensureActiveSession();
      const freshToken = getStoredToken();
      if (freshToken) {
        const retryHeaders = new Headers(init?.headers || {});
        if (!retryHeaders.has('Content-Type') && !(init?.body instanceof FormData)) {
          retryHeaders.set('Content-Type', 'application/json');
        }
        retryHeaders.set('Authorization', `Bearer ${freshToken}`);
        res = await fetch(input, { ...init, headers: retryHeaders });
      }
    } catch (refreshErr) {
      console.warn('Auto-reauth failed on 401:', refreshErr);
    }
  }

  return res;
}

// Authentication API methods
export async function loginUser(
  email: string,
  password: string,
  name?: string,
  role?: string,
  rememberMe = true
): Promise<{ token: string; user: UserSessionProfile }> {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, name, role }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Authentication failed');
  }

  const data = await res.json();
  const profile: UserSessionProfile = {
    userId: data.user.id || data.user.userId || 'usr-default',
    email: data.user.email,
    name: data.user.name,
    role: data.user.role,
    organization: 'CyberTrace SOC Operations',
    badgeNumber: `SOC-${(data.user.id || '9042').slice(-4)}`,
  };
  saveSession(data.token, profile, rememberMe);
  return { token: data.token, user: profile };
}

export async function registerUser(
  email: string,
  password: string,
  name?: string,
  role?: string,
  rememberMe = true
): Promise<{ token: string; user: UserSessionProfile }> {
  const res = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, name, role }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Registration failed');
  }

  const data = await res.json();
  const profile: UserSessionProfile = {
    userId: data.user.id || data.user.userId || 'usr-default',
    email: data.user.email,
    name: data.user.name,
    role: data.user.role,
    organization: 'CyberTrace SOC Operations',
    badgeNumber: `SOC-${(data.user.id || '9042').slice(-4)}`,
  };
  saveSession(data.token, profile, rememberMe);
  return { token: data.token, user: profile };
}

export async function requestPasswordReset(email: string): Promise<{ success: boolean; message: string; resetToken?: string; verificationCode?: string }> {
  const res = await fetch('/api/auth/forgot-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to request password reset');
  }
  return res.json();
}

export async function resetPassword(tokenOrCode: string, newPassword: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch('/api/auth/reset-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: tokenOrCode, newPassword }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Password reset failed');
  }
  return res.json();
}

export async function verifyEmail(email: string, code: string): Promise<{ success: boolean; message: string; user?: UserSessionProfile }> {
  const res = await fetch('/api/auth/verify-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Email verification failed');
  }
  return res.json();
}

export async function logoutUser(): Promise<void> {
  if (isSupabaseConfigured && supabase) {
    try {
      await supabase.auth.signOut();
    } catch (e) {
      console.warn('Supabase signout notice:', e);
    }
  }

  const token = getStoredToken();
  if (token) {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: getAuthHeaders(),
      });
    } catch {
      // Best effort remote logout
    }
  }
  clearSession();
}

export async function verifyCurrentSession(): Promise<UserSessionProfile | null> {
  // 1. If Supabase is configured, check for active Supabase session (including from URL hash redirects)
  if (isSupabaseConfigured && supabase) {
    try {
      const { data } = await supabase.auth.getSession();
      if (data.session?.user) {
        const sbUser = data.session.user;
        const role = (sbUser.user_metadata?.role as any) || 'ANALYST';
        const name = sbUser.user_metadata?.full_name || sbUser.email?.split('@')[0] || 'SOC Operator';
        const profile: UserSessionProfile = {
          userId: sbUser.id,
          email: sbUser.email || '',
          name,
          role,
          organization: 'CyberTrace SOC Operations',
          badgeNumber: `SOC-${sbUser.id.slice(0, 4)}`,
        };
        saveSession(data.session.access_token, profile, true);
        return profile;
      }
    } catch (sbErr) {
      console.warn('Supabase session check notice:', sbErr);
    }
  }

  // 2. Fall back to local Express session token verification
  const token = getStoredToken();
  if (!token) return null;

  try {
    const res = await fetch('/api/auth/me', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) {
      clearSession();
      return null;
    }
    const data = await res.json();
    const profile: UserSessionProfile = {
      userId: data.user.id || data.user.userId || 'usr-default',
      email: data.user.email,
      name: data.user.name,
      role: data.user.role,
      organization: 'CyberTrace SOC Operations',
      badgeNumber: `SOC-${(data.user.id || '9042').slice(-4)}`,
    };
    return profile;
  } catch {
    return null;
  }
}

export async function fetchAuditLogs(): Promise<SecurityAuditLog[]> {
  const res = await authedFetch('/api/audit/logs');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Failed to fetch security audit logs (HTTP ${res.status})`);
  }
  const data = await res.json().catch(() => ({ logs: [] }));
  return Array.isArray(data?.logs) ? data.logs : [];
}

export async function fetchSystemHealth(): Promise<SystemHealth> {
  const res = await fetch('/api/health');
  if (!res.ok) throw new Error('Failed to fetch system health');
  return res.json();
}

export async function fetchAllCases(): Promise<CaseRecord[]> {
  const res = await authedFetch('/api/cases');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch cases');
  }
  return res.json();
}
export const fetchCases = fetchAllCases;

export async function fetchCasePayload(caseId: string): Promise<InvestigationCompletePayload> {
  const res = await authedFetch(`/api/cases/${caseId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Failed to fetch case ${caseId}`);
  }
  return res.json();
}
export const fetchCaseById = fetchCasePayload;

export async function fetchCaseGeolocation(caseId: string): Promise<any> {
  const res = await authedFetch(`/api/cases/${caseId}/geolocation`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Failed to fetch geolocation for case ${caseId}`);
  }
  return res.json();
}

export async function lookupIp(ip: string): Promise<any> {
  const res = await authedFetch(`/api/geolocation/lookup/${encodeURIComponent(ip.trim())}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Failed to look up IP ${ip}`);
  }
  return res.json();
}

export async function analyzeNewEmail(rawEmail: string, title?: string): Promise<InvestigationCompletePayload> {
  const res = await authedFetch('/api/cases/analyze', {
    method: 'POST',
    body: JSON.stringify({ rawEmail, title }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || err.message || 'Analysis request failed');
  }
  return res.json();
}
export const ingestRawEmail = analyzeNewEmail;

export async function updateCaseStatus(caseId: string, status: CaseRecord['status']): Promise<CaseRecord> {
  const res = await authedFetch(`/api/cases/${caseId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to update case status');
  }
  const data = await res.json();
  return data.caseRecord || data;
}

export async function updateCasePriority(caseId: string, priority: CaseRecord['priority']): Promise<CaseRecord> {
  const res = await authedFetch(`/api/cases/${caseId}/priority`, {
    method: 'PATCH',
    body: JSON.stringify({ priority }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to update case priority');
  }
  const data = await res.json();
  return data.caseRecord || data;
}

export async function updateCaseAssignment(caseId: string, assignedAnalystId: string): Promise<CaseRecord> {
  const res = await authedFetch(`/api/cases/${caseId}/assignment`, {
    method: 'PATCH',
    body: JSON.stringify({ assignedAnalystId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to update case assignment');
  }
  const data = await res.json();
  return data.caseRecord || data;
}

export async function fetchAssignableAnalysts(): Promise<Array<{ id: string; name: string; email: string; role: string }>> {
  const res = await authedFetch('/api/cases/assignable-analysts');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch assignable analysts');
  }
  const data = await res.json();
  return data.analysts || [];
}

export async function fetchCaseHistory(caseId: string): Promise<CaseHistoryItem[]> {
  const res = await authedFetch(`/api/cases/${caseId}/history`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch case history');
  }
  const data = await res.json();
  return data.history || [];
}

export async function updateCaseDetails(
  caseId: string,
  details: { status?: CaseRecord['status']; priority?: CaseRecord['priority']; assignedTo?: string; tags?: string[] }
): Promise<CaseRecord> {
  const res = await authedFetch(`/api/cases/${caseId}/details`, {
    method: 'PATCH',
    body: JSON.stringify(details),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to update case details');
  }
  const data = await res.json();
  return data.caseRecord;
}

export async function addCaseNote(
  caseId: string,
  note: { note: string; author?: string }
): Promise<CaseRecord> {
  const res = await authedFetch(`/api/cases/${caseId}/notes`, {
    method: 'POST',
    body: JSON.stringify(note),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to add analyst note');
  }
  const data = await res.json();
  return data.caseRecord;
}

export async function fetchCaseReport(caseId: string): Promise<ForensicReportData> {
  const res = await authedFetch(`/api/cases/${caseId}/report`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to generate report');
  }
  return res.json();
}

export async function fetchLedger(): Promise<{ chain: EvidenceBlock[]; verification: LedgerVerificationResult }> {
  const res = await authedFetch('/api/ledger');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch ledger');
  }
  return res.json();
}

export async function verifyLedgerIntegrity(): Promise<LedgerVerificationResult> {
  const res = await authedFetch('/api/ledger/verify', {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to verify ledger integrity');
  }
  return res.json();
}

export async function simulateLedgerTamper(blockIndex = 1): Promise<{ success: boolean; modifiedBlock?: EvidenceBlock }> {
  const res = await authedFetch('/api/ledger/tamper', {
    method: 'POST',
    body: JSON.stringify({ blockIndex }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to simulate tamper (Admin role required)');
  }
  return res.json();
}

export async function resealLedger(): Promise<LedgerVerificationResult> {
  const res = await authedFetch('/api/ledger/reseal', {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to reseal ledger (Admin role required)');
  }
  return res.json();
}

export async function fetchDemoCases(): Promise<{
  mode: string;
  disclaimer: string;
  cases: { caseId: string; caseNumber: string; title: string; category: string; description: string; analyst: string }[];
}> {
  const res = await fetch('/api/demo-cases');
  if (!res.ok) throw new Error('Failed to fetch demo cases');
  return res.json();
}

export async function loadDemoCase(caseId: string): Promise<InvestigationCompletePayload> {
  const res = await fetch(`/api/demo-cases/${caseId}/load`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to load demo case');
  return res.json();
}

export async function loadDemoScenario(type: 'LEGITIMATE' | 'BEC' | 'PHISHING'): Promise<InvestigationCompletePayload> {
  const mapping: Record<string, string> = {
    LEGITIMATE: 'CASE-2026-003',
    BEC: 'CASE-2026-001',
    PHISHING: 'CASE-2026-002',
  };
  const targetId = mapping[type] || 'CASE-2026-001';
  return loadDemoCase(targetId);
}

export async function askInvestigationCopilot(
  question: string,
  caseId?: string,
  payload?: InvestigationCompletePayload
): Promise<CopilotQueryResponse> {
  const res = await authedFetch('/api/copilot/query', {
    method: 'POST',
    body: JSON.stringify({ question, caseId, payload }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || err.message || 'Investigation Copilot query failed');
  }
  return res.json();
}

// ============================================================================
// BULK EMAIL FORENSIC TRIAGE & CAMPAIGN CORRELATION CLIENT APIS
// ============================================================================

export async function createBulkTriageSession(): Promise<BulkTriageSession> {
  const res = await authedFetch('/api/cases/bulk-triage/session', { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to create triage session');
  }
  return res.json();
}

export async function loadBulkTriageDemo(): Promise<BulkTriageSession> {
  const res = await authedFetch('/api/cases/bulk-triage/demo', { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to initialize simulated bulk triage demo');
  }
  return res.json();
}

export async function uploadBulkTriageBatch(
  sessionId: string,
  files: Array<{ filename: string; content: string }>
): Promise<{ success: boolean; sessionId: string; queuedCount: number }> {
  const res = await authedFetch('/api/cases/bulk-triage/upload', {
    method: 'POST',
    body: JSON.stringify({ sessionId, files }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to upload batch files');
  }
  return res.json();
}

export async function fetchBulkTriageStatus(sessionId: string): Promise<BulkTriageSession> {
  const res = await authedFetch(`/api/cases/bulk-triage/${sessionId}/status`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch triage session status');
  }
  return res.json();
}

export async function cancelBulkTriage(sessionId: string): Promise<boolean> {
  const res = await authedFetch(`/api/cases/bulk-triage/${sessionId}/cancel`, { method: 'POST' });
  return res.ok;
}

export async function fetchBulkTriageEmails(
  sessionId: string,
  params?: {
    page?: number;
    limit?: number;
    mailType?: string;
    riskLevel?: string;
    campaignId?: string;
    search?: string;
  }
): Promise<{ items: BulkTriageItem[]; totalCount: number; page: number; totalPages: number }> {
  const q = new URLSearchParams();
  if (params?.page) q.set('page', String(params.page));
  if (params?.limit) q.set('limit', String(params.limit));
  if (params?.mailType) q.set('mailType', params.mailType);
  if (params?.riskLevel) q.set('riskLevel', params.riskLevel);
  if (params?.campaignId) q.set('campaignId', params.campaignId);
  if (params?.search) q.set('search', params.search);

  const res = await authedFetch(`/api/cases/bulk-triage/${sessionId}/emails?${q.toString()}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch triaged emails');
  }
  return res.json();
}

export async function fetchBulkTriageEmailDetail(
  sessionId: string,
  triageId: string
): Promise<{ item: BulkTriageItem; rawSource?: string }> {
  const res = await authedFetch(`/api/cases/bulk-triage/${sessionId}/emails/${triageId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch email details');
  }
  return res.json();
}

export async function fetchBulkTriageCampaigns(
  sessionId: string
): Promise<{ campaigns: BulkCampaignCluster[]; count: number }> {
  const res = await authedFetch(`/api/cases/bulk-triage/${sessionId}/campaigns`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch triage campaigns');
  }
  return res.json();
}

export async function fetchBulkTriageIndicators(
  sessionId: string
): Promise<{ indicators: BulkIndicatorItem[]; count: number }> {
  const res = await authedFetch(`/api/cases/bulk-triage/${sessionId}/indicators`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch triage indicators');
  }
  return res.json();
}

export async function promoteBulkTriageItem(
  sessionId: string,
  triageId: string
): Promise<{ success: boolean; caseId: string; payload: InvestigationCompletePayload }> {
  const res = await authedFetch(`/api/cases/bulk-triage/${sessionId}/promote`, {
    method: 'POST',
    body: JSON.stringify({ triageId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to promote triage item to case');
  }
  return res.json();
}

export async function requestBulkTriageAiDeepDive(
  sessionId: string,
  triageId: string
): Promise<{ success: boolean; item: BulkTriageItem }> {
  const res = await authedFetch(`/api/cases/bulk-triage/${sessionId}/ai-deep-dive`, {
    method: 'POST',
    body: JSON.stringify({ triageId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to execute AI deep-dive');
  }
  return res.json();
}

// =========================================================================
// GMAIL MONITORING API (PHASE 5)
// =========================================================================

export async function fetchGmailStatus(): Promise<SafeGmailStatus> {
  const res = await authedFetch('/api/gmail/status');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch Gmail status');
  }
  return res.json();
}

export async function fetchGmailAuthUrl(): Promise<{ url: string }> {
  const res = await authedFetch('/api/gmail/oauth/url');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to generate Gmail OAuth URL');
  }
  return res.json();
}

export async function connectGmailDemo(): Promise<{ success: boolean; connected: boolean; gmailEmail: string; connectedAt: string }> {
  const res = await authedFetch('/api/gmail/demo/connect', { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to connect simulated demo mailbox');
  }
  return res.json();
}

export async function disconnectGmail(): Promise<{ success: boolean; disconnected: boolean; message: string }> {
  const res = await authedFetch('/api/gmail/disconnect', { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to disconnect Gmail');
  }
  return res.json();
}

export async function fetchGmailMessages(params?: {
  maxResults?: number;
  pageToken?: string;
  query?: string;
}): Promise<{ messages: GmailMessageSummaryItem[]; nextPageToken?: string; resultSizeEstimate?: number }> {
  const q = new URLSearchParams();
  if (params?.maxResults) q.set('maxResults', String(params.maxResults));
  if (params?.pageToken) q.set('pageToken', params.pageToken);
  if (params?.query) q.set('q', params.query);

  const res = await authedFetch(`/api/gmail/messages?${q.toString()}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to retrieve Gmail messages');
  }
  return res.json();
}

export async function fetchRawGmailMessage(id: string): Promise<GmailRawMessagePayload> {
  const res = await authedFetch(`/api/gmail/messages/${encodeURIComponent(id)}/raw`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to retrieve raw Gmail message');
  }
  return res.json();
}

export async function triageGmailMessage(id: string): Promise<GmailTriageRecord> {
  const res = await authedFetch(`/api/gmail/messages/${encodeURIComponent(id)}/triage`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to triage Gmail message');
  }
  return res.json();
}

export async function triageGmailBatch(messageIds: string[]): Promise<{
  total: number;
  succeeded: number;
  failed: number;
  results: Array<{ messageId: string; success: boolean; data?: GmailTriageRecord; error?: string }>;
}> {
  const res = await authedFetch('/api/gmail/messages/triage-batch', {
    method: 'POST',
    body: JSON.stringify({ messageIds }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to batch triage Gmail messages');
  }
  return res.json();
}

export async function triggerGmailSync(): Promise<GmailSyncResult> {
  const res = await authedFetch('/api/gmail/sync', {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const errorObj: any = new Error(err.error || 'Failed to trigger Gmail synchronization');
    errorObj.statusCode = res.status;
    errorObj.code = err.code;
    errorObj.retryAfterMs = err.retryAfterMs;
    throw errorObj;
  }
  return res.json();
}

export async function fetchGmailSyncStatus(): Promise<GmailSyncStatusState> {
  const res = await authedFetch('/api/gmail/sync/status');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch Gmail synchronization status');
  }
  return res.json();
}

export async function promoteGmailMessage(id: string): Promise<GmailPromotionResponse> {
  const res = await authedFetch(`/api/gmail/messages/${encodeURIComponent(id)}/promote`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const errorObj: any = new Error(err.error || 'Failed to promote Gmail message to case');
    errorObj.statusCode = res.status;
    errorObj.code = err.code;
    throw errorObj;
  }
  return res.json();
}

export async function fetchGmailCampaigns(): Promise<{
  campaigns: GmailCampaignSummary[];
  iocs: GmailNormalizedIOC[];
  totalTriagedMessages: number;
}> {
  const res = await authedFetch('/api/gmail/campaigns');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch Gmail threat campaigns');
  }
  return res.json();
}

export async function fetchGmailCampaignDetail(campaignId: string): Promise<GmailCampaignDetailResponse> {
  const res = await authedFetch(`/api/gmail/campaigns/${encodeURIComponent(campaignId)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch Gmail campaign details');
  }
  return res.json();
}

export async function fetchGmailIocs(): Promise<{ iocs: GmailNormalizedIOC[]; count: number }> {
  const res = await authedFetch('/api/gmail/iocs');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch Gmail indicators');
  }
  return res.json();
}

export async function fetchSocDashboardSummary(): Promise<SocDashboardSummaryResponse> {
  const res = await authedFetch('/api/soc/dashboard-summary');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch SOC dashboard summary');
  }
  return res.json();
}

// ── Real-Time Threat Alerts (Phase 11) ──────────────────────────────────────

export async function fetchAlertHistory(limit = 20): Promise<AlertEvent[]> {
  const res = await authedFetch(`/api/alerts/history?limit=${limit}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to fetch alert history');
  }
  const data = await res.json();
  return data.alerts || [];
}

export async function triggerAlertBroadcast(alert: {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description?: string;
  caseId?: string;
  threatType?: string;
}): Promise<AlertEvent> {
  const res = await authedFetch('/api/alerts/broadcast', {
    method: 'POST',
    body: JSON.stringify(alert),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to trigger alert broadcast');
  }
  const data = await res.json();
  return data.alert;
}

export function createAlertStream(
  onAlert: (alert: AlertEvent) => void,
  onError?: (err: any) => void
): () => void {
  const token = getStoredToken();
  if (!token) {
    if (onError) onError(new Error('No auth token available for SSE stream'));
    return () => {};
  }

  const url = `/api/alerts/stream?token=${encodeURIComponent(token)}`;
  const eventSource = new EventSource(url);

  eventSource.addEventListener('alert', (e) => {
    try {
      const data: AlertEvent = JSON.parse(e.data);
      onAlert(data);
    } catch (err) {
      console.error('Failed to parse SSE alert event:', err);
    }
  });

  eventSource.onerror = (err) => {
    if (onError) onError(err);
  };

  return () => {
    eventSource.close();
  };
}

// ── Threat Hunting Query Engine (Phase 12) ──────────────────────────────────

export async function huntThreats(query: HuntQuery): Promise<HuntResult> {
  const params = new URLSearchParams();
  if (query.q) params.set('q', query.q);
  if (query.iocType) params.set('iocType', query.iocType);
  if (query.minRiskScore !== undefined) params.set('minRiskScore', String(query.minRiskScore));
  if (query.maxRiskScore !== undefined) params.set('maxRiskScore', String(query.maxRiskScore));
  if (query.fromDate) params.set('fromDate', query.fromDate);
  if (query.toDate) params.set('toDate', query.toDate);
  if (query.limit) params.set('limit', String(query.limit));
  if (query.riskLevels && query.riskLevels.length > 0) {
    params.set('riskLevels', query.riskLevels.join(','));
  }
  if (query.threatTypes && query.threatTypes.length > 0) {
    params.set('threatTypes', query.threatTypes.join(','));
  }

  const res = await authedFetch(`/api/hunt/search?${params.toString()}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to execute threat hunting query');
  }
  return res.json();
}

export async function lookupIoc(iocValue: string): Promise<{ found: boolean; hit?: IOCHit }> {
  const res = await authedFetch(`/api/hunt/ioc/${encodeURIComponent(iocValue)}`);
  if (res.status === 404) {
    return { found: false };
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to lookup IOC');
  }
  return res.json();
}



