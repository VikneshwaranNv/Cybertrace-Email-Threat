import dotenv from 'dotenv';
import express from 'express';
import path from 'path';
import { evidenceLedger } from './server/blockchain/evidenceLedger';
import { ALL_DEMO_CASES } from './server/demo/demoCases';
import { caseService } from './server/services/caseService';
import { queryInvestigationCopilot } from './server/ai/copilotEngine';
import { authService } from './server/auth/authService';
import { auditLogger } from './server/auth/auditLogger';
import {
  AuthenticatedRequest,
  authenticateUser,
  requireRole,
} from './server/auth/authMiddleware';
import { ipGeolocationService, validateGeoIpConfig } from './server/geolocation/ipGeolocationService';
import { bulkTriageService } from './server/services/bulkTriageService';
import { gmailOAuthService } from './server/gmail/gmailOAuthService';
import { gmailApiService } from './server/gmail/gmailApiService';
import { gmailTriageService } from './server/gmail/gmailTriageService';
import { gmailSyncService, gmailPollingScheduler } from './server/gmail/gmailSyncService';
import { gmailCasePromotionService } from './server/gmail/gmailCasePromotionService';
import { gmailIocService } from './server/gmail/gmailIocService';
import { gmailCampaignService } from './server/gmail/gmailCampaignService';
import { socDashboardService } from './server/services/socDashboardService';
import { alertService } from './server/services/alertService';
import { threatHuntingService } from './server/services/threatHuntingService';
import { CaseStatus, CasePriority } from './src/types/forensics';

dotenv.config();

const PORT = Number(process.env.PORT) || 3000;

export async function createExpressApp() {
  const app = express();

  // Security Headers & Hardening
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Body Parsing with 10MB forensic boundary
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Path normalization for serverless proxy environments (e.g. Vercel)
  app.use((req, _res, next) => {
    if (!req.url.startsWith('/api') && req.url !== '/' && !req.url.startsWith('/?')) {
      req.url = '/api' + req.url;
    }
    next();
  });

  // Initialize seed demonstration cases
  await caseService.initialize();

  // =========================================================================
  // 1. PUBLIC ENDPOINTS (Intentionally Public & Documented)
  // =========================================================================

  // Health and System Telemetry (Public)
  app.get('/api/health', (_req, res) => {
    const cases = caseService.getAllCases();
    const ledger = evidenceLedger.getChain();
    const geoConfig = validateGeoIpConfig();
    res.json({
      status: 'ok',
      platform: 'SIH 2026 Problem 26106: AI Email Threat & Forensics SOC',
      timestamp: new Date().toISOString(),
      geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
      totalInvestigations: cases.length,
      totalEvidenceBlocks: ledger.length,
      engineVersion: '2.7.0-SECURE-RBAC',
      authConfigured: true,
      geoIpProvider: geoConfig.provider,
      geoIpMaxMindRequired: geoConfig.isMaxMindRequired,
    });
  });

  // Authentication: Analyst / Admin Login (Public)
  app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const result = authService.login(email, password, clientIp);

    if (!result.success) {
      const failure = result as { success: false; error: string; statusCode: number };
      return res.status(failure.statusCode).json({ error: failure.error });
    }

    res.json({
      success: true,
      token: result.token,
      user: result.user,
    });
  });

  // Authentication: User / Operator Registration (Public)
  app.post('/api/auth/register', (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const result = authService.register(email, password, name, clientIp);

    if (!result.success) {
      const failure = result as { success: false; error: string; statusCode: number };
      return res.status(failure.statusCode).json({ error: failure.error });
    }

    res.status(201).json({
      success: true,
      token: result.token,
      user: result.user,
    });
  });

  // Authentication: Request Password Reset (Public)
  app.post('/api/auth/forgot-password', (req, res) => {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email address is required' });
    }

    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const result = authService.requestPasswordReset(email, clientIp);
    if (!result.success) {
      const failure = result as { success: false; error: string; statusCode: number };
      return res.status(failure.statusCode).json({ error: failure.error });
    }
    res.json(result);
  });

  // Authentication: Reset Password with Token/Code (Public)
  app.post('/api/auth/reset-password', (req, res) => {
    const { token, code, newPassword } = req.body;
    const tokenOrCode = token || code;
    if (!tokenOrCode || !newPassword) {
      return res.status(400).json({ error: 'Reset token/code and new password are required' });
    }

    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const result = authService.resetPassword(tokenOrCode, newPassword, clientIp);

    if (!result.success) {
      const failure = result as { success: false; error: string; statusCode: number };
      return res.status(failure.statusCode).json({ error: failure.error });
    }

    res.json(result);
  });

  // Authentication: Verify Email with Code (Public)
  app.post('/api/auth/verify-email', (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ error: 'Email and verification code are required' });
    }

    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const result = authService.verifyEmail(email, code, clientIp);

    if (!result.success) {
      const failure = result as { success: false; error: string; statusCode: number };
      return res.status(failure.statusCode).json({ error: failure.error });
    }

    res.json(result);
  });

  // Automated Operator Bootstrap (Ensures seamless SOC workspace initialization)
  app.post('/api/auth/bootstrap', (_req, res) => {
    try {
      const session = authService.getOrCreateDefaultSession();
      res.json({
        success: true,
        token: session.token,
        user: session.user,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to bootstrap operator session' });
    }
  });

  // Demonstration Case Inventory (Public Demo Mode - Strictly Labelled DEMO/SIMULATED DATA)
  app.get('/api/demo-cases', (_req, res) => {
    res.json({
      mode: 'DEMO/SIMULATED DATA',
      disclaimer: 'Demonstration scenarios contain simulated email telemetry for SOC training and triage evaluation.',
      cases: ALL_DEMO_CASES.map(c => ({
        caseId: c.caseId,
        caseNumber: c.caseNumber,
        title: c.title,
        category: c.category,
        description: c.description,
        analyst: c.analyst,
        classificationNotice: 'DEMO/SIMULATED DATA',
      })),
    });
  });

  // Load Public Demonstration Case (Public Demo Mode)
  app.post('/api/demo-cases/:id/load', (req, res) => {
    const found = ALL_DEMO_CASES.find(c => c.caseId === req.params.id);
    if (!found) {
      return res.status(404).json({ error: 'Demo case not found' });
    }
    const payload = caseService.getCasePayload(found.caseId);
    if (payload) {
      return res.json(payload);
    }
    return res.status(404).json({ error: 'Demo case not yet initialized' });
  });

  // =========================================================================
  // 2. AUTHENTICATED USER SESSION ENDPOINTS
  // =========================================================================

  // Session Verification & Profile (Authenticated)
  app.get('/api/auth/me', authenticateUser, (req: AuthenticatedRequest, res) => {
    res.json({
      user: authService.toPublicProfile(req.user!),
    });
  });

  // Session Logout (Authenticated)
  app.post('/api/auth/logout', authenticateUser, (req: AuthenticatedRequest, res) => {
    authService.logout(req.user!.token, req.ip || req.socket.remoteAddress);
    res.json({ success: true, message: 'Session successfully invalidated' });
  });

  // Admin User Directory (Admin Only)
  app.get('/api/auth/users', authenticateUser, requireRole('ADMIN'), (_req, res) => {
    res.json({ users: authService.getAllUsers() });
  });

  // Security Audit Trail (Admin & Analyst Access)
  app.get('/api/audit/logs', authenticateUser, requireRole('ADMIN', 'ANALYST'), (_req, res) => {
    res.json({ logs: auditLogger.getLogs() });
  });

  // =========================================================================
  // 3. PROTECTED FORENSIC CASE ENDPOINTS (Ownership & RBAC Enforced)
  // =========================================================================

  // Get Case Listing (Scoped strictly to user's authorized cases)
  app.get('/api/cases', authenticateUser, (req: AuthenticatedRequest, res) => {
    const cases = caseService.getCasesForUser(req.user!);
    res.json(cases);
  });

  // List Assignable Analysts for Case Collaboration (Authenticated)
  app.get('/api/cases/assignable-analysts', authenticateUser, (req: AuthenticatedRequest, res) => {
    const users = authService.getAllUsers();
    const analysts = users
      .filter(u => u.role !== 'AUDITOR')
      .map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
      }));
    res.json({ success: true, analysts });
  });

  // Helper handler for single case retrieval with authorization checks
  const handleGetCase = (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;
    const caseId = req.params.id;

    const result = caseService.getCasePayloadForUser(user, caseId);

    if (result.status === 'NOT_FOUND') {
      return res.status(404).json({ error: 'Case not found' });
    }

    if (result.status === 'FORBIDDEN') {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: caseId,
        resourceType: 'CASE_EVIDENCE',
        details: `Access denied: User ${user.email} (${user.role}) attempted unauthorized access to private case ${caseId}`,
      });
      return res.status(403).json({
        error: 'Forbidden: You do not have permission to access this case',
        code: 'CASE_ACCESS_FORBIDDEN',
      });
    }

    auditLogger.record({
      action: 'CASE_ACCESSED',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      ip: req.ip || req.socket.remoteAddress,
      resourceId: caseId,
      resourceType: 'CASE_RECORD',
      details: `Authorized case ${caseId} accessed by ${user.email}`,
    });

    return res.json(result.payload);
  };

  app.get('/api/cases/:id', authenticateUser, handleGetCase);
  app.get('/api/cases/:id/details', authenticateUser, handleGetCase);

  // Forensic IP Geolocation Retrieval & On-Demand Refresh (Authenticated + RBAC)
  const handleCaseGeolocation = async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const caseId = req.params.id;

      const result = caseService.getCasePayloadForUser(user, caseId);

      if (result.status === 'NOT_FOUND') {
        return res.status(404).json({ error: 'Case not found' });
      }

      if (result.status === 'FORBIDDEN') {
        auditLogger.record({
          action: 'AUTHORIZATION_FAILURE',
          status: 'DENIED',
          actorId: user.userId,
          actorEmail: user.email,
          actorRole: user.role,
          ip: req.ip || req.socket.remoteAddress,
          resourceId: caseId,
          resourceType: 'CASE_EVIDENCE',
          details: `Access denied: User ${user.email} (${user.role}) attempted unauthorized geolocation access to case ${caseId}`,
        });
        return res.status(403).json({
          error: 'Forbidden: You do not have permission to access this case geolocation',
          code: 'CASE_ACCESS_FORBIDDEN',
        });
      }

      if (!result.payload) {
        return res.status(404).json({ error: 'Case payload not found' });
      }

      const summary = await ipGeolocationService.resolveCaseGeolocations(result.payload);

      auditLogger.record({
        action: 'CASE_ACCESSED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: caseId,
        resourceType: 'CASE_RECORD',
        details: `Forensic geolocation resolved for case ${caseId} (${summary.geolocations.length} nodes)`,
      });

      return res.json(summary);
    } catch (err: any) {
      console.error('Case geolocation lookup error:', err);
      return res.status(500).json({ error: 'Failed to retrieve forensic geolocation intelligence' });
    }
  };

  app.get('/api/cases/:id/geolocation', authenticateUser, handleCaseGeolocation);
  app.post('/api/cases/:id/geolocation', authenticateUser, handleCaseGeolocation);

  // On-Demand Standalone IP Geolocation Lookup (Authenticated)
  app.get('/api/geolocation/lookup/:ip', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const rawIp = req.params.ip;
      if (!rawIp) {
        return res.status(400).json({ error: 'Missing IP parameter' });
      }
      const geo = await ipGeolocationService.lookupIp(rawIp);
      return res.json(geo);
    } catch (err: any) {
      console.error('IP lookup error:', err);
      return res.status(500).json({ error: 'IP geolocation lookup failed' });
    }
  });

  app.post('/api/geolocation/lookup', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const rawIp = req.body?.ip;
      if (!rawIp || typeof rawIp !== 'string') {
        return res.status(400).json({ error: 'Missing or invalid "ip" in request body' });
      }
      const geo = await ipGeolocationService.lookupIp(rawIp);
      return res.json(geo);
    } catch (err: any) {
      console.error('IP lookup error:', err);
      return res.status(500).json({ error: 'IP geolocation lookup failed' });
    }
  });

  // Ingest and Analyze New Email (Authenticated: Analyst or Admin)
  const handleAnalyzeEmail = async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const { rawEmail, title, analyst } = req.body;

      if (!rawEmail || typeof rawEmail !== 'string') {
        return res.status(400).json({ error: 'Missing or invalid rawEmail content. Payload must be a string.' });
      }

      const trimmedEmail = rawEmail.trim();
      if (trimmedEmail.length < 10) {
        return res.status(400).json({ error: 'Email content too short or empty to constitute a valid RFC-822 message.' });
      }

      const sizeBytes = Buffer.byteLength(rawEmail, 'utf8');
      if (sizeBytes > 10 * 1024 * 1024) {
        return res.status(413).json({ error: 'Payload exceeds maximum forensic file limit of 10MB.' });
      }

      const sanitizedTitle = typeof title === 'string' ? title.slice(0, 200).replace(/[<>]/g, '') : undefined;
      const sanitizedAnalyst = typeof analyst === 'string' ? analyst.slice(0, 100).replace(/[<>]/g, '') : user.name;

      const payload = await caseService.processEmail(rawEmail, {
        title: sanitizedTitle,
        analyst: sanitizedAnalyst,
        ownerId: user.userId,
        ownerEmail: user.email,
        authorizedUsers: [user.userId],
      });

      auditLogger.record({
        action: 'CASE_CREATED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: payload.caseRecord.caseId,
        resourceType: 'CASE_EVIDENCE',
        details: `Forensic case ${payload.caseRecord.caseId} created and sealed in custody by ${user.email}`,
      });

      // Broadcast real-time threat alert for HIGH or CRITICAL threats (Phase 11)
      if (payload.caseRecord.severity === 'CRITICAL' || payload.caseRecord.severity === 'HIGH') {
        alertService.broadcast({
          severity: payload.caseRecord.severity,
          title: `Threat Detected: ${payload.caseRecord.classification}`,
          description: `Case ${payload.caseRecord.caseNumber} scored ${payload.caseRecord.riskScore}/100 (${payload.caseRecord.severity}).`,
          caseId: payload.caseRecord.caseId,
          threatType: payload.caseRecord.classification,
          source: 'CASE_PIPELINE',
        });
      }

      res.status(201).json(payload);
    } catch (err: any) {
      console.error('Error analyzing email:', err);
      res.status(500).json({ error: 'Forensic analysis failed safely', message: err?.message || String(err) });
    }
  };

  app.post('/api/cases/analyze', authenticateUser, handleAnalyzeEmail);
  app.post('/api/analyze', authenticateUser, handleAnalyzeEmail);

  // =========================================================================
  // 3.5 BULK FORENSIC TRIAGE & CAMPAIGN CORRELATION ENDPOINTS (6,000+ Target)
  // =========================================================================

  // Trigger Instant 6,000+ Simulated Demo Triage
  app.post('/api/cases/bulk-triage/demo', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const session = await bulkTriageService.loadDemoSession();

      auditLogger.record({
        action: 'BULK_TRIAGE_DEMO_LOADED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        details: `Loaded 6,000+ simulated demo triage batch (Session: ${session.sessionId})`,
      });

      res.status(201).json(session);
    } catch (err: any) {
      console.error('Bulk triage demo load error:', err);
      res.status(500).json({ error: err.message || 'Failed to load simulated bulk triage session' });
    }
  });

  // Create empty triage session
  app.post('/api/cases/bulk-triage/session', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const session = bulkTriageService.createSession(false);
    res.status(201).json(session);
  });

  // Ingest batch of EML files into triage session
  app.post('/api/cases/bulk-triage/upload', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const { sessionId, files } = req.body;

      if (!sessionId || !Array.isArray(files) || files.length === 0) {
        return res.status(400).json({ error: 'sessionId and non-empty files array are required' });
      }

      // Start asynchronous ingestion in background
      bulkTriageService.ingestBatchAsync(sessionId, files).catch(err => {
        console.error(`Error in bulk triage background ingestion (${sessionId}):`, err);
      });

      auditLogger.record({
        action: 'BULK_TRIAGE_INGESTION_STARTED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        details: `Started triage ingestion of ${files.length} EMLs (Session: ${sessionId})`,
      });

      res.json({ success: true, sessionId, queuedCount: files.length, status: 'PROCESSING' });
    } catch (err: any) {
      console.error('Bulk triage upload error:', err);
      res.status(500).json({ error: err.message || 'Bulk triage ingestion failed' });
    }
  });

  // Get session status and metrics
  app.get('/api/cases/bulk-triage/:sessionId/status', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const session = bulkTriageService.getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Triage session not found' });
    res.json(session);
  });

  // Cancel processing session
  app.post('/api/cases/bulk-triage/:sessionId/cancel', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const success = bulkTriageService.cancelSession(req.params.sessionId);
    if (!success) return res.status(404).json({ error: 'Triage session not found or already completed' });
    res.json({ success: true, message: 'Triage processing cancelled' });
  });

  // Get paginated/filtered emails from session
  app.get('/api/cases/bulk-triage/:sessionId/emails', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const { page, limit, mailType, riskLevel, campaignId, search } = req.query;
    const result = bulkTriageService.getFilteredEmails(req.params.sessionId, {
      page: page ? Number(page) : undefined,
      limit: limit ? Number(limit) : undefined,
      mailType: mailType as string,
      riskLevel: riskLevel as string,
      campaignId: campaignId as string,
      search: search as string,
    });
    res.json(result);
  });

  // Get detail & raw source for a specific email
  app.get('/api/cases/bulk-triage/:sessionId/emails/:triageId', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const detail = bulkTriageService.getEmailDetail(req.params.sessionId, req.params.triageId);
    if (!detail.item) return res.status(404).json({ error: 'Triage item not found' });
    res.json(detail);
  });

  // Get campaign clusters
  app.get('/api/cases/bulk-triage/:sessionId/campaigns', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const clusters = bulkTriageService.getCampaigns(req.params.sessionId);
    res.json({ campaigns: clusters, count: clusters.length });
  });

  // Get deduplicated indicators
  app.get('/api/cases/bulk-triage/:sessionId/indicators', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const indicators = bulkTriageService.getIndicators(req.params.sessionId);
    res.json({ indicators, count: indicators.length });
  });

  // Promote triaged item to formal case
  app.post('/api/cases/bulk-triage/:sessionId/promote', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const { triageId } = req.body;
      if (!triageId) return res.status(400).json({ error: 'triageId is required' });

      const payload = await bulkTriageService.promoteItemToCase(req.params.sessionId, triageId, {
        userId: user.userId,
        name: user.name,
        email: user.email,
      });

      auditLogger.record({
        action: 'BULK_ITEM_PROMOTED_TO_CASE',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: payload.caseRecord.caseId,
        resourceType: 'CASE_RECORD',
        details: `Promoted triage item ${triageId} into investigation case ${payload.caseRecord.caseId}`,
      });

      res.status(201).json({ success: true, caseId: payload.caseRecord.caseId, payload });
    } catch (err: any) {
      console.error('Bulk item promotion error:', err);
      res.status(500).json({ error: err.message || 'Failed to promote triage item to case' });
    }
  });

  // Optional AI Deep Dive on selected triage item
  app.post('/api/cases/bulk-triage/:sessionId/ai-deep-dive', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const { triageId } = req.body;
      if (!triageId) return res.status(400).json({ error: 'triageId is required' });

      const updated = await bulkTriageService.runAiDeepDive(req.params.sessionId, triageId);
      res.json({ success: true, item: updated });
    } catch (err: any) {
      console.error('AI deep-dive error:', err);
      res.status(500).json({ error: err.message || 'AI deep-dive analysis failed' });
    }
  });

  // =========================================================================
  // 3.6 GMAIL OAUTH INTEGRATION (PHASE 1: SECURE CONNECTION & STATUS)
  // =========================================================================

  // 1. Get Google OAuth Authorization URL (Authenticated)
  app.get('/api/gmail/oauth/url', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      if (!gmailOAuthService.isConfigured()) {
        return res.status(400).json({
          error: 'Google OAuth is not configured. GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required in environment.',
          code: 'GMAIL_OAUTH_NOT_CONFIGURED',
        });
      }

      const { url } = gmailOAuthService.generateAuthUrl(user.userId);
      res.json({ url });
    } catch (err: any) {
      console.error('[Gmail OAuth] Failed to generate OAuth URL:', err);
      res.status(500).json({ error: err.message || 'Failed to generate OAuth URL' });
    }
  });

  // 2. Google OAuth Callback (Validates state, exchanges code, resolves email, stores tokens backend-only)
  app.get('/api/gmail/oauth/callback', async (req: any, res: any) => {
    try {
      const { code, state, error: oauthError } = req.query;

      if (oauthError) {
        console.warn(`[Gmail OAuth] Google returned error: ${oauthError}`);
        if (req.headers.accept?.includes('application/json')) {
          return res.status(400).json({ error: `Google OAuth authorization error: ${oauthError}` });
        }
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head><title>Google OAuth Error</title></head>
          <body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
            <div style="background: #1e293b; padding: 2rem; border-radius: 8px; border: 1px solid #ef4444; text-align: center;">
              <h3 style="color: #ef4444;">Google Authorization Denied</h3>
              <p style="color: #94a3b8;">${oauthError}</p>
              <a href="/" style="color: #38bdf8; text-decoration: none;">← Return to CyberTrace</a>
            </div>
          </body>
          </html>
        `);
      }

      if (!code || typeof code !== 'string' || !state || typeof state !== 'string') {
        if (req.headers.accept?.includes('application/json')) {
          return res.status(400).json({ error: 'Missing code or state parameter in OAuth callback' });
        }
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head><title>OAuth Callback Error</title></head>
          <body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
            <div style="background: #1e293b; padding: 2rem; border-radius: 8px; border: 1px solid #ef4444; text-align: center;">
              <h3 style="color: #ef4444;">Invalid Callback Parameters</h3>
              <p style="color: #94a3b8;">Missing required code or state parameter.</p>
              <a href="/" style="color: #38bdf8; text-decoration: none;">← Return to CyberTrace</a>
            </div>
          </body>
          </html>
        `);
      }

      const result = await gmailOAuthService.handleCallback(code, state);

      auditLogger.record({
        action: 'LOGIN_SUCCESS',
        status: 'SUCCESS',
        actorId: result.userId,
        ip: req.ip || req.socket.remoteAddress,
        resourceType: 'GMAIL_ACCOUNT',
        details: `Gmail account successfully authorized and linked: ${result.gmailEmail}`,
      });

      if (req.headers.accept?.includes('application/json')) {
        return res.json({
          success: true,
          connected: true,
          gmailEmail: result.gmailEmail,
          connectedAt: result.connectedAt,
        });
      }

      return res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>CyberTrace - Gmail Connected</title></head>
        <body style="background-color: #0f172a; color: #f8fafc; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
          <div style="text-align: center; background: #1e293b; padding: 2rem 3rem; border-radius: 1rem; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
            <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🔒</div>
            <h2 style="color: #38bdf8; margin-bottom: 0.5rem;">Gmail Connected Successfully</h2>
            <p style="color: #94a3b8; font-size: 0.95rem;">Authorized account: <strong style="color: #f1f5f9;">${result.gmailEmail}</strong></p>
            <p style="color: #64748b; font-size: 0.85rem;">Redirecting to CyberTrace SOC Platform...</p>
            <script>
              if (window.opener) {
                window.opener.postMessage({ type: 'GMAIL_CONNECTED', email: '${result.gmailEmail}' }, '*');
                setTimeout(() => window.close(), 1200);
              } else {
                setTimeout(() => { window.location.href = '/?gmail_connected=true'; }, 1500);
              }
            </script>
          </div>
        </body>
        </html>
      `);
    } catch (err: any) {
      console.error('[Gmail OAuth] Callback error:', err?.message || err);

      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        ip: req.ip || req.socket.remoteAddress,
        resourceType: 'GMAIL_ACCOUNT',
        details: `Gmail OAuth authorization failed: ${err?.message || 'Invalid or expired state'}`,
      });

      if (req.headers.accept?.includes('application/json')) {
        return res.status(400).json({ error: err?.message || 'OAuth authorization failed' });
      }

      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head><title>CyberTrace - Gmail Connection Failed</title></head>
        <body style="background-color: #0f172a; color: #f8fafc; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
          <div style="text-align: center; background: #1e293b; padding: 2rem 3rem; border-radius: 1rem; border: 1px solid #ef4444; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
            <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">⚠️</div>
            <h2 style="color: #ef4444; margin-bottom: 0.5rem;">Gmail Authorization Failed</h2>
            <p style="color: #fca5a5; font-size: 0.95rem;">${err?.message || 'Invalid or expired OAuth state'}</p>
            <a href="/" style="display: inline-block; margin-top: 1rem; color: #38bdf8; text-decoration: none; font-size: 0.9rem;">← Return to CyberTrace Console</a>
          </div>
        </body>
        </html>
      `);
    }
  });

  // 3. Get Gmail Connection Status (Authenticated: Safe Metadata Only)
  app.get('/api/gmail/status', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;
    const status = gmailOAuthService.getStatus(user.userId);
    res.json(status);
  });

  // 4. Disconnect Gmail (Authenticated: Removes ONLY Authenticated User's Connection)
  app.post('/api/gmail/disconnect', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;
    const wasConnected = gmailOAuthService.disconnect(user.userId);

    auditLogger.record({
      action: 'LOGOUT',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      ip: req.ip || req.socket.remoteAddress,
      resourceType: 'GMAIL_ACCOUNT',
      details: `Gmail account disconnected for user ${user.email}`,
    });

    res.json({
      success: true,
      disconnected: wasConnected,
      message: wasConnected ? 'Gmail connection successfully removed' : 'No active Gmail connection found',
    });
  });

  // 4b. Connect Simulated Demo Mailbox (Offline SIH Evaluation Mode)
  app.post('/api/gmail/demo/connect', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;
    const conn = gmailOAuthService.connectUser(user.userId, {
      gmailEmail: 'soc.demo@cybertrace-defense.internal',
      accessToken: 'DEMO_OAUTH_TOKEN',
      expiresIn: 86400,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    auditLogger.record({
      action: 'LOGIN_SUCCESS',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      ip: req.ip || req.socket.remoteAddress,
      resourceType: 'GMAIL_ACCOUNT',
      details: `Simulated demo mailbox connected for user ${user.email} (soc.demo@cybertrace-defense.internal)`,
    });

    res.json({
      success: true,
      connected: true,
      gmailEmail: conn.gmailEmail,
      connectedAt: conn.connectedAt,
    });
  });

  // =========================================================================
  // 3.7 GMAIL API RAW MESSAGE RETRIEVAL & FORENSIC ADAPTER (PHASE 2)
  // =========================================================================

  // 5. List Gmail Messages (Metadata / IDs only, parameterized, no raw MIME downloaded)
  app.get('/api/gmail/messages', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const maxResults = req.query.maxResults ? parseInt(req.query.maxResults as string, 10) : undefined;
      const pageToken = req.query.pageToken ? String(req.query.pageToken) : undefined;
      const query = req.query.q ? String(req.query.q) : undefined;

      const result = await gmailApiService.listMessages(user.userId, {
        maxResults,
        pageToken,
        query,
      });

      res.json(result);
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      console.error(`[Gmail API] listMessages error for user ${req.user?.userId}:`, err?.message || err);
      res.status(statusCode).json({
        error: err.message || 'Failed to retrieve Gmail messages list',
        code: err.code || 'GMAIL_LIST_FAILED',
      });
    }
  });

  // 6. Get Raw Gmail Message (format=raw, decoded Base64URL to RFC-822, safe forensic data)
  app.get('/api/gmail/messages/:id/raw', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const messageId = req.params.id;

      const rawMessage = await gmailApiService.getRawMessage(user.userId, messageId);

      // Return safe raw-email forensic representation (strictly zero tokens)
      res.json({
        id: rawMessage.id,
        threadId: rawMessage.threadId,
        labelIds: rawMessage.labelIds,
        sizeEstimate: rawMessage.sizeEstimate,
        snippet: rawMessage.snippet,
        rawEml: rawMessage.rawEml,
        sha256: rawMessage.sha256,
        md5: rawMessage.md5,
      });
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      console.error(`[Gmail API] getRawMessage error for message ${req.params.id}:`, err?.message || err);
      res.status(statusCode).json({
        error: err.message || 'Failed to retrieve raw Gmail message',
        code: err.code || 'GMAIL_RAW_FAILED',
      });
    }
  });

  // 7. Deterministic Threat Triage for Single Gmail Message (Phase 3)
  app.post('/api/gmail/messages/:id/triage', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const messageId = req.params.id;

      // Verify user has active Gmail connection
      const connection = gmailOAuthService.getConnection(user.userId);
      if (!connection) {
        return res.status(404).json({
          error: `No connected Gmail account found for CyberTrace user: ${user.email}`,
          code: 'GMAIL_NOT_CONNECTED',
        });
      }

      const triageRecord = await gmailTriageService.triageSingleMessage(user.userId, messageId);

      auditLogger.record({
        action: 'CASE_ACCESSED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: `GMAIL-${messageId}`,
        resourceType: 'GMAIL_MESSAGE',
        details: `Deterministic threat triage performed for Gmail message ${messageId} (Score: ${triageRecord.riskScore}, Level: ${triageRecord.riskLevel}, MailType: ${triageRecord.mailClassification.mailType})`,
      });

      res.json(triageRecord);
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      console.error(`[Gmail Triage] Single message triage failed for ${req.params.id}:`, err?.message || err);
      res.status(statusCode).json({
        error: err.message || 'Failed to triage Gmail message',
        code: err.code || 'GMAIL_TRIAGE_FAILED',
      });
    }
  });

  // 8. Bounded Concurrency Batch Triage for Multiple Gmail Messages (Phase 3)
  app.post('/api/gmail/messages/triage-batch', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const { messageIds } = req.body;

      if (!Array.isArray(messageIds) || messageIds.length === 0) {
        return res.status(400).json({ error: 'messageIds must be a non-empty array of strings' });
      }

      // Verify user has active Gmail connection
      const connection = gmailOAuthService.getConnection(user.userId);
      if (!connection) {
        return res.status(404).json({
          error: `No connected Gmail account found for CyberTrace user: ${user.email}`,
          code: 'GMAIL_NOT_CONNECTED',
        });
      }

      const result = await gmailTriageService.triageMessages(user.userId, messageIds);

      auditLogger.record({
        action: 'CASE_ACCESSED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceType: 'GMAIL_BATCH',
        details: `Batch Gmail triage processed ${result.total} messages (${result.succeeded} succeeded, ${result.failed} failed)`,
      });

      res.json(result);
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      console.error(`[Gmail Triage] Batch triage failed:`, err?.message || err);
      res.status(statusCode).json({
        error: err.message || 'Failed to process batch Gmail triage',
        code: err.code || 'GMAIL_BATCH_TRIAGE_FAILED',
      });
    }
  });

  // =========================================================================
  // 3.8 GMAIL INCREMENTAL MONITORING & SYNCHRONIZATION (PHASE 4)
  // =========================================================================

  // 9. Trigger Mailbox Synchronization (Authenticated: uses req.user.userId only)
  app.post('/api/gmail/sync', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;

      // Verify connected Gmail account
      const connection = gmailOAuthService.getConnection(user.userId);
      if (!connection) {
        return res.status(404).json({
          error: `No connected Gmail account found for CyberTrace user: ${user.email}`,
          code: 'GMAIL_NOT_CONNECTED',
        });
      }

      const syncResult = await gmailSyncService.syncUser(user.userId);

      auditLogger.record({
        action: 'CASE_ACCESSED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: `GMAIL-SYNC-${user.userId}`,
        resourceType: 'GMAIL_SYNC',
        details: `Gmail synchronization completed (Discovered: ${syncResult.messagesDiscovered}, Triaged: ${syncResult.messagesTriaged}, Initial: ${syncResult.isInitialSync}, Reset: ${syncResult.historyReset})`,
      });

      res.json(syncResult);
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      console.error(`[Gmail Sync] Synchronization failed for user ${req.user?.userId}:`, err?.message || err);
      res.status(statusCode).json({
        error: err.message || 'Failed to synchronize Gmail mailbox',
        code: err.code || 'GMAIL_SYNC_FAILED',
        retryAfterMs: err.retryAfterMs,
      });
    }
  });

  // 10. Get Synchronization Status & Checkpoint (Authenticated: safe operational metadata only)
  app.get('/api/gmail/sync/status', authenticateUser, (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;

    // Verify connected Gmail account
    const connection = gmailOAuthService.getConnection(user.userId);
    if (!connection) {
      return res.status(404).json({
        error: `No connected Gmail account found for CyberTrace user: ${user.email}`,
        code: 'GMAIL_NOT_CONNECTED',
      });
    }

    const status = gmailSyncService.getStatus(user.userId);
    res.json(status);
  });

  // =========================================================================
  // 3.9 GMAIL FORMAL DFIR CASE PROMOTION (PHASE 6)
  // =========================================================================

  // 11. Promote Triaged Gmail Threat into Formal DFIR Investigation Case
  app.post('/api/gmail/messages/:id/promote', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const messageId = req.params.id;

      const result = await gmailCasePromotionService.promoteMessage(user.userId, messageId, {
        name: user.name,
        email: user.email,
      });

      auditLogger.record({
        action: 'BULK_ITEM_PROMOTED_TO_CASE',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: result.caseId,
        resourceType: 'CASE_RECORD',
        details: `Gmail threat ${messageId} promoted to formal DFIR case ${result.caseId} (Already Promoted: ${result.alreadyPromoted})`,
      });

      res.status(result.alreadyPromoted ? 200 : 201).json(result);
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      console.error(`[Gmail Promotion] Case promotion failed for message ${req.params.id}:`, err?.message || err);
      res.status(statusCode).json({
        error: err.message || 'Failed to promote Gmail message to formal investigation case',
        code: err.code || 'GMAIL_PROMOTION_FAILED',
      });
    }
  });

  // =========================================================================
  // 3.10 GMAIL THREAT INTEL & CAMPAIGN CORRELATION (PHASE 7)
  // =========================================================================

  // 12. Get Correlated Gmail Threat Campaigns for Authenticated User
  app.get('/api/gmail/campaigns', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const result = await gmailCampaignService.getCampaignsForUser(user.userId);

      auditLogger.record({
        action: 'CASE_ACCESSED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: `GMAIL-CAMPAIGNS-${user.userId}`,
        resourceType: 'GMAIL_CAMPAIGN',
        details: `Retrieved ${result.campaigns.length} Gmail threat campaigns (${result.iocs.length} enriched IOCs) for user ${user.email}`,
      });

      res.json(result);
    } catch (err: any) {
      console.error(`[Gmail Campaigns] Failed to get campaigns for user ${req.user?.userId}:`, err?.message || err);
      res.status(500).json({
        error: err.message || 'Failed to retrieve Gmail threat campaigns',
        code: 'GMAIL_CAMPAIGNS_FAILED',
      });
    }
  });

  // 13. Get Specific Campaign Details & Correlated Messages (Tenant-Isolated)
  app.get('/api/gmail/campaigns/:campaignId', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const campaignId = req.params.campaignId;

      const detail = await gmailCampaignService.getCampaignDetailForUser(user.userId, campaignId);
      if (!detail) {
        return res.status(404).json({
          error: `Campaign ${campaignId} not found or unauthorized`,
          code: 'CAMPAIGN_NOT_FOUND',
        });
      }

      auditLogger.record({
        action: 'CASE_ACCESSED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: campaignId,
        resourceType: 'GMAIL_CAMPAIGN',
        details: `Inspected Gmail threat campaign ${campaignId} with ${detail.messages.length} related messages`,
      });

      res.json(detail);
    } catch (err: any) {
      console.error(`[Gmail Campaigns] Failed to get campaign detail ${req.params.campaignId}:`, err?.message || err);
      res.status(500).json({
        error: err.message || 'Failed to retrieve campaign details',
        code: 'GMAIL_CAMPAIGN_DETAIL_FAILED',
      });
    }
  });

  // 14. Get Normalized & Enriched IOCs across User's Triaged Gmail Messages
  app.get('/api/gmail/iocs', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const iocs = await gmailCampaignService.getIocsForUser(user.userId);
      res.json({ iocs, count: iocs.length });
    } catch (err: any) {
      console.error(`[Gmail IOCs] Failed to get IOCs for user ${req.user?.userId}:`, err?.message || err);
      res.status(500).json({
        error: err.message || 'Failed to retrieve Gmail indicators',
        code: 'GMAIL_IOCS_FAILED',
      });
    }
  });

  // =========================================================================
  // 3.11 SOC DASHBOARD & ANALYST OPERATIONS (PHASE 8)
  // =========================================================================

  // 15. SOC Dashboard Summary Telemetry (Tenant-Isolated, Zero-Gemini)
  app.get('/api/soc/dashboard-summary', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
    try {
      const user = req.user!;
      const summary = await socDashboardService.getDashboardSummary(user);

      auditLogger.record({
        action: 'CASE_ACCESSED',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: `SOC-DASHBOARD-${user.userId}`,
        resourceType: 'SOC_DASHBOARD',
        details: `Generated SOC dashboard summary for user ${user.email} (monitored: ${summary.summary.totalMonitoredMessages}, threats: ${summary.summary.totalThreats}, campaigns: ${summary.summary.activeCampaigns})`,
      });

      res.json(summary);
    } catch (err: any) {
      console.error(`[SOC Dashboard] Failed to generate dashboard summary for user ${req.user?.userId}:`, err?.message || err);
      res.status(500).json({
        error: err.message || 'Failed to generate SOC dashboard summary',
        code: 'SOC_DASHBOARD_FAILED',
      });
    }
  });

  const ALLOWED_CASE_STATUSES = new Set([
    'OPEN',
    'IN_PROGRESS',
    'ESCALATED',
    'RESOLVED',
    'CLOSED',
    'FALSE_POSITIVE',
  ]);

  const ALLOWED_CASE_PRIORITIES = new Set([
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL',
  ]);

  // Update Case Status (Authenticated with Case Authorization & Controlled Statuses)
  app.patch('/api/cases/:id/status', authenticateUser, (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const caseId = req.params.id;
    const { status, actor } = req.body;

    if (!status || typeof status !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid status parameter', code: 'INVALID_STATUS' });
    }

    const normalizedStatus = status.trim().toUpperCase() as CaseStatus;
    if (!ALLOWED_CASE_STATUSES.has(normalizedStatus)) {
      return res.status(400).json({
        error: `Invalid status '${status}'. Allowed: ${Array.from(ALLOWED_CASE_STATUSES).join(', ')}`,
        code: 'INVALID_STATUS',
      });
    }

    const access = caseService.canUserMutateCase(user, caseId);
    if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
    if (!access.allowed) {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Unauthorized attempt to alter case status on ${caseId} (${access.reason || 'Forbidden'})`,
      });
      return res.status(403).json({ error: access.reason || 'Forbidden: You do not have permission to modify this case', code: 'FORBIDDEN' });
    }

    const success = caseService.updateCaseStatus(caseId, normalizedStatus, actor || user.name);
    if (!success) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

    auditLogger.record({
      action: 'CASE_STATUS_CHANGED',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      resourceId: caseId,
      details: `Case status changed to ${normalizedStatus} by ${user.email}`,
    });

    const caseRecord = caseService.getCaseRecord(caseId);
    res.json({ success: true, caseId, status: normalizedStatus, caseRecord });
  });

  // Update Case Priority (Authenticated with Case Authorization & Controlled Priorities)
  app.patch('/api/cases/:id/priority', authenticateUser, (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const caseId = req.params.id;
    const { priority, actor } = req.body;

    if (!priority || typeof priority !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid priority parameter', code: 'INVALID_PRIORITY' });
    }

    const normalizedPriority = priority.trim().toUpperCase() as CasePriority;
    if (!ALLOWED_CASE_PRIORITIES.has(normalizedPriority)) {
      return res.status(400).json({
        error: `Invalid priority '${priority}'. Allowed: ${Array.from(ALLOWED_CASE_PRIORITIES).join(', ')}`,
        code: 'INVALID_PRIORITY',
      });
    }

    const access = caseService.canUserMutateCase(user, caseId);
    if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
    if (!access.allowed) {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Unauthorized attempt to alter case priority on ${caseId} (${access.reason || 'Forbidden'})`,
      });
      return res.status(403).json({ error: access.reason || 'Forbidden: You do not have permission to modify this case', code: 'FORBIDDEN' });
    }

    const updated = caseService.updateCasePriority(caseId, normalizedPriority, actor || user.name);
    if (!updated) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

    auditLogger.record({
      action: 'CASE_PRIORITY_CHANGED',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      resourceId: caseId,
      details: `Case operational priority changed to ${normalizedPriority} by ${user.email}`,
    });

    res.json({ success: true, caseId, priority: normalizedPriority, caseRecord: updated });
  });

  // Reassign Case (Authenticated with Directory Authorization Check)
  app.patch('/api/cases/:id/assignment', authenticateUser, (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const caseId = req.params.id;
    const { assignedAnalystId, assignedTo } = req.body;
    const targetQuery = assignedAnalystId || assignedTo;

    if (!targetQuery || typeof targetQuery !== 'string' || !targetQuery.trim()) {
      return res.status(400).json({ error: 'Missing or invalid assignedAnalystId parameter', code: 'INVALID_ASSIGNMENT' });
    }

    const allUsers = authService.getAllUsers();
    const cleanQuery = targetQuery.trim();
    const targetUser = allUsers.find(
      u => u.id === cleanQuery || u.email.toLowerCase() === cleanQuery.toLowerCase() || u.name.toLowerCase() === cleanQuery.toLowerCase()
    );

    if (!targetUser) {
      return res.status(400).json({
        error: `Invalid assignment target '${cleanQuery}': User not found in directory`,
        code: 'INVALID_ASSIGNMENT_TARGET',
      });
    }

    if (targetUser.role === 'AUDITOR') {
      return res.status(400).json({
        error: 'Cannot assign investigation case to an Auditor (Read-Only role)',
        code: 'INVALID_ASSIGNMENT_ROLE',
      });
    }

    const access = caseService.canUserMutateCase(user, caseId);
    if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
    if (!access.allowed) {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Unauthorized attempt to reassign case ${caseId} (${access.reason || 'Forbidden'})`,
      });
      return res.status(403).json({ error: access.reason || 'Forbidden: You do not have permission to reassign this case', code: 'FORBIDDEN' });
    }

    const updated = caseService.updateCaseAssignment(caseId, {
      assignedTo: targetUser.name,
      assignedAnalystId: targetUser.id,
      assignedAnalystName: targetUser.name,
      actor: user.name,
    });
    if (!updated) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

    auditLogger.record({
      action: 'CASE_ASSIGNMENT_CHANGED',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      resourceId: caseId,
      details: `Case reassigned to ${targetUser.name} (${targetUser.id}) by ${user.email}`,
    });

    res.json({
      success: true,
      caseId,
      assignedTo: targetUser.name,
      assignedAnalystId: targetUser.id,
      caseRecord: updated,
    });
  });

  // Update Case Management Details (Authenticated with Case Authorization)
  const handleCaseUpdate = (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;
    const caseId = req.params.id;
    const { status, priority, assignedTo, tags, newNote, actor } = req.body;

    if (status && !ALLOWED_CASE_STATUSES.has(status.trim().toUpperCase())) {
      return res.status(400).json({ error: 'Invalid status', code: 'INVALID_STATUS' });
    }
    if (priority && !ALLOWED_CASE_PRIORITIES.has(priority.trim().toUpperCase())) {
      return res.status(400).json({ error: 'Invalid priority', code: 'INVALID_PRIORITY' });
    }

    const access = caseService.canUserMutateCase(user, caseId);
    if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
    if (!access.allowed) {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Unauthorized attempt to modify case management for ${caseId}`,
      });
      return res.status(403).json({ error: access.reason || 'Forbidden: You do not have permission to modify this case', code: 'FORBIDDEN' });
    }

    const updated = caseService.updateCaseManagement(caseId, {
      status,
      priority,
      assignedTo,
      tags,
      newNote,
      actor: actor || user.name,
    });

    if (!updated) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

    auditLogger.record({
      action: 'CASE_STATUS_CHANGED',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      resourceId: caseId,
      details: `Case management updated for ${caseId} by ${user.email}`,
    });

    res.json({ success: true, case: updated, caseRecord: updated });
  };

  app.patch('/api/cases/:id/management', authenticateUser, handleCaseUpdate);
  app.patch('/api/cases/:id/details', authenticateUser, handleCaseUpdate);

  // Add Analyst Note (Authenticated with Case Authorization & Length Limits)
  app.post('/api/cases/:id/notes', authenticateUser, (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const caseId = req.params.id;
    const { author, content, text, note: noteContent } = req.body;
    const actualContent = text || content || noteContent;

    if (!actualContent || typeof actualContent !== 'string' || !actualContent.trim()) {
      return res.status(400).json({ error: 'Note content string is required', code: 'INVALID_NOTE' });
    }

    const trimmed = actualContent.trim();
    if (trimmed.length > 5000) {
      return res.status(400).json({
        error: `Note exceeds maximum allowed length of 5000 characters (received ${trimmed.length})`,
        code: 'NOTE_TOO_LONG',
      });
    }

    const access = caseService.canUserMutateCase(user, caseId);
    if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
    if (!access.allowed) {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Unauthorized note submission attempt on ${caseId} (${access.reason || 'Forbidden'})`,
      });
      return res.status(403).json({ error: access.reason || 'Forbidden: You do not have permission to add notes to this case', code: 'FORBIDDEN' });
    }

    // Author is strictly server-derived from authenticated user
    const authorName = user.name || user.email || author || 'Analyst';
    const note = caseService.addAnalystNote(caseId, authorName, trimmed);
    if (!note) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

    auditLogger.record({
      action: 'NOTE_ADDED',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      resourceId: caseId,
      details: `Analyst note added to case ${caseId} by ${user.email}`,
    });

    const payload = caseService.getCasePayload(caseId);
    res.status(201).json({ success: true, note, caseRecord: payload?.caseRecord });
  });

  // Get Case Operational History & Audit Information (Authenticated)
  app.get('/api/cases/:id/history', authenticateUser, (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const caseId = req.params.id;

    const access = caseService.canUserAccessCase(user, caseId);
    if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
    if (!access.allowed) {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Unauthorized history access attempt on ${caseId}`,
      });
      return res.status(403).json({ error: 'Forbidden: You do not have permission to access history for this case', code: 'FORBIDDEN' });
    }

    const history = caseService.getCaseHistory(caseId);
    res.json({ success: true, caseId, history: history || [] });
  });

  // Generate DFIR Forensic Report (Authenticated with Case Authorization)
  app.get('/api/cases/:id/report', authenticateUser, (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const caseId = req.params.id;

    const access = caseService.canUserAccessCase(user, caseId);
    if (!access.caseFound) return res.status(404).json({ error: 'Case not found' });
    if (!access.allowed) {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Unauthorized forensic report generation attempt on ${caseId}`,
      });
      return res.status(403).json({ error: 'Forbidden: You do not have permission to access reports for this case' });
    }

    const report = caseService.generateReport(caseId);
    if (!report) return res.status(404).json({ error: 'Case not found' });

    auditLogger.record({
      action: 'REPORT_GENERATED',
      status: 'SUCCESS',
      actorId: user.userId,
      actorEmail: user.email,
      actorRole: user.role,
      resourceId: caseId,
      details: `Forensic DFIR report generated for case ${caseId} by ${user.email}`,
    });

    res.json(report);
  });

  // Evidence-Based Investigation Copilot on Case (Authenticated with Case Authorization)
  app.post('/api/cases/:id/copilot', authenticateUser, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const caseId = req.params.id;
      const { question } = req.body;

      if (!question || typeof question !== 'string') {
        return res.status(400).json({ error: 'Question string is required' });
      }

      const access = caseService.canUserAccessCase(user, caseId);
      if (!access.caseFound) return res.status(404).json({ error: 'Case not found' });
      if (!access.allowed) {
        auditLogger.record({
          action: 'AUTHORIZATION_FAILURE',
          status: 'DENIED',
          actorId: user.userId,
          actorEmail: user.email,
          actorRole: user.role,
          resourceId: caseId,
          details: `Unauthorized Copilot query attempt on private case ${caseId}`,
        });
        return res.status(403).json({ error: 'Forbidden: You do not have permission to query Copilot on this case' });
      }

      const payload = caseService.getCasePayload(caseId);
      if (!payload) return res.status(404).json({ error: 'Case payload unavailable' });

      const copilotResponse = await queryInvestigationCopilot(question, payload);

      auditLogger.record({
        action: 'COPILOT_QUERY',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Copilot inquiry executed for case ${caseId}`,
      });

      res.json(copilotResponse);
    } catch (err: any) {
      console.error('Investigation copilot endpoint error:', err);
      res.status(500).json({ error: err.message || 'Copilot query execution failed' });
    }
  });

  // Copilot Query by CaseId or Payload (Authenticated with Authorization Check)
  app.post('/api/copilot/query', authenticateUser, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const { question, caseId, payload } = req.body;

      if (!question || typeof question !== 'string') {
        return res.status(400).json({ error: 'Question string is required' });
      }

      let targetPayload = payload;
      if (!targetPayload && caseId) {
        const access = caseService.canUserAccessCase(user, caseId);
        if (!access.caseFound) return res.status(404).json({ error: 'Case not found' });
        if (!access.allowed) {
          auditLogger.record({
            action: 'AUTHORIZATION_FAILURE',
            status: 'DENIED',
            actorId: user.userId,
            actorEmail: user.email,
            actorRole: user.role,
            resourceId: caseId,
            details: `Unauthorized copilot query on case ${caseId}`,
          });
          return res.status(403).json({ error: 'Forbidden: You do not have permission to query this case' });
        }
        targetPayload = caseService.getCasePayload(caseId);
      }

      if (!targetPayload) {
        return res.status(400).json({ error: 'Either caseId or complete payload must be provided for evidence grounding' });
      }

      const copilotResponse = await queryInvestigationCopilot(question, targetPayload);

      auditLogger.record({
        action: 'COPILOT_QUERY',
        status: 'SUCCESS',
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: `Investigation Copilot query evaluated by ${user.email}`,
      });

      res.json(copilotResponse);
    } catch (err: any) {
      console.error('Copilot query endpoint error:', err);
      res.status(500).json({ error: err.message || 'Copilot query execution failed' });
    }
  });

  // =========================================================================
  // 4. BLOCKCHAIN EVIDENCE LEDGER ENDPOINTS (RBAC Guarded)
  // =========================================================================

  // View Blockchain Evidence Chain (Authenticated: Analyst or Admin)
  app.get('/api/ledger', authenticateUser, (_req, res) => {
    const chain = evidenceLedger.getChain();
    const verification = evidenceLedger.verifyIntegrity();
    res.json({ chain, verification });
  });

  // Verify Ledger Cryptographic Chain (Authenticated: Analyst or Admin)
  app.post('/api/ledger/verify', authenticateUser, (req: AuthenticatedRequest, res) => {
    const verification = evidenceLedger.verifyIntegrity();

    auditLogger.record({
      action: 'LEDGER_VERIFIED',
      status: verification.isValid ? 'SUCCESS' : 'DENIED',
      actorId: req.user!.userId,
      actorEmail: req.user!.email,
      actorRole: req.user!.role,
      details: `Ledger cryptographic integrity verified. Valid: ${verification.isValid}`,
    });

    res.json(verification);
  });

  // Simulate Ledger Tampering (ADMIN ONLY - Normal Analysts receive 403)
  app.post('/api/ledger/tamper', authenticateUser, requireRole('ADMIN'), (req: AuthenticatedRequest, res) => {
    const { blockIndex } = req.body;
    const result = evidenceLedger.simulateTamper(Number(blockIndex ?? 1));

    auditLogger.record({
      action: 'LEDGER_TAMPER_SIMULATED',
      status: 'SUCCESS',
      actorId: req.user!.userId,
      actorEmail: req.user!.email,
      actorRole: req.user!.role,
      details: `Administrator simulated tamper on evidence block #${blockIndex ?? 1}`,
    });

    res.json(result);
  });

  // Reseal & Repair Blockchain Ledger (ADMIN ONLY - Normal Analysts receive 403)
  app.post('/api/ledger/reseal', authenticateUser, requireRole('ADMIN'), (req: AuthenticatedRequest, res) => {
    const result = evidenceLedger.repairAndReseal();

    auditLogger.record({
      action: 'LEDGER_RESEALED',
      status: 'SUCCESS',
      actorId: req.user!.userId,
      actorEmail: req.user!.email,
      actorRole: req.user!.role,
      details: `Administrator performed cryptographic repair and reseal of evidence ledger`,
    });

    res.json(result);
  });

  // =========================================================================
  // 4.9 REAL-TIME THREAT ALERTS (SSE) — PHASE 11
  // =========================================================================

  // Stream Real-time Alerts via Server-Sent Events (SSE)
  app.get('/api/alerts/stream', (req, res) => {
    let token: string | undefined;
    const authHeader = req.headers.authorization;
    if (typeof authHeader === 'string') {
      const match = authHeader.match(/^bearer\s+(.+)$/i);
      if (match && match[1]) {
        token = match[1].trim();
      }
    }
    if (!token && typeof req.query.token === 'string') {
      token = req.query.token.trim();
    }

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: Authentication token required', code: 'UNAUTHORIZED' });
    }

    const session = authService.validateToken(token);
    if (!session) {
      return res.status(401).json({ error: 'Unauthorized: Invalid or expired token', code: 'INVALID_TOKEN' });
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    res.write(`event: connected\ndata: ${JSON.stringify({ message: 'Connected to CyberTrace real-time threat alert stream', user: session.email })}\n\n`);

    alertService.addClient(res);

    req.on('close', () => {
      alertService.removeClient(res);
    });
  });

  // Get Recent Threat Alerts History (Authenticated)
  app.get('/api/alerts/history', authenticateUser, (req: AuthenticatedRequest, res) => {
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 50);
    const alerts = alertService.getRecentAlerts(limit);
    res.json({ success: true, count: alerts.length, alerts });
  });

  // Trigger Manual Threat Alert Broadcast (Authenticated)
  app.post('/api/alerts/broadcast', authenticateUser, (req: AuthenticatedRequest, res) => {
    const { severity, title, description, caseId, threatType } = req.body;
    if (!severity || !title) {
      return res.status(400).json({ error: 'severity and title are required fields', code: 'INVALID_ALERT_PAYLOAD' });
    }

    const alert = alertService.broadcast({
      severity,
      title: String(title).slice(0, 150),
      description: String(description || '').slice(0, 500),
      caseId: typeof caseId === 'string' ? caseId : undefined,
      threatType: typeof threatType === 'string' ? threatType : undefined,
      source: 'SYSTEM',
    });

    res.status(201).json({ success: true, alert });
  });

  // =========================================================================
  // 4.10 THREAT HUNTING QUERY ENGINE — PHASE 12
  // =========================================================================

  // Search & Correlate across IOCs, Campaigns, and Cases (Authenticated)
  app.get('/api/hunt/search', authenticateUser, (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const q = typeof req.query.q === 'string' ? req.query.q : undefined;
      const iocType = typeof req.query.iocType === 'string' ? req.query.iocType as any : undefined;
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const minRiskScore = req.query.minRiskScore ? parseInt(req.query.minRiskScore as string) : undefined;
      const maxRiskScore = req.query.maxRiskScore ? parseInt(req.query.maxRiskScore as string) : undefined;
      const fromDate = typeof req.query.fromDate === 'string' ? req.query.fromDate : undefined;
      const toDate = typeof req.query.toDate === 'string' ? req.query.toDate : undefined;

      let riskLevels: any[] | undefined;
      if (typeof req.query.riskLevels === 'string') {
        riskLevels = req.query.riskLevels.split(',').map(s => s.trim().toUpperCase());
      } else if (Array.isArray(req.query.riskLevels)) {
        riskLevels = req.query.riskLevels;
      }

      let threatTypes: any[] | undefined;
      if (typeof req.query.threatTypes === 'string') {
        threatTypes = req.query.threatTypes.split(',').map(s => s.trim().toUpperCase());
      } else if (Array.isArray(req.query.threatTypes)) {
        threatTypes = req.query.threatTypes;
      }

      const result = threatHuntingService.hunt(user, {
        q,
        iocType,
        riskLevels,
        threatTypes,
        minRiskScore,
        maxRiskScore,
        fromDate,
        toDate,
        limit,
      });

      res.json(result);
    } catch (err: any) {
      console.error('Threat hunting error:', err);
      res.status(500).json({ error: 'Threat hunting search query failed safely', message: err?.message });
    }
  });

  // Direct Single IOC Lookup across Cases (Authenticated)
  app.get('/api/hunt/ioc/:value', authenticateUser, (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const value = req.params.value;
      if (!value) return res.status(400).json({ error: 'IOC value is required' });

      const hit = threatHuntingService.lookupIoc(user, value);
      if (!hit) {
        return res.status(404).json({ error: 'IOC not found in accessible case inventory', found: false });
      }

      res.json({ found: true, hit });
    } catch (err: any) {
      console.error('IOC lookup error:', err);
      res.status(500).json({ error: 'IOC lookup failed safely' });
    }
  });

  return app;
}

// =========================================================================
// 5. VITE SPA SERVING & STANDALONE SERVER LISTENER
// =========================================================================

export async function startServer() {
  const app = await createExpressApp();

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    const geoConfig = validateGeoIpConfig();
    console.log(`[SOC Platform] Cyber Forensics & Threat Engine listening on http://0.0.0.0:${PORT}`);
    console.log(
      `[GeoIP Configuration] Provider: '${geoConfig.provider}' (MaxMind credentials: ${
        geoConfig.isMaxMindRequired ? (geoConfig.valid ? 'configured' : 'missing') : 'not required'
      })`
    );

    // Initialize background polling scheduler (disabled by default unless GMAIL_AUTO_SYNC_ENABLED=true)
    gmailPollingScheduler.start();
  });

  return app;
}

// Only launch standalone server listener if not running in a Vercel Serverless environment
if (process.env.VERCEL !== '1' && !process.env.VERCEL_ENV) {
  startServer().catch(err => {
    console.error('Fatal server startup error:', err);
    process.exit(1);
  });
}
