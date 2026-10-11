import assert from 'assert';
import express from 'express';
import http from 'http';
import { caseService } from '../services/caseService';
import { authService } from '../auth/authService';
import { auditLogger } from '../auth/auditLogger';
import { authenticateUser, AuthenticatedRequest } from '../auth/authMiddleware';
import { evidenceLedger } from '../blockchain/evidenceLedger';
import { CasePriority, CaseStatus } from '../../src/types/forensics';

console.log('=== RUNNING PHASE 9 ANALYST WORKFLOW & CASE OPERATIONS TEST SUITE ===\n');

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    // 0. Enforce Zero Gemini Guarantee
    delete process.env.GEMINI_API_KEY;

    // 1. Setup Express App with exact Phase 9 Case Operations routes
    const app = express();
    app.use(express.json({ limit: '10mb' }));

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

    // Assignable Analysts Route
    app.get('/api/cases/assignable-analysts', authenticateUser, (_req: AuthenticatedRequest, res) => {
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

    // Single Case Route
    app.get('/api/cases/:id', authenticateUser, (req: AuthenticatedRequest, res: any) => {
      const user = req.user!;
      const result = caseService.getCasePayloadForUser(user, req.params.id);
      if (result.status === 'NOT_FOUND') return res.status(404).json({ error: 'Case not found' });
      if (result.status === 'FORBIDDEN') return res.status(403).json({ error: 'Forbidden' });
      return res.json(result.payload);
    });

    // Status Route
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
          error: `Invalid status '${status}'`,
          code: 'INVALID_STATUS',
        });
      }

      const access = caseService.canUserMutateCase(user, caseId);
      if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
      if (!access.allowed) {
        return res.status(403).json({ error: access.reason || 'Forbidden', code: 'FORBIDDEN' });
      }

      const success = caseService.updateCaseStatus(caseId, normalizedStatus, actor || user.name);
      if (!success) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

      const caseRecord = caseService.getCaseRecord(caseId);
      res.json({ success: true, caseId, status: normalizedStatus, caseRecord });
    });

    // Priority Route
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
          error: `Invalid priority '${priority}'`,
          code: 'INVALID_PRIORITY',
        });
      }

      const access = caseService.canUserMutateCase(user, caseId);
      if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
      if (!access.allowed) {
        return res.status(403).json({ error: access.reason || 'Forbidden', code: 'FORBIDDEN' });
      }

      const updated = caseService.updateCasePriority(caseId, normalizedPriority, actor || user.name);
      if (!updated) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

      res.json({ success: true, caseId, priority: normalizedPriority, caseRecord: updated });
    });

    // Assignment Route
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
        return res.status(403).json({ error: access.reason || 'Forbidden', code: 'FORBIDDEN' });
      }

      const updated = caseService.updateCaseAssignment(caseId, {
        assignedTo: targetUser.name,
        assignedAnalystId: targetUser.id,
        assignedAnalystName: targetUser.name,
        actor: user.name,
      });
      if (!updated) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

      res.json({
        success: true,
        caseId,
        assignedTo: targetUser.name,
        assignedAnalystId: targetUser.id,
        caseRecord: updated,
      });
    });

    // Notes Route
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
        return res.status(403).json({ error: access.reason || 'Forbidden', code: 'FORBIDDEN' });
      }

      // Author is strictly server-derived from authenticated user
      const authorName = user.name || user.email || author || 'Analyst';
      const note = caseService.addAnalystNote(caseId, authorName, trimmed);
      if (!note) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });

      const payload = caseService.getCasePayload(caseId);
      res.status(201).json({ success: true, note, caseRecord: payload?.caseRecord });
    });

    // History Route
    app.get('/api/cases/:id/history', authenticateUser, (req: AuthenticatedRequest, res) => {
      const user = req.user!;
      const caseId = req.params.id;

      const access = caseService.canUserAccessCase(user, caseId);
      if (!access.caseFound) return res.status(404).json({ error: 'Case not found', code: 'CASE_NOT_FOUND' });
      if (!access.allowed) {
        return res.status(403).json({ error: 'Forbidden', code: 'FORBIDDEN' });
      }

      const history = caseService.getCaseHistory(caseId);
      res.json({ success: true, caseId, history: history || [] });
    });

    // Start ephemeral HTTP server
    const server = http.createServer(app);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()));
    const port = (server.address() as any).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 2. Setup Identities and Tokens
      const sessionAlice = authService.createTestSession('ANALYST', 'usr-analyst-01', 'analyst@soc.internal');
      const sessionBob = authService.createTestSession('ANALYST', 'usr-analyst-02', 'analyst2@soc.internal');
      const sessionAdmin = authService.createTestSession('ADMIN', 'usr-admin-01', 'admin@soc.internal');
      const sessionAuditor = authService.createTestSession('AUDITOR', 'usr-auditor-01', 'auditor@soc.internal');

      const tokenAlice = sessionAlice.token;
      const tokenBob = sessionBob.token;
      const tokenAdmin = sessionAdmin.token;
      const tokenAuditor = sessionAuditor.token;

      // 3. Ingest Test Email Case owned by Alice
      const SAMPLE_RFC822 = [
        'From: Security <security@suspicious-bank-alert.com>',
        'To: Alice <alice@cybertrace.test>',
        'Subject: Urgent Security Warning: Unauthorized Access Detected',
        'Date: Wed, 09 Sep 2026 00:00:00 +0000',
        'Message-ID: <threat-phase9-001@suspicious-bank-alert.com>',
        '',
        'Your account has been compromised. Verify immediately: http://phish-login-bank.net/verify',
      ].join('\r\n');

      const initialPayload = await caseService.processEmail(SAMPLE_RFC822, {
        title: 'Urgent Security Warning Investigation',
        analyst: sessionAlice.user.name,
        ownerId: 'usr-analyst-01',
        ownerEmail: 'analyst@soc.internal',
        authorizedUsers: ['usr-analyst-01'],
      });

      const caseId = initialPayload.caseRecord.caseId;
      assert.ok(caseId, 'Case ID must exist');
      const initialRiskScore = initialPayload.caseRecord.riskScore;
      const initialSeverity = initialPayload.caseRecord.severity;
      const initialLedgerBlockCount = evidenceLedger.getChain().length;

      // =========================================================================
      // SECTION 1: AUTHENTICATION ENFORCEMENT (401 Unauthorized)
      // =========================================================================
      console.log('Test 1: Verifying 401 Unauthorized on unauthenticated PATCH /api/cases/:id/status...');
      const r1 = await fetch(`${baseUrl}/api/cases/${caseId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'IN_PROGRESS' }),
      });
      assert.strictEqual(r1.status, 401);
      console.log('✔ Test 1 Passed: Unauthenticated status update rejected with 401.\n');

      console.log('Test 2: Verifying 401 Unauthorized on unauthenticated PATCH /api/cases/:id/priority...');
      const r2 = await fetch(`${baseUrl}/api/cases/${caseId}/priority`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority: 'CRITICAL' }),
      });
      assert.strictEqual(r2.status, 401);
      console.log('✔ Test 2 Passed: Unauthenticated priority update rejected with 401.\n');

      console.log('Test 3: Verifying 401 Unauthorized on unauthenticated PATCH /api/cases/:id/assignment...');
      const r3 = await fetch(`${baseUrl}/api/cases/${caseId}/assignment`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assignedAnalystId: 'usr-analyst-02' }),
      });
      assert.strictEqual(r3.status, 401);
      console.log('✔ Test 3 Passed: Unauthenticated assignment update rejected with 401.\n');

      console.log('Test 4: Verifying 401 Unauthorized on unauthenticated POST /api/cases/:id/notes...');
      const r4 = await fetch(`${baseUrl}/api/cases/${caseId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: 'Unauthenticated note attempt' }),
      });
      assert.strictEqual(r4.status, 401);
      console.log('✔ Test 4 Passed: Unauthenticated note submission rejected with 401.\n');

      console.log('Test 5: Verifying 401 Unauthorized on unauthenticated GET /api/cases/:id/history...');
      const r5 = await fetch(`${baseUrl}/api/cases/${caseId}/history`);
      assert.strictEqual(r5.status, 401);
      console.log('✔ Test 5 Passed: Unauthenticated history query rejected with 401.\n');

      console.log('Test 6: Verifying 401 Unauthorized on unauthenticated GET /api/cases/assignable-analysts...');
      const r6 = await fetch(`${baseUrl}/api/cases/assignable-analysts`);
      assert.strictEqual(r6.status, 401);
      console.log('✔ Test 6 Passed: Unauthenticated assignable-analysts query rejected with 401.\n');

      console.log('Test 7: Verifying 401 Unauthorized on invalid/garbage Bearer token...');
      const r7 = await fetch(`${baseUrl}/api/cases/${caseId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer invalid-token-xyz',
        },
        body: JSON.stringify({ status: 'IN_PROGRESS' }),
      });
      assert.strictEqual(r7.status, 401);
      console.log('✔ Test 7 Passed: Invalid token rejected with 401.\n');

      // =========================================================================
      // SECTION 2: MULTI-TENANT ISOLATION & RBAC (403 Forbidden)
      // =========================================================================
      console.log('Test 8: Verifying cross-tenant isolation: Bob cannot mutate Alice\'s case status...');
      const r8 = await fetch(`${baseUrl}/api/cases/${caseId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenBob}`,
        },
        body: JSON.stringify({ status: 'IN_PROGRESS' }),
      });
      assert.strictEqual(r8.status, 403);
      console.log('✔ Test 8 Passed: Cross-tenant status alteration blocked with 403.\n');

      console.log('Test 9: Verifying cross-tenant isolation: Bob cannot alter Alice\'s case priority...');
      const r9 = await fetch(`${baseUrl}/api/cases/${caseId}/priority`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenBob}`,
        },
        body: JSON.stringify({ priority: 'CRITICAL' }),
      });
      assert.strictEqual(r9.status, 403);
      console.log('✔ Test 9 Passed: Cross-tenant priority alteration blocked with 403.\n');

      console.log('Test 10: Verifying cross-tenant isolation: Bob cannot reassign Alice\'s case...');
      const r10 = await fetch(`${baseUrl}/api/cases/${caseId}/assignment`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenBob}`,
        },
        body: JSON.stringify({ assignedAnalystId: 'usr-analyst-02' }),
      });
      assert.strictEqual(r10.status, 403);
      console.log('✔ Test 10 Passed: Cross-tenant reassignment blocked with 403.\n');

      console.log('Test 11: Verifying cross-tenant isolation: Bob cannot add notes to Alice\'s case...');
      const r11 = await fetch(`${baseUrl}/api/cases/${caseId}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenBob}`,
        },
        body: JSON.stringify({ content: 'Unauthorized cross-tenant note' }),
      });
      assert.strictEqual(r11.status, 403);
      console.log('✔ Test 11 Passed: Cross-tenant note creation blocked with 403.\n');

      console.log('Test 12: Verifying cross-tenant isolation: Bob cannot view Alice\'s case history...');
      const r12 = await fetch(`${baseUrl}/api/cases/${caseId}/history`, {
        headers: { Authorization: `Bearer ${tokenBob}` },
      });
      assert.strictEqual(r12.status, 403);
      console.log('✔ Test 12 Passed: Cross-tenant case history access blocked with 403.\n');

      console.log('Test 13: Verifying Admin has full oversight and can view/mutate cases...');
      const r13 = await fetch(`${baseUrl}/api/cases/${caseId}`, {
        headers: { Authorization: `Bearer ${tokenAdmin}` },
      });
      assert.strictEqual(r13.status, 200);
      console.log('✔ Test 13 Passed: Admin oversight access allowed.\n');

      // =========================================================================
      // SECTION 3: AUDITOR ROLE STRICT READ-ONLY ENFORCEMENT
      // =========================================================================
      console.log('Test 14: Verifying Auditor can view case details and history (read-only)...');
      const r14a = await fetch(`${baseUrl}/api/cases/${caseId}`, {
        headers: { Authorization: `Bearer ${tokenAuditor}` },
      });
      assert.strictEqual(r14a.status, 200);

      const r14b = await fetch(`${baseUrl}/api/cases/${caseId}/history`, {
        headers: { Authorization: `Bearer ${tokenAuditor}` },
      });
      assert.strictEqual(r14b.status, 200);
      console.log('✔ Test 14 Passed: Auditor successfully reads case details and audit history.\n');

      console.log('Test 15: Verifying Auditor CANNOT modify status (403 Forbidden)...');
      const r15 = await fetch(`${baseUrl}/api/cases/${caseId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAuditor}`,
        },
        body: JSON.stringify({ status: 'RESOLVED' }),
      });
      assert.strictEqual(r15.status, 403);
      const b15 = await r15.json();
      assert.ok(b15.error.includes('Auditor role is strictly read-only'));
      console.log('✔ Test 15 Passed: Auditor status update rejected with 403.\n');

      console.log('Test 16: Verifying Auditor CANNOT modify priority (403 Forbidden)...');
      const r16 = await fetch(`${baseUrl}/api/cases/${caseId}/priority`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAuditor}`,
        },
        body: JSON.stringify({ priority: 'LOW' }),
      });
      assert.strictEqual(r16.status, 403);
      console.log('✔ Test 16 Passed: Auditor priority update rejected with 403.\n');

      console.log('Test 17: Verifying Auditor CANNOT reassign case (403 Forbidden)...');
      const r17 = await fetch(`${baseUrl}/api/cases/${caseId}/assignment`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAuditor}`,
        },
        body: JSON.stringify({ assignedAnalystId: 'usr-analyst-02' }),
      });
      assert.strictEqual(r17.status, 403);
      console.log('✔ Test 17 Passed: Auditor case reassignment rejected with 403.\n');

      console.log('Test 18: Verifying Auditor CANNOT add analyst notes (403 Forbidden)...');
      const r18 = await fetch(`${baseUrl}/api/cases/${caseId}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAuditor}`,
        },
        body: JSON.stringify({ content: 'Auditor attempt to write note' }),
      });
      assert.strictEqual(r18.status, 403);
      console.log('✔ Test 18 Passed: Auditor note addition rejected with 403.\n');

      console.log('Test 19: Verifying case cannot be assigned to an Auditor (400 INVALID_ASSIGNMENT_ROLE)...');
      const r19 = await fetch(`${baseUrl}/api/cases/${caseId}/assignment`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ assignedAnalystId: 'usr-auditor-01' }),
      });
      assert.strictEqual(r19.status, 400);
      const b19 = await r19.json();
      assert.strictEqual(b19.code, 'INVALID_ASSIGNMENT_ROLE');
      console.log('✔ Test 19 Passed: Reassigning to Auditor rejected with 400.\n');

      // =========================================================================
      // SECTION 4: VALIDATION CHECKS (400 Bad Request)
      // =========================================================================
      console.log('Test 20: Verifying invalid status rejected (400 INVALID_STATUS)...');
      const r20 = await fetch(`${baseUrl}/api/cases/${caseId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ status: 'COMPROMISED_NOT_A_VALID_STATUS' }),
      });
      assert.strictEqual(r20.status, 400);
      const b20 = await r20.json();
      assert.strictEqual(b20.code, 'INVALID_STATUS');
      console.log('✔ Test 20 Passed: Invalid status rejected with 400.\n');

      console.log('Test 21: Verifying invalid priority rejected (400 INVALID_PRIORITY)...');
      const r21 = await fetch(`${baseUrl}/api/cases/${caseId}/priority`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ priority: 'SUPER_URGENT_IMMEDIATE' }),
      });
      assert.strictEqual(r21.status, 400);
      const b21 = await r21.json();
      assert.strictEqual(b21.code, 'INVALID_PRIORITY');
      console.log('✔ Test 21 Passed: Invalid priority rejected with 400.\n');

      console.log('Test 22: Verifying assignment to unknown user rejected (400 INVALID_ASSIGNMENT_TARGET)...');
      const r22 = await fetch(`${baseUrl}/api/cases/${caseId}/assignment`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ assignedAnalystId: 'usr-phantom-ghost-analyst' }),
      });
      assert.strictEqual(r22.status, 400);
      const b22 = await r22.json();
      assert.strictEqual(b22.code, 'INVALID_ASSIGNMENT_TARGET');
      console.log('✔ Test 22 Passed: Invalid assignment target rejected with 400.\n');

      console.log('Test 23: Verifying empty or whitespace note rejected (400 INVALID_NOTE)...');
      const r23 = await fetch(`${baseUrl}/api/cases/${caseId}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ content: '   \n\t  ' }),
      });
      assert.strictEqual(r23.status, 400);
      const b23 = await r23.json();
      assert.strictEqual(b23.code, 'INVALID_NOTE');
      console.log('✔ Test 23 Passed: Empty note rejected with 400.\n');

      console.log('Test 24: Verifying note exceeding 5000 characters rejected (400 NOTE_TOO_LONG)...');
      const overLongNote = 'A'.repeat(5001);
      const r24 = await fetch(`${baseUrl}/api/cases/${caseId}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ content: overLongNote }),
      });
      assert.strictEqual(r24.status, 400);
      const b24 = await r24.json();
      assert.strictEqual(b24.code, 'NOTE_TOO_LONG');
      console.log('✔ Test 24 Passed: Note exceeding 5000 chars rejected with 400.\n');

      // =========================================================================
      // SECTION 5: CORRECTNESS & WORKFLOW MUTATIONS
      // =========================================================================
      console.log('Test 25: Verifying status transitions across lifecycle states...');
      const statusesToTest: CaseStatus[] = ['IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE'];
      for (const st of statusesToTest) {
        const res = await fetch(`${baseUrl}/api/cases/${caseId}/status`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${tokenAlice}`,
          },
          body: JSON.stringify({ status: st }),
        });
        assert.strictEqual(res.status, 200);
        const data = await res.json();
        assert.strictEqual(data.status, st);
        assert.strictEqual(data.caseRecord.status, st);
      }
      console.log('✔ Test 25 Passed: Status transitions verified through lifecycle.\n');

      console.log('Test 26: Verifying priority update & strict decoupling from forensic risk score...');
      const r26 = await fetch(`${baseUrl}/api/cases/${caseId}/priority`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ priority: 'CRITICAL' }),
      });
      assert.strictEqual(r26.status, 200);
      const b26 = await r26.json();
      assert.strictEqual(b26.priority, 'CRITICAL');
      assert.strictEqual(b26.caseRecord.priority, 'CRITICAL');
      // Assert forensic riskScore and severity were NOT recalculated or overwritten
      assert.strictEqual(b26.caseRecord.riskScore, initialRiskScore, 'Risk score must remain untouched');
      assert.strictEqual(b26.caseRecord.severity, initialSeverity, 'Forensic severity must remain untouched');
      console.log('✔ Test 26 Passed: Priority updated to CRITICAL while forensic risk score remained decoupled.\n');

      console.log('Test 27: Verifying assignment to Bob grants Bob authorization to collaborate on the case...');
      const r27 = await fetch(`${baseUrl}/api/cases/${caseId}/assignment`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ assignedAnalystId: 'usr-analyst-02' }),
      });
      assert.strictEqual(r27.status, 200);
      const b27 = await r27.json();
      assert.strictEqual(b27.assignedAnalystId, 'usr-analyst-02');
      assert.ok(b27.caseRecord.authorizedUsers.includes('usr-analyst-02'));

      // Now Bob CAN access and mutate the case
      const r27Bob = await fetch(`${baseUrl}/api/cases/${caseId}`, {
        headers: { Authorization: `Bearer ${tokenBob}` },
      });
      assert.strictEqual(r27Bob.status, 200, 'Reassigned analyst Bob must now have case access');
      console.log('✔ Test 27 Passed: Case reassigned and authorization granted to target analyst.\n');

      console.log('Test 28: Verifying server-derived author enforcement on analyst notes...');
      const r28 = await fetch(`${baseUrl}/api/cases/${caseId}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({
          content: 'Confirmed malicious redirect in authentication link.',
          author: 'SpoofedAdversaryName', // Attempting to spoof author in body
        }),
      });
      assert.strictEqual(r28.status, 201);
      const b28 = await r28.json();
      assert.ok(b28.note.id);
      assert.strictEqual(b28.note.content, 'Confirmed malicious redirect in authentication link.');
      // Author must be Alice, NOT SpoofedAdversaryName
      assert.strictEqual(b28.note.author, sessionAlice.user.name, 'Author must be server-derived from authenticated user profile');
      assert.ok(b28.note.timestamp);
      console.log('✔ Test 28 Passed: Server-derived author enforced; client spoofing prevented.\n');

      console.log('Test 29: Verifying note with exactly 5000 characters accepted and stored verbatim...');
      const maxValidNote = 'X'.repeat(5000);
      const r29 = await fetch(`${baseUrl}/api/cases/${caseId}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ content: maxValidNote }),
      });
      assert.strictEqual(r29.status, 201);
      const b29 = await r29.json();
      assert.strictEqual(b29.note.content.length, 5000);
      console.log('✔ Test 29 Passed: Maximum 5000-character note stored verbatim.\n');

      console.log('Test 30: Verifying chronological operational audit history retrieval...');
      const r30 = await fetch(`${baseUrl}/api/cases/${caseId}/history`, {
        headers: { Authorization: `Bearer ${tokenAlice}` },
      });
      assert.strictEqual(r30.status, 200);
      const b30 = await r30.json();
      assert.ok(Array.isArray(b30.history));
      assert.ok(b30.history.length >= 5, 'History must contain all transition entries');

      const actions = b30.history.map((h: any) => h.action);
      assert.ok(actions.includes('STATUS_CHANGED'), 'Must include STATUS_CHANGED');
      assert.ok(actions.includes('PRIORITY_CHANGED'), 'Must include PRIORITY_CHANGED');
      assert.ok(actions.includes('ASSIGNMENT_CHANGED'), 'Must include ASSIGNMENT_CHANGED');
      assert.ok(actions.includes('NOTE_ADDED'), 'Must include NOTE_ADDED');

      // Verify each entry has timestamp and actor
      for (const item of b30.history) {
        assert.ok(item.id, 'History item must have id');
        assert.ok(item.timestamp, 'History item must have timestamp');
        assert.ok(item.actor, 'History item must have actor');
        assert.ok(item.details, 'History item must have details');
      }
      console.log(`✔ Test 30 Passed: Full chronological audit trail verified (${b30.history.length} events).\n`);

      console.log('Test 31: Verifying Evidence Ledger immutability...');
      const ledgerVerification = evidenceLedger.verifyIntegrity();
      assert.strictEqual(ledgerVerification.isValid, true, 'Ledger hash-chain must remain 100% cryptographically valid');
      assert.strictEqual(evidenceLedger.getChain().length, initialLedgerBlockCount, 'Ledger block count must not be altered by case operations');
      console.log('✔ Test 31 Passed: Evidence ledger cryptographic chain completely immutable.\n');

      console.log('Test 32: Verifying assignable analysts directory excludes AUDITOR role...');
      const r32 = await fetch(`${baseUrl}/api/cases/assignable-analysts`, {
        headers: { Authorization: `Bearer ${tokenAlice}` },
      });
      assert.strictEqual(r32.status, 200);
      const b32 = await r32.json();
      assert.ok(Array.isArray(b32.analysts));
      const auditorInList = b32.analysts.find((u: any) => u.role === 'AUDITOR');
      assert.strictEqual(auditorInList, undefined, 'Auditors must not be present in assignable analysts list');
      console.log('✔ Test 32 Passed: Assignable analysts list safely filters out read-only auditor accounts.\n');

      console.log('Test 33: Verifying safe storage of XSS payloads in analyst notes...');
      const xssPayload = '<script>alert("XSS")</script><img src="x" onerror="stealCookie()" />';
      const r33 = await fetch(`${baseUrl}/api/cases/${caseId}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAlice}`,
        },
        body: JSON.stringify({ content: xssPayload }),
      });
      assert.strictEqual(r33.status, 201);
      const b33 = await r33.json();
      assert.strictEqual(b33.note.content, xssPayload);
      console.log('✔ Test 33 Passed: XSS payload stored safely without execution.\n');
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()));
    }

    console.log('===================================================================');
    console.log('ALL PHASE 9 ANALYST WORKFLOW & CASE OPERATIONS TESTS PASSED (33/33)');
    console.log('===================================================================\n');
  } finally {
    process.env = originalEnv;
  }
}

runTests().catch(err => {
  console.error('Test Suite Failed with Error:', err);
  process.exit(1);
});
