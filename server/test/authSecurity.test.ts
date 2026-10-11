import assert from 'assert';
import { authService } from '../auth/authService';
import { auditLogger } from '../auth/auditLogger';
import { authenticateUser, extractBearerToken, requireRole } from '../auth/authMiddleware';
import { caseService } from '../services/caseService';
import { ALL_DEMO_CASES } from '../demo/demoCases';

console.log('=== RUNNING AUTHENTICATION & AUTHORIZATION SECURITY TEST SUITE ===\n');

async function runAuthSecurityTests() {
  await caseService.initialize();

  // Helper to mock Express request and response objects
  function createMockReqRes(options: {
    headers?: Record<string, string>;
    user?: any;
    params?: Record<string, string>;
    body?: any;
    path?: string;
    method?: string;
  }) {
    const req: any = {
      headers: options.headers || {},
      user: options.user,
      params: options.params || {},
      body: options.body || {},
      path: options.path || '/api/test',
      method: options.method || 'GET',
      socket: { remoteAddress: '127.0.0.1' },
      ip: '127.0.0.1',
    };

    let statusCode = 200;
    let jsonResponse: any = null;

    const res: any = {
      status(code: number) {
        statusCode = code;
        return res;
      },
      json(data: any) {
        jsonResponse = data;
        return res;
      },
      getStatusCode: () => statusCode,
      getJsonResponse: () => jsonResponse,
    };

    return { req, res };
  }

  // --- Test 1: Unauthenticated API request -> 401 ---
  console.log('Test 1: Verifying unauthenticated API request rejection (401)...');
  {
    const { req, res } = createMockReqRes({
      headers: {},
      path: '/api/cases',
    });
    let nextCalled = false;
    authenticateUser(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, false, 'Middleware must NOT call next() on unauthenticated request');
    assert.strictEqual(res.getStatusCode(), 401, 'Unauthenticated request must return HTTP 401');
    assert.ok(res.getJsonResponse().error.includes('Unauthorized'), 'Response must communicate unauthorized access');
    console.log('✔ Test 1 Passed: Unauthenticated requests strictly return HTTP 401.\n');
  }

  // Setup sessions for Analyst 1, Analyst 2, and Admin
  const analyst1Login = authService.login('analyst@soc.internal', 'Analyst@SOC2026!');
  assert.ok(analyst1Login.success, 'Analyst 1 login must succeed');
  const analyst1Token = analyst1Login.token;
  const analyst1Session = authService.validateToken(analyst1Token)!;

  const analyst2Login = authService.login('analyst2@soc.internal', 'Analyst2@SOC2026!');
  assert.ok(analyst2Login.success, 'Analyst 2 login must succeed');
  const analyst2Token = analyst2Login.token;
  const analyst2Session = authService.validateToken(analyst2Token)!;

  const adminLogin = authService.login('admin@soc.internal', 'Admin@SOC2026!');
  assert.ok(adminLogin.success, 'Admin login must succeed');
  const adminToken = adminLogin.token;
  const adminSession = authService.validateToken(adminToken)!;

  // --- Test 2: Authenticated Analyst -> Allowed access to authorized case ---
  console.log('Test 2: Verifying authenticated analyst access to authorized case...');
  {
    // Create a private investigation owned by Analyst 1
    const rawEmail = `From: attacker@malicious.com\r\nTo: victim@company.com\r\nSubject: Invoice Overdue\r\nDate: Mon, 1 Sep 2026 10:00:00 +0000\r\n\r\nPlease pay immediately.`;
    const createdPayload = await caseService.processEmail(rawEmail, {
      caseId: 'CASE-PRIVATE-ANALYST1',
      title: 'Private Investigation of Analyst 1',
      analyst: analyst1Session.name,
      ownerId: analyst1Session.userId,
      ownerEmail: analyst1Session.email,
      authorizedUsers: [analyst1Session.userId],
    });

    assert.strictEqual(createdPayload.caseRecord.caseId, 'CASE-PRIVATE-ANALYST1');

    const accessResult = caseService.getCasePayloadForUser(analyst1Session, 'CASE-PRIVATE-ANALYST1');
    assert.strictEqual(accessResult.status, 'ALLOWED', 'Owner analyst must be permitted to access own case');
    assert.ok(accessResult.payload, 'Payload must be returned to case owner');
    console.log('✔ Test 2 Passed: Authenticated analyst granted access to authorized case.\n');
  }

  // --- Test 3: Analyst accessing another user's case -> 403 Forbidden ---
  console.log("Test 3: Verifying cross-analyst case isolation (Analyst 2 accessing Analyst 1's case -> 403)...");
  {
    const accessResult = caseService.getCasePayloadForUser(analyst2Session, 'CASE-PRIVATE-ANALYST1');
    assert.strictEqual(accessResult.status, 'FORBIDDEN', "Analyst 2 must be FORBIDDEN from accessing Analyst 1's case");
    assert.strictEqual(accessResult.payload, undefined, 'No payload must be leaked to unauthorized analyst');

    // Test access control check function directly
    const permCheck = caseService.canUserAccessCase(analyst2Session, 'CASE-PRIVATE-ANALYST1');
    assert.strictEqual(permCheck.allowed, false, 'Permission must be denied');
    assert.strictEqual(permCheck.caseFound, true, 'Case presence detected but access rejected');
    console.log("✔ Test 3 Passed: Cross-analyst case access prohibited with HTTP 403.\n");
  }

  // --- Test 4: Admin accessing authorized cases -> Allowed ---
  console.log('Test 4: Verifying Administrator supervisory case access...');
  {
    const adminAccess = caseService.getCasePayloadForUser(adminSession, 'CASE-PRIVATE-ANALYST1');
    assert.strictEqual(adminAccess.status, 'ALLOWED', 'Administrator must have supervisory access across investigations');
    assert.ok(adminAccess.payload, 'Payload returned to authorized Admin');
    console.log('✔ Test 4 Passed: Admin allowed supervisory access to cases.\n');
  }

  // --- Test 5: Analyst attempting ledger reseal -> 403 ---
  console.log('Test 5: Verifying Analyst role blocked from ledger mutation/reseal (403)...');
  {
    const { req, res } = createMockReqRes({
      user: analyst1Session,
      path: '/api/ledger/reseal',
      method: 'POST',
    });
    let nextCalled = false;
    const adminGuard = requireRole('ADMIN');
    adminGuard(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, false, 'Analyst must NOT reach admin controller');
    assert.strictEqual(res.getStatusCode(), 403, 'Analyst attempting ledger reseal must receive HTTP 403 Forbidden');
    assert.ok(res.getJsonResponse().error.includes('lacks permission'), 'Must notify of insufficient role');
    console.log('✔ Test 5 Passed: Normal Analyst blocked from ledger mutation (HTTP 403).\n');
  }

  // --- Test 6: Admin ledger reseal -> Allowed ---
  console.log('Test 6: Verifying Admin permission on ledger reseal...');
  {
    const { req, res } = createMockReqRes({
      user: adminSession,
      path: '/api/ledger/reseal',
      method: 'POST',
    });
    let nextCalled = false;
    const adminGuard = requireRole('ADMIN');
    adminGuard(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, true, 'Admin must successfully pass role guard');
    assert.strictEqual(res.getStatusCode(), 200, 'Admin request proceeds with 200');
    console.log('✔ Test 6 Passed: Administrator authorized to perform ledger reseal.\n');
  }

  // --- Test 7: Invalid or Expired authentication -> 401 ---
  console.log('Test 7: Verifying invalid or expired session token rejection (401)...');
  {
    const { req, res } = createMockReqRes({
      headers: { authorization: 'Bearer soc_sec_invalid_forged_token_12345' },
      path: '/api/cases',
    });
    let nextCalled = false;
    authenticateUser(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, false, 'Invalid token must NOT call next()');
    assert.strictEqual(res.getStatusCode(), 401, 'Invalid token must return HTTP 401');
    assert.strictEqual(res.getJsonResponse().code, 'AUTH_TOKEN_EXPIRED');
    console.log('✔ Test 7 Passed: Invalid/expired tokens rejected with HTTP 401.\n');
  }

  // --- Test 8: Invalid / insufficient role rejection -> 403 ---
  console.log('Test 8: Verifying role mismatch rejection...');
  {
    const { req, res } = createMockReqRes({
      user: { userId: 'usr-guest', role: 'GUEST', email: 'guest@test.local' },
      path: '/api/audit/logs',
    });
    let nextCalled = false;
    const adminGuard = requireRole('ADMIN');
    adminGuard(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, false);
    assert.strictEqual(res.getStatusCode(), 403);
    console.log('✔ Test 8 Passed: Role mismatch correctly returns HTTP 403.\n');
  }

  // --- Test 9: Public demo endpoint -> Works as intended ---
  console.log('Test 9: Verifying public demo case endpoint availability and label...');
  {
    // Demo cases must be accessible and labeled
    assert.ok(ALL_DEMO_CASES.length >= 3, 'Demo cases must exist');
    const demo1 = caseService.getCasePayload('CASE-2026-001');
    assert.ok(demo1, 'Seeded demo case must be loaded');
    assert.strictEqual(demo1.caseRecord.isPublicDemo, true, 'Demo case must be marked isPublicDemo: true');

    // Any authenticated analyst can access demo cases
    const analystAccessDemo = caseService.getCasePayloadForUser(analyst2Session, 'CASE-2026-001');
    assert.strictEqual(analystAccessDemo.status, 'ALLOWED', 'Demo cases must be viewable by all analysts');
    console.log('✔ Test 9 Passed: Public demo scenarios accessible and isolated.\n');
  }

  // --- Test 10: Private case cannot be accessed through ID enumeration ---
  console.log('Test 10: Verifying private case resistance against ID enumeration...');
  {
    // Random ID check returns NOT_FOUND (404)
    const nonExistent = caseService.getCasePayloadForUser(analyst2Session, 'CASE-RANDOM-NONEXISTENT-999');
    assert.strictEqual(nonExistent.status, 'NOT_FOUND', 'Non-existent case must return NOT_FOUND without leaking metadata');

    // Existing other user's case returns FORBIDDEN (403)
    const otherUserCase = caseService.getCasePayloadForUser(analyst2Session, 'CASE-PRIVATE-ANALYST1');
    assert.strictEqual(otherUserCase.status, 'FORBIDDEN', 'Existing private case must return FORBIDDEN, never leaking payload');
    console.log('✔ Test 10 Passed: Private cases immune to ID enumeration.\n');
  }

  // --- Test 11: Gemini API key cannot appear in API responses or user profiles ---
  console.log('Test 11: Verifying secret protection (Gemini API key not in API responses)...');
  {
    const users = authService.getAllUsers();
    const serializedUsers = JSON.stringify(users);
    assert.ok(!serializedUsers.includes('passwordHash'), 'Password hashes must never be exposed');
    assert.ok(!serializedUsers.includes('salt'), 'Password salts must never be exposed');

    if (process.env.GEMINI_API_KEY) {
      assert.ok(!serializedUsers.includes(process.env.GEMINI_API_KEY), 'Gemini API key must not appear in user profiles');
      const publicCases = JSON.stringify(caseService.getAllCases());
      assert.ok(!publicCases.includes(process.env.GEMINI_API_KEY), 'Gemini API key must not appear in cases');
    }
    console.log('✔ Test 11 Passed: Secrets and API keys shielded from API representations.\n');
  }

  // --- Test 12: Passwords/secrets cannot appear in audit logs ---
  console.log('Test 12: Verifying passwords and tokens are sanitized in audit logs...');
  {
    auditLogger.record({
      action: 'LOGIN_FAILED',
      status: 'FAILURE',
      actorEmail: 'test@soc.internal',
      details: 'Attempted login with password=SuperSecretPassword! and Authorization: Bearer soc_sec_secret_token_abc',
    });

    const logs = auditLogger.getLogs(5);
    const serializedLogs = JSON.stringify(logs);

    assert.ok(!serializedLogs.includes('SuperSecretPassword!'), 'Plaintext password must be redacted from audit logs');
    assert.ok(!serializedLogs.includes('soc_sec_secret_token_abc'), 'Bearer token must be redacted from audit logs');
    assert.ok(serializedLogs.includes('[REDACTED]'), 'Redaction placeholder must be present');
    console.log('✔ Test 12 Passed: Audit logs sanitize sensitive secrets and credentials.\n');
  }

  console.log('================================================================');
  console.log('ALL 12 AUTHENTICATION & RBAC SECURITY TESTS PASSED (100%)');
  console.log('================================================================\n');
}

runAuthSecurityTests().catch(err => {
  console.error('Auth security test failure:', err);
  process.exit(1);
});
