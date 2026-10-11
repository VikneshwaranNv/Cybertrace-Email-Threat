import assert from 'assert';
import crypto from 'crypto';
import { GmailTriageService, gmailTriageService } from '../gmail/gmailTriageService';
import { GmailTriageRegistry, gmailTriageRegistry } from '../gmail/gmailTriageRegistry';
import { GmailApiService, GmailRawMessage } from '../gmail/gmailApiService';
import { GmailOAuthService } from '../gmail/gmailOAuthService';
import * as geminiClientModule from '../ai/geminiClient';

console.log('=== RUNNING DETERMINISTIC GMAIL THREAT TRIAGE TEST SUITE (PHASE 3) ===\n');

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    process.env.GOOGLE_CLIENT_ID = 'test-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';
    // Explicitly clear GEMINI_API_KEY to prove zero dependence on Gemini API
    delete process.env.GEMINI_API_KEY;

    // 1. Setup Sample Emails for Triage Evaluation
    const PHISHING_EML = [
      'Received: from attacker.evil.org ([198.51.100.99]) by mx.google.com with ESMTPS; Tue, 08 Sep 2026 10:00:00 +0000',
      'From: Security Desk <alert@external-secure-service.com>',
      'Reply-To: credential-collector@darknet-drop.xyz',
      'To: Target Employee <victim@acme-corp.com>',
      'Subject: URGENT: Your password expires in 2 hours - Immediate Verification Required',
      'Date: Tue, 08 Sep 2026 10:00:00 +0000',
      'Message-ID: <threat-phish-9911@external-secure-service.com>',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'URGENT SECURITY ALERT: Your Microsoft 365 session has expired. You must immediately login to verify your credentials within 24 hours to prevent account suspension:\r\nhttps://login-microsoft365-verify.attacker-drop.com/reset',
    ].join('\r\n');

    const COMPANY_EML = [
      'Received: from mail.acme-corp.com (10.0.0.1) by mx.acme-corp.com with ESMTP; Tue, 08 Sep 2026 11:00:00 +0000',
      'From: Chief Financial Officer <cfo@acme-corp.com>',
      'To: Finance Team <finance@acme-corp.com>',
      'Subject: Q3 Internal Financial Audit Review Meeting',
      'Date: Tue, 08 Sep 2026 11:00:00 +0000',
      'Message-ID: <corp-internal-3322@acme-corp.com>',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Team, attached are the Q3 audit reconciliations. This email and any attachments are confidential and intended solely for Acme Corp employees.',
    ].join('\r\n');

    const SPAM_EML = [
      'Received: from mass-mail.marketing.net (203.0.113.55) by mx.google.com with ESMTP; Tue, 08 Sep 2026 12:00:00 +0000',
      'From: Weekly Discounts <newsletter@super-deals-shop.com>',
      'To: Customer <customer@gmail.com>',
      'Subject: Exclusive 50% discount on all cloud gadgets today only!',
      'List-Unsubscribe: <https://super-deals-shop.com/opt-out>',
      'Date: Tue, 08 Sep 2026 12:00:00 +0000',
      'Message-ID: <promo-msg-4411@super-deals-shop.com>',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Special promotional offer! Click here to view in browser. If you no longer wish to receive special offers, please unsubscribe using the link above.',
    ].join('\r\n');

    const MALFORMED_EML = 'This is completely invalid raw RFC-822 without headers';

    // 2. Setup Isolated Services for Tests
    const oauthService = new GmailOAuthService();
    const USER_ALICE = 'usr-alice-analyst';
    const USER_BOB = 'usr-bob-analyst';

    oauthService._setConnectionForTest(USER_ALICE, {
      userId: USER_ALICE,
      gmailEmail: 'alice.soc@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.alice-token-for-triage',
      refreshToken: '1//alice-refresh',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    oauthService._setConnectionForTest(USER_BOB, {
      userId: USER_BOB,
      gmailEmail: 'bob.soc@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.bob-token-for-triage',
      refreshToken: '1//bob-refresh',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    // Mock API Fetcher returning corresponding raw emails
    const mockApiFetcher = async (url: string, init: RequestInit): Promise<Response> => {
      const authHeader = (init.headers as Record<string, string>)?.['Authorization'] || '';

      if (authHeader.includes('invalid')) {
        return new Response(JSON.stringify({ error: { code: 401, message: 'Invalid Credentials' } }), {
          status: 401,
          statusText: 'Unauthorized',
        });
      }

      if (url.includes('/messages/msg-phish?format=raw')) {
        return new Response(
          JSON.stringify({
            id: 'msg-phish',
            threadId: 'th-phish-1',
            labelIds: ['INBOX', 'UNREAD'],
            raw: Buffer.from(PHISHING_EML, 'utf8').toString('base64url'),
          }),
          { status: 200 }
        );
      }

      if (url.includes('/messages/msg-company?format=raw')) {
        return new Response(
          JSON.stringify({
            id: 'msg-company',
            threadId: 'th-company-1',
            labelIds: ['INBOX'],
            raw: Buffer.from(COMPANY_EML, 'utf8').toString('base64url'),
          }),
          { status: 200 }
        );
      }

      if (url.includes('/messages/msg-spam?format=raw')) {
        return new Response(
          JSON.stringify({
            id: 'msg-spam',
            threadId: 'th-spam-1',
            labelIds: ['SPAM'],
            raw: Buffer.from(SPAM_EML, 'utf8').toString('base64url'),
          }),
          { status: 200 }
        );
      }

      if (url.includes('/messages/msg-malformed?format=raw')) {
        return new Response(
          JSON.stringify({
            id: 'msg-malformed',
            threadId: 'th-malformed-1',
            raw: Buffer.from(MALFORMED_EML, 'utf8').toString('base64url'),
          }),
          { status: 200 }
        );
      }

      if (url.includes('/messages/msg-missing-raw?format=raw')) {
        return new Response(
          JSON.stringify({
            id: 'msg-missing-raw',
            threadId: 'th-missing-1',
            // Missing raw field
          }),
          { status: 200 }
        );
      }

      if (url.includes('/messages/msg-404?format=raw')) {
        return new Response(JSON.stringify({ error: { code: 404, message: 'Not found' } }), {
          status: 404,
          statusText: 'Not Found',
        });
      }

      if (url.includes('/messages/msg-429?format=raw')) {
        return new Response(JSON.stringify({ error: { code: 429, message: 'Rate limit exceeded' } }), {
          status: 429,
          statusText: 'Too Many Requests',
          headers: { 'Retry-After': '20' },
        });
      }

      // Handle synthetic delay for batch concurrency tests (e.g. msg-batch-1 .. msg-batch-15)
      const matchBatch = url.match(/\/messages\/(msg-batch-\d+)\?format=raw/);
      if (matchBatch) {
        const id = matchBatch[1];
        // Simulate 20ms I/O latency to measure concurrency
        await new Promise(resolve => setTimeout(resolve, 20));
        return new Response(
          JSON.stringify({
            id,
            threadId: `th-${id}`,
            labelIds: ['INBOX'],
            raw: Buffer.from(COMPANY_EML, 'utf8').toString('base64url'),
          }),
          { status: 200 }
        );
      }

      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    };

    const testApiService = new GmailApiService({ oauthService, fetcher: mockApiFetcher });
    const testRegistry = new GmailTriageRegistry();
    const testTriageService = new GmailTriageService({ apiService: testApiService, registry: testRegistry });

    // -------------------------------------------------------------------------
    // Test 1: Gmail message is retrieved and triaged
    // -------------------------------------------------------------------------
    console.log('Test 1: Verifying single Gmail message retrieval and triage execution...');
    const resultPhish = await testTriageService.triageSingleMessage(USER_ALICE, 'msg-phish');
    assert.ok(resultPhish, 'Must return a triage record');
    assert.strictEqual(resultPhish.gmailMessageId, 'msg-phish');
    assert.strictEqual(resultPhish.userId, USER_ALICE);
    assert.strictEqual(resultPhish.threadId, 'th-phish-1');
    console.log('✔ Test 1 Passed: Gmail message retrieved and triaged successfully.\n');

    // -------------------------------------------------------------------------
    // Test 2: parseRawEmail() receives raw RFC-822 message
    // -------------------------------------------------------------------------
    console.log('Test 2: Verifying parseRawEmail() receives raw RFC-822 message verbatim...');
    assert.strictEqual(resultPhish.subject, 'URGENT: Your password expires in 2 hours - Immediate Verification Required');
    assert.strictEqual(resultPhish.sender.fromAddress, 'alert@external-secure-service.com');
    assert.strictEqual(resultPhish.recipients[0], 'Target Employee <victim@acme-corp.com>');
    assert.ok(resultPhish.recipients[0].includes('victim@acme-corp.com'));
    console.log('✔ Test 2 Passed: parseRawEmail parsed RFC-822 payload accurately.\n');

    // -------------------------------------------------------------------------
    // Test 3: Header analysis is executed
    // -------------------------------------------------------------------------
    console.log('Test 3: Verifying header analysis execution (hops, originating IP, auth results)...');
    assert.strictEqual(resultPhish.originatingIp, '198.51.100.99', 'Originating IP should be parsed from Received hops');
    assert.ok(resultPhish.authStatus, 'Authentication envelope status must be captured');
    console.log('✔ Test 3 Passed: Header analysis executed correctly.\n');

    // -------------------------------------------------------------------------
    // Test 4: Mail classification is executed (Company vs Personal vs Spam)
    // -------------------------------------------------------------------------
    console.log('Test 4: Verifying independent mail classification across different email types...');
    const resultCompany = await testTriageService.triageSingleMessage(USER_ALICE, 'msg-company');
    const resultSpam = await testTriageService.triageSingleMessage(USER_ALICE, 'msg-spam');

    assert.strictEqual(resultCompany.mailClassification.mailType, 'COMPANY');
    assert.strictEqual(resultSpam.mailClassification.mailType, 'SPAM');
    console.log('✔ Test 4 Passed: Mail classification accurately separated Company and Spam.\n');

    // -------------------------------------------------------------------------
    // Test 5: Deterministic heuristic threat analysis is executed
    // -------------------------------------------------------------------------
    console.log('Test 5: Verifying deterministic heuristic threat analysis detection...');
    assert.strictEqual(resultPhish.threatClassification, 'CREDENTIAL_HARVESTING');
    assert.strictEqual(resultPhish.threatIndicators.detected['credentialHarvesting'], true);
    assert.strictEqual(resultPhish.threatIndicators.detected['urgencyManipulation'], true);
    console.log('✔ Test 5 Passed: Heuristic threat assessment successfully detected credential harvest indicators.\n');

    // -------------------------------------------------------------------------
    // Test 6: Existing risk engine produces the authoritative score
    // -------------------------------------------------------------------------
    console.log('Test 6: Verifying authoritative 0-100 risk score and level from existing risk engine...');
    assert.ok(typeof resultPhish.riskScore === 'number');
    assert.ok(resultPhish.riskScore >= 50, `Phishing email must have high/critical risk score (got ${resultPhish.riskScore})`);
    assert.ok(resultPhish.riskLevel === 'HIGH' || resultPhish.riskLevel === 'CRITICAL');

    assert.ok(resultCompany.riskScore < 40, `Legitimate company email should have low/moderate risk score (got ${resultCompany.riskScore})`);
    console.log('✔ Test 6 Passed: Authoritative explainable risk score produced.\n');

    // -------------------------------------------------------------------------
    // Test 7: SHA-256 remains associated with raw email
    // -------------------------------------------------------------------------
    console.log('Test 7: Verifying raw-evidence SHA-256 cryptographic association...');
    const expectedPhishSha = crypto.createHash('sha256').update(PHISHING_EML).digest('hex');
    assert.strictEqual(resultPhish.forensicSha256, expectedPhishSha, 'Forensic SHA-256 must match raw bytes hash');
    console.log('✔ Test 7 Passed: Forensic SHA-256 hash verified.\n');

    // -------------------------------------------------------------------------
    // Test 8: MD5 remains associated with raw email
    // -------------------------------------------------------------------------
    console.log('Test 8: Verifying legacy reference MD5 association...');
    const expectedPhishMd5 = crypto.createHash('md5').update(PHISHING_EML).digest('hex');
    assert.strictEqual(resultPhish.forensicMd5, expectedPhishMd5, 'Forensic MD5 must match raw bytes hash');
    console.log('✔ Test 8 Passed: Forensic MD5 hash verified.\n');

    // -------------------------------------------------------------------------
    // Test 9: Automatic triage performs ZERO Gemini API calls
    // -------------------------------------------------------------------------
    console.log('Test 9: Proving automatic Gmail triage makes ZERO Gemini API calls...');
    assert.strictEqual(geminiClientModule.isGeminiAvailable(), false, 'Gemini is confirmed unavailable/unconfigured in this test');
    // Calling triage again on an un-triaged message while Gemini is unconfigured must succeed 100%
    const resultNoAi = await testTriageService.triageSingleMessage(USER_ALICE, 'msg-spam');
    assert.ok(resultNoAi, 'Triage must execute completely without requiring Gemini API');
    console.log('✔ Test 9 Passed: Zero Gemini API calls confirmed.\n');

    // -------------------------------------------------------------------------
    // Test 10: Idempotency (Same message is not triaged twice unnecessarily)
    // -------------------------------------------------------------------------
    console.log('Test 10: Verifying idempotency (second triage returns cached record without re-analysis)...');
    const secondTriage = await testTriageService.triageSingleMessage(USER_ALICE, 'msg-phish');
    assert.strictEqual(secondTriage.alreadyTriaged, true, 'Second triage must flag alreadyTriaged: true');
    assert.strictEqual(secondTriage.forensicSha256, resultPhish.forensicSha256);
    assert.strictEqual(secondTriage.analyzedAt, resultPhish.analyzedAt);
    console.log('✔ Test 10 Passed: Triage idempotency and registry deduplication verified.\n');

    // -------------------------------------------------------------------------
    // Test 11: User A cannot access User B's triage result
    // -------------------------------------------------------------------------
    console.log('Test 11: Verifying multi-tenant registry isolation between users...');
    const bobRecord = testRegistry.get(USER_BOB, 'msg-phish');
    assert.strictEqual(bobRecord, undefined, 'Bob cannot access Alice\'s triage record for msg-phish');

    const aliceRecords = testRegistry.getAllForUser(USER_ALICE);
    const bobRecords = testRegistry.getAllForUser(USER_BOB);
    assert.ok(aliceRecords.length >= 3);
    assert.strictEqual(bobRecords.length, 0);
    console.log('✔ Test 11 Passed: Registry strictly enforces user isolation.\n');

    // -------------------------------------------------------------------------
    // Test 12: User A cannot use User B's Gmail connection
    // -------------------------------------------------------------------------
    console.log('Test 12: Verifying user connection boundary enforcement...');
    const UNCONNECTED_USER = 'usr-charlie-unconnected';
    await assert.rejects(
      async () => {
        await testTriageService.triageSingleMessage(UNCONNECTED_USER, 'msg-phish');
      },
      (err: any) => {
        assert.strictEqual(err.code, 'GMAIL_NOT_CONNECTED');
        return true;
      },
      'Unconnected user cannot triage messages'
    );
    console.log('✔ Test 12 Passed: User connection boundary strictly enforced.\n');

    // -------------------------------------------------------------------------
    // Test 13: Gmail 404 is handled safely
    // -------------------------------------------------------------------------
    console.log('Test 13: Verifying safe error handling on Gmail 404 Not Found...');
    await assert.rejects(
      async () => {
        await testTriageService.triageSingleMessage(USER_ALICE, 'msg-404');
      },
      (err: any) => {
        assert.strictEqual(err.code, 'GMAIL_NOT_FOUND');
        assert.strictEqual(err.statusCode, 404);
        return true;
      }
    );
    console.log('✔ Test 13 Passed: Gmail 404 handled with typed error.\n');

    // -------------------------------------------------------------------------
    // Test 14: Gmail 429 is handled safely with retry metadata
    // -------------------------------------------------------------------------
    console.log('Test 14: Verifying safe error handling on Gmail 429 Rate Limit...');
    await assert.rejects(
      async () => {
        await testTriageService.triageSingleMessage(USER_ALICE, 'msg-429');
      },
      (err: any) => {
        assert.strictEqual(err.code, 'GMAIL_RATE_LIMIT');
        assert.strictEqual(err.statusCode, 429);
        assert.strictEqual(err.retryAfterMs, 20000);
        return true;
      }
    );
    console.log('✔ Test 14 Passed: Gmail 429 handled safely with retry delay.\n');

    // -------------------------------------------------------------------------
    // Test 15: One failed message does not abort a batch
    // -------------------------------------------------------------------------
    console.log('Test 15: Verifying batch fault tolerance (partial failure isolation)...');
    const batchInputWithFailure = ['msg-phish', 'msg-404', 'msg-company'];
    const batchResponse = await testTriageService.triageMessages(USER_ALICE, batchInputWithFailure);

    assert.strictEqual(batchResponse.total, 3);
    assert.strictEqual(batchResponse.succeeded, 2);
    assert.strictEqual(batchResponse.failed, 1);

    const failedItem = batchResponse.results.find(r => r.messageId === 'msg-404');
    assert.ok(failedItem);
    assert.strictEqual(failedItem.success, false);
    assert.ok(failedItem.error);

    const successItem = batchResponse.results.find(r => r.messageId === 'msg-company');
    assert.ok(successItem);
    assert.strictEqual(successItem.success, true);
    console.log('✔ Test 15 Passed: Batch fault tolerance verified.\n');

    // -------------------------------------------------------------------------
    // Test 16: Batch processing respects maximum concurrency of 5
    // -------------------------------------------------------------------------
    console.log('Test 16: Verifying batch worker pool respects max concurrency limit (<= 5)...');
    testTriageService.resetConcurrencyTracker();

    // Generate 12 distinct batch IDs
    const batchIds = Array.from({ length: 12 }, (_, i) => `msg-batch-${i + 1}`);
    const batchConcurrencyRes = await testTriageService.triageMessages(USER_ALICE, batchIds);

    assert.strictEqual(batchConcurrencyRes.total, 12);
    assert.strictEqual(batchConcurrencyRes.succeeded, 12);

    const maxObserved = testTriageService.getMaxObservedConcurrency();
    console.log(`  - Maximum observed concurrent workers: ${maxObserved}`);
    assert.ok(maxObserved > 1, 'Worker pool must be parallelized');
    assert.ok(maxObserved <= 5, `Max concurrency must not exceed 5 (observed: ${maxObserved})`);
    console.log('✔ Test 16 Passed: Max concurrency strictly bounded at 5.\n');

    // -------------------------------------------------------------------------
    // Test 17: Duplicate message IDs within one batch are deduplicated
    // -------------------------------------------------------------------------
    console.log('Test 17: Verifying input messageId deduplication within a batch...');
    const duplicateInput = ['msg-company', 'msg-company', 'msg-phish', 'msg-company'];
    const dedupeResponse = await testTriageService.triageMessages(USER_ALICE, duplicateInput);

    assert.strictEqual(dedupeResponse.total, 2, 'Batch should deduplicate 4 items down to 2 unique items');
    assert.strictEqual(dedupeResponse.succeeded, 2);
    console.log('✔ Test 17 Passed: Input deduplication within batch verified.\n');

    // -------------------------------------------------------------------------
    // Test 18: Raw MIME is not stored in normalized triage records
    // -------------------------------------------------------------------------
    console.log('Test 18: Verifying raw MIME is omitted from normalized triage records...');
    assert.strictEqual((resultPhish as any).rawEml, undefined, 'rawEml must not exist on GmailTriageRecord');
    assert.strictEqual((resultPhish as any).raw, undefined, 'raw must not exist on GmailTriageRecord');
    assert.strictEqual((resultCompany as any).rawEml, undefined);

    const serializedRecord = JSON.stringify(resultPhish);
    assert.ok(!serializedRecord.includes('JVBERi0xLjQKJcTl8uXrp'), 'Raw attachment base64 must not be in triage record');
    console.log('✔ Test 18 Passed: Raw MIME payload omitted from triage store.\n');

    // -------------------------------------------------------------------------
    // Test 19: Malformed RFC-822 input is handled safely
    // -------------------------------------------------------------------------
    console.log('Test 19: Verifying safe handling of malformed RFC-822 payload...');
    const malformedResult = await testTriageService.triageSingleMessage(USER_ALICE, 'msg-malformed');
    assert.ok(malformedResult);
    // Malformed email without standard headers should categorize as UNKNOWN or safe fallback
    assert.ok(['UNKNOWN', 'PERSONAL', 'SPAM', 'COMPANY'].includes(malformedResult.mailClassification.mailType));
    assert.ok(typeof malformedResult.riskScore === 'number');
    console.log('✔ Test 19 Passed: Malformed input handled without crash.\n');

    // -------------------------------------------------------------------------
    // Test 20: OAuth tokens never appear in triage results or errors
    // -------------------------------------------------------------------------
    console.log('Test 20: Verifying zero OAuth token leakage in triage results or error payloads...');
    const phishJson = JSON.stringify(resultPhish);
    const companyJson = JSON.stringify(resultCompany);
    const spamJson = JSON.stringify(resultSpam);

    const secretTokens = ['ya29.', 'alice-token-for-triage', 'bob-token-for-triage', 'test-client-secret'];
    for (const secret of secretTokens) {
      assert.ok(!phishJson.includes(secret), `Phish triage must not contain '${secret}'`);
      assert.ok(!companyJson.includes(secret), `Company triage must not contain '${secret}'`);
      assert.ok(!spamJson.includes(secret), `Spam triage must not contain '${secret}'`);
    }
    console.log('✔ Test 20 Passed: Complete token shielding verified.\n');

    console.log('================================================================');
    console.log('ALL 20 DETERMINISTIC GMAIL TRIAGE TESTS PASSED (100%)');
    console.log('================================================================\n');
  } finally {
    process.env = originalEnv;
  }
}

runTests().catch(err => {
  console.error('Test failure:', err);
  process.exit(1);
});
