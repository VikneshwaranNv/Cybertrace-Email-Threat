import assert from 'assert';
import { GmailCasePromotionService, GmailPromotionRegistry } from '../gmail/gmailCasePromotionService';
import { GmailApiService, GmailRawMessage, GmailApiError, GmailNotConnectedError } from '../gmail/gmailApiService';
import { GmailOAuthService } from '../gmail/gmailOAuthService';
import { GmailTriageRegistry } from '../gmail/gmailTriageRegistry';
import { caseService } from '../services/caseService';
import { evidenceLedger } from '../blockchain/evidenceLedger';
import { GmailTriageRecord } from '../../src/types/forensics';

console.log('=== RUNNING GMAIL CASE PROMOTION TEST SUITE (PHASE 6) ===\n');

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    process.env.GOOGLE_CLIENT_ID = 'test-promotion-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-promotion-secret';
    // Explicitly delete GEMINI_API_KEY to verify 0 dependence on external Gemini calls
    delete process.env.GEMINI_API_KEY;

    // 1. Setup Sample Test Emails
    const SAMPLE_PHISH_RFC822 = [
      'Received: from attacker.phish-node.net ([198.51.100.77]) by mx.google.com with ESMTPS; Tue, 08 Sep 2026 14:00:00 +0000',
      'From: Security Team <security-alert@account-verify-support.com>',
      'Reply-To: credential-harvest@external-drop.xyz',
      'To: Target Analyst <analyst@cybertrace-demo.com>',
      'Subject: URGENT: Corporate Access Expiring - Authenticate Credentials Now',
      'Date: Tue, 08 Sep 2026 14:00:00 +0000',
      'Message-ID: <threat-case-promote-001@account-verify-support.com>',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Your corporate credentials will be revoked in 1 hour. Immediate authentication is required: https://login-portal.dark-credentials.org/login',
    ].join('\r\n');

    const SAMPLE_SECOND_RFC822 = [
      'Received: from suspicious-relay.com ([203.0.113.88]) by mx.google.com with ESMTPS; Tue, 08 Sep 2026 14:30:00 +0000',
      'From: Payroll Department <payroll@external-update-notice.com>',
      'To: Employee <employee@cybertrace-demo.com>',
      'Subject: Immediate Direct Deposit Form Update',
      'Date: Tue, 08 Sep 2026 14:30:00 +0000',
      'Message-ID: <threat-case-promote-002@external-update-notice.com>',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Please verify your banking credentials at: http://payroll-portal-spoof.net/banking',
    ].join('\r\n');

    // 2. Setup Test Identities
    const USER_ALICE = 'usr-alice-soc-promoter';
    const USER_BOB = 'usr-bob-soc-promoter';

    const oauthService = new GmailOAuthService();
    oauthService._setConnectionForTest(USER_ALICE, {
      userId: USER_ALICE,
      gmailEmail: 'alice.promoter@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.alice-promo-access-token',
      refreshToken: '1//alice-promo-refresh-token',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    const triageRegistry = new GmailTriageRegistry();
    const promotionRegistry = new GmailPromotionRegistry();

    // Mock API Service returning exact raw bytes
    let rawFetchCalls = 0;
    let lastFetchedRawEml = '';

    const mockApiService = new GmailApiService({
      oauthService,
      fetcher: async (url: string, init: RequestInit): Promise<Response> => {
        rawFetchCalls++;
        const urlStr = String(url);

        if (urlStr.includes('/messages/msg-api-error')) {
          return new Response(JSON.stringify({ error: { message: 'Upstream Gmail API 500 error', code: 500 } }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        if (urlStr.includes('/messages/msg-not-found')) {
          return new Response(JSON.stringify({ error: { message: 'Message not found', code: 404 } }), {
            status: 404,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        let rawEmlToReturn = SAMPLE_PHISH_RFC822;
        let msgId = 'msg-threat-001';

        if (urlStr.includes('msg-threat-002')) {
          rawEmlToReturn = SAMPLE_SECOND_RFC822;
          msgId = 'msg-threat-002';
        }

        lastFetchedRawEml = rawEmlToReturn;
        const base64url = Buffer.from(rawEmlToReturn, 'utf-8').toString('base64url');

        return new Response(
          JSON.stringify({
            id: msgId,
            threadId: 'th-threat-001',
            raw: base64url,
            snippet: 'Your corporate credentials will be revoked...',
            sizeEstimate: rawEmlToReturn.length,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      },
    });

    const promotionService = new GmailCasePromotionService({
      caseService,
      apiService: mockApiService,
      triageRegistry,
      oauthService,
      promotionRegistry,
    });

    // Helper to seed a triaged record into registry for testing
    const seedTriageRecord = (userId: string, messageId: string, subject: string, riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'CRITICAL'): GmailTriageRecord => {
      const record: GmailTriageRecord = {
        gmailMessageId: messageId,
        userId,
        threadId: `th-${messageId}`,
        subject,
        sender: {
          raw: 'Security Team <security-alert@account-verify-support.com>',
          fromAddress: 'security-alert@account-verify-support.com',
          fromDomain: 'account-verify-support.com',
        },
        recipients: ['analyst@cybertrace-demo.com'],
        receivedAt: new Date().toISOString(),
        originatingIp: '198.51.100.77',
        authStatus: { spf: 'FAIL', dkim: 'FAIL', dmarc: 'FAIL' },
        mailClassification: {
          mailType: 'SPAM',
          confidence: 0.95,
          reasons: ['Suspicious origin IP', 'Phishing credential terminology detected'],
        },
        riskScore: 92,
        riskLevel,
        threatClassification: 'Credential Phishing Campaign',
        threatIndicators: {
          detected: { SPOOFED_SENDER: true, SUSPICIOUS_LINKS: true },
          reasons: ['External sender spoofing IT Security', 'Domain registered 2 days ago'],
          riskFactors: ['Suspicious links detected', 'Sender domain mismatch'],
        },
        extractedDomains: ['account-verify-support.com'],
        extractedUrls: ['https://login-portal.dark-credentials.org/login'],
        attachments: [],
        forensicSha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
        forensicMd5: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
        analyzedAt: new Date().toISOString(),
        triageStatus: 'PHISHING_OR_MALICIOUS',
      };
      triageRegistry.set(userId, messageId, record);
      return record;
    };

    // -------------------------------------------------------------------------
    // Test 1: Rejects promotion when user is not connected to Gmail
    // -------------------------------------------------------------------------
    console.log('Test 1: Verifying promotion rejection when user is not connected to Gmail...');
    await assert.rejects(
      async () => {
        await promotionService.promoteMessage('usr-unconnected-user', 'msg-threat-001');
      },
      (err: any) => {
        assert.ok(err instanceof GmailNotConnectedError);
        assert.strictEqual(err.statusCode, 404);
        assert.strictEqual(err.code, 'GMAIL_NOT_CONNECTED');
        return true;
      }
    );
    console.log('✔ Test 1 Passed: Unconnected user correctly rejected with 404 GMAIL_NOT_CONNECTED.\n');

    // -------------------------------------------------------------------------
    // Test 2: Rejects promotion when message has not been triaged
    // -------------------------------------------------------------------------
    console.log('Test 2: Verifying promotion rejection when message is not yet triaged...');
    await assert.rejects(
      async () => {
        await promotionService.promoteMessage(USER_ALICE, 'msg-untriaged-999');
      },
      (err: any) => {
        assert.ok(err instanceof GmailApiError);
        assert.strictEqual(err.statusCode, 400);
        assert.strictEqual(err.code, 'GMAIL_TRIAGE_REQUIRED');
        return true;
      }
    );
    console.log('✔ Test 2 Passed: Untriaged message rejected with 400 GMAIL_TRIAGE_REQUIRED.\n');

    // -------------------------------------------------------------------------
    // Test 3: Rejects promotion when userId or gmailMessageId is missing
    // -------------------------------------------------------------------------
    console.log('Test 3: Verifying promotion rejection on empty or invalid inputs...');
    await assert.rejects(
      async () => {
        await promotionService.promoteMessage('', 'msg-threat-001');
      },
      (err: any) => {
        assert.strictEqual(err.statusCode, 400);
        return true;
      }
    );
    await assert.rejects(
      async () => {
        await promotionService.promoteMessage(USER_ALICE, '   ');
      },
      (err: any) => {
        assert.strictEqual(err.statusCode, 400);
        return true;
      }
    );
    console.log('✔ Test 3 Passed: Invalid parameters rejected.\n');

    // -------------------------------------------------------------------------
    // Test 4: Successfully promotes triaged threat into formal DFIR case
    // -------------------------------------------------------------------------
    console.log('Test 4: Verifying successful promotion of triaged Gmail threat...');
    seedTriageRecord(USER_ALICE, 'msg-threat-001', 'URGENT: Corporate Access Expiring');

    const initialLedgerBlocks = evidenceLedger.getChain().length;
    const initialCases = caseService.getAllCases().length;

    const promoResult = await promotionService.promoteMessage(USER_ALICE, 'msg-threat-001', {
      name: 'Alice Analyst',
      email: 'alice.promoter@gmail.com',
    });

    assert.ok(promoResult);
    assert.strictEqual(promoResult.success, true);
    assert.strictEqual(promoResult.alreadyPromoted, false);
    assert.ok(promoResult.caseId.startsWith('CASE-'));
    assert.ok(promoResult.caseNumber.startsWith('CASE-'));
    assert.ok(promoResult.promotedAt);
    assert.ok(promoResult.caseRecord);
    assert.strictEqual(promoResult.caseRecord.ownerId, USER_ALICE);
    assert.strictEqual(promoResult.caseRecord.analyst, 'Alice Analyst');
    console.log(`✔ Test 4 Passed: Promoted to formal Case ${promoResult.caseId} (${promoResult.caseNumber}).\n`);

    // -------------------------------------------------------------------------
    // Test 5: Exact raw RFC-822 fidelity passed to caseService
    // -------------------------------------------------------------------------
    console.log('Test 5: Verifying exact raw RFC-822 fidelity preservation...');
    assert.strictEqual(lastFetchedRawEml, SAMPLE_PHISH_RFC822, 'Exact raw RFC-822 was retrieved');
    const casePayload = caseService.getCasePayload(promoResult.caseId);
    assert.ok(casePayload, 'Case payload must be accessible in caseService');
    assert.strictEqual(casePayload.evidence.rawSource, SAMPLE_PHISH_RFC822, 'Raw source in evidence must match unaltered RFC-822');
    console.log('✔ Test 5 Passed: 100% exact RFC-822 byte fidelity verified.\n');

    // -------------------------------------------------------------------------
    // Test 6: Correct case metadata and tagging assigned
    // -------------------------------------------------------------------------
    console.log('Test 6: Verifying formal case metadata and tags...');
    assert.ok(promoResult.caseRecord.title.includes('URGENT: Corporate Access Expiring'));
    assert.ok(['OPEN', 'ESCALATED', 'NEW'].includes(promoResult.caseRecord.status));
    assert.ok(promoResult.caseRecord.tags.includes('GMAIL-PROMOTED'));
    assert.ok(promoResult.caseRecord.tags.includes('CRITICAL'));
    assert.ok(promoResult.caseRecord.tags.includes('SPAM'));
    console.log(`✔ Test 6 Passed: Case metadata, status ${promoResult.caseRecord.status}, and forensic tags verified.\n`);

    // -------------------------------------------------------------------------
    // Test 7: Formal case record is persisted and accessible in caseService
    // -------------------------------------------------------------------------
    console.log('Test 7: Verifying case persistence in caseService...');
    const allCases = caseService.getAllCases();
    assert.strictEqual(allCases.length, initialCases + 1, 'Case count must have increased by 1');
    const retrievedCase = caseService.getCaseById(promoResult.caseId);
    assert.ok(retrievedCase, 'Case must be retrievable by ID');
    assert.strictEqual(retrievedCase.caseRecord.caseId, promoResult.caseId);
    console.log('✔ Test 7 Passed: Case verified in caseService registry.\n');

    // -------------------------------------------------------------------------
    // Test 8: Full forensic payload is generated (IOCs, Timeline, Graph)
    // -------------------------------------------------------------------------
    console.log('Test 8: Verifying complete forensic payload generation...');
    assert.ok(casePayload.headerAnalysis, 'Header analysis must exist');
    assert.ok(Array.isArray(casePayload.iocs), 'IOC array must exist');
    assert.ok(casePayload.iocs.length > 0, 'IOCs must have been extracted from raw email');
    assert.ok(casePayload.threatAssessment, 'Threat assessment must exist');
    assert.ok(casePayload.riskScore, 'Risk score must exist');
    assert.ok(Array.isArray(casePayload.attackTimeline), 'Attack timeline must exist');
    assert.ok(casePayload.attackTimeline.length > 0, 'Attack timeline events must be generated');
    console.log(`✔ Test 8 Passed: Complete forensic payload created with ${casePayload.iocs.length} IOCs and ${casePayload.attackTimeline.length} timeline events.\n`);

    // -------------------------------------------------------------------------
    // Test 9: Cryptographic Evidence Ledger entry created
    // -------------------------------------------------------------------------
    console.log('Test 9: Verifying cryptographic evidence ledger block creation...');
    const currentBlocks = evidenceLedger.getChain().length;
    assert.strictEqual(currentBlocks, initialLedgerBlocks + 1, 'Exactly one block must be appended to evidence ledger');
    const chain = evidenceLedger.getChain();
    const latestBlock = chain[chain.length - 1];
    assert.strictEqual(latestBlock.caseId, promoResult.caseId);
    assert.ok(latestBlock.emailSha256);
    assert.ok(latestBlock.analysisSha256);
    assert.ok(latestBlock.blockHash);
    assert.ok(latestBlock.prevBlockHash);
    console.log(`✔ Test 9 Passed: Evidence Ledger Block #${latestBlock.blockIndex} sealed with SHA-256.\n`);

    // -------------------------------------------------------------------------
    // Test 10: Evidence Ledger cryptographic chain integrity verified
    // -------------------------------------------------------------------------
    console.log('Test 10: Verifying blockchain ledger integrity...');
    const verification = evidenceLedger.verifyIntegrity();
    assert.strictEqual(verification.isValid, true, 'Blockchain integrity must be 100% valid');
    assert.strictEqual(verification.invalidBlockIndex, undefined);
    console.log('✔ Test 10 Passed: Blockchain ledger verification passed (isValid: true).\n');

    // -------------------------------------------------------------------------
    // Test 11: Idempotency on repeated promotion clicks
    // -------------------------------------------------------------------------
    console.log('Test 11: Verifying idempotency on duplicate promotion calls...');
    const ledgerBeforeSecondCall = evidenceLedger.getChain().length;
    const casesBeforeSecondCall = caseService.getAllCases().length;
    const fetchCallsBeforeSecondCall = rawFetchCalls;

    const repeatPromo = await promotionService.promoteMessage(USER_ALICE, 'msg-threat-001', {
      name: 'Alice Analyst',
      email: 'alice.promoter@gmail.com',
    });

    assert.strictEqual(repeatPromo.success, true);
    assert.strictEqual(repeatPromo.alreadyPromoted, true, 'Repeat call must indicate alreadyPromoted: true');
    assert.strictEqual(repeatPromo.caseId, promoResult.caseId, 'Must return identical caseId');
    assert.strictEqual(repeatPromo.caseNumber, promoResult.caseNumber, 'Must return identical caseNumber');
    assert.strictEqual(evidenceLedger.getChain().length, ledgerBeforeSecondCall, 'No duplicate evidence block created');
    assert.strictEqual(caseService.getAllCases().length, casesBeforeSecondCall, 'No duplicate case record created');
    assert.strictEqual(rawFetchCalls, fetchCallsBeforeSecondCall, 'Gmail API not called again on idempotent hit');
    console.log('✔ Test 11 Passed: Idempotency verified. Zero duplicate cases or ledger blocks created.\n');

    // -------------------------------------------------------------------------
    // Test 12: Per-message concurrency lock prevents race condition
    // -------------------------------------------------------------------------
    console.log('Test 12: Verifying per-message promotion concurrency lock (409 Conflict)...');
    seedTriageRecord(USER_ALICE, 'msg-concurrency-test', 'Concurrent Email Test');

    // Artificially acquire the lock
    (promotionService as any).activePromotions.add(`${USER_ALICE}:msg-concurrency-test`);

    await assert.rejects(
      async () => {
        await promotionService.promoteMessage(USER_ALICE, 'msg-concurrency-test');
      },
      (err: any) => {
        assert.ok(err instanceof GmailApiError);
        assert.strictEqual(err.statusCode, 409);
        assert.strictEqual(err.code, 'GMAIL_PROMOTION_IN_PROGRESS');
        return true;
      }
    );

    // Release artificial lock
    (promotionService as any).activePromotions.delete(`${USER_ALICE}:msg-concurrency-test`);
    console.log('✔ Test 12 Passed: Concurrency lock successfully triggered 409 GMAIL_PROMOTION_IN_PROGRESS.\n');

    // -------------------------------------------------------------------------
    // Test 13: Multi-tenant isolation - User B cannot promote User A's triaged message
    // -------------------------------------------------------------------------
    console.log('Test 13: Verifying multi-tenant isolation across users...');
    oauthService._setConnectionForTest(USER_BOB, {
      userId: USER_BOB,
      gmailEmail: 'bob.promoter@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.bob-promo-token',
      refreshToken: '1//bob-promo-refresh',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    // User B tries to promote User A's message (which was only triaged in User A's registry)
    await assert.rejects(
      async () => {
        await promotionService.promoteMessage(USER_BOB, 'msg-threat-001');
      },
      (err: any) => {
        assert.ok(err instanceof GmailApiError);
        assert.strictEqual(err.statusCode, 400);
        assert.strictEqual(err.code, 'GMAIL_TRIAGE_REQUIRED');
        return true;
      }
    );
    console.log('✔ Test 13 Passed: Cross-tenant promotion blocked. User B cannot access User A triage registry.\n');

    // -------------------------------------------------------------------------
    // Test 14: Multi-tenant isolation - User B promoting their own message creates distinct case
    // -------------------------------------------------------------------------
    console.log('Test 14: Verifying separate tenant case ownership for User B...');
    seedTriageRecord(USER_BOB, 'msg-threat-bob-1', 'Bob Phishing Incident');

    const bobPromo = await promotionService.promoteMessage(USER_BOB, 'msg-threat-bob-1', {
      name: 'Bob Analyst',
      email: 'bob.promoter@gmail.com',
    });

    assert.ok(bobPromo.success);
    assert.notStrictEqual(bobPromo.caseId, promoResult.caseId);
    assert.strictEqual(bobPromo.caseRecord.ownerId, USER_BOB);
    assert.strictEqual(bobPromo.caseRecord.analyst, 'Bob Analyst');
    console.log('✔ Test 14 Passed: User B created independent case with strict tenant isolation.\n');

    // -------------------------------------------------------------------------
    // Test 15: Zero OAuth token or secret leakage in responses or cases
    // -------------------------------------------------------------------------
    console.log('Test 15: Verifying zero OAuth token leakage in promotion responses and cases...');
    const serializedAlicePromo = JSON.stringify(promoResult);
    const serializedBobPromo = JSON.stringify(bobPromo);
    const serializedCase = JSON.stringify(casePayload);

    const secrets = [
      'ya29.alice-promo-access-token',
      '1//alice-promo-refresh-token',
      'ya29.bob-promo-token',
      '1//bob-promo-refresh',
      'test-promotion-secret',
    ];

    for (const secret of secrets) {
      assert.ok(!serializedAlicePromo.includes(secret), `Response must not contain '${secret}'`);
      assert.ok(!serializedBobPromo.includes(secret), `Response must not contain '${secret}'`);
      assert.ok(!serializedCase.includes(secret), `Stored Case payload must not contain '${secret}'`);
    }
    console.log('✔ Test 15 Passed: Token shielding verified across all structures.\n');

    // -------------------------------------------------------------------------
    // Test 16: Zero raw MIME string leakage in promotion response
    // -------------------------------------------------------------------------
    console.log('Test 16: Verifying promotion response does not leak raw RFC-822 MIME body...');
    assert.strictEqual((promoResult as any).rawEml, undefined, 'rawEml must not exist on GmailPromotionResponse');
    assert.strictEqual((promoResult as any).raw, undefined, 'raw must not exist on GmailPromotionResponse');
    assert.strictEqual((promoResult.caseRecord as any).rawMime, undefined, 'caseRecord summary must omit rawMime');
    console.log('✔ Test 16 Passed: Promotion response strictly returns sanitized metadata.\n');

    // -------------------------------------------------------------------------
    // Test 17: Zero Gemini API calls made by promotion service layer
    // -------------------------------------------------------------------------
    console.log('Test 17: Verifying zero Gemini API dependency in promotion service...');
    assert.strictEqual(process.env.GEMINI_API_KEY, undefined, 'GEMINI_API_KEY must be unset');
    // Case creation succeeded and generated valid analysis without throwing Gemini missing key error
    assert.ok(casePayload.threatAssessment.classification);
    assert.ok(Array.isArray(casePayload.threatAssessment.reasons));
    console.log('✔ Test 17 Passed: 100% deterministic operation without required external Gemini connection.\n');

    // -------------------------------------------------------------------------
    // Test 18: Upstream Gmail API error handled cleanly
    // -------------------------------------------------------------------------
    console.log('Test 18: Verifying upstream Gmail API error handling during promotion...');
    seedTriageRecord(USER_ALICE, 'msg-api-error', 'Server Error Test');

    await assert.rejects(
      async () => {
        await promotionService.promoteMessage(USER_ALICE, 'msg-api-error');
      },
      (err: any) => {
        assert.ok(err.message.includes('Gmail API') || err.message.includes('500'));
        return true;
      }
    );
    console.log('✔ Test 18 Passed: Upstream Gmail API failure handled gracefully.\n');

    // -------------------------------------------------------------------------
    // Test 19: Multiple distinct triaged messages promote to distinct sequential cases
    // -------------------------------------------------------------------------
    console.log('Test 19: Verifying multiple message promotions produce distinct sequential cases...');
    seedTriageRecord(USER_ALICE, 'msg-threat-002', 'Immediate Direct Deposit Form Update');

    const promoSecond = await promotionService.promoteMessage(USER_ALICE, 'msg-threat-002', {
      name: 'Alice Analyst',
      email: 'alice.promoter@gmail.com',
    });

    assert.ok(promoSecond.success);
    assert.notStrictEqual(promoSecond.caseId, promoResult.caseId);
    assert.notStrictEqual(promoSecond.caseNumber, promoResult.caseNumber);
    console.log(`✔ Test 19 Passed: Multiple messages promote cleanly (${promoResult.caseNumber} vs ${promoSecond.caseNumber}).\n`);

    // -------------------------------------------------------------------------
    // Test 20: Promotion registry tracks records and supports getPromotionStatus
    // -------------------------------------------------------------------------
    console.log('Test 20: Verifying promotion registry status inspection...');
    const status1 = promotionService.getPromotionStatus(USER_ALICE, 'msg-threat-001');
    assert.ok(status1);
    assert.strictEqual(status1.caseId, promoResult.caseId);
    assert.strictEqual(status1.gmailMessageId, 'msg-threat-001');

    const statusUnknown = promotionService.getPromotionStatus(USER_ALICE, 'msg-never-promoted');
    assert.strictEqual(statusUnknown, undefined);

    const userAlicePromos = promotionRegistry.getAllForUser(USER_ALICE);
    assert.ok(userAlicePromos.length >= 2, 'User Alice must have at least 2 promoted records');
    console.log(`✔ Test 20 Passed: Registry correctly tracks ${userAlicePromos.length} promoted records for user.\n`);

    // -------------------------------------------------------------------------
    // Test 21: Case status lifecycle updates on promoted case
    // -------------------------------------------------------------------------
    console.log('Test 21: Verifying case status transitions on promoted case...');
    const updateSuccess = caseService.updateCaseStatus(promoResult.caseId, 'IN_PROGRESS', 'Alice Analyst');
    assert.strictEqual(updateSuccess, true, 'Case status update must succeed');

    const updatedCase = caseService.getCaseById(promoResult.caseId);
    assert.strictEqual(updatedCase?.caseRecord.status, 'IN_PROGRESS', 'Case status must be updated to IN_PROGRESS');
    console.log('✔ Test 21 Passed: Promoted case seamlessly participates in caseService lifecycle.\n');

    console.log('================================================================');
    console.log('ALL 21 GMAIL CASE PROMOTION TESTS PASSED (100%)');
    console.log('================================================================\n');
  } finally {
    process.env = originalEnv;
  }
}

runTests().catch(err => {
  console.error('Test failure:', err);
  process.exit(1);
});
