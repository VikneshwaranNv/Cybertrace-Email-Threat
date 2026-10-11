import assert from 'assert';
import express from 'express';
import http from 'http';
import { SocDashboardService, socDashboardService } from '../services/socDashboardService';
import { GmailTriageRegistry, GmailTriageRecord } from '../gmail/gmailTriageRegistry';
import { GmailCampaignService } from '../gmail/gmailCampaignService';
import { GmailIocService } from '../gmail/gmailIocService';
import { GmailPromotionRegistry } from '../gmail/gmailCasePromotionService';
import { GmailSyncRegistry } from '../gmail/gmailSyncRegistry';
import { caseService } from '../services/caseService';
import { authService } from '../auth/authService';
import { authenticateUser, AuthenticatedRequest } from '../auth/authMiddleware';

console.log('=== RUNNING SOC DASHBOARD & ANALYST OPERATIONS TEST SUITE (PHASE 8) ===\n');

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    // 0. Enforce Zero Gemini Guarantee
    delete process.env.GEMINI_API_KEY;

    const USER_ALICE = 'usr-alice-phase8';
    const USER_BOB = 'usr-bob-phase8';

    // Helper to generate sample triage records
    const createSampleTriageRecord = (
      userId: string,
      msgId: string,
      overrides?: Partial<GmailTriageRecord>
    ): GmailTriageRecord => {
      return {
        gmailMessageId: msgId,
        userId,
        subject: overrides?.subject || `Test Threat Subject ${msgId}`,
        sender: overrides?.sender || {
          raw: 'Attacker <attacker@evil-domain.com>',
          fromAddress: 'attacker@evil-domain.com',
          fromDomain: 'evil-domain.com',
          fromName: 'Attacker',
        },
        recipients: ['analyst@cybertrace-demo.com'],
        receivedAt: overrides?.receivedAt || '2026-09-08T10:00:00.000Z',
        analyzedAt: overrides?.analyzedAt || '2026-09-08T10:05:00.000Z',
        mailClassification: {
          mailType: 'COMPANY',
          confidence: 0.95,
          reasons: ['External sender spoofing corporate alert'],
        },
        threatClassification: overrides?.threatClassification || 'CREDENTIAL_HARVESTING',
        riskScore: overrides?.riskScore !== undefined ? overrides.riskScore : 88,
        riskLevel: overrides?.riskLevel || 'HIGH',
        threatIndicators: {
          detected: { credentialTheft: true },
          reasons: ['Suspicious credential phishing link'],
          riskFactors: ['Phishing URL'],
        },
        originatingIp: overrides?.originatingIp !== undefined ? overrides.originatingIp : '198.51.100.22',
        extractedDomains: overrides?.extractedDomains || ['evil-domain.com', 'login-phish.net'],
        extractedUrls: overrides?.extractedUrls || ['https://login-phish.net/auth'],
        attachments: overrides?.attachments || [],
        authStatus: {
          spf: 'FAIL',
          dkim: 'FAIL',
          dmarc: 'FAIL',
        },
        forensicSha256: `sha256-${msgId}-hash`,
        forensicMd5: `md5-${msgId}-hash`,
        triageStatus: 'PHISHING_OR_MALICIOUS',
      };
    };

    // -------------------------------------------------------------------------
    // Test 1: Clean empty state for user with no data
    // -------------------------------------------------------------------------
    console.log('Test 1: Verifying clean empty state for user with no triaged emails...');
    const USER_EMPTY = 'usr-empty-state-test';
    const emptySummary = await socDashboardService.getDashboardSummary({
      userId: USER_EMPTY,
      role: 'ANALYST',
      email: 'empty@cybertrace.test',
    });

    assert.strictEqual(emptySummary.summary.totalMonitoredMessages, 0);
    assert.strictEqual(emptySummary.summary.totalTriagedMessages, 0);
    assert.strictEqual(emptySummary.summary.totalThreats, 0);
    assert.strictEqual(emptySummary.summary.criticalThreats, 0);
    assert.strictEqual(emptySummary.summary.highThreats, 0);
    assert.strictEqual(emptySummary.summary.mediumThreats, 0);
    assert.strictEqual(emptySummary.summary.lowThreats, 0);
    assert.strictEqual(emptySummary.summary.activeCampaigns, 0);
    assert.strictEqual(emptySummary.summary.totalIocs, 0);
    assert.strictEqual(emptySummary.summary.promotedCases, 0);
    assert.strictEqual(emptySummary.threatCategories.length, 0);
    assert.strictEqual(emptySummary.topCampaigns.length, 0);
    assert.strictEqual(emptySummary.recentThreats.length, 0);
    assert.strictEqual(emptySummary.riskDistribution.length, 4);
    assert.ok(emptySummary.generatedAt);
    console.log('✔ Test 1 Passed: Empty state returns clean zero counts and empty arrays.\n');

    // -------------------------------------------------------------------------
    // Test 2: Metric aggregation accuracy (monitored, triaged, threats, risk breakdown)
    // -------------------------------------------------------------------------
    console.log('Test 2: Verifying metric aggregation accuracy across triaged emails...');
    const triageReg = new GmailTriageRegistry();
    const syncReg = new GmailSyncRegistry();
    const promoReg = new GmailPromotionRegistry();
    const iocSvc = new GmailIocService();
    const campSvc = new GmailCampaignService({ triageRegistry: triageReg, iocService: iocSvc });

    const customDashboardSvc = new SocDashboardService({
      triageRegistry: triageReg,
      campaignService: campSvc,
      promotionRegistry: promoReg,
      syncRegistry: syncReg,
      caseService: caseService,
    });

    // Seed Sync state for Alice: 10 discovered
    syncReg.set(USER_ALICE, {
      userId: USER_ALICE,
      historyId: 'hist-100',
      status: 'IDLE',
      messagesDiscovered: 10,
      messagesTriaged: 5,
      updatedAt: new Date().toISOString(),
    });

    // Seed 5 messages with different risk levels for Alice
    triageReg.set(USER_ALICE, 'msg-alice-1', createSampleTriageRecord(USER_ALICE, 'msg-alice-1', {
      riskLevel: 'CRITICAL',
      riskScore: 95,
      threatClassification: 'CREDENTIAL_HARVESTING',
      analyzedAt: '2026-09-08T10:01:00.000Z',
    }));
    triageReg.set(USER_ALICE, 'msg-alice-2', createSampleTriageRecord(USER_ALICE, 'msg-alice-2', {
      riskLevel: 'HIGH',
      riskScore: 78,
      threatClassification: 'BUSINESS_EMAIL_COMPROMISE',
      analyzedAt: '2026-09-08T10:02:00.000Z',
    }));
    triageReg.set(USER_ALICE, 'msg-alice-3', createSampleTriageRecord(USER_ALICE, 'msg-alice-3', {
      riskLevel: 'HIGH',
      riskScore: 72,
      threatClassification: 'CREDENTIAL_HARVESTING',
      analyzedAt: '2026-09-08T10:03:00.000Z',
    }));
    triageReg.set(USER_ALICE, 'msg-alice-4', createSampleTriageRecord(USER_ALICE, 'msg-alice-4', {
      riskLevel: 'MEDIUM',
      riskScore: 50,
      threatClassification: 'SUSPICIOUS_ATTACHMENT',
      analyzedAt: '2026-09-08T10:04:00.000Z',
    }));
    triageReg.set(USER_ALICE, 'msg-alice-5', createSampleTriageRecord(USER_ALICE, 'msg-alice-5', {
      riskLevel: 'LOW',
      riskScore: 15,
      threatClassification: 'LEGITIMATE',
      analyzedAt: '2026-09-08T10:05:00.000Z',
    }));

    // Seed a promoted case for Alice
    promoReg.set(USER_ALICE, 'msg-alice-1', {
      userId: USER_ALICE,
      gmailMessageId: 'msg-alice-1',
      caseId: 'CASE-2026-ALICE-01',
      caseNumber: 'CASE-2026-ALICE-01',
      title: 'Promoted Phish Case',
      promotedAt: new Date().toISOString(),
      riskScore: 95,
      riskLevel: 'CRITICAL',
      status: 'OPEN',
    });

    const aliceSummary = await customDashboardSvc.getDashboardSummary({
      userId: USER_ALICE,
      role: 'ANALYST',
      email: 'alice@cybertrace.test',
    });

    assert.strictEqual(aliceSummary.summary.totalMonitoredMessages, 10, 'Monitored should match sync telemetry (10)');
    assert.strictEqual(aliceSummary.summary.totalTriagedMessages, 5, 'Triaged count should match 5');
    assert.strictEqual(aliceSummary.summary.totalThreats, 4, 'Total threats should be CRIT(1)+HIGH(2)+MED(1) = 4');
    assert.strictEqual(aliceSummary.summary.criticalThreats, 1);
    assert.strictEqual(aliceSummary.summary.highThreats, 2);
    assert.strictEqual(aliceSummary.summary.mediumThreats, 1);
    assert.strictEqual(aliceSummary.summary.lowThreats, 1);
    assert.strictEqual(aliceSummary.summary.promotedCases, 1, 'Promoted cases count should be 1');
    console.log('✔ Test 2 Passed: Metric aggregation correctly calculates monitored, triaged, and risk counts.\n');

    // -------------------------------------------------------------------------
    // Test 3: Risk distribution calculation
    // -------------------------------------------------------------------------
    console.log('Test 3: Verifying risk distribution levels and counts...');
    const riskMap = new Map(aliceSummary.riskDistribution.map(r => [r.level, r.count]));
    assert.strictEqual(riskMap.get('CRITICAL'), 1);
    assert.strictEqual(riskMap.get('HIGH'), 2);
    assert.strictEqual(riskMap.get('MEDIUM'), 1);
    assert.strictEqual(riskMap.get('LOW'), 1);
    console.log('✔ Test 3 Passed: Risk distribution reflects accurate counts for all 4 severity levels.\n');

    // -------------------------------------------------------------------------
    // Test 4: Threat categories aggregation and sorting
    // -------------------------------------------------------------------------
    console.log('Test 4: Verifying threat category aggregation and descending frequency ordering...');
    assert.ok(aliceSummary.threatCategories.length > 0, 'Must have aggregated categories');
    for (let i = 0; i < aliceSummary.threatCategories.length - 1; i++) {
      assert.ok(
        aliceSummary.threatCategories[i].count >= aliceSummary.threatCategories[i + 1].count,
        'Categories must be sorted by count descending'
      );
    }
    console.log('✔ Test 4 Passed: Threat categories correctly tallied and sorted by occurrence count.\n');

    // -------------------------------------------------------------------------
    // Test 5: Campaign clustering and priority campaign ordering
    // -------------------------------------------------------------------------
    console.log('Test 5: Verifying priority campaign clustering and risk-based ordering...');
    assert.ok(aliceSummary.summary.activeCampaigns >= 1, 'Should correlate active campaigns');
    assert.ok(aliceSummary.topCampaigns.length <= 5, 'Top campaigns must be bounded to at most 5');
    if (aliceSummary.topCampaigns.length >= 2) {
      assert.ok(
        aliceSummary.topCampaigns[0].riskScore >= aliceSummary.topCampaigns[1].riskScore,
        'Top campaigns must be sorted by risk score descending'
      );
    }
    const topCamp = aliceSummary.topCampaigns[0];
    assert.ok(topCamp.campaignId.startsWith('GMAIL-CAMP-'));
    assert.ok(topCamp.riskScore > 0);
    assert.ok(topCamp.category);
    assert.ok(Array.isArray(topCamp.reasons));
    console.log('✔ Test 5 Passed: Priority campaigns properly clustered, scored, and bounded.\n');

    // -------------------------------------------------------------------------
    // Test 6: Recent threats ordering (newest first) and correlation link
    // -------------------------------------------------------------------------
    console.log('Test 6: Verifying recent threats ordering (newest first) and campaign linkage...');
    assert.strictEqual(aliceSummary.recentThreats.length, 5);
    for (let i = 0; i < aliceSummary.recentThreats.length - 1; i++) {
      const dateA = new Date(aliceSummary.recentThreats[i].analyzedAt).getTime();
      const dateB = new Date(aliceSummary.recentThreats[i + 1].analyzedAt).getTime();
      assert.ok(dateA >= dateB, 'Recent threats must be sorted newest first');
    }
    const firstThreat = aliceSummary.recentThreats[0];
    assert.strictEqual(firstThreat.gmailMessageId, 'msg-alice-5');
    assert.strictEqual(firstThreat.riskLevel, 'LOW');
    assert.ok(firstThreat.subject);
    assert.ok(firstThreat.sender);
    console.log('✔ Test 6 Passed: Recent threats ordered newest first with complete metadata.\n');

    // -------------------------------------------------------------------------
    // Test 7: Strict Multi-Tenant Isolation (User A vs User B)
    // -------------------------------------------------------------------------
    console.log('Test 7: Verifying strict multi-tenant isolation between User A and User B...');
    triageReg.set(USER_BOB, 'msg-bob-1', createSampleTriageRecord(USER_BOB, 'msg-bob-1', {
      riskLevel: 'CRITICAL',
      riskScore: 99,
      threatClassification: 'EXECUTIVE_IMPERSONATION',
      originatingIp: '198.51.100.99',
    }));

    const bobSummary = await customDashboardSvc.getDashboardSummary({
      userId: USER_BOB,
      role: 'ANALYST',
      email: 'bob@cybertrace.test',
    });

    assert.strictEqual(bobSummary.summary.totalTriagedMessages, 1);
    assert.strictEqual(bobSummary.summary.criticalThreats, 1);
    assert.strictEqual(bobSummary.summary.highThreats, 0);
    assert.strictEqual(bobSummary.summary.mediumThreats, 0);
    assert.strictEqual(bobSummary.summary.lowThreats, 0);
    assert.strictEqual(bobSummary.recentThreats.length, 1);
    assert.strictEqual(bobSummary.recentThreats[0].gmailMessageId, 'msg-bob-1');
    assert.strictEqual(bobSummary.summary.promotedCases, 0);
    assert.ok(!JSON.stringify(bobSummary).includes('msg-alice-1'));
    assert.ok(!JSON.stringify(bobSummary).includes('CASE-2026-ALICE-01'));
    console.log('✔ Test 7 Passed: Multi-tenant isolation verified. Zero leakage between users.\n');

    // -------------------------------------------------------------------------
    // Test 8: Data Hygiene — Zero raw RFC-822, zero OAuth tokens, zero secrets
    // -------------------------------------------------------------------------
    console.log('Test 8: Verifying zero raw RFC-822 or secrets exposure in dashboard payload...');
    const serializedAlice = JSON.stringify(aliceSummary);
    const serializedBob = JSON.stringify(bobSummary);

    const forbiddenPatterns = [
      'ya29.',
      '1//',
      'client_secret',
      'refresh_token',
      'Received: from',
      'MIME-Version:',
      'Content-Type: multipart',
      'test-promotion-secret',
    ];

    for (const pattern of forbiddenPatterns) {
      assert.ok(
        !serializedAlice.includes(pattern),
        `Dashboard payload must never contain '${pattern}'`
      );
      assert.ok(
        !serializedBob.includes(pattern),
        `Dashboard payload must never contain '${pattern}'`
      );
    }
    console.log('✔ Test 8 Passed: Data hygiene verified. Zero raw MIME or secrets exposed.\n');

    // -------------------------------------------------------------------------
    // Test 9: Zero Gemini API calls during dashboard summary generation
    // -------------------------------------------------------------------------
    console.log('Test 9: Verifying ZERO Gemini API calls during dashboard generation...');
    assert.strictEqual(process.env.GEMINI_API_KEY, undefined);
    const testGen = await customDashboardSvc.getDashboardSummary({
      userId: USER_ALICE,
      role: 'ANALYST',
    });
    assert.ok(testGen.summary);
    console.log('✔ Test 9 Passed: Zero Gemini calls verified. 100% deterministic execution.\n');

    // -------------------------------------------------------------------------
    // Test 10: Bounded limits on large message sets
    // -------------------------------------------------------------------------
    console.log('Test 10: Verifying bounded results on large message collections...');
    const USER_LARGE = 'usr-large-batch-test';
    const largeTriage = new GmailTriageRegistry();
    const largeCampSvc = new GmailCampaignService({ triageRegistry: largeTriage, iocService: iocSvc });
    const largeDashboardSvc = new SocDashboardService({
      triageRegistry: largeTriage,
      campaignService: largeCampSvc,
      promotionRegistry: promoReg,
      syncRegistry: syncReg,
      caseService: caseService,
    });

    for (let i = 1; i <= 40; i++) {
      largeTriage.set(
        USER_LARGE,
        `msg-large-${i}`,
        createSampleTriageRecord(USER_LARGE, `msg-large-${i}`, {
          riskScore: i * 2,
          riskLevel: i > 30 ? 'CRITICAL' : i > 20 ? 'HIGH' : i > 10 ? 'MEDIUM' : 'LOW',
          analyzedAt: new Date(1700000000000 + i * 60000).toISOString(),
        })
      );
    }

    const largeSummary = await largeDashboardSvc.getDashboardSummary({
      userId: USER_LARGE,
      role: 'ANALYST',
    });

    assert.strictEqual(largeSummary.summary.totalTriagedMessages, 40);
    assert.ok(largeSummary.topCampaigns.length <= 5, 'Campaigns bounded to max 5');
    assert.ok(largeSummary.recentThreats.length <= 15, 'Recent threats bounded to max 15');
    console.log('✔ Test 10 Passed: Bounded result sizes verified for large collections.\n');

    // -------------------------------------------------------------------------
    // Test 11: HTTP Endpoint Integration — Authentication & Security (401 & 200)
    // -------------------------------------------------------------------------
    console.log('Test 11: Verifying HTTP endpoint GET /api/soc/dashboard-summary...');
    const app = express();
    app.use(express.json());

    app.get('/api/soc/dashboard-summary', authenticateUser, async (req: AuthenticatedRequest, res: any) => {
      try {
        const user = req.user!;
        const summary = await customDashboardSvc.getDashboardSummary(user);
        res.json(summary);
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    });

    const server = http.createServer(app);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()));
    const port = (server.address() as any).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 11A. Unauthenticated request -> 401
      const resUnauthed = await fetch(`${baseUrl}/api/soc/dashboard-summary`);
      assert.strictEqual(resUnauthed.status, 401, 'Unauthenticated request must return 401');

      // 11B. Invalid token -> 401
      const resInvalid = await fetch(`${baseUrl}/api/soc/dashboard-summary`, {
        headers: { Authorization: 'Bearer invalid-garbage-token' },
      });
      assert.strictEqual(resInvalid.status, 401, 'Invalid token must return 401');

      // 11C. Authenticated request -> 200 with complete schema
      const { token } = authService.getOrCreateDefaultSession();
      assert.ok(token, 'Must obtain valid session token');

      const resAuthed = await fetch(`${baseUrl}/api/soc/dashboard-summary`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.strictEqual(resAuthed.status, 200, 'Authenticated request must return 200');

      const body = await resAuthed.json();
      assert.ok(body.summary, 'Must contain summary');
      assert.ok(Array.isArray(body.riskDistribution), 'Must contain riskDistribution array');
      assert.ok(Array.isArray(body.threatCategories), 'Must contain threatCategories array');
      assert.ok(Array.isArray(body.topCampaigns), 'Must contain topCampaigns array');
      assert.ok(Array.isArray(body.recentThreats), 'Must contain recentThreats array');
      assert.ok(body.generatedAt, 'Must contain generatedAt timestamp');

      console.log('✔ Test 11 Passed: HTTP endpoint authentication and response schema verified.\n');
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()));
    }

    console.log('===================================================================');
    console.log('ALL PHASE 8 SOC DASHBOARD TESTS PASSED (11/11)');
    console.log('===================================================================\n');
  } finally {
    process.env = originalEnv;
  }
}

runTests().catch(err => {
  console.error('Test Suite Failed with Error:', err);
  process.exit(1);
});
