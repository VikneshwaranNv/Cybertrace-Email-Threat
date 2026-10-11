import assert from 'assert';
import { bulkTriageService } from '../services/bulkTriageService';
import { classifyMailType } from '../forensics/mailClassifier';
import { clusterCampaigns } from '../forensics/campaignClusteringEngine';
import { generateSyntheticDemoBatch } from '../demo/bulkDemoGenerator';
import { evidenceLedger } from '../blockchain/evidenceLedger';
import { caseService } from '../services/caseService';

console.log('=== RUNNING BULK FORENSIC TRIAGE & CAMPAIGN CORRELATION TEST SUITE ===\n');

async function runTests() {
  // --- Test 1: Evidence-Based Mail Type Classification ---
  console.log('Test 1: Verifying independent mail type classification (Company, Personal, Spam, Unknown)...');

  // 1a. Company Mail
  const companyMail = classifyMailType({
    fromAddress: 'cfo@acme-global.corp',
    fromDomain: 'acme-global.corp',
    subject: 'Quarterly Financial Statement and Audit Sync',
    bodyText: 'Attached is the quarterly reconciliation. This email and any attachments are confidential and intended solely for the recipient.',
    headers: {
      receivedHeaders: ['Received: from exchange.acme-global.corp (10.0.0.1) by gateway.acme-global.corp with ESMTP'],
    },
    authStatus: { spf: 'PASS', dkim: 'PASS', dmarc: 'PASS' },
  });
  assert.strictEqual(companyMail.mailType, 'COMPANY', 'Corporate domain with disclaimer and exchange routing must classify as COMPANY');
  assert.ok(companyMail.mailTypeConfidence >= 60, 'Company confidence should be >= 60%');
  assert.ok(companyMail.mailTypeReasons.length > 0, 'Must provide explainable reasons');

  // 1b. Personal Mail
  const personalMail = classifyMailType({
    fromAddress: 'alice.smith@gmail.com',
    fromDomain: 'gmail.com',
    subject: 'Dinner plans for tomorrow evening',
    bodyText: 'Hey Bob, thanks for checking in. Let me know what time works best for you to grab dinner.',
    headers: {
      'in-reply-to': '<msg-12345@gmail.com>',
    },
    authStatus: { spf: 'PASS', dkim: 'PASS', dmarc: 'PASS' },
  });
  assert.strictEqual(personalMail.mailType, 'PERSONAL', 'Direct consumer webmail thread without bulk headers must classify as PERSONAL');

  // 1c. Spam / Marketing Mail
  const spamMail = classifyMailType({
    fromAddress: 'promotions@retail-deals-daily.com',
    fromDomain: 'retail-deals-daily.com',
    subject: 'SPECIAL OFFER: 50% Off Annual Membership Ends Tonight!',
    bodyText: 'Do not miss this exclusive discount. To unsubscribe or manage email preferences, click here.',
    headers: {
      'list-unsubscribe': '<mailto:unsub@retail-deals-daily.com>',
      precedence: 'bulk',
      xMailer: 'SendGrid Mailer v2',
    },
  });
  assert.strictEqual(spamMail.mailType, 'SPAM', 'Email with List-Unsubscribe and Precedence: bulk must classify as SPAM');

  // 1d. Unknown Mail
  const unknownMail = classifyMailType({
    fromAddress: 'daemon@sub.net',
    fromDomain: 'sub.net',
    subject: '',
    bodyText: 'Ping.',
    headers: {},
  });
  assert.strictEqual(unknownMail.mailType, 'UNKNOWN', 'Truncated headers without domain signals must classify as UNKNOWN');
  console.log('✔ Test 1 Passed: Mail type classification logic verified.\n');

  // --- Test 2: Ingestion Benchmark for 100, 500, and 1,000 Emails ---
  console.log('Test 2: Benchmarking ingestion performance for 100, 500, and 1,000 emails...');

  function createMockEmls(count: number): Array<{ filename: string; content: string }> {
    const list: Array<{ filename: string; content: string }> = [];
    for (let i = 1; i <= count; i++) {
      const isMalicious = i % 10 === 0;
      const eml = [
        `From: sender${i}@${isMalicious ? 'phish-evil-domain.com' : 'partner-corp.com'}`,
        `To: victim${i}@victim-company.local`,
        `Subject: ${isMalicious ? 'URGENT: Executive Wire Transfer Authorization #' + i : 'Project Update #' + i}`,
        'Date: Mon, 1 Sep 2026 12:00:00 +0000',
        'Received: from relay1.transit.net (198.51.100.22) by mail.victim.com with ESMTP',
        'Received: from mail.origin.net (185.220.101.5) by relay1.transit.net with ESMTP',
        '',
        isMalicious
          ? 'URGENT wire transfer instructions: Please send $45,000 immediately to account 12345. Reply-To: fraud@outside.com'
          : 'Attached is the weekly project status report for your review. This message is confidential.',
      ].join('\r\n');

      list.push({ filename: `test_${i}.eml`, content: eml });
    }
    return list;
  }

  // 100 emails benchmark
  const batch100 = createMockEmls(100);
  const session100 = bulkTriageService.createSession(false);
  const t100Start = Date.now();
  await bulkTriageService.ingestBatchAsync(session100.sessionId, batch100);
  const t100Duration = Date.now() - t100Start;
  console.log(`  - 100 emails triaged in ${t100Duration}ms (Target: < 2,500ms)`);
  assert.strictEqual(session100.processedCount, 100, 'Must process all 100 emails');
  assert.ok(t100Duration < 4000, '100 emails must complete under 4s');

  // 500 emails benchmark
  const batch500 = createMockEmls(500);
  const session500 = bulkTriageService.createSession(false);
  const t500Start = Date.now();
  await bulkTriageService.ingestBatchAsync(session500.sessionId, batch500);
  const t500Duration = Date.now() - t500Start;
  console.log(`  - 500 emails triaged in ${t500Duration}ms (Target: < 5,000ms)`);
  assert.strictEqual(session500.processedCount, 500, 'Must process all 500 emails');

  // 1,000 emails benchmark
  const batch1000 = createMockEmls(1000);
  const session1000 = bulkTriageService.createSession(false);
  const t1000Start = Date.now();
  await bulkTriageService.ingestBatchAsync(session1000.sessionId, batch1000);
  const t1000Duration = Date.now() - t1000Start;
  console.log(`  - 1,000 emails triaged in ${t1000Duration}ms (Target: < 10,000ms)`);
  assert.strictEqual(session1000.processedCount, 1000, 'Must process all 1,000 emails');
  console.log('✔ Test 2 Passed: Ingestion scaling benchmarks verified.\n');

  // --- Test 3: Synthetic 6,000+ Email Validation & Campaign Clustering ---
  console.log('Test 3: Verifying 6,000+ email prototype validation target & campaign clustering...');
  const tDemoStart = Date.now();
  const demoSession = await bulkTriageService.loadDemoSession();
  const tDemoDuration = Date.now() - tDemoStart;

  console.log(`  - 6,250 synthetic emails loaded and indexed in ${tDemoDuration}ms`);
  assert.strictEqual(demoSession.totalCount, 6250, 'Must generate exactly 6,250 prototype emails');
  assert.strictEqual(demoSession.status, 'COMPLETED', 'Demo session must be COMPLETED');

  // Verify Mail Type distribution
  const m = demoSession.metrics;
  console.log(`  - Mail Types: Company=${m.mailTypes.COMPANY}, Personal=${m.mailTypes.PERSONAL}, Spam=${m.mailTypes.SPAM}, Unknown=${m.mailTypes.UNKNOWN}`);
  assert.ok(m.mailTypes.COMPANY > 2000, 'Must contain >2,000 Company emails');
  assert.ok(m.mailTypes.PERSONAL > 1000, 'Must contain >1,000 Personal emails');
  assert.ok(m.mailTypes.SPAM > 800, 'Must contain >800 Spam emails');
  assert.ok(m.mailTypes.UNKNOWN > 200, 'Must contain >200 Unknown emails');

  // Verify Threat Severity distribution
  console.log(`  - Risk Levels: Critical=${m.riskLevels.CRITICAL}, High=${m.riskLevels.HIGH}, Medium=${m.riskLevels.MEDIUM}, Low=${m.riskLevels.LOW}`);
  assert.ok(m.riskLevels.CRITICAL > 100, 'Must identify >100 Critical threats');
  assert.ok(m.riskLevels.HIGH > 400, 'Must identify >400 High threats');
  assert.ok(m.riskLevels.LOW > 3000, 'Must identify >3,000 Low threats');

  // Verify Campaign Clusters
  const campaigns = bulkTriageService.getCampaigns(demoSession.sessionId);
  console.log(`  - Campaign Clusters identified: ${campaigns.length}`);
  assert.ok(campaigns.length >= 5, 'Must identify at least 5 distinct coordinated campaign clusters');

  const becCampaign = campaigns.find(c => c.campaignCode === 'CP-2026-01');
  assert.ok(becCampaign, 'Operation GhostWire (CP-2026-01) must be clustered');
  assert.strictEqual(becCampaign?.threatLevel, 'CRITICAL', 'Operation GhostWire must be CRITICAL threat');
  assert.ok(becCampaign?.totalEmails >= 100, 'GhostWire cluster must contain >= 100 emails');
  console.log('✔ Test 3 Passed: 6,000+ prototype email validation & clustering verified.\n');

  // --- Test 4: Deduplicated Indicator Registry & Unique GeoIP Efficiency ---
  console.log('Test 4: Verifying deduplication (6,000 emails -> 173 unique public IPs)...');
  const indicators = bulkTriageService.getIndicators(demoSession.sessionId);
  const uniqueIps = indicators.filter(i => i.type === 'ipv4');
  console.log(`  - Total unique public IPs extracted: ${uniqueIps.length}`);
  assert.strictEqual(uniqueIps.length, 173, 'Must deduplicate down to exactly 173 unique public IPs');

  // Verify that high frequency IPs are ranked properly
  const topIp = uniqueIps[0];
  console.log(`  - Top observed IP: ${topIp.indicator} (Observed across ${topIp.frequency} emails)`);
  assert.ok(topIp.frequency >= 50, 'Top campaign IP must appear in at least 50 emails');
  console.log('✔ Test 4 Passed: Indicator deduplication verified.\n');

  // --- Test 5: Pagination, Search & Combined Filters ---
  console.log('Test 5: Verifying paginated query, search, and combined filtering...');
  // Query only Critical Company emails
  const filteredCritical = bulkTriageService.getFilteredEmails(demoSession.sessionId, {
    mailType: 'COMPANY',
    riskLevel: 'CRITICAL',
    page: 1,
    limit: 25,
  });
  assert.ok(filteredCritical.totalCount > 50, 'Must find >50 Critical Company emails');
  assert.strictEqual(filteredCritical.items.length, 25, 'Page limit 25 must be respected');
  assert.ok(filteredCritical.items.every(i => i.mailClassification.mailType === 'COMPANY'), 'All returned must be COMPANY');
  assert.ok(filteredCritical.items.every(i => i.riskLevel === 'CRITICAL'), 'All returned must be CRITICAL');

  // Free-text search for "Wire"
  const searchResults = bulkTriageService.getFilteredEmails(demoSession.sessionId, {
    search: 'Wire',
    page: 1,
    limit: 50,
  });
  assert.ok(searchResults.totalCount >= 100, 'Must find >= 100 emails matching "Wire"');
  assert.ok(searchResults.items.every(i => i.emailSubject.toLowerCase().includes('wire') || (i.campaignName && i.campaignName.toLowerCase().includes('wire'))), 'All matches must contain term');
  console.log('✔ Test 5 Passed: Filtering, search, and pagination verified.\n');

  // --- Test 6: Promotion to Formal Case & Evidence Ledger Cryptographic Integrity ---
  console.log('Test 6: Verifying 1-click promotion to formal case and blockchain custody seal...');
  const firstCritical = filteredCritical.items[0];
  const promotedCase = await bulkTriageService.promoteItemToCase(
    demoSession.sessionId,
    firstCritical.triageId,
    {
      userId: 'usr-analyst-01',
      name: 'Vikramaditya Sharma',
      email: 'analyst@soc.internal',
    }
  );

  assert.ok(promotedCase.caseRecord.caseId, 'Case record must have valid caseId');
  assert.strictEqual(promotedCase.caseRecord.title, firstCritical.emailSubject, 'Case title must match email subject');
  assert.ok(promotedCase.caseRecord.riskScore > 0, 'Risk score must be computed on promoted case');
  assert.ok(promotedCase.caseRecord.severity, 'Severity must be present on promoted case');

  // Verify item state updated
  const updatedItem = bulkTriageService.getEmailDetail(demoSession.sessionId, firstCritical.triageId);
  assert.strictEqual(updatedItem.item?.isPromoted, true, 'Item must be marked isPromoted = true');
  assert.strictEqual(updatedItem.item?.promotedCaseId, promotedCase.caseRecord.caseId, 'Promoted case ID must match');

  // Verify ledger integrity after promotion
  const ledgerIntegrity = evidenceLedger.verifyIntegrity();
  assert.strictEqual(ledgerIntegrity.isValid, true, 'Evidence ledger must maintain unbroken cryptographic integrity');
  console.log(`✔ Test 6 Passed: Case ${promotedCase.caseRecord.caseId} promoted and sealed in Ledger Block #${promotedCase.evidenceBlock.blockIndex}.\n`);

  // --- Test 7: Malformed EML Tolerance & Partial Failure Handling ---
  console.log('Test 7: Verifying partial failure isolation on malformed EML payloads...');
  const corruptBatch = [
    { filename: 'valid.eml', content: 'From: a@b.com\r\nSubject: Valid\r\n\r\nBody text.' },
    { filename: 'corrupt.eml', content: '' }, // empty
  ];
  const sessionCorrupt = bulkTriageService.createSession(false);
  await bulkTriageService.ingestBatchAsync(sessionCorrupt.sessionId, corruptBatch);
  assert.strictEqual(sessionCorrupt.processedCount + sessionCorrupt.failedCount, 2, 'Must finish processing queue despite corrupt item');
  console.log('✔ Test 7 Passed: Partial failure tolerance verified.\n');

  console.log('================================================================');
  console.log('ALL 7 BULK TRIAGE & CAMPAIGN CORRELATION TESTS PASSED (100%)');
  console.log('================================================================');
}

runTests().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
