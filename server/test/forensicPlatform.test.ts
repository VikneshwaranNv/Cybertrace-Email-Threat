import assert from 'assert';
import { ThreatIntelService } from '../intelligence/threatIntelService';
import { mapMitreAttackTechniques } from '../forensics/mitreAttackEngine';
import { correlateCampaignDNA } from '../forensics/campaignEngine';
import { queryInvestigationCopilot } from '../ai/copilotEngine';
import { evidenceLedger } from '../blockchain/evidenceLedger';
import { caseService } from '../services/caseService';
import { parseRawEmail } from '../forensics/parser';
import { analyzeHeaders } from '../forensics/authChecker';

console.log('=== RUNNING SOC/DFIR PLATFORM VERIFICATION TEST SUITE (SIH 2026 Phase 8) ===\n');

async function runAllTests() {
  // ==========================================
  // Test 1: Threat Intelligence Normalization
  // ==========================================
  console.log('--- Test 1: Threat Intelligence Normalization ---');
  const threatIntel = new ThreatIntelService();
  const testIocs = [
    { type: 'ipv4' as const, value: '185.220.101.5' },
    { type: 'domain' as const, value: 'secure-login-portal-auth.com' },
    { type: 'url' as const, value: 'http://secure-login-portal-auth.com/login.php' },
    { type: 'hash_sha256' as const, value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { type: 'email' as const, value: 'ceo-office@suspicious-bank-wire.com' },
  ];

  const enriched = await threatIntel.enrichBatch(testIocs);
  assert.strictEqual(enriched.length, 5, 'Must normalize all 5 submitted indicators');

  enriched.forEach(ioc => {
    assert.ok(ioc.id, 'Each IOC must have a unique ID');
    assert.ok(ioc.type, 'Each IOC must declare its type');
    assert.ok(ioc.value, 'Each IOC must retain its value');
    assert.ok(ioc.source, 'Each IOC must declare its source');
    assert.ok(['MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'UNKNOWN'].includes(ioc.reputation), 'Reputation must be normalized');
    assert.ok(typeof ioc.confidence === 'number' && ioc.confidence >= 0 && ioc.confidence <= 100, 'Confidence must be between 0 and 100');
    assert.ok(['ENRICHED', 'THREAT INTELLIGENCE UNAVAILABLE', 'PENDING'].includes(ioc.enrichmentStatus), 'Enrichment status must be explicit');
  });

  // Test explicit "THREAT INTELLIGENCE UNAVAILABLE" fallback for unknown item
  const unknownIoc = await threatIntel.enrichIOC({ type: 'ipv4', value: '192.0.2.1' });
  assert.ok(
    unknownIoc.enrichmentStatus === 'THREAT INTELLIGENCE UNAVAILABLE' || unknownIoc.reputation === 'UNKNOWN',
    'Unknown IOCs must be marked as UNAVAILABLE or UNKNOWN'
  );
  console.log('✔ Test 1 Passed: Normalized IOC objects strictly conform to SOC schema.\n');

  // ==========================================
  // Test 2: MITRE ATT&CK Mapping Accuracy
  // ==========================================
  console.log('--- Test 2: MITRE ATT&CK Mapping Accuracy ---');
  const mockPhishingEmail = `Received: from relay.compromised.com (relay.compromised.com [185.220.101.5])
    by mx.victim.com with ESMTP; Mon, 1 Sep 2026 12:00:00 +0000
From: "Security Helpdesk" <alert@compromised.com>
Reply-To: harvest-receiver@external-actor.org
To: user@victim.com
Subject: Urgent: Verify Your Corporate Password Immediately

Please click the link below to verify your corporate credentials:
http://credential-stealer-phish.net/reset`;

  const parsedPhish = parseRawEmail(mockPhishingEmail, 'CASE-TEST-MITRE');
  const headerAnalysis = analyzeHeaders(parsedPhish.headers.receivedHeaders, {
    from: parsedPhish.headers.from,
    fromAddress: parsedPhish.headers.fromAddress,
    fromDomain: parsedPhish.headers.fromDomain,
    rawSource: mockPhishingEmail,
  });

  const enrichedIocs = await threatIntel.enrichBatch([
    { type: 'ipv4', value: '185.220.101.5' },
    { type: 'domain', value: 'credential-stealer-phish.net' },
    { type: 'url', value: 'http://credential-stealer-phish.net/reset' },
  ]);

  const mitreMappings = mapMitreAttackTechniques({
    headerAnalysis,
    iocs: enrichedIocs,
    attachments: parsedPhish.attachments,
    bodyText: parsedPhish.body.text,
    extractedUrls: parsedPhish.extractedUrls,
    senderFrom: parsedPhish.headers.from,
    senderDomain: parsedPhish.headers.fromDomain,
    replyTo: parsedPhish.headers.replyTo,
  });

  assert.ok(mitreMappings.length > 0, 'Must map observable techniques');

  const spearphishLink = mitreMappings.find(m => m.techniqueId === 'T1566.002');
  assert.ok(spearphishLink, 'Must map T1566.002 (Spearphishing Link) when link present');
  assert.strictEqual(spearphishLink?.tactic, 'Initial Access', 'T1566.002 tactic must be Initial Access');
  assert.ok(spearphishLink?.evidenceFound.includes('http'), 'Evidence found must reference observed URL');
  assert.ok(spearphishLink?.evidenceReferences.length > 0, 'Evidence references must be present');

  mitreMappings.forEach(m => {
    assert.ok(m.techniqueId, 'Technique ID required');
    assert.ok(m.techniqueName, 'Technique Name required');
    assert.ok(m.tactic, 'Tactic required');
    assert.ok(m.evidenceFound, 'Evidence found required');
    assert.ok(m.evidenceReferences.length > 0, 'Evidence references required');
  });
  console.log('✔ Test 2 Passed: MITRE ATT&CK techniques mapped strictly from evidence.\n');

  // ==========================================
  // Test 3: Campaign Correlation Logic
  // ==========================================
  console.log('--- Test 3: Campaign Correlation Logic ---');
  const campaignMatches = correlateCampaignDNA({
    subject: 'Security Alert: Action Required: Verify your corporate password',
    fromDomain: 'login-micros0ft-online.com',
    fromAddress: 'security@login-micros0ft-online.com',
    replyTo: 'sec-review@external-actor.org',
    ips: ['185.220.101.5'],
    domains: ['login-micros0ft-online.com', 'credential-stealer-phish.net'],
    urls: ['http://login-micros0ft-online.com/auth'],
    hashes: [],
    headerAnalysis,
    iocs: enrichedIocs,
  });

  assert.ok(campaignMatches.length > 0, 'Must correlate matching threat syndicate');

  const match = campaignMatches[0];
  assert.ok(match.campaignId, 'Campaign ID must be present');
  assert.ok(match.similarityScore > 0, 'Similarity score must be calculated');
  assert.ok(Array.isArray(match.observedCorrelation), 'Observed correlation must be an array');
  assert.ok(Array.isArray(match.aiInference), 'AI inference must be an array');
  assert.ok(
    match.attributionNotice.toLowerCase().includes('attribution') &&
    match.attributionNotice.toLowerCase().includes('definitive'),
    'Attribution notice must be explicit'
  );
  console.log('✔ Test 3 Passed: Campaign correlation enforces strict observed vs AI separation.\n');

  // ==========================================
  // Test 4: Copilot Evidence Grounding
  // ==========================================
  console.log('--- Test 4: Copilot Evidence Grounding ---');
  await caseService.initialize();
  const fullCase = await caseService.getCaseById('CASE-2026-002');
  assert.ok(fullCase, 'Demo case 002 must exist');

  // Question on existing evidence
  const answerExisting = await queryInvestigationCopilot({
    question: 'What is the sender address and risk score for this case?',
    payload: fullCase,
  });
  assert.ok(answerExisting.answer, 'Copilot must provide an answer');
  assert.ok(answerExisting.evidenceUsed.length > 0, 'Copilot must cite evidence used');
  assert.ok(
    String(answerExisting.confidence).toUpperCase() === 'HIGH',
    'Confidence must be HIGH for grounded evidence'
  );

  // Question on non-existent evidence
  const answerMissing = await queryInvestigationCopilot({
    question: 'What is the attacker residential home address and GPS coordinate of the computer?',
    payload: fullCase,
  });
  assert.ok(
    answerMissing.answer.toLowerCase().includes('insufficient evidence') ||
    answerMissing.answer.toLowerCase().includes('does not exist') ||
    answerMissing.answer.toLowerCase().includes('not present'),
    'Copilot must refuse to fabricate missing physical coordinates'
  );
  console.log('✔ Test 4 Passed: Copilot strictly grounded in evidence without hallucination.\n');

  // ==========================================
  // Test 5: Professional Report Structure (18 Sections)
  // ==========================================
  console.log('--- Test 5: Professional Report Structure (18 Sections) ---');
  const report = await caseService.generateReport('CASE-2026-002');
  assert.ok(report, 'Report must be generated');
  assert.strictEqual(report.structuredSections.length, 18, 'Report must contain exactly 18 structured sections');

  const expectedTitles = [
    'Case Information',
    'Executive Summary',
    'Deterministic Risk Score',
    'Risk Factor Breakdown',
    'Email Metadata',
    'Header Analysis',
    'Authentication Results',
    'Transit / Received Chain',
    'IOC Findings',
    'Threat Intelligence',
    'MITRE ATT&CK Mappings',
    'Campaign Correlation',
    'Investigation Timeline',
    'Evidence References',
    'AI Investigation Conclusion',
    'Limitations',
    'SHA-256 Evidence Integrity',
    'Audit Information',
  ];

  expectedTitles.forEach((expectedTitle, idx) => {
    const sec = report.structuredSections[idx];
    assert.strictEqual(sec.sectionNumber, idx + 1, `Section ${idx + 1} number must match`);
    assert.strictEqual(sec.title, expectedTitle, `Section ${idx + 1} title must be ${expectedTitle}`);
    assert.ok(sec.content && sec.content.length > 0, `Section ${idx + 1} content must not be empty`);
    if (expectedTitle === 'AI Investigation Conclusion') {
      assert.strictEqual(sec.isAiGenerated, true, 'Section 15 AI Conclusion must be flagged as AI-generated');
    }
  });
  console.log('✔ Test 5 Passed: All 18 structured forensic sections generated with anti-fabrication controls.\n');

  // ==========================================
  // Test 6: Blockchain Evidence Integrity
  // ==========================================
  console.log('--- Test 6: Blockchain Evidence Integrity ---');
  const verification = evidenceLedger.verifyChain();
  assert.strictEqual(verification.isValid, true, 'Initial evidence ledger chain must be valid');
  assert.strictEqual(verification.compromisedBlockIndex, null, 'No blocks should be compromised initially');

  // Test tamper detection
  const tampered = evidenceLedger.tamperBlock(1, { title: 'TAMPERED TITLE BY ATTACKER' });
  assert.strictEqual(tampered, true, 'Tampering must succeed for audit verification test');

  const postTamperVerification = evidenceLedger.verifyChain();
  assert.strictEqual(postTamperVerification.isValid, false, 'Chain must become invalid after tamper');
  assert.strictEqual(postTamperVerification.compromisedBlockIndex, 1, 'Compromised block index must be block 1');

  // Reseal
  evidenceLedger.resealChain();
  const resealedVerification = evidenceLedger.verifyChain();
  assert.strictEqual(resealedVerification.isValid, true, 'Resealed chain must be valid');
  console.log('✔ Test 6 Passed: SHA-256 cryptographic chain-of-custody and tamper detection verified.\n');

  console.log('================================================================');
  console.log('ALL 6 SOC/DFIR UPGRADE MODULE TESTS PASSED SUCCESSFULLY! (100%)');
  console.log('================================================================\n');
}

runAllTests().catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});

