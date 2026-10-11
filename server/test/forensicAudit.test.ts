import assert from 'assert';
import { analyzeHeaders } from '../forensics/authChecker';
import { calculateExplainableRiskScore } from '../forensics/riskEngine';
import { calculateSha256, parseRawEmail, sanitizeHtml } from '../forensics/parser';
import { evidenceLedger } from '../blockchain/evidenceLedger';
import { ThreatAssessment } from '../../src/types/forensics';

console.log('=== RUNNING FORENSIC PIPELINE AUDIT TESTS (SIH 2026 Problem 26106) ===\n');

// --- Test 1: Raw Evidence SHA-256 Hash Integrity ---
console.log('Test 1: Verifying raw evidence SHA-256 calculation...');
const rawSampleEmail = `From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test Email\r\nDate: Mon, 1 Sep 2026 10:00:00 +0000\r\nMessage-ID: <test-123@example.com>\r\n\r\nHello Bob, this is raw evidence.`;
const expectedSha256 = calculateSha256(rawSampleEmail);
const parsedEvidence = parseRawEmail(rawSampleEmail, 'CASE-TEST-001');

assert.strictEqual(parsedEvidence.sha256, expectedSha256, 'Parsed evidence SHA-256 must match raw input hash');
assert.ok(parsedEvidence.md5, 'Legacy MD5 hash must be present');
assert.ok(parsedEvidence.chainOfCustody && parsedEvidence.chainOfCustody.length > 0, 'Chain of custody must be initialized on ingestion');
assert.strictEqual(parsedEvidence.chainOfCustody[0].action, 'INGESTED', 'First custody event must be INGESTED');
console.log('✔ Test 1 Passed: SHA-256 computed on raw unaltered bytes.\n');

// --- Test 2: Multi-Hop Received Header Extraction & Order Preservation ---
console.log('Test 2: Verifying multi-hop Received header preservation...');
const multiHopEmail = `Received: from mail.internal.corp (mail.internal.corp [10.0.0.15])
    by gateway.corp.com (Postfix) with ESMTP id 4X9L1
    for <victim@corp.com>; Mon, 1 Sep 2026 12:05:00 +0000
Received-SPF: pass (gateway.corp.com: domain of corp.com designates 198.51.100.22 as permitted sender)
Received: from relay2.transit.net (relay2.transit.net [198.51.100.22])
    by mail.internal.corp (Postfix) with ESMTP id 3B8K2; Mon, 1 Sep 2026 12:04:10 +0000
Received: from attacker.origin.xyz (attacker.origin.xyz [185.220.101.5])
    by relay2.transit.net with ESMTP; Mon, 1 Sep 2026 12:02:00 +0000
From: "Executive Service" <spoofed-exec@corp.com>
To: victim@corp.com
Subject: Urgent Transfer Request
Date: Mon, 1 Sep 2026 12:05:00 +0000

Body text here`;

const multiHopParsed = parseRawEmail(multiHopEmail, 'CASE-TEST-002');
assert.strictEqual(multiHopParsed.headers.receivedHeaders.length, 3, 'Must extract exactly 3 Received headers');

const headerAnalysis = analyzeHeaders(multiHopParsed.headers.receivedHeaders, {
  from: multiHopParsed.headers.from,
  fromAddress: multiHopParsed.headers.fromAddress,
  fromDomain: multiHopParsed.headers.fromDomain,
  rawSource: multiHopEmail,
});

assert.strictEqual(headerAnalysis.receivedHops.length, 3, 'All 3 transit hops must be reconstructed in sequence');
assert.strictEqual(headerAnalysis.originatingIp, '185.220.101.5', 'Originating IP must be identified as the earliest external relay');
assert.ok(headerAnalysis.inferredOriginatingHop, 'Inferred originating hop must be populated');
assert.strictEqual(headerAnalysis.inferredOriginatingHop?.relayRole, 'PROBABLE_SOURCE_INFRASTRUCTURE', 'Relay role must be PROBABLE_SOURCE_INFRASTRUCTURE');
console.log('✔ Test 2 Passed: Received header sequence preserved; originating relay identified.\n');

// --- Test 3: Authentication Verification Labeling (Header-Reported vs Unverified) ---
console.log('Test 3: Verifying authentication verification labeling...');
assert.strictEqual(
  headerAnalysis.spf.verificationType,
  'HEADER_REPORTED',
  'SPF must be explicitly flagged as HEADER_REPORTED'
);
assert.strictEqual(
  headerAnalysis.dkim.verificationType,
  'UNVERIFIED',
  'DKIM must be flagged as UNVERIFIED if recipient gateway headers did not evaluate it'
);
assert.ok(headerAnalysis.spf.attributionNotice.includes('Unverified'), 'Attribution disclaimer must be present');
console.log('✔ Test 3 Passed: Authentication headers correctly classified without false trust.\n');

// --- Test 4: HTML Sanitization & Active Content Neutralization ---
console.log('Test 4: Verifying active content neutralization in HTML email...');
const maliciousHtml = `<div>Hello victim <script>alert("XSS")</script><iframe src="evil.html"></iframe><a href="https://example.com" onclick="steal()">Click me</a></div>`;
const sanitized = sanitizeHtml(maliciousHtml);

assert.ok(!sanitized.includes('<script>'), 'Scripts must be completely removed');
assert.ok(!sanitized.includes('<iframe'), 'Iframes must be blocked');
assert.ok(!sanitized.includes('onclick'), 'Inline event handlers must be stripped');
console.log('✔ Test 4 Passed: HTML rendered safely in sanitized text container.\n');

// --- Test 5: Deterministic Risk Score Bounds (0 - 100) ---
console.log('Test 5: Verifying explainable risk score engine...');
const mockThreatBenign: ThreatAssessment = {
  classification: 'LEGITIMATE',
  confidence: 95,
  reasons: ['Legitimate traffic'],
  evidence: ['Valid SPF'],
  observedEvidence: ['Valid SPF observed'],
  aiInference: ['Normal business communication'],
  riskFactors: [],
  counterEvidence: ['SPF Pass', 'No malicious links'],
  attributionAssessment: 'Statistical similarity only.',
  attributionConfidence: 10,
  recommendedActions: ['No action'],
  detectedIndicators: {
    phishing: false,
    spoofing: false,
    impersonation: false,
    bec: false,
    credentialHarvesting: false,
    paymentDiversion: false,
    maliciousLinks: false,
    suspiciousAttachments: false,
    socialEngineering: false,
    executiveImpersonation: false,
    urgencyManipulation: false,
  },
  urgencyLevel: 'LOW',
  executiveSummary: 'Clean email',
  modelUsed: 'Test Engine',
  isAiAssisted: false,
};

const benignRisk = calculateExplainableRiskScore({
  threatAssessment: mockThreatBenign,
  headerAnalysis: {
    ...headerAnalysis,
    spf: { ...headerAnalysis.spf, status: 'PASS' },
    dkim: { ...headerAnalysis.dkim, status: 'PASS' },
    dmarc: { ...headerAnalysis.dmarc, status: 'PASS' },
    inconsistencies: {
      replyToMismatch: false,
      returnPathMismatch: false,
      messageIdAnomaly: false,
      displaySpoofing: false,
      punycodeHomograph: false,
      timezoneAnomaly: false,
      notes: [],
    },
  },
  iocs: [],
  geolocations: [],
  attachments: [],
  bodyText: 'Hi team, please find attached the quarterly meeting agenda.',
});

assert.ok(benignRisk.totalScore >= 0 && benignRisk.totalScore <= 100, 'Score must be bounded between 0 and 100');
assert.strictEqual(benignRisk.level, 'LOW', 'Benign email must receive LOW risk rating');
assert.ok(benignRisk.totalScore < 20, 'Benign email score must not be artificially inflated');

// Test Critical/Phishing Email Score
const mockThreatMalicious: ThreatAssessment = {
  ...mockThreatBenign,
  classification: 'CREDENTIAL_HARVESTING',
  confidence: 98,
  detectedIndicators: { ...mockThreatBenign.detectedIndicators, phishing: true, credentialHarvesting: true, urgencyManipulation: true },
};
const maliciousRisk = calculateExplainableRiskScore({
  threatAssessment: mockThreatMalicious,
  headerAnalysis,
  iocs: [
    {
      id: 'ioc-1',
      type: 'url',
      value: 'http://phish.xyz/login',
      reputation: 'MALICIOUS',
      reputationScore: 95,
      confidence: 90,
      source: 'Demo',
      firstSeen: '2026-09-01T00:00:00Z',
      relatedCases: [],
      isSimulated: true,
    },
  ],
  geolocations: [
    {
      ip: '185.220.101.5',
      country: 'RU',
      countryCode: 'RU',
      region: 'Europe',
      city: 'Moscow',
      latitude: 55.75,
      longitude: 37.61,
      isp: 'Bulletproof Host',
      asn: 'AS999',
      hostingProvider: 'Bulletproof',
      confidence: 80,
      infrastructureRole: 'Direct Relay Host',
      attributionNote: 'Sample',
      isOriginating: true,
      vpnTorProxy: { isVpn: false, isTor: true, isProxy: false, isDatacenter: true },
    },
  ],
  attachments: [
    {
      filename: 'invoice.iso',
      contentType: 'application/x-iso9660-image',
      sizeBytes: 15000,
      isSuspicious: true,
      sha256: 'abc',
      md5: '1234567890abcdef1234567890abcdef',
      threatDetails: 'Executable ISO container',
    },
  ],
  bodyText: 'URGENT: Your Office 365 password expires in 1 hour. Immediate payment required via wire transfer!',
});

assert.ok(maliciousRisk.totalScore >= 75, 'Weaponized email must receive CRITICAL score (>=75)');
assert.strictEqual(maliciousRisk.level, 'CRITICAL', 'Weaponized email must be classified as CRITICAL');
console.log(`✔ Test 5 Passed: Benign Score=${benignRisk.totalScore}/100, Malicious Score=${maliciousRisk.totalScore}/100.\n`);

// --- Test 6: Blockchain / Hash-Chain Evidence Ledger Integrity & Tamper Detection ---
console.log('Test 6: Verifying hash-chain ledger integrity and tamper demonstration...');
const initialStatus = evidenceLedger.verifyIntegrity();
assert.strictEqual(initialStatus.isValid, true, 'Clean ledger must pass cryptographic verification');

// Append an evidence block
const newBlock = evidenceLedger.appendEvidence({
  evidenceId: 'EVID-TEST-099',
  caseId: 'CASE-TEST-099',
  emailSha256: expectedSha256,
  analysisSha256: calculateSha256('analysis payload'),
  investigator: 'Audit Officer',
  action: 'AUDIT_INTEGRITY_CHECK',
});

assert.ok(newBlock.blockHash.length === 64, 'Block hash must be a valid 64-char SHA-256 hex string');
assert.strictEqual(evidenceLedger.verifyIntegrity().isValid, true, 'Ledger must remain valid after append');

// Demonstrate Tampering
const targetIndex = newBlock.blockIndex;
const tamperResult = evidenceLedger.simulateTamper(targetIndex);
assert.strictEqual(tamperResult.success, true, 'Tamper simulation should succeed');

const tamperedStatus = evidenceLedger.verifyIntegrity();
assert.strictEqual(tamperedStatus.isValid, false, 'Tampered ledger MUST fail verification');
assert.strictEqual(tamperedStatus.invalidBlockIndex, targetIndex, 'Broken link must identify exact tampered block index');

// Demonstrate Resealing
const resealStatus = evidenceLedger.repairAndReseal();
assert.strictEqual(resealStatus.isValid, true, 'Resealing must restore cryptographic chain validity');
console.log('✔ Test 6 Passed: Hash-chain ledger detects alteration at exact block; reseals accurately.\n');

console.log('================================================================');
console.log('ALL 6 FORENSIC AUDIT TESTS COMPLETED SUCCESSFULLY (100% PASS)');
console.log('================================================================\n');
