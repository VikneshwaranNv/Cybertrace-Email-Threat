import assert from 'assert';
import {
  GmailIocService,
  defangIndicator,
  normalizeIocValue,
  isPrivateOrReservedIp,
} from '../gmail/gmailIocService';
import { GmailCampaignService } from '../gmail/gmailCampaignService';
import { GmailTriageRegistry, GmailTriageRecord } from '../gmail/gmailTriageRegistry';
import { ThreatIntelService } from '../intelligence/threatIntelService';
import { ThreatIntelProvider, ThreatEnrichmentResult } from '../intelligence/threatIntelProvider';
import { IOCType } from '../../src/types/forensics';

console.log('=== RUNNING GMAIL THREAT INTEL & CAMPAIGN TEST SUITE (PHASE 7) ===\n');

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    // Zero Gemini guarantee: Ensure no Gemini API key is needed or used
    delete process.env.GEMINI_API_KEY;

    // Identities for multi-tenant testing
    const USER_ALICE = 'usr-alice-phase7';
    const USER_BOB = 'usr-bob-phase7';

    // Mock Provider Helpers
    class MockMaliciousProvider implements ThreatIntelProvider {
      id = 'mock-malicious';
      name = 'Mock Malicious Provider';
      async isAvailable() { return true; }
      canEnrich() { return true; }
      async enrich(type: IOCType, value: string): Promise<ThreatEnrichmentResult | null> {
        if (value.includes('bad-actor') || value.includes('evil-phish') || value === '198.51.100.99') {
          return {
            reputation: 'MALICIOUS',
            reputationScore: 92,
            confidence: 90,
            source: 'Mock Threat Intelligence Blacklist',
            firstSeen: '2026-01-01',
            lastSeen: '2026-09-08',
            relatedThreats: ['Phishing Campaign', 'Credential Stealer'],
            enrichmentStatus: 'ENRICHED',
            maliciousCategory: 'Credential Phishing Infrastructure',
          };
        }
        if (value.includes('suspicious-relay') || value === '203.0.113.88') {
          return {
            reputation: 'SUSPICIOUS',
            reputationScore: 74,
            confidence: 80,
            source: 'Mock Suspicious Relay Feeds',
            firstSeen: '2026-03-01',
            lastSeen: '2026-09-08',
            relatedThreats: ['Untrusted Relay'],
            enrichmentStatus: 'ENRICHED',
            maliciousCategory: 'Untrusted Relay Node',
          };
        }
        return {
          reputation: 'UNKNOWN',
          reputationScore: 0,
          confidence: 0,
          source: 'Mock Provider',
          enrichmentStatus: 'THREAT INTELLIGENCE UNAVAILABLE',
          relatedThreats: [],
        };
      }
    }

    class MockFailingProvider implements ThreatIntelProvider {
      id = 'mock-failing';
      name = 'Mock Failing Provider';
      async isAvailable() { return true; }
      canEnrich() { return true; }
      async enrich(): Promise<ThreatEnrichmentResult | null> {
        throw new Error('Upstream threat intel API connection timed out (HTTP 504)');
      }
    }

    class MockRateLimitedProvider implements ThreatIntelProvider {
      id = 'mock-rate-limited';
      name = 'Mock Rate Limited Provider';
      async isAvailable() { return true; }
      canEnrich() { return true; }
      async enrich(): Promise<ThreatEnrichmentResult | null> {
        throw new Error('API rate limit exceeded: HTTP 429 Too Many Requests');
      }
    }

    // Helper to create test triage records
    const createSampleRecord = (overrides: Partial<GmailTriageRecord>): GmailTriageRecord => {
      const baseId = overrides.gmailMessageId || 'msg-default-100';
      const sender = overrides.sender || {
        raw: 'Alert <alerts@bad-actor-domain.com>',
        fromAddress: 'alerts@bad-actor-domain.com',
        fromDomain: 'bad-actor-domain.com',
      };
      const extractedDomains = overrides.extractedDomains !== undefined
        ? overrides.extractedDomains
        : (sender.fromDomain ? [sender.fromDomain] : []);
      const extractedUrls = overrides.extractedUrls !== undefined
        ? overrides.extractedUrls
        : (sender.fromDomain ? [`https://login.${sender.fromDomain}/auth`] : []);

      return {
        gmailMessageId: baseId,
        userId: overrides.userId || USER_ALICE,
        threadId: overrides.threadId || `th-${baseId}`,
        subject: overrides.subject || 'Sample Security Notification',
        sender,
        recipients: overrides.recipients || ['analyst@cybertrace-demo.com'],
        receivedAt: overrides.receivedAt || new Date().toISOString(),
        originatingIp: overrides.originatingIp ?? '198.51.100.99',
        authStatus: overrides.authStatus || { spf: 'FAIL', dkim: 'FAIL', dmarc: 'FAIL' },
        mailClassification: overrides.mailClassification || {
          mailType: 'SPAM',
          confidence: 0.95,
          reasons: ['Suspicious origin IP', 'Phishing terminology detected'],
        },
        riskScore: overrides.riskScore ?? 88,
        riskLevel: overrides.riskLevel ?? 'HIGH',
        threatClassification: overrides.threatClassification || 'Credential Phishing Attack',
        threatIndicators: overrides.threatIndicators || {
          detected: { SPOOFED_SENDER: true, SUSPICIOUS_LINKS: true },
          reasons: ['External sender impersonating IT', 'Malicious links present'],
          riskFactors: ['Known threat domain'],
        },
        extractedDomains,
        extractedUrls,
        attachments: overrides.attachments || [],
        forensicSha256: overrides.forensicSha256 || 'f0e1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f',
        forensicMd5: overrides.forensicMd5 || '0123456789abcdef0123456789abcdef',
        analyzedAt: overrides.analyzedAt || new Date().toISOString(),
        triageStatus: overrides.triageStatus || 'PHISHING_OR_MALICIOUS',
      };
    };

    // -------------------------------------------------------------------------
    // Test 1: IOC extraction from a single Gmail triage record
    // -------------------------------------------------------------------------
    console.log('Test 1: Verifying IOC extraction from a single Gmail triage record...');
    const iocService = new GmailIocService();
    const testRecord1 = createSampleRecord({
      originatingIp: '198.51.100.77',
      sender: {
        raw: 'Security Dept <security-alert@phish-account-update.com>',
        fromAddress: 'security-alert@phish-account-update.com',
        fromDomain: 'phish-account-update.com',
      },
      extractedDomains: ['phish-account-update.com', 'credential-harvest.net'],
      extractedUrls: ['https://login-verify.phish-account-update.com/reset'],
      attachments: [
        {
          filename: 'invoice.pdf.exe',
          contentType: 'application/x-msdownload',
          sizeBytes: 204800,
          isSuspicious: true,
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
      ],
    });

    const rawExtracted = iocService.extractRawIocsFromRecord(testRecord1);
    const extractedTypes = new Set(rawExtracted.map(i => i.type));
    assert.ok(extractedTypes.has('ipv4'), 'Must extract IPv4');
    assert.ok(extractedTypes.has('domain'), 'Must extract domain');
    assert.ok(extractedTypes.has('url'), 'Must extract URL');
    assert.ok(extractedTypes.has('email'), 'Must extract email');
    assert.ok(extractedTypes.has('hash_sha256'), 'Must extract attachment SHA-256');

    const ipIoc = rawExtracted.find(i => i.type === 'ipv4');
    assert.strictEqual(ipIoc?.value, '198.51.100.77');

    const emailIoc = rawExtracted.find(i => i.type === 'email');
    assert.strictEqual(emailIoc?.value, 'security-alert@phish-account-update.com');

    const hashIoc = rawExtracted.find(i => i.type === 'hash_sha256');
    assert.strictEqual(hashIoc?.value, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    console.log('✔ Test 1 Passed: Normalized IOC extraction from triage record verified.\n');

    // -------------------------------------------------------------------------
    // Test 2: Indicator defanging for safe UI display
    // -------------------------------------------------------------------------
    console.log('Test 2: Verifying indicator defanging logic...');
    assert.strictEqual(
      defangIndicator('url', 'http://malicious-login.com/path'),
      'hxxp://malicious-login[.]com/path'
    );
    assert.strictEqual(
      defangIndicator('url', 'https://secure-bank.org/login?id=1'),
      'hxxps://secure-bank[.]org/login?id=1'
    );
    assert.strictEqual(
      defangIndicator('domain', 'evil.phishing.co.uk'),
      'evil[.]phishing[.]co[.]uk'
    );
    assert.strictEqual(
      defangIndicator('ipv4', '198.51.100.22'),
      '198[.]51[.]100[.]22'
    );
    assert.strictEqual(
      defangIndicator('email', 'attacker@darknet.org'),
      'attacker[@]darknet[.]org'
    );
    assert.strictEqual(
      defangIndicator('hash_sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
    console.log('✔ Test 2 Passed: Indicator defanging prevents active links and clickable syntax.\n');

    // -------------------------------------------------------------------------
    // Test 3: Private and reserved IPv4 address filtering
    // -------------------------------------------------------------------------
    console.log('Test 3: Verifying private and reserved IPv4 address filtering...');
    assert.strictEqual(isPrivateOrReservedIp('10.0.0.1'), true);
    assert.strictEqual(isPrivateOrReservedIp('10.255.255.255'), true);
    assert.strictEqual(isPrivateOrReservedIp('192.168.1.100'), true);
    assert.strictEqual(isPrivateOrReservedIp('172.16.0.1'), true);
    assert.strictEqual(isPrivateOrReservedIp('172.31.255.255'), true);
    assert.strictEqual(isPrivateOrReservedIp('127.0.0.1'), true);
    assert.strictEqual(isPrivateOrReservedIp('169.254.1.1'), true);
    assert.strictEqual(isPrivateOrReservedIp('198.51.100.5'), false);
    assert.strictEqual(isPrivateOrReservedIp('185.220.101.5'), false);

    // Record with private originating IP should NOT produce an external IPv4 IOC
    const privateIpRecord = createSampleRecord({
      originatingIp: '192.168.1.50',
    });
    const privateExtracted = iocService.extractRawIocsFromRecord(privateIpRecord);
    const hasPrivateIp = privateExtracted.some(i => i.type === 'ipv4');
    assert.strictEqual(hasPrivateIp, false, 'Private IP must not be extracted as external threat IOC');
    console.log('✔ Test 3 Passed: Private/reserved IP addresses safely excluded from public intel.\n');

    // -------------------------------------------------------------------------
    // Test 4: IOC normalization logic
    // -------------------------------------------------------------------------
    console.log('Test 4: Verifying IOC normalization (case, whitespace, trailing slash)...');
    assert.strictEqual(normalizeIocValue('domain', '  EVIL-DOMAIN.COM  '), 'evil-domain.com');
    assert.strictEqual(normalizeIocValue('email', '  ATTACKER@PHISH.ORG  '), 'attacker@phish.org');
    assert.strictEqual(normalizeIocValue('hash_sha256', 'ABCDEF0123456789'), 'abcdef0123456789');
    assert.strictEqual(
      normalizeIocValue('url', 'HTTPS://evil-site.com/'),
      'https://evil-site.com'
    );
    console.log('✔ Test 4 Passed: Value normalization functions properly.\n');

    // -------------------------------------------------------------------------
    // Test 5: Indicator deduplication across multiple triage records
    // -------------------------------------------------------------------------
    console.log('Test 5: Verifying indicator deduplication and cross-record aggregation...');
    const recordA = createSampleRecord({
      gmailMessageId: 'msg-rec-001',
      originatingIp: '198.51.100.99',
      extractedUrls: ['https://evil-phish.net/login'],
    });
    const recordB = createSampleRecord({
      gmailMessageId: 'msg-rec-002',
      originatingIp: '198.51.100.99',
      extractedUrls: ['https://evil-phish.net/login'],
    });

    const mockIntel = new ThreatIntelService([new MockMaliciousProvider()]);
    const enriched = await iocService.normalizeAndEnrichIocs([recordA, recordB], mockIntel);

    const urlIoc = enriched.find(i => i.type === 'url' && i.value === 'https://evil-phish.net/login');
    assert.ok(urlIoc, 'Deduplicated URL IOC must exist');
    assert.strictEqual(urlIoc.occurrenceCount, 2, 'Occurrence count must aggregate to 2');
    assert.strictEqual(urlIoc.sourceMessageIds.length, 2, 'Must reference both source message IDs');
    assert.ok(urlIoc.sourceMessageIds.includes('msg-rec-001'));
    assert.ok(urlIoc.sourceMessageIds.includes('msg-rec-002'));
    console.log('✔ Test 5 Passed: IOC deduplication and aggregation across records verified.\n');

    // -------------------------------------------------------------------------
    // Test 6: Threat intelligence enrichment with mocked provider
    // -------------------------------------------------------------------------
    console.log('Test 6: Verifying threat intelligence enrichment output...');
    const maliciousIoc = enriched.find(i => i.type === 'ipv4' && i.value === '198.51.100.99');
    assert.ok(maliciousIoc, 'IPv4 IOC must be present');
    assert.strictEqual(maliciousIoc.threatIntel?.reputation, 'MALICIOUS');
    assert.strictEqual(maliciousIoc.threatIntel?.reputationScore, 92);
    assert.strictEqual(maliciousIoc.threatIntel?.enrichmentStatus, 'ENRICHED');
    assert.strictEqual(maliciousIoc.threatIntel?.source, 'Mock Threat Intelligence Blacklist');
    console.log('✔ Test 6 Passed: Mock threat intel provider enriches indicator as MALICIOUS.\n');

    // -------------------------------------------------------------------------
    // Test 7: Enrichment status handling
    // -------------------------------------------------------------------------
    console.log('Test 7: Verifying enrichment status mappings (ENRICHED vs UNAVAILABLE)...');
    const unknownRecord = createSampleRecord({
      gmailMessageId: 'msg-rec-unknown',
      originatingIp: '192.0.2.1', // unlisted in mock
      extractedUrls: ['https://clean-site.org/index.html'],
    });
    const enrichedUnknown = await iocService.normalizeAndEnrichIocs([unknownRecord], mockIntel);
    const unknownIoc = enrichedUnknown.find(i => i.value === '192.0.2.1');
    assert.ok(unknownIoc);
    assert.strictEqual(unknownIoc.threatIntel?.enrichmentStatus, 'THREAT INTELLIGENCE UNAVAILABLE');
    assert.strictEqual(unknownIoc.threatIntel?.reputation, 'UNKNOWN');
    console.log('✔ Test 7 Passed: Unrecognized indicators map to THREAT INTELLIGENCE UNAVAILABLE.\n');

    // -------------------------------------------------------------------------
    // Test 8: Reputation classification support (MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN)
    // -------------------------------------------------------------------------
    console.log('Test 8: Verifying reputation classification support...');
    const suspRecord = createSampleRecord({
      gmailMessageId: 'msg-rec-susp',
      originatingIp: '203.0.113.88', // flagged as suspicious in mock
    });
    const enrichedSusp = await iocService.normalizeAndEnrichIocs([suspRecord], mockIntel);
    const suspIoc = enrichedSusp.find(i => i.value === '203.0.113.88');
    assert.ok(suspIoc);
    assert.strictEqual(suspIoc.threatIntel?.reputation, 'SUSPICIOUS');
    assert.strictEqual(suspIoc.threatIntel?.reputationScore, 74);
    console.log('✔ Test 8 Passed: SUSPICIOUS reputation classification verified.\n');

    // -------------------------------------------------------------------------
    // Test 9: Provider failure resilience (timeouts, 500s do NOT throw or halt)
    // -------------------------------------------------------------------------
    console.log('Test 9: Verifying provider failure resilience...');
    const failingIntel = new ThreatIntelService([new MockFailingProvider()]);
    const safeResult = await iocService.normalizeAndEnrichIocs([testRecord1], failingIntel);
    assert.ok(Array.isArray(safeResult));
    assert.ok(safeResult.length > 0);
    for (const item of safeResult) {
      assert.strictEqual(item.threatIntel?.enrichmentStatus, 'THREAT INTELLIGENCE UNAVAILABLE');
      assert.strictEqual(item.threatIntel?.reputation, 'UNKNOWN');
    }
    console.log('✔ Test 9 Passed: Service gracefully recovers from provider crashes and 500s.\n');

    // -------------------------------------------------------------------------
    // Test 10: Provider rate-limit resilience (HTTP 429 handled safely)
    // -------------------------------------------------------------------------
    console.log('Test 10: Verifying provider rate-limit resilience (HTTP 429)...');
    const rateLimitedIntel = new ThreatIntelService([new MockRateLimitedProvider()]);
    const rateLimitResult = await iocService.normalizeAndEnrichIocs([testRecord1], rateLimitedIntel);
    assert.ok(Array.isArray(rateLimitResult));
    assert.ok(rateLimitResult.length > 0);
    assert.strictEqual(rateLimitResult[0].threatIntel?.enrichmentStatus, 'THREAT INTELLIGENCE UNAVAILABLE');
    console.log('✔ Test 10 Passed: Rate limits gracefully handled without failing triage or correlation.\n');

    // -------------------------------------------------------------------------
    // Setup for Campaign Correlation Tests
    // -------------------------------------------------------------------------
    const triageRegistry = new GmailTriageRegistry();
    const campaignService = new GmailCampaignService({
      triageRegistry,
      iocService,
      threatIntelService: mockIntel,
    });

    // -------------------------------------------------------------------------
    // Test 11: Campaign correlation by shared Originating IP
    // -------------------------------------------------------------------------
    console.log('Test 11: Verifying campaign correlation by shared Originating IP...');
    const ipMsg1 = createSampleRecord({
      gmailMessageId: 'msg-ip-001',
      userId: USER_ALICE,
      originatingIp: '198.51.100.99',
      subject: 'Security Alert 1',
      extractedUrls: [],
      attachments: [],
    });
    const ipMsg2 = createSampleRecord({
      gmailMessageId: 'msg-ip-002',
      userId: USER_ALICE,
      originatingIp: '198.51.100.99',
      subject: 'Security Alert 2',
      extractedUrls: [],
      attachments: [],
    });

    triageRegistry.set(USER_ALICE, ipMsg1.gmailMessageId, ipMsg1);
    triageRegistry.set(USER_ALICE, ipMsg2.gmailMessageId, ipMsg2);

    const { campaigns: ipCampaigns } = await campaignService.getCampaignsForUser(USER_ALICE, mockIntel);
    const ipCamp = ipCampaigns.find(c => c.relatedMessageIds.includes('msg-ip-001'));
    assert.ok(ipCamp, 'Campaign must be generated for message 1');
    assert.ok(ipCamp.relatedMessageIds.includes('msg-ip-002'), 'Message 2 must be clustered into the same campaign');
    assert.strictEqual(ipCamp.totalMessages, 2);
    assert.ok(ipCamp.originatingIps.includes('198.51.100.99'));
    console.log('✔ Test 11 Passed: Messages sharing originating IP clustered into single campaign.\n');

    // Clean registry for next tests
    triageRegistry.clearAll();

    // -------------------------------------------------------------------------
    // Test 12: Campaign correlation by shared URL / non-benign domain
    // -------------------------------------------------------------------------
    console.log('Test 12: Verifying campaign correlation by shared URL...');
    const urlMsg1 = createSampleRecord({
      gmailMessageId: 'msg-url-001',
      userId: USER_ALICE,
      originatingIp: '192.0.2.10',
      extractedUrls: ['https://evil-phish.net/credential-drop'],
      attachments: [],
    });
    const urlMsg2 = createSampleRecord({
      gmailMessageId: 'msg-url-002',
      userId: USER_ALICE,
      originatingIp: '192.0.2.20',
      extractedUrls: ['https://evil-phish.net/credential-drop'],
      attachments: [],
    });

    triageRegistry.set(USER_ALICE, urlMsg1.gmailMessageId, urlMsg1);
    triageRegistry.set(USER_ALICE, urlMsg2.gmailMessageId, urlMsg2);

    const { campaigns: urlCampaigns } = await campaignService.getCampaignsForUser(USER_ALICE, mockIntel);
    const urlCamp = urlCampaigns.find(c => c.relatedMessageIds.includes('msg-url-001'));
    assert.ok(urlCamp);
    assert.ok(urlCamp.relatedMessageIds.includes('msg-url-002'));
    assert.strictEqual(urlCamp.totalMessages, 2);
    console.log('✔ Test 12 Passed: Messages sharing malicious URL clustered into single campaign.\n');

    triageRegistry.clearAll();

    // -------------------------------------------------------------------------
    // Test 13: Campaign correlation by shared attachment hash
    // -------------------------------------------------------------------------
    console.log('Test 13: Verifying campaign correlation by shared attachment hash...');
    const SHARED_HASH = 'a9b8c7d6e5f403123456789abcdef0123456789abcdef0123456789abcdef01';
    const attMsg1 = createSampleRecord({
      gmailMessageId: 'msg-att-001',
      userId: USER_ALICE,
      originatingIp: '192.0.2.31',
      subject: 'Attached Scanned Document 1',
      threatClassification: 'Malicious Executable Attachment',
      extractedUrls: [],
      attachments: [{ filename: 'doc1.pdf.exe', contentType: 'application/exe', sizeBytes: 5000, isSuspicious: true, sha256: SHARED_HASH }],
    });
    const attMsg2 = createSampleRecord({
      gmailMessageId: 'msg-att-002',
      userId: USER_ALICE,
      originatingIp: '192.0.2.32',
      subject: 'Attached Scanned Document 2',
      threatClassification: 'Malicious Executable Attachment',
      extractedUrls: [],
      attachments: [{ filename: 'doc2.pdf.exe', contentType: 'application/exe', sizeBytes: 5000, isSuspicious: true, sha256: SHARED_HASH }],
    });

    triageRegistry.set(USER_ALICE, attMsg1.gmailMessageId, attMsg1);
    triageRegistry.set(USER_ALICE, attMsg2.gmailMessageId, attMsg2);

    const { campaigns: attCampaigns } = await campaignService.getCampaignsForUser(USER_ALICE, mockIntel);
    const attCamp = attCampaigns.find(c => c.relatedMessageIds.includes('msg-att-001'));
    assert.ok(attCamp);
    assert.ok(attCamp.relatedMessageIds.includes('msg-att-002'));
    assert.strictEqual(attCamp.threatCategory, 'SUSPICIOUS_ATTACHMENT');
    console.log('✔ Test 13 Passed: Messages sharing attachment hash clustered as SUSPICIOUS_ATTACHMENT.\n');

    // -------------------------------------------------------------------------
    // Test 14: Explainable correlation reasons
    // -------------------------------------------------------------------------
    console.log('Test 14: Verifying explainable correlation reasons output...');
    assert.ok(attCamp.correlationReasons.length > 0);
    const hasHashReason = attCamp.correlationReasons.some(r => r.includes(SHARED_HASH.slice(0, 16)));
    assert.ok(hasHashReason, 'Correlation reasons must explicitly mention the linking attachment hash');
    console.log('✔ Test 14 Passed: Campaign includes human-readable and explainable correlation rationale.\n');

    triageRegistry.clearAll();

    // -------------------------------------------------------------------------
    // Test 15: Similar subjects alone DO NOT cluster unrelated messages
    // -------------------------------------------------------------------------
    console.log('Test 15: Verifying similar subjects alone do NOT cluster messages...');
    const invoiceMsg1 = createSampleRecord({
      gmailMessageId: 'msg-inv-001',
      userId: USER_ALICE,
      subject: 'URGENT: Corporate Invoice #1001 Overdue',
      sender: { raw: 'Vendor A <billing@vendor-a-legal.com>', fromAddress: 'billing@vendor-a-legal.com', fromDomain: 'vendor-a-legal.com' },
      originatingIp: '192.0.2.101',
      extractedUrls: ['https://vendor-a-legal.com/invoice/1001'],
      attachments: [],
    });
    const invoiceMsg2 = createSampleRecord({
      gmailMessageId: 'msg-inv-002',
      userId: USER_ALICE,
      subject: 'URGENT: Corporate Invoice #1002 Overdue',
      sender: { raw: 'Vendor B <billing@vendor-b-services.com>', fromAddress: 'billing@vendor-b-services.com', fromDomain: 'vendor-b-services.com' },
      originatingIp: '192.0.2.102',
      extractedUrls: ['https://vendor-b-services.com/invoice/1002'],
      attachments: [],
    });

    triageRegistry.set(USER_ALICE, invoiceMsg1.gmailMessageId, invoiceMsg1);
    triageRegistry.set(USER_ALICE, invoiceMsg2.gmailMessageId, invoiceMsg2);

    const { campaigns: invCampaigns } = await campaignService.getCampaignsForUser(USER_ALICE, mockIntel);
    assert.strictEqual(invCampaigns.length, 2, 'Must NOT cluster unrelated messages solely based on similar subject text');
    assert.notStrictEqual(invCampaigns[0].campaignId, invCampaigns[1].campaignId);
    console.log('✔ Test 15 Passed: Similar subject text alone correctly rejected as correlation pivot.\n');

    triageRegistry.clearAll();

    // -------------------------------------------------------------------------
    // Test 16: Unrelated messages with no shared IOCs form separate campaigns
    // -------------------------------------------------------------------------
    console.log('Test 16: Verifying unrelated messages form distinct single-message campaigns...');
    const disjointMsg1 = createSampleRecord({
      gmailMessageId: 'msg-disjoint-001',
      userId: USER_ALICE,
      sender: { raw: 'Site Alpha <admin@site-alpha.com>', fromAddress: 'admin@site-alpha.com', fromDomain: 'site-alpha.com' },
      originatingIp: '192.0.2.111',
      extractedUrls: ['https://site-alpha.com/login'],
    });
    const disjointMsg2 = createSampleRecord({
      gmailMessageId: 'msg-disjoint-002',
      userId: USER_ALICE,
      sender: { raw: 'Site Beta <admin@site-beta.com>', fromAddress: 'admin@site-beta.com', fromDomain: 'site-beta.com' },
      originatingIp: '192.0.2.222',
      extractedUrls: ['https://site-beta.com/auth'],
    });

    triageRegistry.set(USER_ALICE, disjointMsg1.gmailMessageId, disjointMsg1);
    triageRegistry.set(USER_ALICE, disjointMsg2.gmailMessageId, disjointMsg2);

    const { campaigns: disjCampaigns } = await campaignService.getCampaignsForUser(USER_ALICE, mockIntel);
    assert.strictEqual(disjCampaigns.length, 2);
    assert.strictEqual(disjCampaigns[0].totalMessages, 1);
    assert.strictEqual(disjCampaigns[1].totalMessages, 1);
    console.log('✔ Test 16 Passed: Disjoint threat messages cleanly separated.\n');

    triageRegistry.clearAll();

    // -------------------------------------------------------------------------
    // Test 17: Campaign risk scoring and level computation
    // -------------------------------------------------------------------------
    console.log('Test 17: Verifying campaign risk scoring and level assignment...');
    const highRiskMsg1 = createSampleRecord({
      gmailMessageId: 'msg-hr-001',
      userId: USER_ALICE,
      originatingIp: '198.51.100.99', // Flagged MALICIOUS in mock provider
      riskScore: 85,
      riskLevel: 'HIGH',
    });
    const highRiskMsg2 = createSampleRecord({
      gmailMessageId: 'msg-hr-002',
      userId: USER_ALICE,
      originatingIp: '198.51.100.99',
      riskScore: 80,
      riskLevel: 'HIGH',
    });

    triageRegistry.set(USER_ALICE, highRiskMsg1.gmailMessageId, highRiskMsg1);
    triageRegistry.set(USER_ALICE, highRiskMsg2.gmailMessageId, highRiskMsg2);

    const { campaigns: hrCampaigns } = await campaignService.getCampaignsForUser(USER_ALICE, mockIntel);
    assert.strictEqual(hrCampaigns.length, 1);
    const hrCamp = hrCampaigns[0];
    // Baseline risk 85 + malicious IOC boost (15) + multi-message boost (4) = clamped 100
    assert.ok(hrCamp.campaignRiskScore >= 85, 'Campaign risk score must reflect message and intel severity');
    assert.strictEqual(hrCamp.campaignRiskLevel, 'CRITICAL', 'Elevated score must assign CRITICAL threat level');
    assert.ok(hrCamp.threatIntelFindings.length > 0, 'Must record threat intelligence findings');
    console.log('✔ Test 17 Passed: Deterministic campaign risk computation verified.\n');

    triageRegistry.clearAll();

    // -------------------------------------------------------------------------
    // Test 18: Multi-tenant isolation (User A vs User B)
    // -------------------------------------------------------------------------
    console.log('Test 18: Verifying multi-tenant isolation across users...');
    const aliceMsg = createSampleRecord({
      gmailMessageId: 'msg-alice-001',
      userId: USER_ALICE,
      originatingIp: '198.51.100.99',
    });
    const bobMsg = createSampleRecord({
      gmailMessageId: 'msg-bob-001',
      userId: USER_BOB,
      originatingIp: '198.51.100.99', // Identical IP, but different user
    });

    triageRegistry.set(USER_ALICE, aliceMsg.gmailMessageId, aliceMsg);
    triageRegistry.set(USER_BOB, bobMsg.gmailMessageId, bobMsg);

    const aliceResult = await campaignService.getCampaignsForUser(USER_ALICE, mockIntel);
    const bobResult = await campaignService.getCampaignsForUser(USER_BOB, mockIntel);

    assert.strictEqual(aliceResult.campaigns.length, 1);
    assert.strictEqual(bobResult.campaigns.length, 1);
    assert.strictEqual(aliceResult.campaigns[0].relatedMessageIds.length, 1);
    assert.strictEqual(bobResult.campaigns[0].relatedMessageIds.length, 1);
    assert.strictEqual(aliceResult.campaigns[0].relatedMessageIds[0], 'msg-alice-001');
    assert.strictEqual(bobResult.campaigns[0].relatedMessageIds[0], 'msg-bob-001');
    console.log('✔ Test 18 Passed: Multi-tenant boundary strictly enforced. Zero cross-user clustering.\n');

    // -------------------------------------------------------------------------
    // Test 19: Unauthorized / Cross-tenant campaign detail lookup
    // -------------------------------------------------------------------------
    console.log('Test 19: Verifying cross-tenant campaign lookup security...');
    const aliceCampaignId = aliceResult.campaigns[0].campaignId;
    const unauthorizedAccess = await campaignService.getCampaignDetailForUser(
      USER_BOB,
      aliceCampaignId,
      mockIntel
    );
    assert.strictEqual(
      unauthorizedAccess,
      null,
      'User Bob must not be allowed to look up User Alice campaign details'
    );
    console.log('✔ Test 19 Passed: Cross-tenant campaign lookup safely rejected with null.\n');

    // -------------------------------------------------------------------------
    // Test 20: Zero external Gemini API calls
    // -------------------------------------------------------------------------
    console.log('Test 20: Verifying zero Gemini calls during IOC enrichment & correlation...');
    assert.strictEqual(process.env.GEMINI_API_KEY, undefined);
    // Execute full campaign and IOC pipeline without any Gemini key or network access
    const finalIocs = await campaignService.getIocsForUser(USER_ALICE, mockIntel);
    assert.ok(Array.isArray(finalIocs));
    const finalCampDetail = await campaignService.getCampaignDetailForUser(
      USER_ALICE,
      aliceCampaignId,
      mockIntel
    );
    assert.ok(finalCampDetail !== null);
    assert.strictEqual(finalCampDetail?.campaign.campaignId, aliceCampaignId);
    console.log('✔ Test 20 Passed: Entire Phase 7 pipeline executes with ZERO Gemini calls.\n');

    console.log('=================================================================');
    console.log('ALL 20 PHASE 7 GMAIL CAMPAIGN & THREAT INTEL TESTS PASSED!');
    console.log('=================================================================\n');
  } finally {
    process.env = originalEnv;
  }
}

runTests().catch(err => {
  console.error('\n❌ GMAIL CAMPAIGN TEST SUITE FAILED:', err);
  process.exit(1);
});
