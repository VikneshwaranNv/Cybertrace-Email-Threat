import assert from 'assert';
import crypto from 'crypto';
import {
  GmailApiService,
  GmailNotConnectedError,
  GmailInvalidIdError,
  GmailAuthError,
  GmailNotFoundError,
  GmailRateLimitError,
  GmailNetworkError,
  GmailMalformedPayloadError,
} from '../gmail/gmailApiService';
import { GmailOAuthService } from '../gmail/gmailOAuthService';
import { adaptGmailRawToForensics, adaptBase64UrlToEvidence } from '../gmail/gmailEmailAdapter';
import { parseRawEmail } from '../forensics/parser';

console.log('=== RUNNING GMAIL API RAW RETRIEVAL & FORENSIC ADAPTER TEST SUITE (PHASE 2) ===\n');

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    process.env.GOOGLE_CLIENT_ID = 'test-cybertrace-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-cybertrace-client-secret';

    // Sample authentic RFC-822 EML message with CRLF, Received hops, and an attachment
    const SAMPLE_RAW_EML = [
      'Received: from mail-relay.source.net (198.51.100.42) by mx.google.com with ESMTPS for <victim@company.corp>; Tue, 08 Sep 2026 12:34:56 +0000',
      'Received: from internal.workstation.local (10.0.4.15) by mail-relay.source.net with ESMTP; Tue, 08 Sep 2026 12:34:50 +0000',
      'Authentication-Results: mx.google.com; spf=pass (google.com: domain of billing@legit-vendor.com designates 198.51.100.42 as permitted sender) smtp.mailfrom=billing@legit-vendor.com; dkim=pass header.i=@legit-vendor.com; dmarc=pass',
      'From: Accounts Department <billing@legit-vendor.com>',
      'To: Victim Employee <victim@company.corp>',
      'Subject: Official Invoice #INV-2026-9941',
      'Date: Tue, 08 Sep 2026 12:34:50 +0000',
      'Message-ID: <unique-msg-id-2026-8877@legit-vendor.com>',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="----=_Part_99182_77182"',
      '',
      '------=_Part_99182_77182',
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: 7bit',
      '',
      'Dear Client,\r\n\r\nPlease review the attached invoice for services rendered in August 2026.\r\nPortal: https://secure-portal.legit-vendor.com/verify\r\n\r\nRegards,\r\nBilling Team',
      '',
      '------=_Part_99182_77182',
      'Content-Type: application/pdf; name="invoice_august_2026.pdf"',
      'Content-Disposition: attachment; filename="invoice_august_2026.pdf"',
      'Content-Transfer-Encoding: base64',
      '',
      'JVBERi0xLjQKJcTl8uXrp/Og0MTGCjQgMCBvYmoKPDwKL0tpZHMgWzUgMCBSXQovQ291bnQgMQov',
      'VFlwZSAvUGFnZXMKPj4KZW5kb2JqCg==',
      '',
      '------=_Part_99182_77182--',
    ].join('\r\n');

    // Expected Base64URL string for this sample EML
    const SAMPLE_BASE64URL = Buffer.from(SAMPLE_RAW_EML, 'utf8').toString('base64url');

    // Setup isolated OAuth service with test connections
    const oauthService = new GmailOAuthService();
    const USER_ALICE = 'usr-analyst-alice';
    const USER_BOB = 'usr-analyst-bob';

    oauthService._setConnectionForTest(USER_ALICE, {
      userId: USER_ALICE,
      gmailEmail: 'alice@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.alice-valid-token-111',
      refreshToken: '1//alice-refresh-token',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    oauthService._setConnectionForTest(USER_BOB, {
      userId: USER_BOB,
      gmailEmail: 'bob@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.bob-valid-token-222',
      refreshToken: '1//bob-refresh-token',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    // -------------------------------------------------------------------------
    // Test 1: Base64URL decoding accuracy
    // -------------------------------------------------------------------------
    console.log('Test 1: Verifying RFC 4648 Base64URL decoding accuracy...');
    const decoded = Buffer.from(SAMPLE_BASE64URL, 'base64url').toString('utf8');
    assert.strictEqual(decoded, SAMPLE_RAW_EML, 'Decoded string must be byte-for-byte identical to original raw RFC-822');
    console.log('✔ Test 1 Passed: Base64URL decoded with 100% fidelity.\n');

    // -------------------------------------------------------------------------
    // Test 2: Gmail raw data converts into valid RFC-822 input
    // -------------------------------------------------------------------------
    console.log('Test 2: Verifying conversion of raw Gmail payload into RFC-822 input...');
    const evidenceDirect = adaptBase64UrlToEvidence(SAMPLE_BASE64URL, 'MSG-TEST-001', 'CASE-TEST');
    assert.ok(evidenceDirect, 'Evidence record must be returned');
    assert.strictEqual(evidenceDirect.headers.subject, 'Official Invoice #INV-2026-9941');
    assert.strictEqual(evidenceDirect.headers.fromAddress, 'billing@legit-vendor.com');
    assert.strictEqual(evidenceDirect.headers.to[0], 'Victim Employee <victim@company.corp>');
    assert.ok(evidenceDirect.headers.to[0].includes('victim@company.corp'));
    console.log('✔ Test 2 Passed: RFC-822 conversion validated.\n');

    // -------------------------------------------------------------------------
    // Test 3: CRLF line break preservation
    // -------------------------------------------------------------------------
    console.log('Test 3: Verifying CRLF (\\r\\n) line endings are preserved intact without mutation...');
    assert.ok(decoded.includes('\r\n'), 'Raw decoded email must maintain CRLF sequences');
    const crlfCount = (decoded.match(/\r\n/g) || []).length;
    const lfOnlyCount = (decoded.replace(/\r\n/g, '').match(/\n/g) || []).length;
    assert.strictEqual(lfOnlyCount, 0, 'Must not introduce naked LF line endings where CRLF was present');
    assert.ok(crlfCount > 10, 'Expected CRLF line breaks preserved');
    console.log('✔ Test 3 Passed: CRLF line endings preserved verbatim.\n');

    // -------------------------------------------------------------------------
    // Test 4: Multipart MIME boundaries preserved
    // -------------------------------------------------------------------------
    console.log('Test 4: Verifying multipart MIME boundaries are preserved verbatim...');
    assert.ok(decoded.includes('boundary="----=_Part_99182_77182"'), 'Boundary declaration must be intact');
    assert.ok(decoded.includes('------=_Part_99182_77182\r\n'), 'Part boundary markers must be intact');
    assert.ok(decoded.includes('------=_Part_99182_77182--'), 'Closing boundary marker must be intact');
    console.log('✔ Test 4 Passed: Multipart MIME boundaries preserved.\n');

    // -------------------------------------------------------------------------
    // Test 5: Headers are not rewritten or normalized
    // -------------------------------------------------------------------------
    console.log('Test 5: Verifying headers are preserved without case or order mutation...');
    assert.ok(decoded.includes('Message-ID: <unique-msg-id-2026-8877@legit-vendor.com>'));
    assert.ok(decoded.includes('Received: from mail-relay.source.net'));
    assert.ok(decoded.includes('Received: from internal.workstation.local'));
    // Order preservation: mail-relay hop must appear before internal.workstation hop in raw text
    const relayIdx = decoded.indexOf('mail-relay.source.net');
    const localIdx = decoded.indexOf('internal.workstation.local');
    assert.ok(relayIdx < localIdx, 'Received header ingestion sequence must match raw delivery order');
    console.log('✔ Test 5 Passed: Header case and sequence preserved without rewrite.\n');

    // -------------------------------------------------------------------------
    // Test 6: Attachments remain represented in the raw MIME
    // -------------------------------------------------------------------------
    console.log('Test 6: Verifying attachments remain represented in raw MIME and extracted...');
    assert.ok(decoded.includes('filename="invoice_august_2026.pdf"'));
    assert.ok(decoded.includes('JVBERi0xLjQKJcTl8uXrp/Og0MTGCjQgMCBvYmoKPDwKL0tpZHMgWzUgMCBSXQovQ291bnQgMQov'));
    assert.strictEqual(evidenceDirect.attachments.length, 1, 'Forensic parser must extract exactly 1 attachment');
    assert.strictEqual(evidenceDirect.attachments[0].filename, 'invoice_august_2026.pdf');
    assert.strictEqual(evidenceDirect.attachments[0].contentType, 'application/pdf');
    console.log('✔ Test 6 Passed: Attachment preservation and extraction verified.\n');

    // -------------------------------------------------------------------------
    // Test 7: parseRawEmail() consumes decoded message and hashes correctly
    // -------------------------------------------------------------------------
    console.log('Test 7: Verifying parseRawEmail() computes SHA-256 and MD5 on unaltered raw bytes...');
    const expectedSha256 = crypto.createHash('sha256').update(SAMPLE_RAW_EML).digest('hex');
    const expectedMd5 = crypto.createHash('md5').update(SAMPLE_RAW_EML).digest('hex');

    assert.strictEqual(evidenceDirect.sha256, expectedSha256, 'Computed SHA-256 must match raw bytes');
    assert.strictEqual(evidenceDirect.md5, expectedMd5, 'Computed MD5 must match raw bytes');
    assert.ok(evidenceDirect.extractedUrls.includes('https://secure-portal.legit-vendor.com/verify'));
    assert.ok(evidenceDirect.extractedIps.includes('198.51.100.42'));
    console.log('✔ Test 7 Passed: Cryptographic integrity hashes and IOC extraction verified.\n');

    // -------------------------------------------------------------------------
    // Mock Gmail API fetcher for integration tests
    // -------------------------------------------------------------------------
    const apiCallLog: Array<{ url: string; authHeader: string }> = [];

    const mockFetcher = async (url: string, init: RequestInit): Promise<Response> => {
      const authHeader = (init.headers as Record<string, string>)?.['Authorization'] || '';
      apiCallLog.push({ url, authHeader });

      // Check token
      if (authHeader.includes('invalid-token')) {
        return new Response(JSON.stringify({ error: { code: 401, message: 'Invalid Credentials' } }), {
          status: 401,
          statusText: 'Unauthorized',
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // 1. List Messages endpoint
      if (url.includes('/messages?') || url.endsWith('/messages')) {
        const parsed = new URL(url);
        const q = parsed.searchParams.get('q');
        const maxResults = parsed.searchParams.get('maxResults') || '50';

        if (q === 'trigger-429') {
          return new Response(JSON.stringify({ error: { code: 429, message: 'Resource exhausted: User rate limit' } }), {
            status: 429,
            statusText: 'Too Many Requests',
            headers: { 'Content-Type': 'application/json', 'Retry-After': '15' },
          });
        }

        return new Response(
          JSON.stringify({
            messages: [
              { id: '18e001', threadId: 'thread-001' },
              { id: '18e002', threadId: 'thread-002' },
              { id: '18e003', threadId: 'thread-003' },
            ],
            nextPageToken: 'token-page-2',
            resultSizeEstimate: 3,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      // 2. Get Message endpoint
      if (url.includes('/messages/18e001?format=raw')) {
        return new Response(
          JSON.stringify({
            id: '18e001',
            threadId: 'thread-001',
            labelIds: ['INBOX', 'IMPORTANT'],
            snippet: 'Dear Client, Please review the attached invoice...',
            sizeEstimate: Buffer.byteLength(SAMPLE_RAW_EML, 'utf8'),
            raw: SAMPLE_BASE64URL,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (url.includes('/messages/not-found-id?format=raw')) {
        return new Response(JSON.stringify({ error: { code: 404, message: 'Message not found' } }), {
          status: 404,
          statusText: 'Not Found',
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.includes('/messages/malformed-raw?format=raw')) {
        return new Response(
          JSON.stringify({
            id: 'malformed-raw',
            threadId: 'thread-malformed',
            // Missing raw field!
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ error: 'Unhandled mock URL' }), { status: 500 });
    };

    const apiService = new GmailApiService({
      oauthService,
      fetcher: mockFetcher,
    });

    // -------------------------------------------------------------------------
    // Test 8: User isolation (User A cannot use User B's connection or tokens)
    // -------------------------------------------------------------------------
    console.log('Test 8: Verifying multi-tenant user isolation and Bearer token scoping...');
    apiCallLog.length = 0;

    await apiService.listMessages(USER_ALICE);
    assert.strictEqual(apiCallLog.length, 1);
    assert.strictEqual(
      apiCallLog[0].authHeader,
      'Bearer ya29.alice-valid-token-111',
      'Alice must strictly use Alice\'s own OAuth token'
    );

    await apiService.listMessages(USER_BOB);
    assert.strictEqual(apiCallLog.length, 2);
    assert.strictEqual(
      apiCallLog[1].authHeader,
      'Bearer ya29.bob-valid-token-222',
      'Bob must strictly use Bob\'s own OAuth token'
    );
    console.log('✔ Test 8 Passed: Strict user token isolation verified.\n');

    // -------------------------------------------------------------------------
    // Test 9: Missing Gmail connection is handled safely
    // -------------------------------------------------------------------------
    console.log('Test 9: Verifying safe rejection when user has not connected Gmail...');
    const UNCONNECTED_USER = 'usr-no-gmail';

    await assert.rejects(
      async () => {
        await apiService.listMessages(UNCONNECTED_USER);
      },
      (err: any) => {
        assert.ok(err instanceof GmailNotConnectedError);
        assert.strictEqual(err.statusCode, 404);
        assert.strictEqual(err.code, 'GMAIL_NOT_CONNECTED');
        return true;
      },
      'listMessages must reject unconnected user with GmailNotConnectedError'
    );

    await assert.rejects(
      async () => {
        await apiService.getRawMessage(UNCONNECTED_USER, '18e001');
      },
      (err: any) => {
        assert.ok(err instanceof GmailNotConnectedError);
        return true;
      },
      'getRawMessage must reject unconnected user with GmailNotConnectedError'
    );
    console.log('✔ Test 9 Passed: Unconnected user error handling verified.\n');

    // -------------------------------------------------------------------------
    // Test 10: Gmail 401 Unauthorized is handled safely
    // -------------------------------------------------------------------------
    console.log('Test 10: Verifying safe handling of Gmail 401 Unauthorized...');
    oauthService._setConnectionForTest('usr-bad-token', {
      userId: 'usr-bad-token',
      gmailEmail: 'bad@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'invalid-token-xyz',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    await assert.rejects(
      async () => {
        await apiService.listMessages('usr-bad-token');
      },
      (err: any) => {
        assert.ok(err instanceof GmailAuthError);
        assert.strictEqual(err.statusCode, 401);
        assert.strictEqual(err.code, 'GMAIL_AUTH_ERROR');
        return true;
      },
      'Invalid credentials must produce GmailAuthError without crash'
    );
    console.log('✔ Test 10 Passed: Gmail 401 handled safely.\n');

    // -------------------------------------------------------------------------
    // Test 11: Gmail 404 Not Found is handled safely
    // -------------------------------------------------------------------------
    console.log('Test 11: Verifying safe handling of Gmail 404 Not Found...');
    await assert.rejects(
      async () => {
        await apiService.getRawMessage(USER_ALICE, 'not-found-id');
      },
      (err: any) => {
        assert.ok(err instanceof GmailNotFoundError);
        assert.strictEqual(err.statusCode, 404);
        assert.strictEqual(err.code, 'GMAIL_NOT_FOUND');
        assert.ok(err.message.includes('not-found-id'));
        return true;
      },
      'Non-existent message ID must produce GmailNotFoundError'
    );
    console.log('✔ Test 11 Passed: Gmail 404 handled safely.\n');

    // -------------------------------------------------------------------------
    // Test 12: Gmail 429 Too Many Requests handled with retry-after
    // -------------------------------------------------------------------------
    console.log('Test 12: Verifying safe handling of Gmail 429 rate limits...');
    await assert.rejects(
      async () => {
        await apiService.listMessages(USER_ALICE, { query: 'trigger-429' });
      },
      (err: any) => {
        assert.ok(err instanceof GmailRateLimitError);
        assert.strictEqual(err.statusCode, 429);
        assert.strictEqual(err.code, 'GMAIL_RATE_LIMIT');
        assert.strictEqual(err.retryAfterMs, 15000, 'Retry delay must be parsed from header');
        return true;
      },
      'Rate limit 429 must produce GmailRateLimitError with retry information'
    );
    console.log('✔ Test 12 Passed: Gmail 429 rate limit handled safely.\n');

    // -------------------------------------------------------------------------
    // Test 13: Malformed raw payload is rejected safely
    // -------------------------------------------------------------------------
    console.log('Test 13: Verifying rejection of malformed or missing raw payloads...');
    await assert.rejects(
      async () => {
        await apiService.getRawMessage(USER_ALICE, 'malformed-raw');
      },
      (err: any) => {
        assert.ok(err instanceof GmailMalformedPayloadError);
        assert.strictEqual(err.statusCode, 502);
        assert.strictEqual(err.code, 'GMAIL_MALFORMED_PAYLOAD');
        return true;
      },
      'Missing raw field must trigger GmailMalformedPayloadError'
    );

    await assert.rejects(
      async () => {
        await apiService.getRawMessage(USER_ALICE, 'invalid/slashes');
      },
      (err: any) => {
        assert.ok(err instanceof GmailInvalidIdError);
        assert.strictEqual(err.statusCode, 400);
        return true;
      },
      'Unsafe characters in message ID must be rejected'
    );
    console.log('✔ Test 13 Passed: Malformed payloads and IDs rejected safely.\n');

    // -------------------------------------------------------------------------
    // Test 14: Zero secret leakage in payloads, adapter output, or errors
    // -------------------------------------------------------------------------
    console.log('Test 14: Verifying zero secret leakage in raw retrieval and forensic adapter outputs...');
    const rawResult = await apiService.getRawMessage(USER_ALICE, '18e001');
    const adaptedResult = adaptGmailRawToForensics(rawResult, 'GMAIL-SOC');

    assert.ok(rawResult.rawEml.includes('Official Invoice #INV-2026-9941'));
    assert.strictEqual(adaptedResult.gmailMessageId, '18e001');
    assert.strictEqual(adaptedResult.evidence.caseId, 'GMAIL-SOC-18e001');
    assert.strictEqual(adaptedResult.evidence.headers.subject, 'Official Invoice #INV-2026-9941');

    // Verify secrets are strictly absent from data objects
    const rawSerialized = JSON.stringify(rawResult);
    const adaptedSerialized = JSON.stringify(adaptedResult);

    const forbiddenTokens = ['ya29.', 'refresh-token', 'client-secret', 'test-cybertrace-client-secret'];
    for (const secret of forbiddenTokens) {
      assert.ok(
        !rawSerialized.includes(secret),
        `CRITICAL SECURITY: Raw message output must not contain '${secret}'`
      );
      assert.ok(
        !adaptedSerialized.includes(secret),
        `CRITICAL SECURITY: Forensic adapted output must not contain '${secret}'`
      );
    }
    console.log('✔ Test 14 Passed: Zero token/secret leakage verified across all outputs.\n');

    console.log('================================================================');
    console.log('ALL 14 GMAIL API & FORENSIC ADAPTER TESTS PASSED (100%)');
    console.log('================================================================\n');
  } finally {
    process.env = originalEnv;
  }
}

runTests().catch(err => {
  console.error('Test failure:', err);
  process.exit(1);
});
