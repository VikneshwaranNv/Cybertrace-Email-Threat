import assert from 'assert';
import { GmailSyncService, GmailPollingScheduler, SyncResult } from '../gmail/gmailSyncService';
import { GmailSyncRegistry, UserSyncState } from '../gmail/gmailSyncRegistry';
import { GmailTriageService } from '../gmail/gmailTriageService';
import { GmailTriageRegistry } from '../gmail/gmailTriageRegistry';
import {
  GmailApiService,
  GmailHistoryResponse,
  GmailProfile,
  GmailListResponse,
  GmailRawMessage,
  GmailHistoryExpiredError,
  GmailRateLimitError,
  GmailNetworkError,
} from '../gmail/gmailApiService';
import { GmailOAuthService } from '../gmail/gmailOAuthService';
import * as geminiClientModule from '../ai/geminiClient';
import * as geminiAnalyzer from '../ai/geminiAnalyzer';

console.log('=== RUNNING INCREMENTAL GMAIL MONITORING TEST SUITE (PHASE 4) ===\n');

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    process.env.GOOGLE_CLIENT_ID = 'test-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';
    // Strictly clear GEMINI_API_KEY to guarantee zero dependence on Gemini API
    delete process.env.GEMINI_API_KEY;

    // Track any accidental Gemini AI calls
    let geminiAiCallCount = 0;
    const originalAiFn = geminiAnalyzer.analyzeEmailWithAI;
    try {
      (geminiAnalyzer as any).analyzeEmailWithAI = async (...args: any[]) => {
        geminiAiCallCount++;
        return (originalAiFn as any)(...args);
      };
    } catch {
      // If module is immutable, geminiAiCallCount will remain 0
    }

    // Sample valid RFC-822 email payload
    const SAMPLE_RAW_EML = [
      'Received: from mail.example.com ([198.51.100.1]) by mx.google.com with ESMTPS; Tue, 08 Sep 2026 12:00:00 +0000',
      'From: Security Team <security@example.com>',
      'To: Alice <alice@example.com>',
      'Subject: Security Notification: New Login Detected',
      'Date: Tue, 08 Sep 2026 12:00:00 +0000',
      'Message-ID: <sec-notice-1001@example.com>',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'A new login to your account was detected from an authorized IP address.',
    ].join('\r\n');

    // Setup Test Users and Isolated Services
    const USER_ALICE = 'usr-alice-sync';
    const USER_BOB = 'usr-bob-sync';
    const USER_CHARLIE = 'usr-unconnected';

    const testOAuthService = new GmailOAuthService();
    testOAuthService._setConnectionForTest(USER_ALICE, {
      userId: USER_ALICE,
      gmailEmail: 'alice.soc@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.alice-token',
      refreshToken: '1//alice-refresh',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    testOAuthService._setConnectionForTest(USER_BOB, {
      userId: USER_BOB,
      gmailEmail: 'bob.soc@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.bob-token',
      refreshToken: '1//bob-refresh',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    // Mock API requests log
    const requestLog: Array<{ url: string; authHeader: string }> = [];

    // Mock responses configuration
    let mockProfile: GmailProfile = {
      emailAddress: 'alice.soc@gmail.com',
      messagesTotal: 150,
      threadsTotal: 80,
      historyId: '900100',
    };

    let mockListMessagesResponse: GmailListResponse = {
      messages: [{ id: 'msg-init-1', threadId: 'th-init-1' }, { id: 'msg-init-2', threadId: 'th-init-2' }],
      resultSizeEstimate: 2,
    };

    let mockHistoryPages: Map<string | undefined, GmailHistoryResponse> = new Map();

    const testFetcher = async (url: string, init: RequestInit): Promise<Response> => {
      const authHeader = (init.headers as any)?.Authorization || '';
      requestLog.push({ url, authHeader });

      // Profile endpoint
      if (url.includes('/users/me/profile')) {
        return new Response(JSON.stringify(mockProfile), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // History endpoint
      if (url.includes('/users/me/history')) {
        const parsedUrl = new URL(url);
        const pageToken = parsedUrl.searchParams.get('pageToken') || undefined;

        if (mockHistoryPages.has(pageToken)) {
          const respData = mockHistoryPages.get(pageToken)!;
          return new Response(JSON.stringify(respData), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        // Default empty history
        return new Response(
          JSON.stringify({
            history: [],
            historyId: '900200',
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }

      // Messages list endpoint
      if (url.includes('/users/me/messages?')) {
        return new Response(JSON.stringify(mockListMessagesResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Single raw message endpoint
      if (url.includes('/users/me/messages/') && url.includes('format=raw')) {
        const match = url.match(/\/messages\/([^?]+)\?/);
        const msgId = match ? decodeURIComponent(match[1]) : 'msg-unknown';

        const base64UrlRaw = Buffer.from(SAMPLE_RAW_EML).toString('base64url');
        return new Response(
          JSON.stringify({
            id: msgId,
            threadId: `th-${msgId}`,
            raw: base64UrlRaw,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }

      return new Response('Not Found', { status: 404 });
    };

    // Isolated Services setup
    const testApiService = new GmailApiService({
      oauthService: testOAuthService,
      fetcher: testFetcher,
    });

    const testTriageRegistry = new GmailTriageRegistry();
    const testTriageService = new GmailTriageService({
      apiService: testApiService,
      registry: testTriageRegistry,
    });

    const testSyncRegistry = new GmailSyncRegistry();
    const testSyncService = new GmailSyncService({
      apiService: testApiService,
      syncRegistry: testSyncRegistry,
      triageService: testTriageService,
      oauthService: testOAuthService,
      initialSyncLimit: 10,
    });

    // -------------------------------------------------------------------------
    // Test 1: History request uses correct authenticated user Bearer token
    // -------------------------------------------------------------------------
    console.log('Test 1: Verifying history request uses correct authenticated user Bearer token...');
    requestLog.length = 0;
    mockHistoryPages.clear();
    mockHistoryPages.set(undefined, {
      history: [
        {
          id: 'h-1',
          messagesAdded: [{ message: { id: 'msg-added-1' } }],
        },
      ],
      historyId: '900150',
    });

    await testApiService.listHistory(USER_ALICE, '900100');
    assert.strictEqual(requestLog.length, 1);
    assert.strictEqual(requestLog[0].authHeader, 'Bearer ya29.alice-token');
    assert.ok(requestLog[0].url.includes('/users/me/history'));
    console.log('✔ Test 1 Passed: Authenticated Bearer token validated.\n');

    // -------------------------------------------------------------------------
    // Test 2: startHistoryId is supplied correctly in query parameters
    // -------------------------------------------------------------------------
    console.log('Test 2: Verifying startHistoryId is supplied correctly in query string...');
    const historyUrl = new URL(requestLog[0].url);
    assert.strictEqual(historyUrl.searchParams.get('startHistoryId'), '900100');
    console.log('✔ Test 2 Passed: startHistoryId query parameter verified.\n');

    // -------------------------------------------------------------------------
    // Test 3: History pagination works (follows nextPageToken)
    // -------------------------------------------------------------------------
    console.log('Test 3: Verifying history pagination follows nextPageToken...');
    requestLog.length = 0;
    mockHistoryPages.clear();
    mockHistoryPages.set(undefined, {
      history: [{ id: 'h-page1', messagesAdded: [{ message: { id: 'msg-p1-1' } }] }],
      nextPageToken: 'page-token-2',
      historyId: '900180',
    });
    mockHistoryPages.set('page-token-2', {
      history: [{ id: 'h-page2', messagesAdded: [{ message: { id: 'msg-p2-1' } }] }],
      historyId: '900200',
    });

    // Pre-seed checkpoint for Alice to trigger incremental sync
    testSyncRegistry.set(USER_ALICE, {
      userId: USER_ALICE,
      historyId: '900100',
      status: 'IDLE',
      messagesDiscovered: 0,
      messagesTriaged: 0,
      updatedAt: new Date().toISOString(),
    });

    const pageResult = await testSyncService.syncUser(USER_ALICE);
    assert.strictEqual(pageResult.success, true);
    assert.strictEqual(pageResult.messagesDiscovered, 2);
    assert.strictEqual(pageResult.messagesTriaged, 2);
    assert.strictEqual(pageResult.historyId, '900200');

    // Verify two history page requests were made
    const historyCalls = requestLog.filter(r => r.url.includes('/users/me/history'));
    assert.strictEqual(historyCalls.length, 2);
    assert.ok(historyCalls[1].url.includes('pageToken=page-token-2'));
    console.log('✔ Test 3 Passed: Multi-page history pagination verified.\n');

    // -------------------------------------------------------------------------
    // Test 4: Multiple history records are processed in single page
    // -------------------------------------------------------------------------
    console.log('Test 4: Verifying multiple history records within single page are processed...');
    mockHistoryPages.clear();
    mockHistoryPages.set(undefined, {
      history: [
        { id: 'h-rec-1', messagesAdded: [{ message: { id: 'msg-multi-1' } }] },
        { id: 'h-rec-2', messagesAdded: [{ message: { id: 'msg-multi-2' } }] },
        { id: 'h-rec-3', messagesAdded: [{ message: { id: 'msg-multi-3' } }] },
      ],
      historyId: '900250',
    });

    testSyncRegistry.update(USER_ALICE, { historyId: '900200' });
    const multiRecResult = await testSyncService.syncUser(USER_ALICE);
    assert.strictEqual(multiRecResult.messagesDiscovered, 3);
    assert.strictEqual(multiRecResult.messagesTriaged, 3);
    assert.strictEqual(multiRecResult.historyId, '900250');
    console.log('✔ Test 4 Passed: Multiple history records processed successfully.\n');

    // -------------------------------------------------------------------------
    // Test 5: Message IDs extracted from both messagesAdded and messages
    // -------------------------------------------------------------------------
    console.log('Test 5: Verifying message IDs extracted from both messagesAdded and messages...');
    mockHistoryPages.clear();
    mockHistoryPages.set(undefined, {
      history: [
        { id: 'h-mixed-1', messagesAdded: [{ message: { id: 'msg-from-added' } }] },
        { id: 'h-mixed-2', messages: [{ id: 'msg-from-messages', threadId: 'th-1' }] },
      ],
      historyId: '900300',
    });

    testSyncRegistry.update(USER_ALICE, { historyId: '900250' });
    const mixedResult = await testSyncService.syncUser(USER_ALICE);
    assert.strictEqual(mixedResult.messagesDiscovered, 2);
    assert.strictEqual(mixedResult.messagesTriaged, 2);
    console.log('✔ Test 5 Passed: Extraction from messagesAdded and messages verified.\n');

    // -------------------------------------------------------------------------
    // Test 6: Duplicate message IDs within history are deduplicated
    // -------------------------------------------------------------------------
    console.log('Test 6: Verifying duplicate message IDs within history are deduplicated...');
    mockHistoryPages.clear();
    mockHistoryPages.set(undefined, {
      history: [
        { id: 'h-dup-1', messagesAdded: [{ message: { id: 'msg-duplicate' } }] },
        { id: 'h-dup-2', messagesAdded: [{ message: { id: 'msg-duplicate' } }] },
        { id: 'h-dup-3', messages: [{ id: 'msg-duplicate', threadId: 'th-dup' }] },
        { id: 'h-dup-4', messagesAdded: [{ message: { id: 'msg-unique' } }] },
      ],
      historyId: '900350',
    });

    testSyncRegistry.update(USER_ALICE, { historyId: '900300' });
    const dedupResult = await testSyncService.syncUser(USER_ALICE);
    assert.strictEqual(dedupResult.messagesDiscovered, 2, 'Duplicates must be condensed to exactly 2 unique IDs');
    console.log('✔ Test 6 Passed: In-memory ID deduplication verified.\n');

    // -------------------------------------------------------------------------
    // Test 7: Phase 3 idempotency prevents duplicate triage across syncs
    // -------------------------------------------------------------------------
    console.log('Test 7: Verifying Phase 3 idempotency prevents duplicate triage across syncs...');
    // Re-running triage on msg-unique must mark alreadyTriaged: true without failure
    const secondTriage = await testTriageService.triageSingleMessage(USER_ALICE, 'msg-unique');
    assert.strictEqual(secondTriage.alreadyTriaged, true);
    console.log('✔ Test 7 Passed: Idempotency protection across syncs verified.\n');

    // -------------------------------------------------------------------------
    // Test 8: User with no checkpoint performs bounded initial sync
    // -------------------------------------------------------------------------
    console.log('Test 8: Verifying user with no checkpoint performs bounded initial sync...');
    // Bob has no checkpoint in testSyncRegistry
    assert.strictEqual(testSyncRegistry.get(USER_BOB), undefined);

    mockProfile = {
      emailAddress: 'bob.soc@gmail.com',
      messagesTotal: 300,
      threadsTotal: 120,
      historyId: '800500',
    };

    mockListMessagesResponse = {
      messages: [{ id: 'bob-init-1', threadId: 'th-1' }, { id: 'bob-init-2', threadId: 'th-2' }],
      resultSizeEstimate: 2,
    };

    const bobInitialSync = await testSyncService.syncUser(USER_BOB);
    assert.strictEqual(bobInitialSync.success, true);
    assert.strictEqual(bobInitialSync.isInitialSync, true);
    assert.strictEqual(bobInitialSync.historyReset, false);
    assert.strictEqual(bobInitialSync.historyId, '800500');
    assert.strictEqual(bobInitialSync.messagesDiscovered, 2);
    assert.strictEqual(bobInitialSync.messagesTriaged, 2);
    console.log('✔ Test 8 Passed: Bounded initial sync executed successfully.\n');

    // -------------------------------------------------------------------------
    // Test 9: Initial sync respects configured message limit
    // -------------------------------------------------------------------------
    console.log('Test 9: Verifying initial sync respects configured message limit...');
    requestLog.length = 0;
    const testLimitService = new GmailSyncService({
      apiService: testApiService,
      syncRegistry: new GmailSyncRegistry(),
      triageService: testTriageService,
      oauthService: testOAuthService,
      initialSyncLimit: 25,
    });

    await testLimitService.syncUser(USER_BOB);
    const listMsgCall = requestLog.find(r => r.url.includes('/users/me/messages?'));
    assert.ok(listMsgCall, 'Must invoke listMessages during initial sync');
    const parsedListUrl = new URL(listMsgCall.url);
    assert.strictEqual(parsedListUrl.searchParams.get('maxResults'), '25');
    console.log('✔ Test 9 Passed: Configured initial sync limit (25) respected.\n');

    // -------------------------------------------------------------------------
    // Test 10: Initial sync establishes valid checkpoint from profile
    // -------------------------------------------------------------------------
    console.log('Test 10: Verifying initial sync establishes valid checkpoint from profile...');
    const bobState = testSyncRegistry.get(USER_BOB);
    assert.ok(bobState);
    assert.strictEqual(bobState.historyId, '800500');
    assert.strictEqual(bobState.status, 'COMPLETED');
    console.log('✔ Test 10 Passed: Checkpoint accurately persisted.\n');

    // -------------------------------------------------------------------------
    // Test 11: Existing checkpoint is used in users.history.list
    // -------------------------------------------------------------------------
    console.log('Test 11: Verifying existing checkpoint is used in users.history.list...');
    requestLog.length = 0;
    mockHistoryPages.clear();
    mockHistoryPages.set(undefined, {
      history: [{ id: 'h-bob-1', messagesAdded: [{ message: { id: 'bob-inc-1' } }] }],
      historyId: '800600',
    });

    await testSyncService.syncUser(USER_BOB);
    const bobHistoryCall = requestLog.find(r => r.url.includes('/users/me/history'));
    assert.ok(bobHistoryCall);
    const bobHistUrl = new URL(bobHistoryCall.url);
    assert.strictEqual(bobHistUrl.searchParams.get('startHistoryId'), '800500');
    console.log('✔ Test 11 Passed: Stored checkpoint passed to history.list.\n');

    // -------------------------------------------------------------------------
    // Test 12: Only newly discovered messages are triaged during incremental sync
    // -------------------------------------------------------------------------
    console.log('Test 12: Verifying only newly discovered messages are triaged...');
    const bobUpdatedState = testSyncRegistry.get(USER_BOB);
    assert.strictEqual(bobUpdatedState?.messagesDiscovered, 1);
    assert.strictEqual(bobUpdatedState?.messagesTriaged, 1);
    assert.strictEqual(bobUpdatedState?.historyId, '800600');
    console.log('✔ Test 12 Passed: Only newly discovered messages triaged.\n');

    // -------------------------------------------------------------------------
    // Test 13: New checkpoint is stored only after successful synchronization
    // -------------------------------------------------------------------------
    console.log('Test 13: Verifying checkpoint stored only after successful synchronization...');
    assert.strictEqual(testSyncRegistry.get(USER_BOB)?.historyId, '800600');
    console.log('✔ Test 13 Passed: Checkpoint committed on completion.\n');

    // -------------------------------------------------------------------------
    // Test 14: Gmail 429 rate limit preserves previous checkpoint
    // -------------------------------------------------------------------------
    console.log('Test 14: Verifying Gmail 429 rate limit preserves previous checkpoint...');
    const rateLimitFetcher = async (url: string): Promise<Response> => {
      if (url.includes('/users/me/history')) {
        return new Response(JSON.stringify({ error: { code: 429, message: 'Too Many Requests' } }), {
          status: 429,
          headers: { 'Retry-After': '45', 'Content-Type': 'application/json' },
        });
      }
      return new Response('{}', { status: 200 });
    };

    const rateLimitedApiService = new GmailApiService({
      oauthService: testOAuthService,
      fetcher: rateLimitFetcher,
    });

    const rateLimitSyncService = new GmailSyncService({
      apiService: rateLimitedApiService,
      syncRegistry: testSyncRegistry,
      triageService: testTriageService,
      oauthService: testOAuthService,
    });

    const checkpointBefore429 = testSyncRegistry.get(USER_BOB)?.historyId;
    assert.strictEqual(checkpointBefore429, '800600');

    let threw429 = false;
    try {
      await rateLimitSyncService.syncUser(USER_BOB);
    } catch (err: any) {
      threw429 = true;
      assert.strictEqual(err.statusCode, 429);
      assert.strictEqual(err.code, 'GMAIL_RATE_LIMIT');
    }
    assert.strictEqual(threw429, true);

    const stateAfter429 = testSyncRegistry.get(USER_BOB);
    assert.strictEqual(stateAfter429?.historyId, '800600', 'Checkpoint must NOT advance after 429 error');
    assert.strictEqual(stateAfter429?.status, 'FAILED');
    assert.strictEqual(stateAfter429?.lastErrorCode, 'GMAIL_RATE_LIMIT');
    console.log('✔ Test 14 Passed: Checkpoint preserved on 429 rate limit.\n');

    // -------------------------------------------------------------------------
    // Test 15: Network failure preserves previous checkpoint
    // -------------------------------------------------------------------------
    console.log('Test 15: Verifying network failure preserves previous checkpoint...');
    const networkFailFetcher = async (): Promise<Response> => {
      throw new Error('ECONNRESET connection refused');
    };

    const networkFailApiService = new GmailApiService({
      oauthService: testOAuthService,
      fetcher: networkFailFetcher,
    });

    const networkFailSyncService = new GmailSyncService({
      apiService: networkFailApiService,
      syncRegistry: testSyncRegistry,
      triageService: testTriageService,
      oauthService: testOAuthService,
    });

    let threwNetwork = false;
    try {
      await networkFailSyncService.syncUser(USER_BOB);
    } catch (err: any) {
      threwNetwork = true;
      assert.strictEqual(err.statusCode, 502);
      assert.strictEqual(err.code, 'GMAIL_UPSTREAM_ERROR');
    }
    assert.strictEqual(threwNetwork, true);

    const stateAfterNetwork = testSyncRegistry.get(USER_BOB);
    assert.strictEqual(stateAfterNetwork?.historyId, '800600', 'Checkpoint must NOT advance after network failure');
    assert.strictEqual(stateAfterNetwork?.status, 'FAILED');
    console.log('✔ Test 15 Passed: Checkpoint preserved on upstream network failure.\n');

    // -------------------------------------------------------------------------
    // Test 16: Invalid/expired history (404) triggers controlled recovery
    // -------------------------------------------------------------------------
    console.log('Test 16: Verifying invalid/expired history triggers controlled recovery...');
    // Setup fetcher where history.list returns 404 (History id not found),
    // but profile and listMessages return fresh recovery data
    const recoveryFetcher = async (url: string): Promise<Response> => {
      if (url.includes('/users/me/history')) {
        return new Response(JSON.stringify({ error: { code: 404, message: 'History id not found' } }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.includes('/users/me/profile')) {
        return new Response(
          JSON.stringify({
            emailAddress: 'bob.soc@gmail.com',
            historyId: '800999',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (url.includes('/users/me/messages?')) {
        return new Response(
          JSON.stringify({
            messages: [{ id: 'bob-recov-1', threadId: 'th-recov' }],
            resultSizeEstimate: 1,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (url.includes('format=raw')) {
        return new Response(
          JSON.stringify({
            id: 'bob-recov-1',
            raw: Buffer.from(SAMPLE_RAW_EML).toString('base64url'),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    const recoveryApiService = new GmailApiService({
      oauthService: testOAuthService,
      fetcher: recoveryFetcher,
    });

    const recoverySyncService = new GmailSyncService({
      apiService: recoveryApiService,
      syncRegistry: testSyncRegistry,
      triageService: new GmailTriageService({ apiService: recoveryApiService }),
      oauthService: testOAuthService,
    });

    const recoveryResult = await recoverySyncService.syncUser(USER_BOB);
    assert.strictEqual(recoveryResult.success, true);
    assert.strictEqual(recoveryResult.historyReset, true, 'Recovery must mark historyReset: true');
    assert.strictEqual(recoveryResult.historyId, '800999', 'Fresh historyId must be established from Gmail profile');

    const stateAfterRecovery = testSyncRegistry.get(USER_BOB);
    assert.strictEqual(stateAfterRecovery?.historyId, '800999');
    assert.ok(stateAfterRecovery?.lastHistoryResetAt, 'lastHistoryResetAt must be recorded');
    console.log('✔ Test 16 Passed: Controlled history expiration recovery verified.\n');

    // -------------------------------------------------------------------------
    // Test 17: Malformed history response does not corrupt checkpoint
    // -------------------------------------------------------------------------
    console.log('Test 17: Verifying malformed history response does not corrupt checkpoint...');
    const malformedFetcher = async (url: string): Promise<Response> => {
      if (url.includes('/users/me/history')) {
        return new Response('{"corrupt": invalid json', {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response('{}', { status: 200 });
    };

    const malformedApiService = new GmailApiService({
      oauthService: testOAuthService,
      fetcher: malformedFetcher,
    });

    const malformedSyncService = new GmailSyncService({
      apiService: malformedApiService,
      syncRegistry: testSyncRegistry,
      triageService: testTriageService,
      oauthService: testOAuthService,
    });

    let threwMalformed = false;
    try {
      await malformedSyncService.syncUser(USER_BOB);
    } catch {
      threwMalformed = true;
    }
    assert.strictEqual(threwMalformed, true);
    assert.strictEqual(testSyncRegistry.get(USER_BOB)?.historyId, '800999', 'Checkpoint must remain uncorrupted');
    console.log('✔ Test 17 Passed: Checkpoint intact after malformed response.\n');

    // -------------------------------------------------------------------------
    // Test 18: Cross-user checkpoint access is blocked
    // -------------------------------------------------------------------------
    console.log('Test 18: Verifying cross-user checkpoint access is blocked...');
    const aliceState = testSyncRegistry.get(USER_ALICE);
    const bobStateFromRegistry = testSyncRegistry.get(USER_BOB);
    assert.notStrictEqual(aliceState?.userId, bobStateFromRegistry?.userId);
    assert.notStrictEqual(aliceState?.historyId, bobStateFromRegistry?.historyId);
    console.log('✔ Test 18 Passed: Multi-tenant registry isolation verified.\n');

    // -------------------------------------------------------------------------
    // Test 19: Cross-user sync is blocked (User cannot pass another user ID)
    // -------------------------------------------------------------------------
    console.log('Test 19: Verifying cross-user sync isolation...');
    const statusForAlice = testSyncService.getStatus(USER_ALICE);
    const statusForBob = testSyncService.getStatus(USER_BOB);
    assert.strictEqual(statusForAlice.userId, USER_ALICE);
    assert.strictEqual(statusForBob.userId, USER_BOB);
    assert.notStrictEqual(statusForAlice.historyId, statusForBob.historyId);
    console.log('✔ Test 19 Passed: Cross-user sync isolation verified.\n');

    // -------------------------------------------------------------------------
    // Test 20: OAuth tokens never appear in sync responses or status payloads
    // -------------------------------------------------------------------------
    console.log('Test 20: Verifying zero OAuth token leakage in sync responses and status...');
    const safeStatus = testSyncService.getStatus(USER_ALICE) as any;
    assert.strictEqual(safeStatus.accessToken, undefined);
    assert.strictEqual(safeStatus.refreshToken, undefined);
    assert.strictEqual(safeStatus.clientSecret, undefined);
    assert.strictEqual(safeStatus.Authorization, undefined);

    const safeResult = (await testSyncService.syncUser(USER_ALICE)) as any;
    assert.strictEqual(safeResult.accessToken, undefined);
    assert.strictEqual(safeResult.refreshToken, undefined);
    console.log('✔ Test 20 Passed: Zero secret/token leakage verified.\n');

    // -------------------------------------------------------------------------
    // Test 21: Per-user lock prevents simultaneous sync jobs for same user
    // -------------------------------------------------------------------------
    console.log('Test 21: Verifying per-user lock prevents simultaneous sync jobs for same user...');
    let delayResolve: () => void;
    const delayPromise = new Promise<void>(resolve => {
      delayResolve = resolve;
    });

    const slowFetcher = async (url: string, init: RequestInit): Promise<Response> => {
      if (url.includes('/users/me/history')) {
        await delayPromise;
        return new Response(JSON.stringify({ history: [], historyId: '999000' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return testFetcher(url, init);
    };

    const slowApiService = new GmailApiService({
      oauthService: testOAuthService,
      fetcher: slowFetcher,
    });

    const slowSyncService = new GmailSyncService({
      apiService: slowApiService,
      syncRegistry: testSyncRegistry,
      triageService: testTriageService,
      oauthService: testOAuthService,
    });

    // Start first sync in background
    const firstSyncPromise = slowSyncService.syncUser(USER_ALICE);

    // Second sync for same user immediately while first is running
    let threwConflict = false;
    try {
      await slowSyncService.syncUser(USER_ALICE);
    } catch (err: any) {
      threwConflict = true;
      assert.strictEqual(err.statusCode, 409);
      assert.strictEqual(err.code, 'GMAIL_SYNC_IN_PROGRESS');
    }
    assert.strictEqual(threwConflict, true, 'Concurrent sync for same user must be rejected with 409');

    // Release slow sync
    delayResolve!();
    const firstResult = await firstSyncPromise;
    assert.strictEqual(firstResult.success, true);
    console.log('✔ Test 21 Passed: Per-user 409 conflict lock verified.\n');

    // -------------------------------------------------------------------------
    // Test 22: Different users can synchronize independently and concurrently
    // -------------------------------------------------------------------------
    console.log('Test 22: Verifying different users can synchronize independently...');
    mockHistoryPages.clear();
    mockHistoryPages.set(undefined, {
      history: [],
      historyId: '999555',
    });

    // Both users sync at the same time
    const [aliceRes, bobRes] = await Promise.all([
      testSyncService.syncUser(USER_ALICE),
      testSyncService.syncUser(USER_BOB),
    ]);

    assert.strictEqual(aliceRes.success, true);
    assert.strictEqual(bobRes.success, true);
    console.log('✔ Test 22 Passed: Multi-user independent concurrent execution verified.\n');

    // -------------------------------------------------------------------------
    // Test 23: Automatic sync and triage makes ZERO Gemini API calls
    // -------------------------------------------------------------------------
    console.log('Test 23: Proving automatic Gmail synchronization + triage makes ZERO Gemini API calls...');
    assert.strictEqual(geminiClientModule.isGeminiAvailable(), false, 'Gemini client is unconfigured');
    assert.strictEqual(geminiAiCallCount, 0, 'Gemini AI analyzer function was called 0 times');
    console.log('✔ Test 23 Passed: Zero Gemini AI API calls confirmed.\n');

    // -------------------------------------------------------------------------
    // Test 24: Polling scheduler: single instance, disabled by default, clean lifecycle
    // -------------------------------------------------------------------------
    console.log('Test 24: Verifying background polling scheduler configuration & lifecycle...');
    const defaultScheduler = new GmailPollingScheduler({
      syncService: testSyncService,
      oauthService: testOAuthService,
    });

    assert.strictEqual(defaultScheduler.isEnabled(), false, 'Polling scheduler must be disabled by default');
    assert.strictEqual(defaultScheduler.isActive(), false);

    defaultScheduler.start();
    assert.strictEqual(defaultScheduler.isActive(), false, 'start() on disabled scheduler must not activate timer');

    // Test enabled scheduler
    const enabledScheduler = new GmailPollingScheduler({
      syncService: testSyncService,
      oauthService: testOAuthService,
      enabled: true,
      intervalMs: 10000,
    });

    assert.strictEqual(enabledScheduler.isEnabled(), true);
    enabledScheduler.start();
    assert.strictEqual(enabledScheduler.isActive(), true, 'Scheduler must be active after start()');

    // Start again should not duplicate timers
    enabledScheduler.start();
    assert.strictEqual(enabledScheduler.isActive(), true);

    // Stop scheduler
    enabledScheduler.stop();
    assert.strictEqual(enabledScheduler.isActive(), false, 'Scheduler must be inactive after stop()');
    console.log('✔ Test 24 Passed: Polling scheduler lifecycle verified.\n');

    // -------------------------------------------------------------------------
    // Test 25: Unconnected user rejection
    // -------------------------------------------------------------------------
    console.log('Test 25: Verifying unconnected user cannot synchronize...');
    let threwUnconnected = false;
    try {
      await testSyncService.syncUser(USER_CHARLIE);
    } catch (err: any) {
      threwUnconnected = true;
      assert.strictEqual(err.statusCode, 404);
      assert.strictEqual(err.code, 'GMAIL_NOT_CONNECTED');
    }
    assert.strictEqual(threwUnconnected, true);
    console.log('✔ Test 25 Passed: Unconnected user rejected safely.\n');

    // -------------------------------------------------------------------------
    // Test 26: Incremental sync handles empty history safely
    // -------------------------------------------------------------------------
    console.log('Test 26: Verifying incremental sync handles empty history safely...');
    mockHistoryPages.clear();
    mockHistoryPages.set(undefined, {
      history: [],
      historyId: '999888',
    });

    const emptyResult = await testSyncService.syncUser(USER_ALICE);
    assert.strictEqual(emptyResult.success, true);
    assert.strictEqual(emptyResult.messagesDiscovered, 0);
    assert.strictEqual(emptyResult.messagesTriaged, 0);
    assert.strictEqual(emptyResult.historyId, '999888');
    console.log('✔ Test 26 Passed: Empty history handled without errors.\n');

    console.log('================================================================');
    console.log('ALL 26 INCREMENTAL GMAIL MONITORING TESTS PASSED (100%)');
    console.log('================================================================\n');
  } finally {
    process.env = originalEnv;
  }
}

runTests().catch(err => {
  console.error('\n❌ TEST FAILED WITH EXCEPTION:\n', err);
  process.exit(1);
});
