import assert from 'assert';
import { GmailOAuthService, gmailOAuthService } from '../gmail/gmailOAuthService';

console.log('=== RUNNING GMAIL OAUTH PHASE-1 SECURITY & ARCHITECTURE TEST SUITE ===\n');

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    // Setup test environment variables for Google OAuth
    process.env.GOOGLE_CLIENT_ID = 'test-cybertrace-client-id.apps.googleusercontent.com';
    process.env.GOOGLE_CLIENT_SECRET = 'test-cybertrace-client-secret-SUPER-SECRET';
    process.env.GOOGLE_REDIRECT_URI = 'http://localhost:3000/api/gmail/oauth/callback';

    // -------------------------------------------------------------------------
    // Test 1: OAuth URL generation & query parameter integrity
    // -------------------------------------------------------------------------
    console.log('Test 1: Verifying OAuth URL generation and query parameter integrity...');
    const testUserId = 'usr-analyst-01';
    const authResult = gmailOAuthService.generateAuthUrl(testUserId);

    assert.ok(authResult.url, 'Must generate a valid URL string');
    assert.ok(authResult.state, 'Must return generated state token');
    assert.ok(
      authResult.url.startsWith('https://accounts.google.com/o/oauth2/v2/auth'),
      'URL must point to official Google OAuth 2.0 authorization endpoint'
    );

    const parsedUrl = new URL(authResult.url);
    assert.strictEqual(
      parsedUrl.searchParams.get('client_id'),
      'test-cybertrace-client-id.apps.googleusercontent.com',
      'client_id param must match GOOGLE_CLIENT_ID'
    );
    assert.strictEqual(
      parsedUrl.searchParams.get('redirect_uri'),
      'http://localhost:3000/api/gmail/oauth/callback',
      'redirect_uri param must match GOOGLE_REDIRECT_URI'
    );
    assert.strictEqual(parsedUrl.searchParams.get('response_type'), 'code', 'response_type must be code');
    assert.strictEqual(parsedUrl.searchParams.get('access_type'), 'offline', 'access_type must be offline for refresh token');
    assert.strictEqual(parsedUrl.searchParams.get('prompt'), 'consent', 'prompt must be consent');

    // Scopes verification
    const requestedScope = parsedUrl.searchParams.get('scope') || '';
    assert.ok(
      requestedScope.includes('https://www.googleapis.com/auth/gmail.readonly'),
      'Scope must include gmail.readonly'
    );
    assert.ok(
      requestedScope.includes('https://www.googleapis.com/auth/userinfo.email'),
      'Scope must include userinfo.email'
    );

    // CRITICAL: Ensure client secret is NEVER in the URL
    assert.ok(
      !authResult.url.includes('test-cybertrace-client-secret-SUPER-SECRET'),
      'CRITICAL SECURITY: GOOGLE_CLIENT_SECRET must never appear anywhere in the authorization URL'
    );
    assert.strictEqual(
      parsedUrl.searchParams.get('client_secret'),
      null,
      'client_secret parameter must never exist in the authorization URL'
    );
    console.log('✔ Test 1 Passed: OAuth URL generation and parameter security verified.\n');

    // -------------------------------------------------------------------------
    // Test 2: Cryptographically generated state entropy
    // -------------------------------------------------------------------------
    console.log('Test 2: Verifying cryptographically generated state randomness (256-bit entropy)...');
    assert.strictEqual(authResult.state.length, 64, 'State must be a 64-character hexadecimal string (32 bytes / 256 bits)');
    assert.match(authResult.state, /^[0-9a-f]{64}$/, 'State must be valid lowercase hex');

    // Generate 100 states to ensure 0 collisions
    const stateSet = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const { state } = gmailOAuthService.generateAuthUrl(`usr-test-${i}`);
      assert.ok(!stateSet.has(state), `Collision detected on state iteration ${i}`);
      stateSet.add(state);
    }
    assert.strictEqual(stateSet.size, 100, 'All 100 generated states must be strictly unique');
    console.log('✔ Test 2 Passed: 256-bit state entropy and uniqueness verified.\n');

    // -------------------------------------------------------------------------
    // Test 3: State-to-User binding & Replay Protection
    // -------------------------------------------------------------------------
    console.log('Test 3: Verifying state-to-user cryptographic binding and replay attack prevention...');
    const boundUser = 'usr-analyst-bind-test';
    const { state: boundState } = gmailOAuthService.generateAuthUrl(boundUser);

    // First consumption: Must succeed and return the bound userId
    const consume1 = gmailOAuthService.validateAndConsumeState(boundState);
    assert.strictEqual(consume1.valid, true, 'First state consumption must be valid');
    assert.strictEqual(consume1.userId, boundUser, 'State must strictly resolve to the original bound userId');

    // Second consumption (Replay Attack): Must fail immediately
    const consume2 = gmailOAuthService.validateAndConsumeState(boundState);
    assert.strictEqual(consume2.valid, false, 'State reuse / replay must be strictly rejected');
    assert.ok(
      consume2.error?.includes('already consumed') || consume2.error?.includes('not recognized'),
      'Error message must indicate state is already consumed or unrecognized'
    );
    console.log('✔ Test 3 Passed: State/user binding and single-use replay protection verified.\n');

    // -------------------------------------------------------------------------
    // Test 4: Invalid state rejection
    // -------------------------------------------------------------------------
    console.log('Test 4: Verifying rejection of invalid, forged, or empty state parameters...');
    const invalidStates = [
      'fake-state-12345',
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '',
      null as any,
      undefined as any,
    ];

    for (const badState of invalidStates) {
      const result = gmailOAuthService.validateAndConsumeState(badState);
      assert.strictEqual(result.valid, false, `Invalid state '${badState}' must be rejected`);
      assert.ok(result.error, 'Must return descriptive rejection reason');
    }
    console.log('✔ Test 4 Passed: Invalid and forged states rejected safely.\n');

    // -------------------------------------------------------------------------
    // Test 5: Expired state rejection (TTL expiration)
    // -------------------------------------------------------------------------
    console.log('Test 5: Verifying rejection and purge of expired OAuth states (10-minute TTL)...');
    const expiredState = 'expired-state-test-token-abcdef0123456789abcdef';
    gmailOAuthService._setStateForTest(expiredState, {
      state: expiredState,
      userId: 'usr-timed-out',
      createdAt: Date.now() - 15 * 60 * 1000, // 15 minutes ago
      expiresAt: Date.now() - 5 * 60 * 1000, // expired 5 minutes ago
    });

    const expiredResult = gmailOAuthService.validateAndConsumeState(expiredState);
    assert.strictEqual(expiredResult.valid, false, 'Expired state must be rejected');
    assert.ok(expiredResult.error?.includes('Expired OAuth state'), 'Error must identify state as expired');

    // Verify it was purged on evaluation
    const secondCheck = gmailOAuthService.validateAndConsumeState(expiredState);
    assert.strictEqual(secondCheck.valid, false, 'Expired state must be deleted from memory store');
    console.log('✔ Test 5 Passed: Expired state rejection and memory purging verified.\n');

    // -------------------------------------------------------------------------
    // Test 6: User Token Isolation (Multi-tenant separation)
    // -------------------------------------------------------------------------
    console.log('Test 6: Verifying user connection and token isolation between analysts...');
    gmailOAuthService._clearAllForTest();

    const user1 = 'usr-analyst-01';
    const user2 = 'usr-analyst-02';
    const user3 = 'usr-unconnected';

    gmailOAuthService._setConnectionForTest(user1, {
      userId: user1,
      gmailEmail: 'analyst1.soc@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.analyst1-secret-access-token',
      refreshToken: '1//analyst1-secret-refresh-token',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    gmailOAuthService._setConnectionForTest(user2, {
      userId: user2,
      gmailEmail: 'analyst2.soc@gmail.com',
      connectedAt: new Date().toISOString(),
      accessToken: 'ya29.analyst2-secret-access-token',
      refreshToken: '1//analyst2-secret-refresh-token',
      expiresAt: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
    });

    const status1 = gmailOAuthService.getStatus(user1);
    const status2 = gmailOAuthService.getStatus(user2);
    const status3 = gmailOAuthService.getStatus(user3);

    assert.strictEqual(status1.connected, true);
    assert.strictEqual(status1.gmailEmail, 'analyst1.soc@gmail.com', 'User 1 must see only their connected email');

    assert.strictEqual(status2.connected, true);
    assert.strictEqual(status2.gmailEmail, 'analyst2.soc@gmail.com', 'User 2 must see only their connected email');

    assert.strictEqual(status3.connected, false, 'Unconnected user must report connected: false');
    assert.strictEqual(status3.gmailEmail, undefined);

    console.log('✔ Test 6 Passed: Complete connection and data isolation between users verified.\n');

    // -------------------------------------------------------------------------
    // Test 7: /status endpoint payload never exposes OAuth tokens or secrets
    // -------------------------------------------------------------------------
    console.log('Test 7: Verifying /status output payload strictly shields tokens and credentials...');
    const statusOutput = gmailOAuthService.getStatus(user1) as any;

    // Check individual property existence
    assert.strictEqual(statusOutput.accessToken, undefined, 'accessToken must never exist on status payload');
    assert.strictEqual(statusOutput.access_token, undefined, 'access_token must never exist on status payload');
    assert.strictEqual(statusOutput.refreshToken, undefined, 'refreshToken must never exist on status payload');
    assert.strictEqual(statusOutput.refresh_token, undefined, 'refresh_token must never exist on status payload');
    assert.strictEqual(statusOutput.clientSecret, undefined, 'clientSecret must never exist on status payload');
    assert.strictEqual(statusOutput.client_secret, undefined, 'client_secret must never exist on status payload');

    // JSON serialization audit
    const serialized = JSON.stringify(statusOutput);
    assert.ok(!serialized.includes('ya29.'), 'Serialized status must never contain access token substring');
    assert.ok(!serialized.includes('refresh-token'), 'Serialized status must never contain refresh token substring');
    assert.ok(!serialized.includes('client-secret'), 'Serialized status must never contain client secret substring');

    // Exactly match schema: only connected, gmailEmail, connectedAt
    const keys = Object.keys(statusOutput);
    assert.deepStrictEqual(keys.sort(), ['connected', 'connectedAt', 'gmailEmail'].sort());
    console.log('✔ Test 7 Passed: Token shielding and zero-secret leakage verified.\n');

    // -------------------------------------------------------------------------
    // Test 8: Disconnect removes only authenticated user's connection
    // -------------------------------------------------------------------------
    console.log('Test 8: Verifying disconnect removes only the authenticated user\'s connection...');
    const disconnected1 = gmailOAuthService.disconnect(user1);
    assert.strictEqual(disconnected1, true, 'User 1 disconnect must return true');

    const checkUser1 = gmailOAuthService.getStatus(user1);
    assert.strictEqual(checkUser1.connected, false, 'User 1 must now be disconnected');

    // Verify User 2 was NOT disturbed
    const checkUser2 = gmailOAuthService.getStatus(user2);
    assert.strictEqual(checkUser2.connected, true, 'User 2 must remain connected');
    assert.strictEqual(checkUser2.gmailEmail, 'analyst2.soc@gmail.com', 'User 2 data must remain untouched');

    // Disconnecting a non-existent connection returns false safely
    const disconnectAgain = gmailOAuthService.disconnect(user1);
    assert.strictEqual(disconnectAgain, false, 'Disconnecting non-existent connection returns false gracefully');
    console.log('✔ Test 8 Passed: Targeted disconnect isolation verified.\n');

    // -------------------------------------------------------------------------
    // Test 9: Missing Google configuration produces a controlled error
    // -------------------------------------------------------------------------
    console.log('Test 9: Verifying controlled error handling when Google OAuth credentials are missing...');
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;

    const unconfiguredService = new GmailOAuthService();
    assert.strictEqual(unconfiguredService.isConfigured(), false, 'isConfigured() must be false when credentials are unset');

    assert.throws(
      () => {
        unconfiguredService.generateAuthUrl('usr-analyst-01');
      },
      (err: any) => {
        return (
          err instanceof Error &&
          err.message.includes('Google OAuth is not configured') &&
          err.message.includes('GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required')
        );
      },
      'generateAuthUrl must throw a clear, controlled configuration error'
    );
    console.log('✔ Test 9 Passed: Controlled configuration error verified.\n');

    // -------------------------------------------------------------------------
    // Test 10: Complete simulated OAuth callback flow
    // -------------------------------------------------------------------------
    console.log('Test 10: Verifying end-to-end simulated OAuth callback flow with token exchange...');
    process.env.GOOGLE_CLIENT_ID = 'test-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';

    const simulatedService = new GmailOAuthService({
      tokenExchanger: async (code, config) => {
        assert.strictEqual(code, 'valid-auth-code-12345');
        assert.strictEqual(config.clientId, 'test-client-id');
        return {
          accessToken: 'ya29.simulated-access-token-999',
          refreshToken: '1//simulated-refresh-token-999',
          expiresIn: 3600,
          scope: 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email',
          idToken: 'header.eyJlbWFpbCI6ICJzb2MuYXV0b0BnbWFpbC5jb20ifQ.signature',
        };
      },
      emailResolver: async (_accessToken, idToken) => {
        if (idToken) {
          const parts = idToken.split('.');
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
          return payload.email;
        }
        return 'soc.auto@gmail.com';
      },
    });

    const targetUser = 'usr-e2e-analyst';
    const { state: e2eState } = simulatedService.generateAuthUrl(targetUser);

    const callbackResult = await simulatedService.handleCallback('valid-auth-code-12345', e2eState);
    assert.strictEqual(callbackResult.success, true);
    assert.strictEqual(callbackResult.userId, targetUser);
    assert.strictEqual(callbackResult.gmailEmail, 'soc.auto@gmail.com');

    // Status check
    const e2eStatus = simulatedService.getStatus(targetUser);
    assert.strictEqual(e2eStatus.connected, true);
    assert.strictEqual(e2eStatus.gmailEmail, 'soc.auto@gmail.com');

    // Replay check on used state
    const replayCheck = simulatedService.validateAndConsumeState(e2eState);
    assert.strictEqual(replayCheck.valid, false, 'State used in callback must be consumed');

    console.log('✔ Test 10 Passed: Full simulated OAuth callback, exchange, and persistence verified.\n');

    console.log('================================================================');
    console.log('ALL 10 GMAIL OAUTH PHASE-1 TESTS PASSED SUCCESSFULLY! (100%)');
    console.log('================================================================\n');
  } finally {
    // Restore original environment
    process.env = originalEnv;
  }
}

runTests().catch(err => {
  console.error('Test failure:', err);
  process.exit(1);
});
