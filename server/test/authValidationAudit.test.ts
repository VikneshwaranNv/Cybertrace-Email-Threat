import assert from 'assert';
import { authService } from '../auth/authService';
import { auditLogger } from '../auth/auditLogger';

console.log('=== RUNNING AUTHENTICATION INPUT VALIDATION & SECURITY AUDIT TEST SUITE ===\n');

async function runAuthValidationAuditTests() {
  // Test 1: Empty or missing fields on registration
  console.log('Test 1: Verifying registration rejection on empty/missing fields (400)...');
  {
    const res1 = authService.register('', 'Password123!', 'Analyst User');
    assert.strictEqual(res1.success, false);
    assert.strictEqual((res1 as any).statusCode, 400);

    const res2 = authService.register('test@example.com', '');
    assert.strictEqual(res2.success, false);
    assert.strictEqual((res2 as any).statusCode, 400);
    console.log('✔ Test 1 Passed: Missing email or password rejected with HTTP 400.\n');
  }

  // Test 2: Invalid email format rejection
  console.log('Test 2: Verifying rejection of malformed and invalid email formats (400)...');
  {
    const invalidEmails = [
      'not-an-email',
      'user@',
      '@domain.com',
      'user@domain',
      'user space@domain.com',
      'user@.com',
    ];

    for (const invalidEmail of invalidEmails) {
      const res = authService.register(invalidEmail, 'SecurePass123!');
      assert.strictEqual(res.success, false, `Failed to reject invalid email: ${invalidEmail}`);
      assert.strictEqual((res as any).statusCode, 400);
      assert.ok((res as any).error.includes('Invalid email'));
    }
    console.log('✔ Test 2 Passed: Malformed email formats rejected with HTTP 400.\n');
  }

  // Test 3: Password policy and boundary constraints (< 8 chars, > 128 chars DoS)
  console.log('Test 3: Verifying password policy boundaries (8-128 chars)...');
  {
    // Too short (< 8)
    const shortRes = authService.register('analyst_boundary@soc.test', 'short');
    assert.strictEqual(shortRes.success, false);
    assert.strictEqual((shortRes as any).statusCode, 400);
    assert.ok((shortRes as any).error.includes('at least 8 characters'));

    // Oversized (> 128 chars - DoS / PBKDF2 hash exhaustion prevention)
    const oversizedPass = 'A'.repeat(129);
    const oversizedRes = authService.register('analyst_boundary@soc.test', oversizedPass);
    assert.strictEqual(oversizedRes.success, false);
    assert.strictEqual((oversizedRes as any).statusCode, 400);
    assert.ok((oversizedRes as any).error.includes('maximum permitted length'));
    console.log('✔ Test 3 Passed: Password length strictly bounded to 8-128 characters.\n');
  }

  // Test 4: Name sanitization and XSS neutralization
  console.log('Test 4: Verifying XSS sanitization in user profile names...');
  {
    const xssPayload = '<script>alert("pwned")</script>Dr. Forensic';
    const regRes = authService.register('xss_test@soc.test', 'ValidPass2026!', xssPayload);
    assert.strictEqual(regRes.success, true);
    assert.ok(regRes.user);
    assert.strictEqual(regRes.user.name, 'alert("pwned")Dr. Forensic', 'HTML tags must be stripped');
    assert.ok(!regRes.user.name.includes('<script>'), 'Script tags must be eliminated');
    console.log('✔ Test 4 Passed: Profile names sanitized against script tags.\n');
  }

  // Test 5: Privilege Escalation Prevention (SEC-01)
  console.log('Test 5: Verifying Privilege Escalation protection (public registration cannot grant ADMIN)...');
  {
    const clientSuppliedRoleEmail = 'hacker_attempt@soc.test';
    const regRes = authService.register(clientSuppliedRoleEmail, 'HackerPass2026!', 'Sneaky User');
    assert.strictEqual(regRes.success, true);
    assert.strictEqual(regRes.user.role, 'ANALYST', 'Public registration MUST always assign ANALYST');

    // Attempt role elevation via registerOrLogin helper
    const elevationAttempt = authService.registerOrLogin(
      clientSuppliedRoleEmail,
      'HackerPass2026!',
      'Sneaky User',
      'ADMIN' as any
    );
    assert.strictEqual(elevationAttempt.success, true);
    assert.strictEqual(elevationAttempt.user.role, 'ANALYST', 'Existing user role MUST NOT be elevated via login payload');
    console.log('✔ Test 5 Passed: Privilege escalation strictly blocked; roles cannot be elevated.\n');
  }

  // Test 6: Duplicate registration rejection (SEC-02 - HTTP 409 Conflict)
  console.log('Test 6: Verifying duplicate account registration returns 409 Conflict...');
  {
    const duplicateEmail = 'duplicate_test@soc.test';
    const firstReg = authService.register(duplicateEmail, 'Password123!', 'First Registrant');
    assert.strictEqual(firstReg.success, true);

    const secondReg = authService.register(duplicateEmail, 'Password123!', 'Second Registrant');
    assert.strictEqual(secondReg.success, false);
    assert.strictEqual((secondReg as any).statusCode, 409, 'Duplicate registration must return HTTP 409');
    assert.ok((secondReg as any).error.includes('already exists'), 'Error must communicate existing account');
    console.log('✔ Test 6 Passed: Duplicate account creation rejected with HTTP 409 Conflict.\n');
  }

  // Test 7: Unknown user login does NOT auto-register (HTTP 401 Unauthorized)
  console.log('Test 7: Verifying login with non-existent account returns 401 Unauthorized...');
  {
    const nonExistentLogin = authService.login('nonexistent_user_999@soc.test', 'RandomPassword123!');
    assert.strictEqual(nonExistentLogin.success, false);
    assert.strictEqual((nonExistentLogin as any).statusCode, 401);
    assert.strictEqual((nonExistentLogin as any).error, 'Invalid email or password');
    console.log('✔ Test 7 Passed: Non-existent accounts rejected with HTTP 401 without auto-registration.\n');
  }

  // Test 8: Incorrect password rejection (HTTP 401 Unauthorized)
  console.log('Test 8: Verifying incorrect password returns 401 Unauthorized...');
  {
    const badPassLogin = authService.login('analyst@soc.internal', 'WrongPassword999!');
    assert.strictEqual(badPassLogin.success, false);
    assert.strictEqual((badPassLogin as any).statusCode, 401);
    assert.strictEqual((badPassLogin as any).error, 'Invalid email or password');
    console.log('✔ Test 8 Passed: Incorrect password rejected with HTTP 401.\n');
  }

  // Test 9: Rate limiting & Brute Force Lockout (HTTP 429)
  console.log('Test 9: Verifying brute-force rate limiting (5 failed attempts -> 429 Lockout)...');
  {
    const bruteForceEmail = 'bruteforce_target@soc.test';
    authService.register(bruteForceEmail, 'ValidTargetPass123!', 'Target User');

    const testIp = '198.51.100.42';
    // 4 failed attempts
    for (let i = 1; i <= 4; i++) {
      const attempt = authService.login(bruteForceEmail, 'WrongAttempt', testIp);
      assert.strictEqual(attempt.success, false);
      assert.strictEqual((attempt as any).statusCode, 401);
    }

    // 5th failed attempt triggers lockout
    const attempt5 = authService.login(bruteForceEmail, 'WrongAttempt', testIp);
    assert.strictEqual(attempt5.success, false);
    assert.strictEqual((attempt5 as any).statusCode, 401);

    // 6th attempt is blocked with 429
    const attempt6 = authService.login(bruteForceEmail, 'ValidTargetPass123!', testIp);
    assert.strictEqual(attempt6.success, false);
    assert.strictEqual((attempt6 as any).statusCode, 429, 'Account must be locked with HTTP 429');
    assert.ok((attempt6 as any).error.includes('Too many failed login attempts'));
    console.log('✔ Test 9 Passed: Brute-force protection activates 429 lockout.\n');
  }

  // Test 10: Password reset rate limiting (SEC-04 - HTTP 429)
  console.log('Test 10: Verifying password reset abuse prevention & rate limiting...');
  {
    const resetTargetEmail = 'reset_rate_target@soc.test';
    authService.register(resetTargetEmail, 'InitialPassword123!', 'Reset Target');

    const resetIp = '203.0.113.88';
    // 3 requests allowed within 10-minute window
    const r1 = authService.requestPasswordReset(resetTargetEmail, resetIp);
    assert.strictEqual(r1.success, true);

    const r2 = authService.requestPasswordReset(resetTargetEmail, resetIp);
    assert.strictEqual(r2.success, true);

    const r3 = authService.requestPasswordReset(resetTargetEmail, resetIp);
    assert.strictEqual(r3.success, true);

    // 4th request must be rate-limited
    const r4 = authService.requestPasswordReset(resetTargetEmail, resetIp);
    assert.strictEqual(r4.success, false);
    assert.strictEqual((r4 as any).statusCode, 429, '4th reset request must return HTTP 429');
    assert.ok((r4 as any).error.includes('Too many password reset requests'));
    console.log('✔ Test 10 Passed: Password reset rate limiting enforced (HTTP 429).\n');
  }

  // Test 11: Password reset invalidates prior active sessions
  console.log('Test 11: Verifying password reset invalidates all existing active sessions...');
  {
    const sessionEmail = 'session_inval_target@soc.test';
    const regRes = authService.register(sessionEmail, 'OldPassword123!', 'Session Target');
    assert.strictEqual(regRes.success, true);
    const oldSessionToken = regRes.token;

    // Verify session is active
    assert.ok(authService.validateToken(oldSessionToken), 'Initial session token must be valid');

    // Request reset from fresh IP
    const reqReset = authService.requestPasswordReset(sessionEmail, '192.0.2.15');
    assert.strictEqual(reqReset.success, true);
    assert.ok(reqReset.resetToken, 'Reset token generated');

    // Complete password reset
    const resetResult = authService.resetPassword(reqReset.resetToken!, 'NewPassword2026!');
    assert.strictEqual(resetResult.success, true);

    // Prior session token MUST be invalidated
    const invalidatedSession = authService.validateToken(oldSessionToken);
    assert.strictEqual(invalidatedSession, null, 'Old session token must be revoked upon password reset');

    // Old password rejected
    const oldLogin = authService.login(sessionEmail, 'OldPassword123!', '192.0.2.15');
    assert.strictEqual(oldLogin.success, false);

    // New password succeeds
    const newLogin = authService.login(sessionEmail, 'NewPassword2026!', '192.0.2.15');
    assert.strictEqual(newLogin.success, true);
    console.log('✔ Test 11 Passed: Password reset invalidates active sessions and applies new credentials.\n');
  }

  // Test 12: Logout explicitly revokes session
  console.log('Test 12: Verifying explicit logout revokes server session...');
  {
    const logoutEmail = 'logout_test@soc.test';
    const regRes = authService.register(logoutEmail, 'LogoutPass123!', 'Logout User');
    assert.strictEqual(regRes.success, true);

    const token = regRes.token;
    assert.ok(authService.validateToken(token), 'Session valid before logout');

    const logoutSuccess = authService.logout(token);
    assert.strictEqual(logoutSuccess, true);

    const validatedAfterLogout = authService.validateToken(token);
    assert.strictEqual(validatedAfterLogout, null, 'Session must be null after logout');
    console.log('✔ Test 12 Passed: Explicit logout reliably revokes server session.\n');
  }

  console.log('===================================================================');
  console.log('ALL 12 AUTHENTICATION INPUT VALIDATION & SECURITY AUDIT TESTS PASSED (12/12)');
  console.log('===================================================================\n');
}

runAuthValidationAuditTests().catch(err => {
  console.error('Auth validation audit test failure:', err);
  process.exit(1);
});
