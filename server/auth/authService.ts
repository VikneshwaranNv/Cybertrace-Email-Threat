import crypto from 'crypto';
import { AuthSession, UserPublicProfile, UserRecord, UserRole } from './types';
import { auditLogger } from './auditLogger';

export class AuthService {
  private users: Map<string, UserRecord> = new Map();
  private sessions: Map<string, AuthSession> = new Map();
  private failedAttempts: Map<string, { count: number; lockedUntil: number }> = new Map();

  constructor() {
    this.seedDefaultUsers();
  }

  private hashPassword(password: string, salt: string): string {
    return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  }

  private seedDefaultUsers() {
    // 1. Primary SOC Analyst
    this.registerInternalUser({
      id: 'usr-analyst-01',
      email: 'analyst@soc.internal',
      name: 'SOC Analyst',
      role: 'ANALYST',
      passwordPlain: 'Analyst@SOC2026!',
    });

    // 2. Secondary Analyst (for multi-tenant authorization testing)
    this.registerInternalUser({
      id: 'usr-analyst-02',
      email: 'analyst2@soc.internal',
      name: 'Neha Patel (Forensic Investigator)',
      role: 'ANALYST',
      passwordPlain: 'Analyst2@SOC2026!',
    });

    // 3. SOC Security Administrator
    this.registerInternalUser({
      id: 'usr-admin-01',
      email: 'admin@soc.internal',
      name: 'Chief SOC Security Admin',
      role: 'ADMIN',
      passwordPlain: 'Admin@SOC2026!',
    });

    // 4. Senior SOC Analyst
    this.registerInternalUser({
      id: 'usr-senior-01',
      email: 'senior@soc.internal',
      name: 'Aditi Rao (Senior SOC Analyst)',
      role: 'SENIOR_ANALYST',
      passwordPlain: 'Senior@SOC2026!',
    });

    // 5. Compliance & Security Auditor
    this.registerInternalUser({
      id: 'usr-auditor-01',
      email: 'auditor@soc.internal',
      name: 'Rohan Gupta (Compliance Auditor)',
      role: 'AUDITOR',
      passwordPlain: 'Auditor@SOC2026!',
    });

    // Seed default active session for seamless SOC workbench startup
    this.getOrCreateDefaultSession();
  }

  public getOrCreateDefaultSession(): { token: string; user: UserPublicProfile } {
    const defaultEmail = 'analyst@soc.internal';
    const user = this.users.get(defaultEmail);
    if (!user) {
      throw new Error('Default user not found');
    }
    for (const [token, session] of this.sessions.entries()) {
      if (session.email === defaultEmail && new Date(session.expiresAt).getTime() > Date.now()) {
        return { token, user: this.toPublicProfile(user) };
      }
    }
    const token = `soc_sec_primary_${crypto.randomBytes(24).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const session: AuthSession = {
      token,
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: new Date().toISOString(),
      expiresAt,
    };
    this.sessions.set(token, session);
    return { token, user: this.toPublicProfile(user) };
  }

  private registerInternalUser(params: {
    id: string;
    email: string;
    name: string;
    role: UserRole;
    passwordPlain: string;
  }) {
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = this.hashPassword(params.passwordPlain, salt);

    const record: UserRecord = {
      id: params.id,
      email: params.email.toLowerCase(),
      name: params.name,
      role: params.role,
      passwordHash,
      salt,
      createdAt: new Date().toISOString(),
      emailVerified: true,
      verificationCode: Math.floor(100000 + Math.random() * 900000).toString(),
    };

    this.users.set(record.email, record);
  }

  public toPublicProfile(user: UserRecord | AuthSession): UserPublicProfile {
    const id = 'userId' in user ? user.userId : user.id;
    const userRec = this.users.get(user.email.toLowerCase());
    return {
      id,
      email: user.email,
      name: user.name,
      role: user.role,
      emailVerified: userRec?.emailVerified ?? true,
      badgeNumber: `SOC-${id.slice(-4).toUpperCase()}`,
      organization: 'CyberTrace SOC Operations',
      createdAt: userRec?.createdAt || user.createdAt,
    };
  }

  public login(
    emailRaw: string,
    passwordPlain: string,
    ip = '127.0.0.1'
  ): { success: true; token: string; user: UserPublicProfile } | { success: false; error: string; statusCode: number } {
    const email = (emailRaw || '').trim().toLowerCase();
    const rateKey = `${ip}:${email}`;
    const now = Date.now();

    // Rate-limiting check: 5 failed attempts locks account for 2 minutes
    const lockInfo = this.failedAttempts.get(rateKey);
    if (lockInfo && lockInfo.lockedUntil > now) {
      const waitSeconds = Math.ceil((lockInfo.lockedUntil - now) / 1000);
      auditLogger.record({
        action: 'LOGIN_FAILED',
        status: 'DENIED',
        actorEmail: email,
        ip,
        details: `Login blocked due to rate limiting. Locked for ${waitSeconds}s.`,
      });
      return {
        success: false,
        error: `Too many failed login attempts. Please try again in ${waitSeconds} seconds.`,
        statusCode: 429,
      };
    }

    const user = this.users.get(email);
    if (!user) {
      this.recordFailedAttempt(rateKey);
      auditLogger.record({
        action: 'LOGIN_FAILED',
        status: 'FAILURE',
        actorEmail: email,
        ip,
        details: 'Failed authentication attempt: User email not recognized.',
      });
      return { success: false, error: 'Invalid email or password', statusCode: 401 };
    }

    const computedHash = this.hashPassword(passwordPlain, user.salt);
    const hashesMatch = crypto.timingSafeEqual(
      Buffer.from(computedHash, 'hex'),
      Buffer.from(user.passwordHash, 'hex')
    );

    if (!hashesMatch) {
      this.recordFailedAttempt(rateKey);
      auditLogger.record({
        action: 'LOGIN_FAILED',
        status: 'FAILURE',
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        ip,
        details: 'Failed authentication attempt: Password verification mismatch.',
      });
      return { success: false, error: 'Invalid email or password', statusCode: 401 };
    }

    // Reset failed counter on successful login
    this.failedAttempts.delete(rateKey);

    return this.createSessionForUser(user, ip);
  }

  public registerOrLogin(
    emailRaw: string,
    passwordPlain: string,
    nameRaw?: string,
    roleRaw?: UserRole,
    ip = '127.0.0.1'
  ): { success: true; token: string; user: UserPublicProfile } | { success: false; error: string; statusCode: number } {
    const email = (emailRaw || '').trim().toLowerCase();
    if (!email || !passwordPlain) {
      return { success: false, error: 'Email and password are required', statusCode: 400 };
    }

    const existingUser = this.users.get(email);
    if (existingUser) {
      const computedHash = this.hashPassword(passwordPlain, existingUser.salt);
      const hashesMatch = crypto.timingSafeEqual(
        Buffer.from(computedHash, 'hex'),
        Buffer.from(existingUser.passwordHash, 'hex')
      );
      if (!hashesMatch) {
        return { success: false, error: 'Invalid password for this account', statusCode: 401 };
      }
      if (nameRaw && nameRaw.trim()) {
        existingUser.name = nameRaw.trim();
      }
      if (roleRaw) {
        existingUser.role = roleRaw;
      }
      return this.createSessionForUser(existingUser, ip);
    }

    // New user registration (e.g. user entering their gmail and password)
    const formattedName = (nameRaw && nameRaw.trim())
      ? nameRaw.trim()
      : email.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

    const role: UserRole = roleRaw || 'ANALYST';
    const userId = `usr-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;

    this.registerInternalUser({
      id: userId,
      email,
      name: formattedName,
      role,
      passwordPlain,
    });

    const newUser = this.users.get(email)!;
    return this.createSessionForUser(newUser, ip);
  }

  private createSessionForUser(
    user: UserRecord,
    ip = '127.0.0.1'
  ): { success: true; token: string; user: UserPublicProfile } {
    user.lastLoginAt = new Date().toISOString();
    const token = `soc_sec_${crypto.randomBytes(32).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    const session: AuthSession = {
      token,
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: new Date().toISOString(),
      expiresAt,
    };

    this.sessions.set(token, session);

    auditLogger.record({
      action: 'LOGIN_SUCCESS',
      status: 'SUCCESS',
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ip,
      details: `Successful analyst authentication session established for ${user.name} (Role: ${user.role}).`,
    });

    return {
      success: true,
      token,
      user: this.toPublicProfile(user),
    };
  }

  public requestPasswordReset(
    emailRaw: string,
    ip = '127.0.0.1'
  ): { success: true; message: string; resetToken?: string; verificationCode?: string } {
    const email = (emailRaw || '').trim().toLowerCase();
    const user = this.users.get(email);
    const token = crypto.randomBytes(24).toString('hex');
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    if (user) {
      user.resetToken = token;
      user.verificationCode = code;
      user.resetExpiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes

      auditLogger.record({
        action: 'PASSWORD_RESET_REQUESTED',
        status: 'SUCCESS',
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        ip,
        details: `Password reset requested for ${user.email}. Verification code generated.`,
      });
    }

    return {
      success: true,
      message: 'If an account exists for this email, password reset instructions and a verification code have been generated.',
      resetToken: user ? token : undefined,
      verificationCode: user ? code : undefined,
    };
  }

  public resetPassword(
    tokenOrCode: string,
    newPasswordPlain: string,
    ip = '127.0.0.1'
  ): { success: true; message: string } | { success: false; error: string; statusCode: number } {
    if (!tokenOrCode || !newPasswordPlain) {
      return { success: false, error: 'Reset token/code and new password are required', statusCode: 400 };
    }

    if (newPasswordPlain.length < 8) {
      return { success: false, error: 'Password must be at least 8 characters in length', statusCode: 400 };
    }

    const trimmedInput = tokenOrCode.trim();
    let targetUser: UserRecord | null = null;
    const now = Date.now();

    for (const u of this.users.values()) {
      if (
        (u.resetToken === trimmedInput || u.verificationCode === trimmedInput) &&
        u.resetExpiresAt &&
        u.resetExpiresAt > now
      ) {
        targetUser = u;
        break;
      }
    }

    if (!targetUser) {
      return { success: false, error: 'Invalid or expired password reset token or code', statusCode: 400 };
    }

    // Update password with newly generated salt & PBKDF2 hash
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = this.hashPassword(newPasswordPlain, salt);
    targetUser.passwordHash = passwordHash;
    targetUser.salt = salt;
    targetUser.resetToken = undefined;
    targetUser.resetExpiresAt = undefined;

    // Invalidate prior sessions for security
    for (const [token, session] of this.sessions.entries()) {
      if (session.userId === targetUser.id) {
        this.sessions.delete(token);
      }
    }

    auditLogger.record({
      action: 'PASSWORD_RESET_COMPLETED',
      status: 'SUCCESS',
      actorId: targetUser.id,
      actorEmail: targetUser.email,
      actorRole: targetUser.role,
      ip,
      details: `Password successfully reset for account ${targetUser.email}. Prior sessions invalidated.`,
    });

    return {
      success: true,
      message: 'Password successfully updated. You may now log in with your new credentials.',
    };
  }

  public verifyEmail(
    emailRaw: string,
    code: string,
    ip = '127.0.0.1'
  ): { success: true; message: string; user: UserPublicProfile } | { success: false; error: string; statusCode: number } {
    const email = (emailRaw || '').trim().toLowerCase();
    const user = this.users.get(email);
    if (!user) {
      return { success: false, error: 'User account not found', statusCode: 404 };
    }

    if (user.verificationCode && user.verificationCode !== code.trim()) {
      return { success: false, error: 'Invalid verification code', statusCode: 400 };
    }

    user.emailVerified = true;
    auditLogger.record({
      action: 'EMAIL_VERIFIED',
      status: 'SUCCESS',
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ip,
      details: `Email verification confirmed for ${user.email}.`,
    });

    return {
      success: true,
      message: 'Email successfully verified.',
      user: this.toPublicProfile(user),
    };
  }

  private recordFailedAttempt(key: string) {
    const current = this.failedAttempts.get(key) || { count: 0, lockedUntil: 0 };
    current.count += 1;
    if (current.count >= 5) {
      current.lockedUntil = Date.now() + 2 * 60 * 1000; // 2 min lockout
    }
    this.failedAttempts.set(key, current);
  }

  public validateToken(token: string): AuthSession | null {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session) return null;

    if (new Date(session.expiresAt).getTime() < Date.now()) {
      this.sessions.delete(token);
      return null;
    }

    return session;
  }

  public logout(token: string, ip = '127.0.0.1'): boolean {
    const session = this.sessions.get(token);
    if (session) {
      this.sessions.delete(token);
      auditLogger.record({
        action: 'LOGOUT',
        status: 'SUCCESS',
        actorId: session.userId,
        actorEmail: session.email,
        actorRole: session.role,
        ip,
        details: 'User explicitly invalidated authentication session.',
      });
      return true;
    }
    return false;
  }

  public getAllUsers(): UserPublicProfile[] {
    const profiles: UserPublicProfile[] = [];
    for (const u of this.users.values()) {
      profiles.push(this.toPublicProfile(u));
    }
    return profiles;
  }

  /**
   * Helper for tests or automated bootstrapping to create an active session
   */
  public createTestSession(role: UserRole = 'ANALYST', userId?: string, email?: string): { token: string; user: UserPublicProfile } {
    const userEmail = email || (role === 'ADMIN' ? 'admin@soc.internal' : 'analyst@soc.internal');
    const user = this.users.get(userEmail) || Array.from(this.users.values()).find(u => u.role === role)!;
    const token = `soc_sec_test_${crypto.randomBytes(24).toString('hex')}`;
    const session: AuthSession = {
      token,
      userId: userId || user.id,
      email: userEmail,
      name: user.name,
      role: role,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
    this.sessions.set(token, session);
    return { token, user: this.toPublicProfile(session) };
  }
}

export const authService = new AuthService();
