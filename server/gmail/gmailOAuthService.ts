import crypto from 'crypto';

export interface GmailOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface OAuthStateRecord {
  state: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
}

export interface UserGmailConnection {
  userId: string;
  gmailEmail: string;
  connectedAt: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  scope: string;
}

export interface SafeGmailStatus {
  connected: boolean;
  gmailEmail?: string;
  connectedAt?: string;
}

export type TokenExchanger = (
  code: string,
  config: GmailOAuthConfig
) => Promise<{
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  scope: string;
  idToken?: string;
}>;

export type EmailResolver = (accessToken: string, idToken?: string) => Promise<string>;

export class GmailOAuthService {
  private stateStore: Map<string, OAuthStateRecord> = new Map();
  private connections: Map<string, UserGmailConnection> = new Map();
  private customTokenExchanger?: TokenExchanger;
  private customEmailResolver?: EmailResolver;

  // State lifespan: 10 minutes (600,000 ms)
  private readonly STATE_TTL_MS = 10 * 60 * 1000;

  constructor(options?: { tokenExchanger?: TokenExchanger; emailResolver?: EmailResolver }) {
    if (options?.tokenExchanger) this.customTokenExchanger = options.tokenExchanger;
    if (options?.emailResolver) this.customEmailResolver = options.emailResolver;
  }

  /**
   * Retrieves Google OAuth configuration from environment variables.
   * Never hardcoded; clientSecret is strictly kept on the server.
   */
  public getConfig(): GmailOAuthConfig {
    const defaultRedirect = `${process.env.APP_URL || 'http://localhost:3000'}/api/gmail/oauth/callback`;
    return {
      clientId: (process.env.GOOGLE_CLIENT_ID || '').trim(),
      clientSecret: (process.env.GOOGLE_CLIENT_SECRET || '').trim(),
      redirectUri: (process.env.GOOGLE_REDIRECT_URI || defaultRedirect).trim(),
    };
  }

  /**
   * Checks whether required Google OAuth credentials are present in the environment.
   */
  public isConfigured(): boolean {
    const config = this.getConfig();
    return Boolean(config.clientId.length > 0 && config.clientSecret.length > 0);
  }

  /**
   * Generates a cryptographically secure OAuth 2.0 authorization URL.
   * Generates 256-bit random state and securely binds it to req.user.userId.
   */
  public generateAuthUrl(userId: string): { url: string; state: string } {
    if (!userId || typeof userId !== 'string') {
      throw new Error('Authenticated user ID is required to initiate OAuth flow');
    }

    if (!this.isConfigured()) {
      throw new Error(
        'Google OAuth is not configured. GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required in environment.'
      );
    }

    const config = this.getConfig();

    // 256-bit cryptographically secure state
    const state = crypto.randomBytes(32).toString('hex');
    const now = Date.now();

    this.stateStore.set(state, {
      state,
      userId,
      createdAt: now,
      expiresAt: now + this.STATE_TTL_MS,
    });

    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      scope: 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email',
      access_type: 'offline',
      prompt: 'consent',
      state,
    });

    const url = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    return { url, state };
  }

  /**
   * Validates and consumes the OAuth state with replay protection.
   * The state is single-use and deleted immediately upon evaluation.
   */
  public validateAndConsumeState(state: string): { valid: boolean; userId?: string; error?: string } {
    if (!state || typeof state !== 'string') {
      return { valid: false, error: 'OAuth state parameter is missing or invalid' };
    }

    const record = this.stateStore.get(state);
    if (!record) {
      return { valid: false, error: 'Invalid OAuth state: state not recognized or already consumed' };
    }

    // Immediately remove from store to prevent replay attacks
    this.stateStore.delete(state);

    if (Date.now() > record.expiresAt) {
      return { valid: false, error: 'Expired OAuth state: authorization flow timed out' };
    }

    return { valid: true, userId: record.userId };
  }

  /**
   * Exchanges authorization code for Google OAuth tokens.
   */
  public async exchangeCodeForTokens(code: string): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresIn: number;
    scope: string;
    idToken?: string;
  }> {
    if (this.customTokenExchanger) {
      return this.customTokenExchanger(code, this.getConfig());
    }

    if (!this.isConfigured()) {
      throw new Error('Google OAuth is not configured');
    }

    const config = this.getConfig();
    const tokenUrl = 'https://oauth2.googleapis.com/token';

    const bodyParams = new URLSearchParams({
      code,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      redirect_uri: config.redirectUri,
      grant_type: 'authorization_code',
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: bodyParams.toString(),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        `Google token exchange failed (${response.status}): ${
          (errorData as any).error_description || (errorData as any).error || response.statusText
        }`
      );
    }

    const data: any = await response.json();
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresIn: data.expires_in || 3600,
      scope: data.scope || '',
      idToken: data.id_token,
    };
  }

  /**
   * Resolves the user's Gmail email address using ID token or Google userinfo/profile APIs.
   */
  public async resolveGmailEmail(accessToken: string, idToken?: string): Promise<string> {
    if (this.customEmailResolver) {
      return this.customEmailResolver(accessToken, idToken);
    }

    // 1. Try decoding ID Token if present
    if (idToken) {
      try {
        const parts = idToken.split('.');
        if (parts.length === 3) {
          const payloadJson = Buffer.from(parts[1], 'base64').toString('utf8');
          const claims = JSON.parse(payloadJson);
          if (claims.email && typeof claims.email === 'string') {
            return claims.email.toLowerCase().trim();
          }
        }
      } catch {
        // Fall back to API endpoints
      }
    }

    // 2. Query userinfo API
    try {
      const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (res.ok) {
        const info: any = await res.json();
        if (info.email && typeof info.email === 'string') {
          return info.email.toLowerCase().trim();
        }
      }
    } catch {
      // Fall through to Gmail profile
    }

    // 3. Query Gmail profile API
    const profileRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (profileRes.ok) {
      const profile: any = await profileRes.json();
      if (profile.emailAddress && typeof profile.emailAddress === 'string') {
        return profile.emailAddress.toLowerCase().trim();
      }
    }

    throw new Error('Unable to resolve connected Gmail email address from Google APIs');
  }

  /**
   * Complete callback handler: validates state, exchanges tokens, resolves email,
   * binds connection to the authenticated CyberTrace user, and stores tokens securely on backend.
   */
  public async handleCallback(
    code: string,
    state: string
  ): Promise<{ success: boolean; userId: string; gmailEmail: string; connectedAt: string }> {
    const stateCheck = this.validateAndConsumeState(state);
    if (!stateCheck.valid || !stateCheck.userId) {
      throw new Error(stateCheck.error || 'Invalid or expired OAuth state');
    }

    const userId = stateCheck.userId;
    const tokens = await this.exchangeCodeForTokens(code);
    const gmailEmail = await this.resolveGmailEmail(tokens.accessToken, tokens.idToken);

    const connectedAt = new Date().toISOString();
    const expiresAt = Date.now() + tokens.expiresIn * 1000;

    this.connections.set(userId, {
      userId,
      gmailEmail,
      connectedAt,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt,
      scope: tokens.scope,
    });

    return {
      success: true,
      userId,
      gmailEmail,
      connectedAt,
    };
  }

  /**
   * Retrieves safe connection metadata for the authenticated user.
   * Strictly guarantees that tokens and client secrets are never exposed.
   */
  public getStatus(userId: string): SafeGmailStatus {
    const conn = this.connections.get(userId);
    if (!conn) {
      return { connected: false };
    }

    return {
      connected: true,
      gmailEmail: conn.gmailEmail,
      connectedAt: conn.connectedAt,
    };
  }

  /**
   * Disconnects and removes only the authenticated user's Gmail connection.
   * Cannot affect any other user's connection.
   */
  public disconnect(userId: string): boolean {
    return this.connections.delete(userId);
  }

  /**
   * Directly establishes an authenticated Gmail connection record.
   * Used for simulated demo mailboxes (offline SIH evaluation) and test harness connections.
   */
  public connectUser(
    userId: string,
    data: {
      gmailEmail: string;
      accessToken: string;
      expiresIn?: number;
      scope?: string;
    }
  ): UserGmailConnection {
    const connection: UserGmailConnection = {
      userId,
      gmailEmail: data.gmailEmail,
      connectedAt: new Date().toISOString(),
      accessToken: data.accessToken,
      expiresAt: Date.now() + (data.expiresIn || 86400) * 1000,
      scope: data.scope || 'https://www.googleapis.com/auth/gmail.readonly',
    };
    this.connections.set(userId, connection);
    return connection;
  }

  /**
   * Internal server-side access to tokens for future sync phases.
   * NEVER exposed through any public or authenticated HTTP endpoint.
   */
  public getConnection(userId: string): UserGmailConnection | undefined {
    return this.connections.get(userId);
  }

  /**
   * Retrieves all currently connected user IDs.
   * Used exclusively by backend background services (e.g. polling scheduler).
   */
  public getAllConnectedUserIds(): string[] {
    return Array.from(this.connections.keys());
  }

  /**
   * Refreshes an expired access token using the stored refresh token.
   * Updates stored tokens and expiration time in memory.
   */
  public async refreshAccessToken(userId: string): Promise<string> {
    const conn = this.connections.get(userId);
    if (!conn) {
      throw new Error(`No Gmail connection found for user ${userId}`);
    }
    if (!conn.refreshToken) {
      throw new Error(`No refresh token available for user ${userId}. Please re-authenticate.`);
    }

    if (this.customTokenExchanger) {
      const refreshed = await this.customTokenExchanger(conn.refreshToken, this.getConfig());
      conn.accessToken = refreshed.accessToken;
      conn.expiresAt = Date.now() + refreshed.expiresIn * 1000;
      if (refreshed.refreshToken) {
        conn.refreshToken = refreshed.refreshToken;
      }
      return conn.accessToken;
    }

    const config = this.getConfig();
    const tokenUrl = 'https://oauth2.googleapis.com/token';
    const bodyParams = new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      refresh_token: conn.refreshToken,
      grant_type: 'refresh_token',
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: bodyParams.toString(),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        `Failed to refresh Gmail access token (${response.status}): ${
          (errorData as any).error_description || (errorData as any).error || response.statusText
        }`
      );
    }

    const data: any = await response.json();
    conn.accessToken = data.access_token;
    conn.expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
    if (data.refresh_token) {
      conn.refreshToken = data.refresh_token;
    }
    return conn.accessToken;
  }

  /**
   * Safely returns a valid access token for the authenticated user, automatically
   * refreshing if expired or expiring within 60 seconds.
   */
  public async getValidAccessToken(userId: string): Promise<string> {
    const conn = this.connections.get(userId);
    if (!conn) {
      throw new Error(`No Gmail connection found for user ${userId}`);
    }

    // If token is still valid (with 60-second safety margin), return it
    if (conn.expiresAt && Date.now() < conn.expiresAt - 60000) {
      return conn.accessToken;
    }

    // Token is expired or expiring soon; attempt refresh if refresh_token exists
    if (conn.refreshToken) {
      return this.refreshAccessToken(userId);
    }

    // If no refresh token exists, return current access token (upstream API call will determine validity)
    return conn.accessToken;
  }

  // --- Testing / Simulation Hooks ---

  public _setStateForTest(state: string, record: OAuthStateRecord): void {
    this.stateStore.set(state, record);
  }

  public _setConnectionForTest(userId: string, connection: UserGmailConnection): void {
    this.connections.set(userId, connection);
  }

  public _clearAllForTest(): void {
    this.stateStore.clear();
    this.connections.clear();
  }
}

export const gmailOAuthService = new GmailOAuthService();
