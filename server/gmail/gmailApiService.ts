import crypto from 'crypto';
import { GmailOAuthService, gmailOAuthService } from './gmailOAuthService';

// --- Error Definitions ---

export class GmailApiError extends Error {
  public statusCode: number;
  public code: string;
  public retryAfterMs?: number;

  constructor(message: string, statusCode = 500, code = 'GMAIL_API_ERROR', retryAfterMs?: number) {
    super(message);
    this.name = 'GmailApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.retryAfterMs = retryAfterMs;
  }
}

export class GmailNotConnectedError extends GmailApiError {
  constructor(userId: string) {
    super(`No connected Gmail account found for CyberTrace user: ${userId}`, 404, 'GMAIL_NOT_CONNECTED');
    this.name = 'GmailNotConnectedError';
  }
}

export class GmailInvalidIdError extends GmailApiError {
  constructor(messageId: string) {
    super(`Invalid Gmail message ID format: ${messageId}`, 400, 'GMAIL_INVALID_ID');
    this.name = 'GmailInvalidIdError';
  }
}

export class GmailAuthError extends GmailApiError {
  constructor(details = 'Gmail API authentication failed (401 Unauthorized)') {
    super(details, 401, 'GMAIL_AUTH_ERROR');
    this.name = 'GmailAuthError';
  }
}

export class GmailForbiddenError extends GmailApiError {
  constructor(details = 'Access to Gmail resource is forbidden (403 Forbidden)') {
    super(details, 403, 'GMAIL_FORBIDDEN');
    this.name = 'GmailForbiddenError';
  }
}

export class GmailNotFoundError extends GmailApiError {
  constructor(messageId: string) {
    super(`Gmail message not found (404): ${messageId}`, 404, 'GMAIL_NOT_FOUND');
    this.name = 'GmailNotFoundError';
  }
}

export class GmailRateLimitError extends GmailApiError {
  constructor(retryAfterMs = 30000, details = 'Gmail API rate limit exceeded (429 Too Many Requests)') {
    super(details, 429, 'GMAIL_RATE_LIMIT', retryAfterMs);
    this.name = 'GmailRateLimitError';
  }
}

export class GmailNetworkError extends GmailApiError {
  constructor(details = 'Temporary upstream network failure connecting to Gmail API') {
    super(details, 502, 'GMAIL_UPSTREAM_ERROR');
    this.name = 'GmailNetworkError';
  }
}

export class GmailMalformedPayloadError extends GmailApiError {
  constructor(details = 'Gmail API response returned malformed or missing raw RFC-822 field') {
    super(details, 502, 'GMAIL_MALFORMED_PAYLOAD');
    this.name = 'GmailMalformedPayloadError';
  }
}

export class GmailHistoryExpiredError extends GmailApiError {
  constructor(details = 'Gmail historyId has expired or is invalid (404)') {
    super(details, 404, 'GMAIL_HISTORY_EXPIRED');
    this.name = 'GmailHistoryExpiredError';
  }
}

// --- Data Interfaces ---

export interface GmailProfile {
  emailAddress: string;
  messagesTotal: number;
  threadsTotal: number;
  historyId: string;
}

export interface GmailHistoryMessageAdded {
  message: {
    id: string;
    threadId?: string;
    labelIds?: string[];
  };
}

export interface GmailHistoryRecord {
  id: string;
  messages?: GmailMessageSummary[];
  messagesAdded?: GmailHistoryMessageAdded[];
  messagesDeleted?: any[];
  labelsAdded?: any[];
  labelsRemoved?: any[];
}

export interface GmailHistoryListOptions {
  maxResults?: number;
  pageToken?: string;
  historyTypes?: string[];
  labelId?: string;
}

export interface GmailHistoryResponse {
  history: GmailHistoryRecord[];
  nextPageToken?: string;
  historyId: string;
}

export interface GmailMessageSummary {
  id: string;
  threadId: string;
}

export interface GmailListOptions {
  maxResults?: number;
  pageToken?: string;
  query?: string;
}

export interface GmailListResponse {
  messages: GmailMessageSummary[];
  nextPageToken?: string;
  resultSizeEstimate?: number;
}

export interface GmailRawMessage {
  id: string;
  threadId: string;
  labelIds?: string[];
  snippet?: string;
  sizeEstimate?: number;
  rawEml: string;
  sha256: string;
  md5: string;
}

export type GmailApiFetcher = (url: string, init: RequestInit) => Promise<Response>;

// --- Service Implementation ---


// --- Simulated In-Memory Demo Mailbox Store for Offline SIH Evaluation ---
const DEMO_MAILBOX_STORE: Record<string, { threadId: string; snippet: string; rawEml: string }> = {
  'demo-msg-001': {
    threadId: 'thread-demo-001',
    snippet: 'URGENT: Acquisition Escrow Wire Transfer #89410 - Strict Confidentiality',
    rawEml: [
      'Received: from mail.external-spoof.net (198.51.100.45) by mx.google.com with ESMTP; Sun, 13 Sep 2026 14:00:00 +0000',
      'From: "David Chen (Chief Executive Officer)" <ceo-direct@executive-corp-urgent.com>',
      'Reply-To: david.chen.private@attacker-inbox.com',
      'To: finance.desk@cybertrace-defense.internal',
      'Subject: URGENT: Acquisition Escrow Wire Transfer #89410 - Strict Confidentiality',
      'Date: Sun, 13 Sep 2026 14:00:00 +0000',
      'Message-ID: <bec-urgent-wire-89410@executive-corp-urgent.com>',
      'Authentication-Results: mx.google.com; spf=fail (google.com: domain of executive-corp-urgent.com does not designate 198.51.100.45 as permitted sender) smtp.mailfrom=ceo-direct@executive-corp-urgent.com; dkim=neutral (bad sig); dmarc=fail (p=REJECT)',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Team, I am currently in confidential discussions regarding an overseas acquisition. We need an immediate wire transfer of $450,000 to the escrow account before 4:00 PM today.',
      'Please confirm when ready to process. Do not discuss this over phone or corporate Slack.',
    ].join('\r\n'),
  },
  'demo-msg-002': {
    threadId: 'thread-demo-002',
    snippet: 'Action Required: Your Microsoft 365 Password Expires Today',
    rawEml: [
      'Received: from relay-node.attacker-cloud.org (185.220.101.5) by mx.google.com with ESMTP; Sun, 13 Sep 2026 14:15:00 +0000',
      'From: "Microsoft 365 Security Team" <security-alerts@login-microsoft-portal-sec.com>',
      'To: employee@cybertrace-defense.internal',
      'Subject: Action Required: Your Microsoft 365 Password Expires Today',
      'Date: Sun, 13 Sep 2026 14:15:00 +0000',
      'Message-ID: <phish-alert-99124@login-microsoft-portal-sec.com>',
      'Authentication-Results: mx.google.com; spf=softfail; dkim=fail; dmarc=fail (p=REJECT)',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Your Microsoft 365 corporate account requires immediate password verification.',
      'If not completed within 2 hours, access to Outlook, Teams, and OneDrive will be locked.',
      'Verify credentials here: https://login-microsoft365-verify.attacker-drop.com/reset',
    ].join('\r\n'),
  },
  'demo-msg-003': {
    threadId: 'thread-demo-003',
    snippet: 'Overdue Invoice #INV-2026-9918 Payment Demand - Suspicious attachment',
    rawEml: [
      'Received: from invoice-billing.biz (203.0.113.88) by mx.google.com with ESMTP; Sun, 13 Sep 2026 14:30:00 +0000',
      'From: "Global Vendor Billing" <accounts@global-vendor-billing.com>',
      'To: ap@cybertrace-defense.internal',
      'Subject: Overdue Invoice #INV-2026-9918 Payment Demand',
      'Date: Sun, 13 Sep 2026 14:30:00 +0000',
      'Message-ID: <invoice-threat-4412@global-vendor-billing.com>',
      'Authentication-Results: mx.google.com; spf=pass; dkim=none; dmarc=none',
      'Content-Type: multipart/mixed; boundary="BOUNDARY_INVOICE_DEMO"',
      '',
      '--BOUNDARY_INVOICE_DEMO',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Please review the overdue invoice attached. Immediate remittance is required to prevent legal escalation.',
      'Payment portal: http://malicious-pay-escrow.ru/invoice.php',
      '',
      '--BOUNDARY_INVOICE_DEMO',
      'Content-Type: application/octet-stream; name="Invoice_September_2026.pdf.exe"',
      'Content-Disposition: attachment; filename="Invoice_September_2026.pdf.exe"',
      'Content-Transfer-Encoding: base64',
      '',
      'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      'AAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v',
      'ZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA',
      '--BOUNDARY_INVOICE_DEMO--',
    ].join('\r\n'),
  },
  'demo-msg-004': {
    threadId: 'thread-demo-004',
    snippet: 'Scheduled Maintenance Notice: SOC Infrastructure Upgrades',
    rawEml: [
      'Received: from mail.cybertrace-defense.internal (10.0.0.5) by mx.google.com with ESMTP; Sun, 13 Sep 2026 15:00:00 +0000',
      'From: "CyberTrace IT Support" <it-support@cybertrace-defense.internal>',
      'To: staff@cybertrace-defense.internal',
      'Subject: Scheduled Maintenance Notice: SOC Infrastructure Upgrades',
      'Date: Sun, 13 Sep 2026 15:00:00 +0000',
      'Message-ID: <it-notice-2026@cybertrace-defense.internal>',
      'Authentication-Results: mx.google.com; spf=pass; dkim=pass (header.d=cybertrace-defense.internal); dmarc=pass',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Hello Team,',
      '',
      'This is an official announcement that routine database maintenance will occur this Sunday from 02:00 UTC to 04:00 UTC.',
      'No action is required on your part. All email protection services will remain operational without downtime.',
      '',
      'Best regards,',
      'CyberTrace IT Operations Team',
    ].join('\r\n'),
  },
};

export class GmailApiService {
  private oauthService: GmailOAuthService;
  private customFetcher?: GmailApiFetcher;

  constructor(options?: { oauthService?: GmailOAuthService; fetcher?: GmailApiFetcher }) {
    this.oauthService = options?.oauthService || gmailOAuthService;
    this.customFetcher = options?.fetcher;
  }

  private async fetchWithAuth(userId: string, url: string): Promise<Response> {
    const accessToken = await this.oauthService.getValidAccessToken(userId);

    const init: RequestInit = {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
    };

    const fetcher = this.customFetcher || fetch;
    let response: Response;

    try {
      response = await fetcher(url, init);
    } catch (err: any) {
      throw new GmailNetworkError(`Network request to Gmail API failed: ${err?.message || err}`);
    }

    // If 401 Unauthorized, attempt proactive refresh once if refresh token exists
    if (response.status === 401) {
      try {
        const newAccessToken = await this.oauthService.refreshAccessToken(userId);
        const retryInit: RequestInit = {
          ...init,
          headers: {
            ...init.headers,
            Authorization: `Bearer ${newAccessToken}`,
          },
        };
        response = await fetcher(url, retryInit);
      } catch {
        throw new GmailAuthError('Gmail access token is invalid or revoked and could not be refreshed.');
      }
    }

    return response;
  }

  /**
   * Retrieves Gmail message headers/IDs without downloading raw MIME for every message.
   * Parameterized for pagination and optional search queries.
   */
  public async listMessages(userId: string, options?: GmailListOptions): Promise<GmailListResponse> {
    if (!userId || typeof userId !== 'string') {
      throw new GmailApiError('User ID is required to list Gmail messages', 400);
    }

    const conn = this.oauthService.getConnection(userId);
    if (!conn) {
      throw new GmailNotConnectedError(userId);
    }

    // Support Simulated Demo Mailbox for Offline SIH Evaluations
    if (conn.accessToken === 'DEMO_OAUTH_TOKEN') {
      const demoKeys = Object.keys(DEMO_MAILBOX_STORE);
      return {
        messages: demoKeys.map(id => ({ id, threadId: DEMO_MAILBOX_STORE[id].threadId })),
        resultSizeEstimate: demoKeys.length,
      };
    }

    const maxResults = Math.max(1, Math.min(500, options?.maxResults || 50));
    const queryParams = new URLSearchParams({
      maxResults: String(maxResults),
    });

    if (options?.pageToken) {
      queryParams.set('pageToken', options.pageToken);
    }
    if (options?.query) {
      queryParams.set('q', options.query);
    }

    const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages?${queryParams.toString()}`;
    const response = await this.fetchWithAuth(userId, url);

    if (!response.ok) {
      this.handleErrorStatus(response);
    }

    const data: any = await response.json();
    const rawMessages = Array.isArray(data.messages) ? data.messages : [];

    const messages: GmailMessageSummary[] = rawMessages.map((m: any) => ({
      id: String(m.id || ''),
      threadId: String(m.threadId || ''),
    })).filter((m: GmailMessageSummary) => m.id.length > 0);

    return {
      messages,
      nextPageToken: data.nextPageToken || undefined,
      resultSizeEstimate: typeof data.resultSizeEstimate === 'number' ? data.resultSizeEstimate : messages.length,
    };
  }

  /**
   * Retrieves a single message from Gmail using format=raw.
   * Decodes the Base64URL representation into pure, unaltered RFC-822 string
   * ready for consumption by parseRawEmail().
   */
  public async getRawMessage(userId: string, gmailMessageId: string): Promise<GmailRawMessage> {
    if (!userId || typeof userId !== 'string') {
      throw new GmailApiError('User ID is required to retrieve Gmail message', 400);
    }

    if (!gmailMessageId || typeof gmailMessageId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(gmailMessageId.trim())) {
      throw new GmailInvalidIdError(gmailMessageId || 'EMPTY');
    }

    const trimmedId = gmailMessageId.trim();
    const conn = this.oauthService.getConnection(userId);
    if (!conn) {
      throw new GmailNotConnectedError(userId);
    }

    // Support Simulated Demo Mailbox for Offline SIH Evaluations
    if (conn.accessToken === 'DEMO_OAUTH_TOKEN') {
      const demo = DEMO_MAILBOX_STORE[trimmedId];
      if (!demo) {
        throw new GmailNotFoundError(trimmedId);
      }
      const rawEml = demo.rawEml;
      const sha256 = crypto.createHash('sha256').update(rawEml).digest('hex');
      const md5 = crypto.createHash('md5').update(rawEml).digest('hex');
      return {
        id: trimmedId,
        threadId: demo.threadId,
        labelIds: ['INBOX'],
        snippet: demo.snippet,
        sizeEstimate: Buffer.byteLength(rawEml, 'utf8'),
        rawEml,
        sha256,
        md5,
      };
    }

    const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(trimmedId)}?format=raw`;
    const response = await this.fetchWithAuth(userId, url);

    if (!response.ok) {
      this.handleErrorStatus(response, trimmedId);
    }

    const data: any = await response.json();

    if (!data.raw || typeof data.raw !== 'string') {
      throw new GmailMalformedPayloadError(`Gmail message ${trimmedId} did not contain a raw RFC-822 field`);
    }

    // Decode Base64URL representation into standard UTF-8 string
    let rawEml: string;
    try {
      rawEml = Buffer.from(data.raw, 'base64url').toString('utf8');
    } catch (err: any) {
      throw new GmailMalformedPayloadError(`Failed to decode Base64URL payload: ${err?.message || err}`);
    }

    if (!rawEml || rawEml.length === 0) {
      throw new GmailMalformedPayloadError(`Decoded RFC-822 content for message ${trimmedId} is empty`);
    }

    const sha256 = crypto.createHash('sha256').update(rawEml).digest('hex');
    const md5 = crypto.createHash('md5').update(rawEml).digest('hex');

    return {
      id: data.id || trimmedId,
      threadId: data.threadId || trimmedId,
      labelIds: Array.isArray(data.labelIds) ? data.labelIds : [],
      snippet: data.snippet || '',
      sizeEstimate: typeof data.sizeEstimate === 'number' ? data.sizeEstimate : Buffer.byteLength(rawEml, 'utf8'),
      rawEml,
      sha256,
      md5,
    };
  }

  /**
   * Retrieves the user's Gmail profile, including total counts and current historyId.
   * Essential for establishing the initial synchronization checkpoint and recovery.
   */
  public async getProfile(userId: string): Promise<GmailProfile> {
    if (!userId || typeof userId !== 'string') {
      throw new GmailApiError('User ID is required to get Gmail profile', 400);
    }

    const conn = this.oauthService.getConnection(userId);
    if (!conn) {
      throw new GmailNotConnectedError(userId);
    }

    // Support Simulated Demo Mailbox for Offline SIH Evaluations
    if (conn.accessToken === 'DEMO_OAUTH_TOKEN') {
      return {
        emailAddress: String(conn.gmailEmail || 'soc.demo@cybertrace-defense.internal'),
        messagesTotal: 4,
        threadsTotal: 4,
        historyId: '10004',
      };
    }

    const url = 'https://gmail.googleapis.com/gmail/v1/users/me/profile';
    const response = await this.fetchWithAuth(userId, url);

    if (!response.ok) {
      this.handleErrorStatus(response);
    }

    const data: any = await response.json();

    if (!data.historyId) {
      throw new GmailMalformedPayloadError('Gmail profile response missing valid historyId');
    }

    return {
      emailAddress: String(data.emailAddress || conn.gmailEmail || ''),
      messagesTotal: typeof data.messagesTotal === 'number' ? data.messagesTotal : 0,
      threadsTotal: typeof data.threadsTotal === 'number' ? data.threadsTotal : 0,
      historyId: String(data.historyId),
    };
  }

  /**
   * Incremental history synchronization using Gmail users.history.list.
   * Parameterized for startHistoryId, pagination, and history types.
   */
  public async listHistory(
    userId: string,
    startHistoryId: string,
    options?: GmailHistoryListOptions
  ): Promise<GmailHistoryResponse> {
    if (!userId || typeof userId !== 'string') {
      throw new GmailApiError('User ID is required to list Gmail history', 400);
    }

    if (!startHistoryId || typeof startHistoryId !== 'string' || startHistoryId.trim().length === 0) {
      throw new GmailApiError('Valid startHistoryId is required to list Gmail history', 400, 'GMAIL_INVALID_HISTORY_ID');
    }

    const conn = this.oauthService.getConnection(userId);
    if (!conn) {
      throw new GmailNotConnectedError(userId);
    }

    // Support Simulated Demo Mailbox for Offline SIH Evaluations
    if (conn.accessToken === 'DEMO_OAUTH_TOKEN') {
      return {
        history: [],
        historyId: '10004',
      };
    }

    const trimmedHistoryId = startHistoryId.trim();
    const queryParams = new URLSearchParams({
      startHistoryId: trimmedHistoryId,
    });

    const maxResults = Math.max(1, Math.min(500, options?.maxResults || 100));
    queryParams.set('maxResults', String(maxResults));

    if (options?.pageToken) {
      queryParams.set('pageToken', options.pageToken);
    }
    if (options?.labelId) {
      queryParams.set('labelId', options.labelId);
    }
    if (Array.isArray(options?.historyTypes)) {
      for (const type of options.historyTypes) {
        queryParams.append('historyTypes', type);
      }
    }

    const url = `https://gmail.googleapis.com/gmail/v1/users/me/history?${queryParams.toString()}`;
    const response = await this.fetchWithAuth(userId, url);

    if (!response.ok) {
      if (response.status === 404) {
        throw new GmailHistoryExpiredError(`Gmail historyId ${trimmedHistoryId} has expired or is invalid (404)`);
      }
      this.handleErrorStatus(response);
    }

    const data: any = await response.json();
    const rawHistory = Array.isArray(data.history) ? data.history : [];

    const history: GmailHistoryRecord[] = rawHistory.map((h: any) => ({
      id: String(h.id || ''),
      messages: Array.isArray(h.messages)
        ? h.messages.map((m: any) => ({ id: String(m.id || ''), threadId: String(m.threadId || '') }))
        : undefined,
      messagesAdded: Array.isArray(h.messagesAdded)
        ? h.messagesAdded.map((item: any) => ({
            message: {
              id: String(item.message?.id || ''),
              threadId: item.message?.threadId ? String(item.message.threadId) : undefined,
              labelIds: Array.isArray(item.message?.labelIds) ? item.message.labelIds : [],
            },
          }))
        : undefined,
      messagesDeleted: Array.isArray(h.messagesDeleted) ? h.messagesDeleted : undefined,
      labelsAdded: Array.isArray(h.labelsAdded) ? h.labelsAdded : undefined,
      labelsRemoved: Array.isArray(h.labelsRemoved) ? h.labelsRemoved : undefined,
    }));

    return {
      history,
      nextPageToken: data.nextPageToken || undefined,
      historyId: data.historyId ? String(data.historyId) : trimmedHistoryId,
    };
  }

  private handleErrorStatus(response: Response, messageId?: string): never {
    const status = response.status;

    if (status === 401) {
      throw new GmailAuthError();
    }
    if (status === 403) {
      throw new GmailForbiddenError();
    }
    if (status === 404) {
      throw new GmailNotFoundError(messageId || 'unknown');
    }
    if (status === 429) {
      const retryHeader = response.headers.get('Retry-After');
      const retryMs = retryHeader ? parseInt(retryHeader, 10) * 1000 : 30000;
      throw new GmailRateLimitError(isNaN(retryMs) ? 30000 : retryMs);
    }
    if (status >= 500) {
      throw new GmailNetworkError(`Gmail upstream server error (${status}): ${response.statusText}`);
    }

    throw new GmailApiError(`Gmail API responded with error status (${status}): ${response.statusText}`, status);
  }
}

export const gmailApiService = new GmailApiService();
