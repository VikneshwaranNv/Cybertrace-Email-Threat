import {
  GmailApiService,
  gmailApiService,
  GmailApiError,
  GmailNotConnectedError,
  GmailHistoryExpiredError,
  GmailMalformedPayloadError,
} from './gmailApiService';
import {
  GmailSyncRegistry,
  gmailSyncRegistry,
  GmailSyncStatus,
  UserSyncState,
} from './gmailSyncRegistry';
import { GmailTriageService, gmailTriageService } from './gmailTriageService';
import { GmailOAuthService, gmailOAuthService } from './gmailOAuthService';

export interface SyncResult {
  success: boolean;
  status: GmailSyncStatus;
  isInitialSync: boolean;
  historyReset: boolean;
  historyId: string | null;
  messagesDiscovered: number;
  messagesTriaged: number;
  lastSyncStartedAt?: string;
  lastSyncCompletedAt?: string;
  error?: string;
  errorCode?: string;
}

export class GmailSyncService {
  private apiService: GmailApiService;
  private syncRegistry: GmailSyncRegistry;
  private triageService: GmailTriageService;
  private oauthService: GmailOAuthService;

  // Per-user synchronization lock to prevent overlapping sync runs for the same user
  private activeSyncUsers: Set<string> = new Set();

  // Configurable bounds
  private initialSyncLimit: number;
  private maxHistoryPages: number;

  constructor(options?: {
    apiService?: GmailApiService;
    syncRegistry?: GmailSyncRegistry;
    triageService?: GmailTriageService;
    oauthService?: GmailOAuthService;
    initialSyncLimit?: number;
    maxHistoryPages?: number;
  }) {
    this.apiService = options?.apiService || gmailApiService;
    this.syncRegistry = options?.syncRegistry || gmailSyncRegistry;
    this.triageService = options?.triageService || gmailTriageService;
    this.oauthService = options?.oauthService || gmailOAuthService;

    const envLimit = parseInt(process.env.GMAIL_INITIAL_SYNC_LIMIT || '50', 10);
    this.initialSyncLimit = options?.initialSyncLimit || (isNaN(envLimit) ? 50 : envLimit);
    this.maxHistoryPages = options?.maxHistoryPages || 10;
  }

  /**
   * Triggers synchronization for a specific user.
   *
   * Enforces:
   * 1. Multi-tenant isolation: Scoped strictly to the provided userId.
   * 2. Per-user concurrency lock: If user is already syncing, rejects concurrent execution with 409.
   * 3. Independent multi-user execution: User B is never blocked by User A.
   * 4. Zero Gemini API calls: Relies strictly on Phase 3 deterministic triage.
   */
  public async syncUser(userId: string): Promise<SyncResult> {
    if (!userId || typeof userId !== 'string') {
      throw new GmailApiError('User ID is required for Gmail synchronization', 400);
    }

    const cleanUserId = userId.trim();

    // Verify user has an active Gmail connection
    const conn = this.oauthService.getConnection(cleanUserId);
    if (!conn) {
      throw new GmailNotConnectedError(cleanUserId);
    }

    // Enforce per-user synchronization lock
    if (this.activeSyncUsers.has(cleanUserId)) {
      throw new GmailApiError(
        `Gmail synchronization is already in progress for user: ${cleanUserId}`,
        409,
        'GMAIL_SYNC_IN_PROGRESS'
      );
    }

    this.activeSyncUsers.add(cleanUserId);

    try {
      const currentState = this.syncRegistry.getOrCreate(cleanUserId);
      const startTime = new Date().toISOString();

      if (!currentState.historyId) {
        // No checkpoint exists: Perform controlled initial sync
        return await this.performInitialSync(cleanUserId, startTime);
      } else {
        // Checkpoint exists: Perform incremental sync
        return await this.performIncrementalSync(cleanUserId, currentState.historyId, startTime);
      }
    } finally {
      this.activeSyncUsers.delete(cleanUserId);
    }
  }

  /**
   * First-sync strategy:
   * 1. Fetches recent messages bounded by initialSyncLimit (default 50).
   * 2. Deduplicates message IDs.
   * 3. Runs deterministic Phase 3 triage.
   * 4. Obtains genuine mailbox historyId from Gmail profile API.
   * 5. Commits checkpoint only after successful triage.
   */
  private async performInitialSync(userId: string, startTime: string): Promise<SyncResult> {
    this.syncRegistry.update(userId, {
      status: 'SYNCING',
      lastSyncStartedAt: startTime,
      lastError: null,
      lastErrorCode: null,
    });

    try {
      // 1. List recent messages bounded by limit
      const listRes = await this.apiService.listMessages(userId, {
        maxResults: this.initialSyncLimit,
      });

      // 2. Deduplicate message IDs
      const rawIds = (listRes.messages || []).map(m => m.id).filter(Boolean);
      const uniqueIds = Array.from(new Set(rawIds));

      // 3. Triage via Phase 3 deterministic pipeline
      let triagedCount = 0;
      if (uniqueIds.length > 0) {
        this.syncRegistry.update(userId, {
          status: 'TRIAGING',
          messagesDiscovered: uniqueIds.length,
        });

        const triageRes = await this.triageService.triageMessages(userId, uniqueIds);
        triagedCount = triageRes.succeeded;
      }

      // 4. Establish valid Gmail history checkpoint directly from Gmail profile
      const profile = await this.apiService.getProfile(userId);
      const newHistoryId = profile.historyId;

      if (!newHistoryId) {
        throw new GmailMalformedPayloadError('Gmail profile response did not return a valid historyId');
      }

      // 5. Commit new checkpoint
      const completedTime = new Date().toISOString();
      this.syncRegistry.update(userId, {
        status: 'COMPLETED',
        historyId: newHistoryId,
        lastSyncCompletedAt: completedTime,
        messagesDiscovered: uniqueIds.length,
        messagesTriaged: triagedCount,
      });

      return {
        success: true,
        status: 'COMPLETED',
        isInitialSync: true,
        historyReset: false,
        historyId: newHistoryId,
        messagesDiscovered: uniqueIds.length,
        messagesTriaged: triagedCount,
        lastSyncStartedAt: startTime,
        lastSyncCompletedAt: completedTime,
      };
    } catch (err: any) {
      this.syncRegistry.update(userId, {
        status: 'FAILED',
        lastError: err?.message || 'Initial sync failed',
        lastErrorCode: err?.code || 'INITIAL_SYNC_FAILED',
      });
      throw err;
    }
  }

  /**
   * Incremental sync strategy:
   * 1. Queries users.history.list starting from stored historyId with pagination.
   * 2. Extracts newly added messages from history records.
   * 3. Deduplicates message IDs.
   * 4. Triages newly discovered messages using Phase 3.
   * 5. Advances checkpoint only after successful completion.
   * 6. Preserves previous checkpoint if transient errors occur.
   * 7. Initiates bounded recovery if history has expired (404).
   */
  private async performIncrementalSync(
    userId: string,
    startHistoryId: string,
    startTime: string
  ): Promise<SyncResult> {
    this.syncRegistry.update(userId, {
      status: 'SYNCING',
      lastSyncStartedAt: startTime,
      lastError: null,
      lastErrorCode: null,
    });

    try {
      let pageToken: string | undefined = undefined;
      let pageCount = 0;
      const discoveredIds: string[] = [];
      let latestHistoryId = startHistoryId;

      do {
        pageCount++;
        const historyRes = await this.apiService.listHistory(userId, startHistoryId, {
          pageToken,
          maxResults: 100,
          historyTypes: ['messageAdded'],
        });

        if (historyRes.historyId) {
          latestHistoryId = historyRes.historyId;
        }

        if (Array.isArray(historyRes.history)) {
          for (const rec of historyRes.history) {
            // Extract from messagesAdded
            if (Array.isArray(rec.messagesAdded)) {
              for (const item of rec.messagesAdded) {
                if (item.message?.id) {
                  discoveredIds.push(item.message.id);
                }
              }
            }
            // Also inspect rec.messages if messagesAdded is absent
            if (Array.isArray(rec.messages)) {
              for (const m of rec.messages) {
                if (m?.id) {
                  discoveredIds.push(m.id);
                }
              }
            }
          }
        }

        pageToken = historyRes.nextPageToken;
      } while (pageToken && pageCount < this.maxHistoryPages);

      // Deduplicate discovered IDs within history records
      const uniqueIds = Array.from(new Set(discoveredIds.map(id => id.trim()).filter(Boolean)));

      // Triage discovered messages
      let triagedCount = 0;
      if (uniqueIds.length > 0) {
        this.syncRegistry.update(userId, {
          status: 'TRIAGING',
          messagesDiscovered: uniqueIds.length,
        });

        const triageRes = await this.triageService.triageMessages(userId, uniqueIds);
        triagedCount = triageRes.succeeded;
      }

      // Commit advanced checkpoint
      const completedTime = new Date().toISOString();
      this.syncRegistry.update(userId, {
        status: 'COMPLETED',
        historyId: latestHistoryId,
        lastSyncCompletedAt: completedTime,
        messagesDiscovered: uniqueIds.length,
        messagesTriaged: triagedCount,
      });

      return {
        success: true,
        status: 'COMPLETED',
        isInitialSync: false,
        historyReset: false,
        historyId: latestHistoryId,
        messagesDiscovered: uniqueIds.length,
        messagesTriaged: triagedCount,
        lastSyncStartedAt: startTime,
        lastSyncCompletedAt: completedTime,
      };
    } catch (err: any) {
      // Check for history expiration / invalidation (404)
      if (
        err instanceof GmailHistoryExpiredError ||
        err?.statusCode === 404 ||
        err?.code === 'GMAIL_HISTORY_EXPIRED'
      ) {
        return await this.performHistoryRecovery(userId, startHistoryId, startTime);
      }

      // Checkpoint safety: Preserve previous historyId on any other failure
      this.syncRegistry.update(userId, {
        status: 'FAILED',
        lastError: err?.message || 'Incremental sync failed',
        lastErrorCode: err?.code || 'INCREMENTAL_SYNC_FAILED',
      });

      throw err;
    }
  }

  /**
   * History expiration recovery:
   * When Gmail reports that the stored startHistoryId is expired or invalid (404),
   * perform bounded recovery sync without crashing or corrupting data.
   */
  private async performHistoryRecovery(
    userId: string,
    expiredHistoryId: string,
    startTime: string
  ): Promise<SyncResult> {
    const resetTimestamp = new Date().toISOString();
    this.syncRegistry.update(userId, {
      status: 'SYNCING',
      lastHistoryResetAt: resetTimestamp,
    });

    try {
      // 1. Fetch recent messages bounded by limit
      const listRes = await this.apiService.listMessages(userId, {
        maxResults: this.initialSyncLimit,
      });

      // 2. Deduplicate message IDs
      const rawIds = (listRes.messages || []).map(m => m.id).filter(Boolean);
      const uniqueIds = Array.from(new Set(rawIds));

      // 3. Triage via Phase 3 (Idempotency handles messages already triaged)
      let triagedCount = 0;
      if (uniqueIds.length > 0) {
        this.syncRegistry.update(userId, {
          status: 'TRIAGING',
          messagesDiscovered: uniqueIds.length,
        });

        const triageRes = await this.triageService.triageMessages(userId, uniqueIds);
        triagedCount = triageRes.succeeded;
      }

      // 4. Establish fresh valid historyId from Gmail profile
      const profile = await this.apiService.getProfile(userId);
      const freshHistoryId = profile.historyId;

      if (!freshHistoryId) {
        throw new GmailMalformedPayloadError('Failed to establish fresh history checkpoint during recovery');
      }

      // 5. Commit fresh checkpoint
      const completedTime = new Date().toISOString();
      this.syncRegistry.update(userId, {
        status: 'COMPLETED',
        historyId: freshHistoryId,
        lastSyncCompletedAt: completedTime,
        messagesDiscovered: uniqueIds.length,
        messagesTriaged: triagedCount,
      });

      return {
        success: true,
        status: 'COMPLETED',
        isInitialSync: false,
        historyReset: true,
        historyId: freshHistoryId,
        messagesDiscovered: uniqueIds.length,
        messagesTriaged: triagedCount,
        lastSyncStartedAt: startTime,
        lastSyncCompletedAt: completedTime,
      };
    } catch (err: any) {
      this.syncRegistry.update(userId, {
        status: 'FAILED',
        lastError: `History recovery failed: ${err?.message || err}`,
        lastErrorCode: err?.code || 'HISTORY_RECOVERY_FAILED',
      });
      throw err;
    }
  }

  /**
   * Retrieves safe operational synchronization status for the user.
   * Strictly shields tokens, credentials, and raw email content.
   */
  public getStatus(userId: string): UserSyncState {
    if (!userId || typeof userId !== 'string') {
      throw new GmailApiError('User ID is required to get sync status', 400);
    }
    return this.syncRegistry.getOrCreate(userId.trim());
  }

  /**
   * Check if a synchronization is currently in progress for the specified user.
   */
  public isUserSyncing(userId: string): boolean {
    if (!userId || typeof userId !== 'string') return false;
    return this.activeSyncUsers.has(userId.trim());
  }
}

export const gmailSyncService = new GmailSyncService();

/**
 * Lightweight, safe background polling scheduler.
 *
 * Characteristics:
 * - Disabled by default (GMAIL_AUTO_SYNC_ENABLED=false).
 * - Default interval 5 minutes (300,000 ms).
 * - Single interval timer instance (prevents runaway timer proliferation).
 * - Graceful lifecycle control (start / stop).
 * - Respects per-user concurrency lock.
 * - Absolute zero Gemini AI calls.
 */
export class GmailPollingScheduler {
  private syncService: GmailSyncService;
  private oauthService: GmailOAuthService;
  private timer: NodeJS.Timeout | null = null;
  private isRunning = false;
  private intervalMs: number;
  private enabled: boolean;

  constructor(options?: {
    syncService?: GmailSyncService;
    oauthService?: GmailOAuthService;
    intervalMs?: number;
    enabled?: boolean;
  }) {
    this.syncService = options?.syncService || gmailSyncService;
    this.oauthService = options?.oauthService || gmailOAuthService;

    const envEnabled = process.env.GMAIL_AUTO_SYNC_ENABLED === 'true';
    const envInterval = parseInt(process.env.GMAIL_AUTO_SYNC_INTERVAL_MS || '300000', 10);

    this.enabled = options?.enabled !== undefined ? options.enabled : envEnabled;
    this.intervalMs = options?.intervalMs || (isNaN(envInterval) ? 300000 : envInterval);
  }

  public start(): void {
    if (this.timer) {
      return; // Single timer protection
    }
    if (!this.enabled) {
      return; // Disabled by default
    }

    this.isRunning = true;
    this.timer = setInterval(() => {
      this.pollAllUsers().catch(err => {
        console.error('[Gmail Polling] Auto-sync poll encountered error:', err?.message || err);
      });
    }, this.intervalMs);

    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.isRunning = false;
  }

  public isActive(): boolean {
    return this.isRunning && this.timer !== null;
  }

  public isEnabled(): boolean {
    return this.enabled;
  }

  public async pollAllUsers(): Promise<void> {
    const userIds = this.oauthService.getAllConnectedUserIds();
    for (const userId of userIds) {
      try {
        await this.syncService.syncUser(userId);
      } catch (err: any) {
        // Log controlled failure without stopping polling of other users
        console.warn(`[Gmail Polling] Auto-sync skipped/failed for user ${userId}:`, err?.message || err);
      }
    }
  }
}

export const gmailPollingScheduler = new GmailPollingScheduler();
