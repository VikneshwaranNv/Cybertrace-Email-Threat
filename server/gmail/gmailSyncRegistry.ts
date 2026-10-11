export type GmailSyncStatus = 'IDLE' | 'SYNCING' | 'TRIAGING' | 'COMPLETED' | 'FAILED';

export interface UserSyncState {
  userId: string;
  historyId: string | null;
  status: GmailSyncStatus;
  lastSyncStartedAt?: string;
  lastSyncCompletedAt?: string;
  lastError?: string | null;
  lastErrorCode?: string | null;
  messagesDiscovered: number;
  messagesTriaged: number;
  updatedAt: string;
  lastHistoryResetAt?: string | null;
}

/**
 * Multi-tenant Sync Checkpoint Registry.
 *
 * Security & Integrity Guarantees:
 * 1. Strict user-isolation: Records are keyed strictly by sanitized `userId`.
 * 2. Zero-token persistence: Never stores OAuth access tokens, refresh tokens, or client secrets.
 * 3. Zero raw-email persistence: Never stores raw RFC-822 MIME bodies.
 * 4. Mutation defense: Returns defensive copies to prevent external in-place state mutation.
 */
export class GmailSyncRegistry {
  private states: Map<string, UserSyncState> = new Map();

  private sanitizeUserId(userId: string): string {
    if (!userId || typeof userId !== 'string') {
      throw new Error('User ID is required for Gmail sync registry operation');
    }
    return userId.trim();
  }

  public get(userId: string): UserSyncState | undefined {
    if (!userId || typeof userId !== 'string') return undefined;
    const cleanId = this.sanitizeUserId(userId);
    const state = this.states.get(cleanId);
    return state ? { ...state } : undefined;
  }

  public getOrCreate(userId: string): UserSyncState {
    const cleanId = this.sanitizeUserId(userId);
    const existing = this.states.get(cleanId);
    if (existing) {
      return { ...existing };
    }

    const initial: UserSyncState = {
      userId: cleanId,
      historyId: null,
      status: 'IDLE',
      messagesDiscovered: 0,
      messagesTriaged: 0,
      updatedAt: new Date().toISOString(),
      lastError: null,
      lastErrorCode: null,
      lastHistoryResetAt: null,
    };
    this.states.set(cleanId, initial);
    return { ...initial };
  }

  public set(userId: string, state: UserSyncState): void {
    const cleanId = this.sanitizeUserId(userId);
    this.states.set(cleanId, {
      ...state,
      userId: cleanId,
      updatedAt: new Date().toISOString(),
    });
  }

  public update(userId: string, partial: Partial<UserSyncState>): UserSyncState {
    const cleanId = this.sanitizeUserId(userId);
    const current = this.getOrCreate(cleanId);
    const updated: UserSyncState = {
      ...current,
      ...partial,
      userId: cleanId,
      updatedAt: new Date().toISOString(),
    };
    this.states.set(cleanId, updated);
    return { ...updated };
  }

  public delete(userId: string): boolean {
    if (!userId || typeof userId !== 'string') return false;
    const cleanId = this.sanitizeUserId(userId);
    return this.states.delete(cleanId);
  }

  public clear(): void {
    this.states.clear();
  }

  public getAll(): UserSyncState[] {
    return Array.from(this.states.values()).map(s => ({ ...s }));
  }
}

export const gmailSyncRegistry = new GmailSyncRegistry();
