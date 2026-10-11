import { GmailApiService, gmailApiService, GmailApiError, GmailNotConnectedError } from './gmailApiService';
import { GmailOAuthService, gmailOAuthService } from './gmailOAuthService';
import { GmailTriageRegistry, gmailTriageRegistry } from './gmailTriageRegistry';
import { caseService as defaultCaseService } from '../services/caseService';
import { CaseRecord, CaseStatus, RiskLevel } from '../../src/types/forensics';

export interface GmailPromotionRecord {
  userId: string;
  gmailMessageId: string;
  caseId: string;
  caseNumber: string;
  title: string;
  promotedAt: string;
  riskScore: number;
  riskLevel: RiskLevel;
  status: CaseStatus;
}

export interface GmailPromotionResponse {
  success: boolean;
  caseId: string;
  caseNumber: string;
  alreadyPromoted: boolean;
  promotedAt: string;
  caseRecord: {
    caseId: string;
    caseNumber: string;
    title: string;
    severity: RiskLevel;
    priority: string;
    status: CaseStatus;
    riskScore: number;
    createdAt: string;
    analyst: string;
    ownerId: string;
    tags: string[];
  };
}

/**
 * Multi-tenant registry tracking Gmail message IDs promoted to formal DFIR cases.
 * Strictly keyed by composite key `${userId}:${gmailMessageId}` to prevent cross-tenant contamination.
 * Stores zero raw MIME, zero OAuth access tokens, and zero refresh tokens.
 */
export class GmailPromotionRegistry {
  private records: Map<string, GmailPromotionRecord> = new Map();

  private compositeKey(userId: string, gmailMessageId: string): string {
    return `${userId.trim()}:${gmailMessageId.trim()}`;
  }

  public has(userId: string, gmailMessageId: string): boolean {
    if (!userId || !gmailMessageId) return false;
    return this.records.has(this.compositeKey(userId, gmailMessageId));
  }

  public get(userId: string, gmailMessageId: string): GmailPromotionRecord | undefined {
    if (!userId || !gmailMessageId) return undefined;
    return this.records.get(this.compositeKey(userId, gmailMessageId));
  }

  public set(userId: string, gmailMessageId: string, record: GmailPromotionRecord): void {
    if (!userId || !gmailMessageId) return;
    this.records.set(this.compositeKey(userId, gmailMessageId), { ...record });
  }

  public getAllForUser(userId: string): GmailPromotionRecord[] {
    if (!userId) return [];
    const prefix = `${userId.trim()}:`;
    const userRecords: GmailPromotionRecord[] = [];
    for (const [key, val] of this.records.entries()) {
      if (key.startsWith(prefix)) {
        userRecords.push({ ...val });
      }
    }
    return userRecords;
  }

  public delete(userId: string, gmailMessageId: string): boolean {
    return this.records.delete(this.compositeKey(userId, gmailMessageId));
  }

  public clear(): void {
    this.records.clear();
  }
}

export const gmailPromotionRegistry = new GmailPromotionRegistry();

/**
 * GmailCasePromotionService
 *
 * Responsibilities:
 * 1. Enforces analyst-initiated workflow (no automatic case creation).
 * 2. Requires prior deterministic triage in Phase 3 registry.
 * 3. Enforces idempotency: repeated clicks return existing case without duplicate creation.
 * 4. Enforces per-message concurrency lock (409 Conflict).
 * 5. Retrieves unaltered RFC-822 raw message from Gmail API.
 * 6. Delegates directly to existing caseService.processEmail() - no duplicate forensic logic.
 * 7. Evidence ledger entry is naturally created and cryptographically sealed by caseService.
 * 8. Zero Gemini API calls made directly by the promotion service layer.
 */
export class GmailCasePromotionService {
  private caseService: typeof defaultCaseService;
  private apiService: GmailApiService;
  private triageRegistry: GmailTriageRegistry;
  private oauthService: GmailOAuthService;
  private promotionRegistry: GmailPromotionRegistry;

  // Per-message promotion lock
  private activePromotions: Set<string> = new Set();

  constructor(options?: {
    caseService?: typeof defaultCaseService;
    apiService?: GmailApiService;
    triageRegistry?: GmailTriageRegistry;
    oauthService?: GmailOAuthService;
    promotionRegistry?: GmailPromotionRegistry;
  }) {
    this.caseService = options?.caseService || defaultCaseService;
    this.apiService = options?.apiService || gmailApiService;
    this.triageRegistry = options?.triageRegistry || gmailTriageRegistry;
    this.oauthService = options?.oauthService || gmailOAuthService;
    this.promotionRegistry = options?.promotionRegistry || gmailPromotionRegistry;
  }

  private lockKey(userId: string, gmailMessageId: string): string {
    return `${userId.trim()}:${gmailMessageId.trim()}`;
  }

  /**
   * Promotes a triaged Gmail message into a formal DFIR investigation case.
   */
  public async promoteMessage(
    userId: string,
    gmailMessageId: string,
    analystUser?: { name?: string; email?: string }
  ): Promise<GmailPromotionResponse> {
    if (!userId || typeof userId !== 'string') {
      throw new GmailApiError('User ID is required to promote Gmail threat to case', 400);
    }
    if (!gmailMessageId || typeof gmailMessageId !== 'string' || gmailMessageId.trim().length === 0) {
      throw new GmailApiError('Gmail message ID is required to promote to case', 400);
    }

    const cleanUserId = userId.trim();
    const cleanMessageId = gmailMessageId.trim();
    const lock = this.lockKey(cleanUserId, cleanMessageId);

    // 1. Verify user has an active Gmail connection
    const conn = this.oauthService.getConnection(cleanUserId);
    if (!conn) {
      throw new GmailNotConnectedError(cleanUserId);
    }

    // 2. Idempotency Check: Return existing case if already promoted
    const existingPromo = this.promotionRegistry.get(cleanUserId, cleanMessageId);
    if (existingPromo) {
      const existingCase = this.caseService.getCasePayload(existingPromo.caseId);
      const caseRecord = existingCase?.caseRecord || {
        caseId: existingPromo.caseId,
        caseNumber: existingPromo.caseNumber,
        title: existingPromo.title,
        severity: existingPromo.riskLevel,
        priority: 'HIGH',
        status: existingPromo.status,
        riskScore: existingPromo.riskScore,
        createdAt: existingPromo.promotedAt,
        analyst: analystUser?.name || 'SOC Analyst',
        ownerId: cleanUserId,
        tags: ['GMAIL-PROMOTED'],
      };

      return {
        success: true,
        caseId: existingPromo.caseId,
        caseNumber: existingPromo.caseNumber,
        alreadyPromoted: true,
        promotedAt: existingPromo.promotedAt,
        caseRecord: caseRecord as any,
      };
    }

    // 3. Triage Requirement Check: Message MUST be deterministically triaged first
    const triageRecord = this.triageRegistry.get(cleanUserId, cleanMessageId);
    if (!triageRecord) {
      throw new GmailApiError(
        `Gmail message ${cleanMessageId} must be deterministically triaged before promotion to a formal DFIR case`,
        400,
        'GMAIL_TRIAGE_REQUIRED'
      );
    }

    // 4. Per-Message Concurrency Lock
    if (this.activePromotions.has(lock)) {
      throw new GmailApiError(
        `Promotion already in progress for Gmail message: ${cleanMessageId}`,
        409,
        'GMAIL_PROMOTION_IN_PROGRESS'
      );
    }

    this.activePromotions.add(lock);

    try {
      // 5. Retrieve unaltered raw RFC-822 message from Gmail API
      const rawMessage = await this.apiService.getRawMessage(cleanUserId, cleanMessageId);

      // 6. Delegate to existing caseService.processEmail()
      const analystName = analystUser?.name || 'SOC Analyst';
      const analystEmail = analystUser?.email || conn.gmailEmail;

      const payload = await this.caseService.processEmail(rawMessage.rawEml, {
        title: triageRecord.subject || `Gmail Incident ${cleanMessageId}`,
        analyst: analystName,
        ownerId: cleanUserId,
        ownerEmail: analystEmail,
        authorizedUsers: [cleanUserId],
        tags: [
          triageRecord.threatClassification,
          triageRecord.riskLevel,
          triageRecord.mailClassification.mailType,
          'GMAIL-PROMOTED',
        ],
      });

      const caseRecord = payload.caseRecord;
      const promotedAt = new Date().toISOString();

      // 7. Store promotion association in registry
      this.promotionRegistry.set(cleanUserId, cleanMessageId, {
        userId: cleanUserId,
        gmailMessageId: cleanMessageId,
        caseId: caseRecord.caseId,
        caseNumber: caseRecord.caseNumber,
        title: caseRecord.title,
        promotedAt,
        riskScore: caseRecord.riskScore,
        riskLevel: caseRecord.severity,
        status: caseRecord.status,
      });

      // 8. Return safe formal case information (zero secrets, zero raw MIME)
      return {
        success: true,
        caseId: caseRecord.caseId,
        caseNumber: caseRecord.caseNumber,
        alreadyPromoted: false,
        promotedAt,
        caseRecord: {
          caseId: caseRecord.caseId,
          caseNumber: caseRecord.caseNumber,
          title: caseRecord.title,
          severity: caseRecord.severity,
          priority: caseRecord.priority,
          status: caseRecord.status,
          riskScore: caseRecord.riskScore,
          createdAt: caseRecord.createdAt,
          analyst: caseRecord.analyst,
          ownerId: caseRecord.ownerId,
          tags: caseRecord.tags,
        },
      };
    } finally {
      this.activePromotions.delete(lock);
    }
  }

  /**
   * Retrieves promotion status for a given Gmail message if already promoted.
   */
  public getPromotionStatus(userId: string, gmailMessageId: string): GmailPromotionRecord | undefined {
    if (!userId || !gmailMessageId) return undefined;
    return this.promotionRegistry.get(userId.trim(), gmailMessageId.trim());
  }
}

export const gmailCasePromotionService = new GmailCasePromotionService();
