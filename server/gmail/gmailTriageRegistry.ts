export type GmailTriageStatus = 'SAFE' | 'SUSPICIOUS' | 'PHISHING_OR_MALICIOUS' | 'NEEDS_REVIEW';

export interface GmailTriageRecord {
  gmailMessageId: string;
  userId: string;
  threadId?: string;
  sender: {
    raw: string;
    fromAddress: string;
    fromDomain: string;
    fromName?: string;
  };
  recipients: string[];
  subject: string;
  receivedAt?: string;
  mailClassification: {
    mailType: 'COMPANY' | 'PERSONAL' | 'SPAM' | 'UNKNOWN';
    confidence: number;
    reasons: string[];
  };
  threatClassification: string;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threatIndicators: {
    detected: Record<string, boolean>;
    reasons: string[];
    riskFactors: string[];
  };
  originatingIp?: string | null;
  extractedDomains: string[];
  extractedUrls: string[];
  attachments: Array<{
    filename: string;
    contentType: string;
    sizeBytes: number;
    sha256: string;
    isSuspicious: boolean;
    threatDetails?: string;
  }>;
  authStatus: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
  forensicSha256: string;
  forensicMd5: string;
  analyzedAt: string;
  triageStatus: GmailTriageStatus;
  alreadyTriaged?: boolean;
}

export class GmailTriageRegistry {
  // Keyed strictly by composite key `${userId}:${gmailMessageId}` for guaranteed multi-tenant isolation
  private records: Map<string, GmailTriageRecord> = new Map();

  private compositeKey(userId: string, gmailMessageId: string): string {
    return `${userId.trim()}:${gmailMessageId.trim()}`;
  }

  public has(userId: string, gmailMessageId: string): boolean {
    if (!userId || !gmailMessageId) return false;
    return this.records.has(this.compositeKey(userId, gmailMessageId));
  }

  public get(userId: string, gmailMessageId: string): GmailTriageRecord | undefined {
    if (!userId || !gmailMessageId) return undefined;
    return this.records.get(this.compositeKey(userId, gmailMessageId));
  }

  public set(userId: string, gmailMessageId: string, record: GmailTriageRecord): void {
    if (!userId || !gmailMessageId) return;
    this.records.set(this.compositeKey(userId, gmailMessageId), record);
  }

  public getAllForUser(userId: string): GmailTriageRecord[] {
    if (!userId) return [];
    const userPrefix = `${userId.trim()}:`;
    const userRecords: GmailTriageRecord[] = [];
    for (const [key, value] of this.records.entries()) {
      if (key.startsWith(userPrefix)) {
        userRecords.push(value);
      }
    }
    return userRecords;
  }

  public delete(userId: string, gmailMessageId: string): boolean {
    return this.records.delete(this.compositeKey(userId, gmailMessageId));
  }

  public clearForUser(userId: string): void {
    if (!userId) return;
    const userPrefix = `${userId.trim()}:`;
    for (const key of Array.from(this.records.keys())) {
      if (key.startsWith(userPrefix)) {
        this.records.delete(key);
      }
    }
  }

  public clearAll(): void {
    this.records.clear();
  }

  public count(): number {
    return this.records.size;
  }
}

export const gmailTriageRegistry = new GmailTriageRegistry();
