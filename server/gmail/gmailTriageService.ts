import { parseRawEmail } from '../forensics/parser';
import { analyzeHeaders } from '../forensics/authChecker';
import { classifyMailType } from '../forensics/mailClassifier';
import { analyzeEmailHeuristically } from '../ai/geminiAnalyzer';
import { calculateExplainableRiskScore } from '../forensics/riskEngine';
import { GmailApiService, gmailApiService, GmailRawMessage } from './gmailApiService';
import {
  GmailTriageRecord,
  GmailTriageRegistry,
  GmailTriageStatus,
  gmailTriageRegistry,
} from './gmailTriageRegistry';

export interface BatchTriageItemResult {
  messageId: string;
  success: boolean;
  data?: GmailTriageRecord;
  error?: string;
  errorCode?: string;
}

export interface BatchTriageResponse {
  total: number;
  succeeded: number;
  failed: number;
  results: BatchTriageItemResult[];
}

export class GmailTriageService {
  private apiService: GmailApiService;
  private registry: GmailTriageRegistry;

  // Maximum concurrent worker limit mandated for batch operations
  private readonly MAX_CONCURRENCY = 5;

  // Telemetry for concurrency validation
  private activeConcurrency = 0;
  private maxObservedConcurrency = 0;

  constructor(options?: { apiService?: GmailApiService; registry?: GmailTriageRegistry }) {
    this.apiService = options?.apiService || gmailApiService;
    this.registry = options?.registry || gmailTriageRegistry;
  }

  /**
   * Deterministically triages a single Gmail message.
   *
   * Idempotency guarantee:
   * If the message has already been triaged for this user, returns the existing record
   * immediately without re-running forensic analysis or downloading the message again.
   *
   * Zero Gemini API calls:
   * Analysis uses 100% deterministic local heuristic scoring (analyzeEmailHeuristically)
   * and the authoritative CyberTrace explainable risk engine (calculateExplainableRiskScore).
   */
  public async triageSingleMessage(userId: string, gmailMessageId: string): Promise<GmailTriageRecord> {
    if (!userId || typeof userId !== 'string') {
      throw new Error('User ID is required to triage Gmail message');
    }
    if (!gmailMessageId || typeof gmailMessageId !== 'string') {
      throw new Error('Gmail message ID is required to triage Gmail message');
    }

    const cleanId = gmailMessageId.trim();

    // 1. Idempotency check: Return existing record if already triaged for this user
    const existing = this.registry.get(userId, cleanId);
    if (existing) {
      return {
        ...existing,
        alreadyTriaged: true,
      };
    }

    // 2. Retrieve raw RFC-822 message from Gmail API
    const rawMessage: GmailRawMessage = await this.apiService.getRawMessage(userId, cleanId);

    // 3. Execute deterministic forensic pipeline
    const triageRecord = this.executeDeterministicForensics(userId, rawMessage);

    // 4. Store normalized record in registry (no raw MIME stored)
    this.registry.set(userId, cleanId, triageRecord);

    return triageRecord;
  }

  /**
   * Batch triages multiple Gmail message IDs with strictly bounded concurrency (max 5 simultaneous).
   *
   * Features:
   * - Automatic deduplication of input message IDs.
   * - Bounded concurrency worker pool (<= 5 active tasks).
   * - Partial failure tolerance: one failed message does not crash or abort the batch.
   * - Per-message success / failure reporting.
   */
  public async triageMessages(userId: string, messageIds: string[]): Promise<BatchTriageResponse> {
    if (!userId || typeof userId !== 'string') {
      throw new Error('User ID is required for batch Gmail triage');
    }
    if (!Array.isArray(messageIds)) {
      throw new Error('messageIds must be an array of string IDs');
    }

    // 1. Deduplicate message IDs within the requested batch
    const uniqueIds = Array.from(new Set(messageIds.map(id => (typeof id === 'string' ? id.trim() : '')).filter(Boolean)));

    if (uniqueIds.length === 0) {
      return {
        total: 0,
        succeeded: 0,
        failed: 0,
        results: [],
      };
    }

    const results: BatchTriageItemResult[] = new Array(uniqueIds.length);
    let queueIndex = 0;

    // Bounded worker pool implementation
    const workerCount = Math.min(this.MAX_CONCURRENCY, uniqueIds.length);
    const workers: Promise<void>[] = [];

    for (let w = 0; w < workerCount; w++) {
      workers.push(
        (async () => {
          while (queueIndex < uniqueIds.length) {
            const currentIndex = queueIndex++;
            const targetId = uniqueIds[currentIndex];

            this.activeConcurrency++;
            if (this.activeConcurrency > this.maxObservedConcurrency) {
              this.maxObservedConcurrency = this.activeConcurrency;
            }

            try {
              const record = await this.triageSingleMessage(userId, targetId);
              results[currentIndex] = {
                messageId: targetId,
                success: true,
                data: record,
              };
            } catch (err: any) {
              results[currentIndex] = {
                messageId: targetId,
                success: false,
                error: err?.message || 'Failed to triage message',
                errorCode: err?.code || 'TRIAGE_FAILED',
              };
            } finally {
              this.activeConcurrency--;
            }
          }
        })()
      );
    }

    await Promise.all(workers);

    const succeeded = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    return {
      total: uniqueIds.length,
      succeeded,
      failed,
      results,
    };
  }

  /**
   * Internal pure deterministic forensic execution coordinating:
   * parseRawEmail -> analyzeHeaders -> classifyMailType -> analyzeEmailHeuristically -> calculateExplainableRiskScore
   */
  private executeDeterministicForensics(userId: string, rawMessage: GmailRawMessage): GmailTriageRecord {
    const rawEml = rawMessage.rawEml;
    const caseId = `GMAIL-${rawMessage.id}`;

    // 1. Parse Email: Computes raw SHA-256 and MD5 on unaltered bytes; extracts headers, body, attachments
    const evidence = parseRawEmail(rawEml, caseId);

    // 2. Header Forensics: Reconstructs Received hops, extracts originating IP, checks SPF/DKIM/DMARC
    const headerAnalysis = analyzeHeaders(evidence.headers.receivedHeaders, {
      from: evidence.headers.from,
      fromAddress: evidence.headers.fromAddress,
      fromDomain: evidence.headers.fromDomain,
      fromName: evidence.headers.fromName,
      replyTo: evidence.headers.replyTo,
      returnPath: evidence.headers.returnPath,
      messageId: evidence.headers.messageId,
      date: evidence.headers.date,
      rawSource: rawEml,
    });

    // 3. Mail Type Classification (Independent: COMPANY | PERSONAL | SPAM | UNKNOWN)
    const mailClassification = classifyMailType({
      fromAddress: evidence.headers.fromAddress,
      fromDomain: evidence.headers.fromDomain,
      fromName: evidence.headers.fromName,
      subject: evidence.headers.subject,
      bodyText: evidence.body.text,
      headers: evidence.headers as any,
      authStatus: {
        spf: headerAnalysis.spf.status,
        dkim: headerAnalysis.dkim.status,
        dmarc: headerAnalysis.dmarc.status,
      },
    });

    // 4. Deterministic Heuristic Threat Evaluation (ZERO Gemini calls)
    const threatAssessment = analyzeEmailHeuristically({
      subject: evidence.headers.subject,
      from: evidence.headers.from,
      fromDomain: evidence.headers.fromDomain,
      replyTo: evidence.headers.replyTo,
      bodyText: evidence.body.text,
      urls: evidence.extractedUrls,
      attachments: evidence.attachments,
      authStatus: {
        spf: headerAnalysis.spf.status,
        dkim: headerAnalysis.dkim.status,
        dmarc: headerAnalysis.dmarc.status,
      },
      inconsistencies: headerAnalysis.inconsistencies,
    });

    // 5. Authoritative Explainable Risk Scoring
    const riskScore = calculateExplainableRiskScore({
      threatAssessment,
      headerAnalysis,
      iocs: [],
      geolocations: [],
      attachments: evidence.attachments,
      bodyText: evidence.body.text,
    });

    // 6. Derive overall triage status
    let triageStatus: GmailTriageStatus = 'SAFE';
    if (
      riskScore.level === 'CRITICAL' ||
      threatAssessment.classification === 'PHISHING' ||
      threatAssessment.classification === 'BUSINESS_EMAIL_COMPROMISE' ||
      threatAssessment.classification === 'CREDENTIAL_HARVESTING'
    ) {
      triageStatus = 'PHISHING_OR_MALICIOUS';
    } else if (riskScore.level === 'HIGH' || riskScore.level === 'MEDIUM') {
      triageStatus = 'SUSPICIOUS';
    } else if (mailClassification.mailType === 'SPAM' || riskScore.totalScore >= 25) {
      triageStatus = 'NEEDS_REVIEW';
    }

    // 7. Format clean, normalized triage record (Omit complete raw RFC-822 message)
    const triageRecord: GmailTriageRecord = {
      gmailMessageId: rawMessage.id,
      userId,
      threadId: rawMessage.threadId,
      sender: {
        raw: evidence.headers.from,
        fromAddress: evidence.headers.fromAddress,
        fromDomain: evidence.headers.fromDomain,
        fromName: evidence.headers.fromName,
      },
      recipients: evidence.headers.to,
      subject: evidence.headers.subject,
      receivedAt: evidence.headers.date,
      mailClassification: {
        mailType: mailClassification.mailType,
        confidence: mailClassification.mailTypeConfidence,
        reasons: mailClassification.mailTypeReasons,
      },
      threatClassification: threatAssessment.classification,
      riskScore: riskScore.totalScore,
      riskLevel: riskScore.level,
      threatIndicators: {
        detected: threatAssessment.detectedIndicators as any,
        reasons: threatAssessment.reasons,
        riskFactors: threatAssessment.riskFactors,
      },
      originatingIp: headerAnalysis.originatingIp,
      extractedDomains: evidence.extractedDomains,
      extractedUrls: evidence.extractedUrls,
      attachments: evidence.attachments.map(att => ({
        filename: att.filename,
        contentType: att.contentType,
        sizeBytes: att.sizeBytes,
        sha256: att.sha256,
        isSuspicious: att.isSuspicious,
        threatDetails: att.threatDetails,
      })),
      authStatus: {
        spf: headerAnalysis.spf.status,
        dkim: headerAnalysis.dkim.status,
        dmarc: headerAnalysis.dmarc.status,
      },
      forensicSha256: evidence.sha256,
      forensicMd5: evidence.md5,
      analyzedAt: new Date().toISOString(),
      triageStatus,
    };

    return triageRecord;
  }

  // --- Telemetry & Testing Methods ---

  public getMaxObservedConcurrency(): number {
    return this.maxObservedConcurrency;
  }

  public resetConcurrencyTracker(): void {
    this.maxObservedConcurrency = 0;
    this.activeConcurrency = 0;
  }
}

export const gmailTriageService = new GmailTriageService();
