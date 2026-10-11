import {
  BulkTriageSession,
  BulkTriageItem,
  BulkCampaignCluster,
  BulkIndicatorItem,
  MailType,
  RiskLevel,
  ThreatClassification,
  InvestigationCompletePayload,
} from '../../src/types/forensics';
import { parseRawEmail } from '../forensics/parser';
import { analyzeHeaders } from '../forensics/authChecker';
import { analyzeEmailHeuristically, analyzeEmailWithAI } from '../ai/geminiAnalyzer';
import { calculateExplainableRiskScore } from '../forensics/riskEngine';
import { classifyMailType } from '../forensics/mailClassifier';
import { clusterCampaigns } from '../forensics/campaignClusteringEngine';
import { generateSyntheticDemoBatch } from '../demo/bulkDemoGenerator';
import { ipGeolocationService } from '../geolocation/ipGeolocationService';
import { caseService } from './caseService';

interface IngestionFileEntry {
  filename: string;
  content: string;
}

class BulkTriageService {
  private sessions: Map<string, BulkTriageSession> = new Map();
  private sessionItems: Map<string, Map<string, BulkTriageItem>> = new Map();
  private sessionClusters: Map<string, BulkCampaignCluster[]> = new Map();
  private sessionIndicators: Map<string, BulkIndicatorItem[]> = new Map();
  private sessionRawMime: Map<string, Map<string, string>> = new Map();
  private abortControllers: Map<string, AbortController> = new Map();

  /**
   * Creates a new bulk triage session
   */
  public createSession(isDemo = false): BulkTriageSession {
    const sessionId = `SESSION-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const session: BulkTriageSession = {
      sessionId,
      createdAt: new Date().toISOString(),
      status: 'QUEUED',
      totalCount: 0,
      processedCount: 0,
      failedCount: 0,
      progressPercent: 0,
      isDemo,
      metrics: {
        totalEmails: 0,
        mailTypes: { PERSONAL: 0, COMPANY: 0, SPAM: 0, UNKNOWN: 0 },
        riskLevels: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        campaignClustersCount: 0,
        uniquePublicIpsCount: 0,
        uniqueDomainsCount: 0,
        promotedCount: 0,
      },
    };

    this.sessions.set(sessionId, session);
    this.sessionItems.set(sessionId, new Map());
    this.sessionClusters.set(sessionId, []);
    this.sessionIndicators.set(sessionId, []);
    this.sessionRawMime.set(sessionId, new Map());
    this.abortControllers.set(sessionId, new AbortController());

    return session;
  }

  /**
   * Initializes session with pre-generated synthetic demo batch (6,000+ emails)
   */
  public async loadDemoSession(): Promise<BulkTriageSession> {
    const session = this.createSession(true);
    session.status = 'PROCESSING';

    const items = generateSyntheticDemoBatch(6250);
    session.totalCount = items.length;

    const itemsMap = this.sessionItems.get(session.sessionId)!;
    const rawMimeMap = this.sessionRawMime.get(session.sessionId)!;

    // Index items and calculate metrics
    for (const item of items) {
      itemsMap.set(item.triageId, item);
      session.metrics.mailTypes[item.mailClassification.mailType]++;
      session.metrics.riskLevels[item.riskLevel]++;
      const urlText = item.extractedUrls.length > 0 ? `\r\nVerify link: ${item.extractedUrls.join('\n')}\r\n` : '';
      const replyToHeader = item.threatCategory === 'BUSINESS_EMAIL_COMPROMISE' ? `Reply-To: wire-exec-divert@foreign-holding.com\r\n` : '';
      const urgencyText = item.riskLevel === 'CRITICAL' ? `URGENT ACTION REQUIRED: Please execute the transfer immediately.\r\n` : '';
      rawMimeMap.set(
        item.triageId,
        `Received: from relay.transit.net (198.51.100.22) by mail.victim.com with ESMTP\r\nReceived: from attacker.source.xyz (${item.originatingIp || '185.220.101.5'}) by relay.transit.net with ESMTP\r\nFrom: ${item.fromAddress}\r\n${replyToHeader}To: ${item.toAddresses.join(', ')}\r\nSubject: ${item.emailSubject}\r\nDate: ${item.date}\r\n\r\n${urgencyText}DEMO / SIMULATED FORENSIC TELEMETRY for ${item.emailSubject}.${urlText}`
      );
    }

    // Cluster campaigns across the batch
    const { clusters } = clusterCampaigns(items);
    this.sessionClusters.set(session.sessionId, clusters);
    session.metrics.campaignClustersCount = clusters.length;

    // Index unique indicators
    const indicatorMap = new Map<string, BulkIndicatorItem>();
    for (const item of items) {
      if (item.originatingIp) {
        const existing = indicatorMap.get(item.originatingIp) || {
          indicator: item.originatingIp,
          type: 'ipv4',
          frequency: 0,
          country: item.originatingCountry,
          asn: item.originatingAsn,
          associatedCampaigns: [],
          sampleTriageIds: [],
        };
        existing.frequency++;
        if (item.campaignCode && !existing.associatedCampaigns.includes(item.campaignCode)) {
          existing.associatedCampaigns.push(item.campaignCode);
        }
        if (existing.sampleTriageIds.length < 5) {
          existing.sampleTriageIds.push(item.triageId);
        }
        indicatorMap.set(item.originatingIp, existing);
      }

      for (const dom of item.extractedDomains) {
        const existing = indicatorMap.get(dom) || {
          indicator: dom,
          type: 'domain',
          frequency: 0,
          associatedCampaigns: [],
          sampleTriageIds: [],
        };
        existing.frequency++;
        if (item.campaignCode && !existing.associatedCampaigns.includes(item.campaignCode)) {
          existing.associatedCampaigns.push(item.campaignCode);
        }
        if (existing.sampleTriageIds.length < 5) {
          existing.sampleTriageIds.push(item.triageId);
        }
        indicatorMap.set(dom, existing);
      }
    }

    const indicatorList = Array.from(indicatorMap.values()).sort((a, b) => b.frequency - a.frequency);
    this.sessionIndicators.set(session.sessionId, indicatorList);

    session.metrics.uniquePublicIpsCount = indicatorList.filter(i => i.type === 'ipv4').length;
    session.metrics.uniqueDomainsCount = indicatorList.filter(i => i.type === 'domain').length;
    session.metrics.totalEmails = items.length;
    session.processedCount = items.length;
    session.progressPercent = 100;
    session.status = 'COMPLETED';

    return session;
  }

  /**
   * Asynchronously processes raw EML messages with bounded worker concurrency
   */
  public async ingestBatchAsync(sessionId: string, files: IngestionFileEntry[]): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    const abortController = this.abortControllers.get(sessionId);
    session.status = 'PROCESSING';
    session.totalCount = files.length;

    const itemsMap = this.sessionItems.get(sessionId)!;
    const rawMimeMap = this.sessionRawMime.get(sessionId)!;

    // 1. First pass: Collect all unique public IPs across the entire batch for deduplicated enrichment
    const rawUniqueIps = new Set<string>();

    // Concurrency settings: 8 parallel worker tasks
    const CONCURRENCY = 8;
    let fileIndex = 0;

    const runWorker = async () => {
      while (fileIndex < files.length) {
        if (abortController?.signal.aborted) {
          session.status = 'CANCELLED';
          break;
        }

        const idx = fileIndex++;
        const file = files[idx];
        const triageId = `TRIAGE-${String(idx + 1).padStart(5, '0')}`;

        try {
          rawMimeMap.set(triageId, file.content);

          // 1. Parse Email
          const evidence = parseRawEmail(file.content, triageId);

          // 2. Header Forensics
          const headerAnalysis = analyzeHeaders(evidence.headers.receivedHeaders, {
            from: evidence.headers.from,
            fromAddress: evidence.headers.fromAddress,
            fromDomain: evidence.headers.fromDomain,
            fromName: evidence.headers.fromName,
            replyTo: evidence.headers.replyTo,
            returnPath: evidence.headers.returnPath,
            messageId: evidence.headers.messageId,
            date: evidence.headers.date,
            rawSource: file.content,
          });

          // 3. Mail Type Classification (Independent)
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

          // 4. Deterministic Threat Scoring (0 Gemini calls)
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

          const riskScore = calculateExplainableRiskScore({
            threatAssessment,
            headerAnalysis,
            iocs: [],
            geolocations: [],
            attachments: evidence.attachments,
            bodyText: evidence.body.text,
          });

          const originatingIp = headerAnalysis.originatingIp;
          if (originatingIp) {
            rawUniqueIps.add(originatingIp);
          }

          const triageItem: BulkTriageItem = {
            triageId,
            batchId: sessionId,
            emailSubject: evidence.headers.subject || file.filename,
            fromAddress: evidence.headers.fromAddress,
            fromDomain: evidence.headers.fromDomain,
            toAddresses: evidence.headers.to || [],
            date: evidence.headers.date || new Date().toISOString(),
            rawSha256: evidence.sha256,
            sizeBytes: evidence.sizeBytes,
            hasAttachments: evidence.attachments.length > 0,
            attachmentNames: evidence.attachments.map(a => a.filename),
            mailClassification,
            riskScore: riskScore.totalScore,
            riskLevel: riskScore.level,
            threatCategory: threatAssessment.classification,
            riskReasons: threatAssessment.reasons.slice(0, 3),
            originatingIp,
            extractedIps: evidence.extractedIps,
            extractedDomains: evidence.extractedDomains,
            extractedUrls: evidence.extractedUrls,
            isPromoted: false,
          };

          itemsMap.set(triageItem.triageId, triageItem);
          session.metrics.mailTypes[triageItem.mailClassification.mailType]++;
          session.metrics.riskLevels[triageItem.riskLevel]++;
          session.processedCount++;
        } catch (err) {
          session.failedCount++;
        }

        // Live progress calculation
        session.progressPercent = Math.round((session.processedCount / session.totalCount) * 100);

        // Non-blocking event loop yield every 25 emails
        if (idx % 25 === 0) {
          await new Promise(r => setImmediate(r));
        }
      }
    };

    // Run parallel workers
    const workers = Array.from({ length: Math.min(CONCURRENCY, files.length) }, () => runWorker());
    await Promise.all(workers);

    if (abortController?.signal.aborted) return;

    // 5. Deduplicated Unique GeoIP Lookups
    const uniqueIpsList = Array.from(rawUniqueIps);
    session.metrics.uniquePublicIpsCount = uniqueIpsList.length;

    const geoMap = new Map<string, { country?: string; city?: string; asn?: string }>();
    for (const ip of uniqueIpsList) {
      try {
        const geo = await ipGeolocationService.lookupIp(ip);
        if (geo && geo.geolocatable) {
          geoMap.set(ip, { country: geo.country, city: geo.city, asn: geo.asn });
        }
      } catch {
        // Cache miss or network error handled gracefully
      }
    }

    // Attach enriched geo metadata to triage items
    for (const item of itemsMap.values()) {
      if (item.originatingIp && geoMap.has(item.originatingIp)) {
        const g = geoMap.get(item.originatingIp)!;
        item.originatingCountry = g.country;
        item.originatingCity = g.city;
        item.originatingAsn = g.asn;
      }
    }

    // 6. Campaign Clustering
    const allItems = Array.from(itemsMap.values());
    const { clusters } = clusterCampaigns(allItems);
    this.sessionClusters.set(sessionId, clusters);
    session.metrics.campaignClustersCount = clusters.length;

    // 7. Indicators Registry
    const indicatorMap = new Map<string, BulkIndicatorItem>();
    for (const item of allItems) {
      if (item.originatingIp) {
        const g = geoMap.get(item.originatingIp);
        const existing = indicatorMap.get(item.originatingIp) || {
          indicator: item.originatingIp,
          type: 'ipv4',
          frequency: 0,
          country: g?.country,
          asn: g?.asn,
          associatedCampaigns: [],
          sampleTriageIds: [],
        };
        existing.frequency++;
        if (item.campaignCode && !existing.associatedCampaigns.includes(item.campaignCode)) {
          existing.associatedCampaigns.push(item.campaignCode);
        }
        if (existing.sampleTriageIds.length < 5) existing.sampleTriageIds.push(item.triageId);
        indicatorMap.set(item.originatingIp, existing);
      }

      for (const dom of item.extractedDomains) {
        const existing = indicatorMap.get(dom) || {
          indicator: dom,
          type: 'domain',
          frequency: 0,
          associatedCampaigns: [],
          sampleTriageIds: [],
        };
        existing.frequency++;
        if (item.campaignCode && !existing.associatedCampaigns.includes(item.campaignCode)) {
          existing.associatedCampaigns.push(item.campaignCode);
        }
        if (existing.sampleTriageIds.length < 5) existing.sampleTriageIds.push(item.triageId);
        indicatorMap.set(dom, existing);
      }
    }

    const indicatorList = Array.from(indicatorMap.values()).sort((a, b) => b.frequency - a.frequency);
    this.sessionIndicators.set(sessionId, indicatorList);
    session.metrics.uniqueDomainsCount = indicatorList.filter(i => i.type === 'domain').length;
    session.metrics.totalEmails = allItems.length;

    session.status = 'COMPLETED';
    session.progressPercent = 100;
  }

  public getSession(sessionId: string): BulkTriageSession | undefined {
    return this.sessions.get(sessionId);
  }

  public cancelSession(sessionId: string): boolean {
    const controller = this.abortControllers.get(sessionId);
    if (controller) {
      controller.abort();
      const session = this.sessions.get(sessionId);
      if (session) session.status = 'CANCELLED';
      return true;
    }
    return false;
  }

  /**
   * Paginated, filtered query for triage items
   */
  public getFilteredEmails(
    sessionId: string,
    params: {
      page?: number;
      limit?: number;
      mailType?: string;
      riskLevel?: string;
      campaignId?: string;
      search?: string;
    }
  ): { items: BulkTriageItem[]; totalCount: number; page: number; totalPages: number } {
    const itemsMap = this.sessionItems.get(sessionId);
    if (!itemsMap) return { items: [], totalCount: 0, page: 1, totalPages: 0 };

    let results = Array.from(itemsMap.values());

    if (params.mailType && params.mailType !== 'ALL') {
      results = results.filter(i => i.mailClassification.mailType === params.mailType);
    }

    if (params.riskLevel && params.riskLevel !== 'ALL') {
      results = results.filter(i => i.riskLevel === params.riskLevel);
    }

    if (params.campaignId && params.campaignId !== 'ALL') {
      results = results.filter(i => i.campaignId === params.campaignId);
    }

    if (params.search && params.search.trim()) {
      const q = params.search.toLowerCase().trim();
      results = results.filter(
        i =>
          i.emailSubject.toLowerCase().includes(q) ||
          i.fromAddress.toLowerCase().includes(q) ||
          (i.originatingIp && i.originatingIp.toLowerCase().includes(q)) ||
          (i.campaignName && i.campaignName.toLowerCase().includes(q)) ||
          i.extractedDomains.some(d => d.toLowerCase().includes(q))
      );
    }

    // Sort by Risk Score descending (highest risk first)
    results.sort((a, b) => b.riskScore - a.riskScore);

    const page = Math.max(1, Number(params.page) || 1);
    const limit = Math.min(200, Math.max(10, Number(params.limit) || 50));
    const totalCount = results.length;
    const totalPages = Math.ceil(totalCount / limit) || 1;
    const offset = (page - 1) * limit;
    const paginatedItems = results.slice(offset, offset + limit);

    return {
      items: paginatedItems,
      totalCount,
      page,
      totalPages,
    };
  }

  public getEmailDetail(sessionId: string, triageId: string): { item?: BulkTriageItem; rawSource?: string } {
    const itemsMap = this.sessionItems.get(sessionId);
    const rawMimeMap = this.sessionRawMime.get(sessionId);
    const item = itemsMap?.get(triageId);
    const rawSource = rawMimeMap?.get(triageId);
    return { item, rawSource };
  }

  public getCampaigns(sessionId: string): BulkCampaignCluster[] {
    return this.sessionClusters.get(sessionId) || [];
  }

  public getIndicators(sessionId: string): BulkIndicatorItem[] {
    return this.sessionIndicators.get(sessionId) || [];
  }

  /**
   * Promotes a triaged item to a full case in CaseService and EvidenceLedger
   */
  public async promoteItemToCase(
    sessionId: string,
    triageId: string,
    user: { userId: string; name: string; email: string }
  ): Promise<InvestigationCompletePayload> {
    const itemsMap = this.sessionItems.get(sessionId);
    const rawMimeMap = this.sessionRawMime.get(sessionId);

    const item = itemsMap?.get(triageId);
    if (!item) throw new Error('Triage item not found');

    const rawMime = rawMimeMap?.get(triageId);
    const emailContent =
      rawMime ||
      `From: ${item.fromAddress}\r\nSubject: ${item.emailSubject}\r\nDate: ${item.date}\r\n\r\n(Forensic bulk promoted evidence - SHA-256: ${item.rawSha256})`;

    // Execute standard processEmail in caseService
    const payload = await caseService.processEmail(emailContent, {
      title: item.emailSubject,
      analyst: user.name,
      ownerId: user.userId,
      ownerEmail: user.email,
      tags: [item.threatCategory, item.riskLevel, item.mailClassification.mailType, item.campaignCode || 'TRIAGE-PROMOTED'].filter(Boolean) as string[],
    });

    item.isPromoted = true;
    item.promotedCaseId = payload.caseRecord.caseId;

    const session = this.sessions.get(sessionId);
    if (session) {
      session.metrics.promotedCount++;
    }

    return payload;
  }

  /**
   * Runs optional Gemini AI Deep-Dive on an individual triaged item
   */
  public async runAiDeepDive(
    sessionId: string,
    triageId: string
  ): Promise<BulkTriageItem> {
    const itemsMap = this.sessionItems.get(sessionId);
    const rawMimeMap = this.sessionRawMime.get(sessionId);
    const item = itemsMap?.get(triageId);
    if (!item) throw new Error('Triage item not found');

    const rawSource = rawMimeMap?.get(triageId) || '';

    // Invoke Gemini Analyzer with full parameters
    const assessment = await analyzeEmailWithAI({
      subject: item.emailSubject,
      from: item.fromAddress,
      fromDomain: item.fromDomain,
      to: item.toAddresses,
      bodyText: rawSource.substring(0, 3000),
      urls: item.extractedUrls,
      ips: item.extractedIps,
      domains: item.extractedDomains,
      attachments: item.attachmentNames.map(f => ({ filename: f, isSuspicious: item.hasAttachments })),
      authStatus: { spf: 'UNKNOWN', dkim: 'UNKNOWN', dmarc: 'UNKNOWN' },
      inconsistencies: { replyToMismatch: false, returnPathMismatch: false, displaySpoofing: false },
    });

    item.aiDeepAnalysis = {
      analyzedAt: new Date().toISOString(),
      model: 'gemini-3.8-flash',
      assessment,
    };

    return item;
  }
}

export const bulkTriageService = new BulkTriageService();
