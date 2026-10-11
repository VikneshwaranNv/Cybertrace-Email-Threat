import crypto from 'crypto';
import {
  RiskLevel,
  GmailCampaignSummary,
  GmailCampaignDetailResponse,
  GmailNormalizedIOC,
} from '../../src/types/forensics';
import { GmailTriageRecord, GmailTriageRegistry, gmailTriageRegistry } from './gmailTriageRegistry';
import { GmailIocService, gmailIocService, isPrivateOrReservedIp } from './gmailIocService';
import { ThreatIntelService } from '../intelligence/threatIntelService';

const BENIGN_SHARED_DOMAINS = new Set([
  'gmail.com',
  'google.com',
  'googlemail.com',
  'microsoft.com',
  'outlook.com',
  'yahoo.com',
  'apple.com',
  'amazon.com',
  'cloudflare.com',
  'example.com',
]);

export class GmailCampaignService {
  private triageRegistry: GmailTriageRegistry;
  private iocService: GmailIocService;
  private threatIntelService?: ThreatIntelService;

  constructor(options?: {
    triageRegistry?: GmailTriageRegistry;
    iocService?: GmailIocService;
    threatIntelService?: ThreatIntelService;
  }) {
    this.triageRegistry = options?.triageRegistry || gmailTriageRegistry;
    this.iocService = options?.iocService || gmailIocService;
    this.threatIntelService = options?.threatIntelService;
  }

  /**
   * Disjoint Set Union (Union-Find) helper to cluster connected items
   */
  private buildUnionFind(itemIds: string[]): {
    find: (x: string) => string;
    union: (x: string, y: string) => void;
  } {
    const parent = new Map<string, string>();
    for (const id of itemIds) {
      parent.set(id, id);
    }

    function find(x: string): string {
      if (!parent.has(x)) parent.set(x, x);
      if (parent.get(x) !== x) {
        parent.set(x, find(parent.get(x)!));
      }
      return parent.get(x)!;
    }

    function union(x: string, y: string) {
      const rx = find(x);
      const ry = find(y);
      if (rx !== ry) {
        parent.set(rx, ry);
      }
    }

    return { find, union };
  }

  /**
   * Deterministically calculates campaign risk score and level from observable evidence.
   */
  private computeCampaignRisk(
    highestMessageRisk: number,
    groupSize: number,
    sharedIocs: GmailNormalizedIOC[],
    distinctSenders: number
  ): { riskScore: number; riskLevel: RiskLevel; threatIntelFindings: string[] } {
    let score = highestMessageRisk;
    const findings: string[] = [];

    // 1. Evidence-based boost from threat intelligence
    let hasMalicious = false;
    let hasSuspicious = false;

    for (const ioc of sharedIocs) {
      const rep = ioc.threatIntel?.reputation;
      if (rep === 'MALICIOUS') {
        hasMalicious = true;
        const category = ioc.threatIntel?.maliciousCategory ? ` [${ioc.threatIntel.maliciousCategory}]` : '';
        findings.push(
          `${ioc.threatIntel?.source || 'Threat Intel'} flagged ${ioc.type.toUpperCase()} ${ioc.defangedValue} as MALICIOUS (Score: ${ioc.threatIntel?.reputationScore || 90})${category}`
        );
      } else if (rep === 'SUSPICIOUS') {
        hasSuspicious = true;
        findings.push(
          `${ioc.threatIntel?.source || 'Threat Intel'} flagged ${ioc.type.toUpperCase()} ${ioc.defangedValue} as SUSPICIOUS (Score: ${ioc.threatIntel?.reputationScore || 70})`
        );
      }
    }

    if (hasMalicious) {
      score += 15;
    } else if (hasSuspicious) {
      score += 8;
    }

    // 2. Coordinated scale factor
    if (groupSize >= 5) {
      score += 10;
    } else if (groupSize >= 2) {
      score += 5;
    }

    // 3. Infrastructure reuse across distinct senders (e.g. spoofed accounts using same relay/domain)
    if (distinctSenders >= 2) {
      score += 5;
    }

    // Clamp score to 0 - 100
    score = Math.min(100, Math.max(0, Math.round(score)));

    let riskLevel: RiskLevel = 'LOW';
    if (score >= 80) riskLevel = 'CRITICAL';
    else if (score >= 60) riskLevel = 'HIGH';
    else if (score >= 40) riskLevel = 'MEDIUM';

    if (findings.length === 0) {
      findings.push('No external threat intelligence blacklists triggered on shared campaign indicators.');
    }

    return { riskScore: score, riskLevel, threatIntelFindings: findings };
  }

  /**
   * Correlates triaged Gmail messages for a single user into campaign clusters.
   * STRICT MULTI-TENANT ISOLATION: Scoped only to user's triaged messages.
   * ZERO GEMINI CALLS.
   */
  public async getCampaignsForUser(
    userId: string,
    customIntelService?: ThreatIntelService
  ): Promise<{
    campaigns: GmailCampaignSummary[];
    iocs: GmailNormalizedIOC[];
    totalTriagedMessages: number;
  }> {
    if (!userId || typeof userId !== 'string') {
      return { campaigns: [], iocs: [], totalTriagedMessages: 0 };
    }

    // 1. Retrieve all triaged records for this specific user
    const records = this.triageRegistry.getAllForUser(userId);
    if (records.length === 0) {
      return { campaigns: [], iocs: [], totalTriagedMessages: 0 };
    }

    // 2. Normalize and enrich all IOCs across this user's records
    const intelService = customIntelService || this.threatIntelService;
    const allIocs = await this.iocService.normalizeAndEnrichIocs(records, intelService);
    const iocLookup = new Map<string, GmailNormalizedIOC>(
      allIocs.map(ioc => [`${ioc.type}:${ioc.value}`, ioc])
    );

    // 3. Build Inverted Indices for Correlation
    const ipToMessages = new Map<string, string[]>();
    const domainToMessages = new Map<string, string[]>();
    const urlToMessages = new Map<string, string[]>();
    const hashToMessages = new Map<string, string[]>();
    const senderToMessages = new Map<string, string[]>();

    const recordMap = new Map<string, GmailTriageRecord>();
    for (const r of records) {
      recordMap.set(r.gmailMessageId, r);

      // Originating IP
      if (r.originatingIp && !isPrivateOrReservedIp(r.originatingIp)) {
        const ip = r.originatingIp.trim();
        const list = ipToMessages.get(ip) || [];
        list.push(r.gmailMessageId);
        ipToMessages.set(ip, list);
      }

      // Domains
      const domainsToCheck = new Set<string>();
      if (r.sender?.fromDomain) domainsToCheck.add(r.sender.fromDomain.toLowerCase());
      if (Array.isArray(r.extractedDomains)) {
        for (const d of r.extractedDomains) {
          if (d) domainsToCheck.add(d.toLowerCase());
        }
      }
      for (const d of domainsToCheck) {
        if (!BENIGN_SHARED_DOMAINS.has(d)) {
          const list = domainToMessages.get(d) || [];
          list.push(r.gmailMessageId);
          domainToMessages.set(d, list);
        }
      }

      // URLs
      if (Array.isArray(r.extractedUrls)) {
        for (const u of r.extractedUrls) {
          if (u) {
            const cleanUrl = u.trim();
            const list = urlToMessages.get(cleanUrl) || [];
            list.push(r.gmailMessageId);
            urlToMessages.set(cleanUrl, list);
          }
        }
      }

      // Attachment Hashes
      if (Array.isArray(r.attachments)) {
        for (const a of r.attachments) {
          if (a?.sha256) {
            const hash = a.sha256.toLowerCase();
            const list = hashToMessages.get(hash) || [];
            list.push(r.gmailMessageId);
            hashToMessages.set(hash, list);
          }
        }
      }

      // Sender Email
      if (r.sender?.fromAddress) {
        const sender = r.sender.fromAddress.toLowerCase();
        const list = senderToMessages.get(sender) || [];
        list.push(r.gmailMessageId);
        senderToMessages.set(sender, list);
      }
    }

    // 4. Union-Find Clustering
    const messageIds = records.map(r => r.gmailMessageId);
    const { find, union } = this.buildUnionFind(messageIds);

    const linkShared = (indexMap: Map<string, string[]>) => {
      for (const [, msgIds] of indexMap) {
        if (msgIds.length >= 2) {
          for (let i = 1; i < msgIds.length; i++) {
            union(msgIds[0], msgIds[i]);
          }
        }
      }
    };

    linkShared(ipToMessages);
    linkShared(domainToMessages);
    linkShared(urlToMessages);
    linkShared(hashToMessages);
    linkShared(senderToMessages);

    // 5. Group by Component Root
    const groups = new Map<string, GmailTriageRecord[]>();
    for (const r of records) {
      const root = find(r.gmailMessageId);
      const list = groups.get(root) || [];
      list.push(r);
      groups.set(root, list);
    }

    // 6. Build Structured Explainable Campaigns (Multi-message and single-message clusters)
    const campaigns: GmailCampaignSummary[] = [];
    let campaignCounter = 1;

    for (const [, groupItems] of groups) {
      if (groupItems.length === 0) continue;

      const relatedMessageIds = groupItems.map(g => g.gmailMessageId);
      const sampleSubjects = Array.from(new Set(groupItems.map(g => g.subject).filter(Boolean))).slice(0, 4);
      const senderAddresses = Array.from(
        new Set(groupItems.map(g => g.sender?.fromAddress).filter(Boolean))
      );
      const originatingIps = Array.from(
        new Set(
          groupItems
            .map(g => g.originatingIp)
            .filter(ip => ip && !isPrivateOrReservedIp(ip)) as string[]
        )
      );

      // Collect shared correlation reasons
      const correlationReasons: string[] = [];

      // Check shared IPs
      for (const [ip, msgList] of ipToMessages) {
        const overlap = msgList.filter(id => relatedMessageIds.includes(id));
        if (overlap.length >= 2) {
          correlationReasons.push(`Shared Originating IP: ${ip} (${overlap.length} messages)`);
        }
      }

      // Check shared Domains
      for (const [dom, msgList] of domainToMessages) {
        const overlap = msgList.filter(id => relatedMessageIds.includes(id));
        if (overlap.length >= 2) {
          correlationReasons.push(`Shared Destination Domain: ${dom} (${overlap.length} messages)`);
        }
      }

      // Check shared URLs
      for (const [url, msgList] of urlToMessages) {
        const overlap = msgList.filter(id => relatedMessageIds.includes(id));
        if (overlap.length >= 2) {
          const shortUrl = url.length > 60 ? `${url.slice(0, 57)}...` : url;
          correlationReasons.push(`Shared Phishing URL: ${shortUrl} (${overlap.length} messages)`);
        }
      }

      // Check shared Attachment Hashes
      for (const [hash, msgList] of hashToMessages) {
        const overlap = msgList.filter(id => relatedMessageIds.includes(id));
        if (overlap.length >= 2) {
          correlationReasons.push(`Shared Attachment SHA-256: ${hash.slice(0, 16)}... (${overlap.length} messages)`);
        }
      }

      // Check shared Attacker/Sender
      for (const [sender, msgList] of senderToMessages) {
        const overlap = msgList.filter(id => relatedMessageIds.includes(id));
        if (overlap.length >= 2) {
          correlationReasons.push(`Shared Attacker/Sender: ${sender} (${overlap.length} messages)`);
        }
      }

      if (correlationReasons.length === 0) {
        correlationReasons.push('Single isolated threat incident; awaiting additional telemetry peers');
      }

      // Highest risk among group
      const highestMessageRisk = Math.max(...groupItems.map(g => g.riskScore || 0));

      // Shared IOCs
      const groupMessageIdSet = new Set(relatedMessageIds);
      const sharedIocs = allIocs.filter(ioc =>
        ioc.sourceMessageIds.some(id => groupMessageIdSet.has(id))
      );

      // Deterministic risk score & level
      const { riskScore: campaignRiskScore, riskLevel: campaignRiskLevel, threatIntelFindings } =
        this.computeCampaignRisk(
          highestMessageRisk,
          groupItems.length,
          sharedIocs,
          senderAddresses.length
        );

      // Threat category & campaign naming
      let threatCategory = 'DISTRIBUTED_PHISHING';
      let campaignName = groupItems.length > 1
        ? `Distributed Threat Wave #${campaignCounter}`
        : `Targeted Threat Incident #${campaignCounter}`;

      const subjectsStr = sampleSubjects.join(' ').toLowerCase();
      const hasCred = groupItems.some(
        g => g.threatClassification?.toLowerCase().includes('credential') || /login|password|verify|account|microsoft/i.test(subjectsStr)
      );
      const hasBec = groupItems.some(
        g => g.threatClassification?.toLowerCase().includes('compromise') || /wire|payment|invoice|payroll|transfer/i.test(subjectsStr)
      );
      const hasAttachment = groupItems.some(g => g.attachments && g.attachments.length > 0);

      if (hasCred) {
        threatCategory = 'CREDENTIAL_HARVESTING';
        campaignName = groupItems.length > 1
          ? `Adversary Credential Harvesting Wave #${campaignCounter}`
          : `Targeted Credential Phishing Incident #${campaignCounter}`;
      } else if (hasBec) {
        threatCategory = 'BUSINESS_EMAIL_COMPROMISE';
        campaignName = groupItems.length > 1
          ? `Financial BEC / Wire Impersonation Campaign #${campaignCounter}`
          : `Targeted Executive/BEC Impersonation #${campaignCounter}`;
      } else if (hasAttachment) {
        threatCategory = 'SUSPICIOUS_ATTACHMENT';
        campaignName = groupItems.length > 1
          ? `Malicious Document Delivery Campaign #${campaignCounter}`
          : `Suspicious Document Delivery Incident #${campaignCounter}`;
      }

      const clusterSig = `${userId}:${relatedMessageIds.slice().sort().join(',')}`;
      const sigHash = crypto.createHash('sha256').update(clusterSig).digest('hex').slice(0, 8).toUpperCase();
      const campaignId = `GMAIL-CAMP-${sigHash}`;
      const campaignCode = `GC-2026-${String(campaignCounter).padStart(2, '0')}`;

      // Dates
      const sortedDates = groupItems
        .map(g => g.receivedAt || g.analyzedAt)
        .filter(Boolean)
        .sort();
      const firstSeen = sortedDates[0] || new Date().toISOString();
      const lastSeen = sortedDates[sortedDates.length - 1] || new Date().toISOString();

      campaigns.push({
        campaignId,
        campaignName,
        campaignCode,
        threatLevel: campaignRiskLevel,
        relatedMessageIds,
        totalMessages: groupItems.length,
        highestMessageRisk,
        campaignRiskScore,
        campaignRiskLevel,
        threatCategory,
        sampleSubjects,
        senderAddresses,
        originatingIps,
        sharedIocs,
        correlationReasons,
        threatIntelFindings,
        firstSeen,
        lastSeen,
      });

      campaignCounter++;
    }

    // Sort campaigns by risk score descending, then message count descending
    campaigns.sort((a, b) => {
      if (b.campaignRiskScore !== a.campaignRiskScore) {
        return b.campaignRiskScore - a.campaignRiskScore;
      }
      return b.totalMessages - a.totalMessages;
    });

    return {
      campaigns,
      iocs: allIocs,
      totalTriagedMessages: records.length,
    };
  }

  /**
   * Retrieves full details for a specific campaign for an authenticated user.
   * Multi-tenant safe: returns null if campaign does not belong to user.
   */
  public async getCampaignDetailForUser(
    userId: string,
    campaignId: string,
    customIntelService?: ThreatIntelService
  ): Promise<GmailCampaignDetailResponse | null> {
    if (!userId || !campaignId) return null;

    const { campaigns } = await this.getCampaignsForUser(userId, customIntelService);
    const campaign = campaigns.find(c => c.campaignId === campaignId);
    if (!campaign) return null;

    const messages: GmailTriageRecord[] = [];
    for (const msgId of campaign.relatedMessageIds) {
      const record = this.triageRegistry.get(userId, msgId);
      if (record) {
        messages.push(record);
      }
    }

    return {
      campaign,
      messages,
    };
  }

  /**
   * Retrieves enriched IOCs for a user across all their triaged Gmail messages.
   */
  public async getIocsForUser(
    userId: string,
    customIntelService?: ThreatIntelService
  ): Promise<GmailNormalizedIOC[]> {
    if (!userId) return [];
    const records = this.triageRegistry.getAllForUser(userId);
    return this.iocService.normalizeAndEnrichIocs(records, customIntelService);
  }
}

export const gmailCampaignService = new GmailCampaignService();
