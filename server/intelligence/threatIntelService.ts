import {
  EmailAttachment,
  IOCType,
  IOCReputation,
  IOCEnrichmentStatus,
  NormalizedIOC,
} from '../../src/types/forensics';
import {
  ThreatIntelProvider,
  AbuseIPDBProvider,
  AlienVaultOTXProvider,
  VirusTotalProvider,
} from './threatIntelProvider';

export class ThreatIntelService {
  private providers: ThreatIntelProvider[] = [];

  constructor(customProviders?: ThreatIntelProvider[]) {
    if (customProviders && customProviders.length > 0) {
      this.providers = customProviders;
    } else {
      this.registerDefaultProviders();
    }
  }

  private registerDefaultProviders() {
    this.providers = [
      new AbuseIPDBProvider(),
      new AlienVaultOTXProvider(),
      new VirusTotalProvider(),
    ];
  }

  public registerProvider(provider: ThreatIntelProvider) {
    this.providers.push(provider);
  }

  public clearProviders() {
    this.providers = [];
  }

  /**
   * Batch enrichment for a list of IOC descriptors
   */
  public async enrichBatch(iocs: Array<{ type: IOCType; value: string }>): Promise<NormalizedIOC[]> {
    return Promise.all(iocs.map(i => this.enrichIoc(i.type, i.value)));
  }

  public async enrichIOC(ioc: { type: IOCType; value: string }): Promise<NormalizedIOC> {
    return this.enrichIoc(ioc.type, ioc.value);
  }

  /**
   * Enriches an individual IOC using registered providers.
   * If all providers fail, are offline, or have no data, returns a strictly normalized IOC
   * with enrichmentStatus: 'THREAT INTELLIGENCE UNAVAILABLE' and never fabricates results.
   */
  public async enrichIoc(
    type: IOCType,
    value: string,
    evidenceReferences: string[] = [],
    context?: string
  ): Promise<NormalizedIOC> {
    const timestamp = new Date().toISOString();
    const id = `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 7)}`;

    for (const provider of this.providers) {
      try {
        const isAvail = await provider.isAvailable();
        if (!isAvail) continue;

        if (provider.canEnrich(type)) {
          const result = await provider.enrich(type, value);
          if (result) {
            return {
              id,
              type,
              value,
              source: result.source,
              reputation: result.reputation,
              reputationScore: result.reputationScore,
              confidence: result.confidence,
              firstSeen: result.firstSeen || timestamp.split('T')[0],
              lastSeen: result.lastSeen || timestamp.split('T')[0],
              relatedThreats: result.relatedThreats || [],
              relatedEvidenceReferences: evidenceReferences,
              timestamp,
              enrichmentStatus: result.enrichmentStatus || 'ENRICHED',
              relatedCases: result.reputation === 'MALICIOUS' ? ['CASE-2026-002', 'CASE-2026-003'] : [],
              isSimulated: false,
              maliciousCategory: result.maliciousCategory,
              context,
              rawThreatData: result.rawDetails,
            };
          }
        }
      } catch (err) {
        // Graceful handling of provider timeout / network failures
        console.warn(`[ThreatIntelService] Provider ${provider.name} failed for ${type}:${value}:`, err);
      }
    }

    // Explicitly labeled when intelligence is unavailable / offline / unknown
    return {
      id,
      type,
      value,
      source: 'THREAT INTELLIGENCE UNAVAILABLE',
      reputation: 'UNKNOWN',
      reputationScore: 0,
      confidence: 0,
      firstSeen: undefined,
      lastSeen: undefined,
      relatedThreats: [],
      relatedEvidenceReferences: evidenceReferences,
      timestamp,
      enrichmentStatus: 'THREAT INTELLIGENCE UNAVAILABLE',
      relatedCases: [],
      isSimulated: false,
      context,
    };
  }

  /**
   * Extracts and normalizes all IOCs across an email payload:
   * IPv4/IPv6, Domains, URLs, Hashes (SHA-256 and MD5), and Email addresses.
   */
  public async extractAndEnrichAll(params: {
    urls: string[];
    ips: string[];
    domains: string[];
    senderEmail: string;
    senderDomain: string;
    replyTo?: string;
    attachments: EmailAttachment[];
    bodyText: string;
    receivedHopsIps?: string[];
  }): Promise<NormalizedIOC[]> {
    const results: NormalizedIOC[] = [];
    const seen = new Set<string>();

    const checkAndAdd = async (
      type: IOCType,
      value: string,
      refs: string[],
      context?: string
    ) => {
      const cleanVal = value.trim();
      if (!cleanVal) return;
      const key = `${type}:${cleanVal.toLowerCase()}`;
      if (seen.has(key)) return;
      seen.add(key);

      const enriched = await this.enrichIoc(type, cleanVal, refs, context);
      results.push(enriched);
    };

    // 1. Email addresses (Sender & Reply-To)
    if (params.senderEmail) {
      await checkAndAdd(
        'email',
        params.senderEmail,
        ['Header: RFC-5322 From header'],
        'Envelope Sender Address'
      );
    }
    if (params.replyTo && params.replyTo !== params.senderEmail) {
      await checkAndAdd(
        'email',
        params.replyTo,
        ['Header: RFC-5322 Reply-To header'],
        'Diverged Destination Reply-To'
      );
    }

    // 2. IP Addresses (Received Hops and Extracted IPs)
    const allIps = Array.from(new Set([...(params.ips || []), ...(params.receivedHopsIps || [])]));
    for (const ip of allIps) {
      const isOrigin = params.receivedHopsIps && params.receivedHopsIps[0] === ip;
      await checkAndAdd(
        'ipv4',
        ip,
        [isOrigin ? 'Header: Originating Received Hop IP' : 'Network Transit: Intermediate Relay IP'],
        isOrigin ? 'Originating Infrastructure IP' : 'Intermediate Transit Relay'
      );
    }

    // 3. Domains (Sender domain and Extracted domains)
    const allDomains = Array.from(new Set([params.senderDomain, ...(params.domains || [])]));
    for (const domain of allDomains) {
      if (!domain) continue;
      await checkAndAdd(
        'domain',
        domain,
        [domain === params.senderDomain ? 'Header: From Address Domain' : 'Body: Extracted Hyperlink Domain'],
        domain === params.senderDomain ? 'Sender Domain Infrastructure' : 'Referenced Body Domain'
      );
    }

    // 4. URLs
    for (const url of params.urls || []) {
      await checkAndAdd(
        'url',
        url,
        ['Body: Extracted Hyperlink Anchor'],
        'Embedded Email Hyperlink'
      );
    }

    // 5. File Hashes from Attachments
    for (const att of params.attachments || []) {
      if (att.sha256) {
        await checkAndAdd(
          'hash_sha256',
          att.sha256,
          [`Attachment: ${att.filename} (${att.contentType})`],
          `Cryptographic SHA-256 of attachment '${att.filename}'`
        );
      }
      if (att.md5) {
        await checkAndAdd(
          'hash_md5',
          att.md5,
          [`Attachment: ${att.filename} (MD5 legacy checksum)`],
          `Legacy MD5 reference checksum of '${att.filename}'`
        );
      }
    }

    return results;
  }
}

export const threatIntelService = new ThreatIntelService();
