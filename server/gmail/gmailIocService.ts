import {
  IOCType,
  IOCReputation,
  IOCEnrichmentStatus,
  GmailNormalizedIOC,
} from '../../src/types/forensics';
import { GmailTriageRecord } from './gmailTriageRegistry';
import { ThreatIntelService } from '../intelligence/threatIntelService';

/**
 * Defangs indicators so they cannot be accidentally clicked, parsed as live hyperlinks,
 * or executed in analyst browsers.
 */
export function defangIndicator(type: IOCType, value: string): string {
  if (!value) return '';
  const trimmed = value.trim();

  switch (type) {
    case 'url':
      return trimmed
        .replace(/^https?:\/\//i, match => (match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'))
        .replace(/\./g, '[.]');

    case 'ipv4':
    case 'domain':
      return trimmed.replace(/\./g, '[.]');

    case 'email':
      return trimmed.replace('@', '[@]').replace(/\./g, '[.]');

    case 'ipv6':
      return trimmed.replace(/:/g, '[:]');

    case 'hash_sha256':
    case 'hash_md5':
    default:
      return trimmed;
  }
}

/**
 * Normalizes IOC values (lowercases domains/emails/hashes, trims whitespace, standardizes URLs)
 */
export function normalizeIocValue(type: IOCType, rawValue: string): string {
  if (!rawValue) return '';
  const val = rawValue.trim();

  switch (type) {
    case 'email':
    case 'domain':
    case 'hash_sha256':
    case 'hash_md5':
      return val.toLowerCase();

    case 'ipv4':
      return val.trim();

    case 'ipv6':
      return val.toLowerCase().trim();

    case 'url': {
      try {
        const parsed = new URL(val);
        parsed.hostname = parsed.hostname.toLowerCase();
        // Return normalized string without trailing slash for root paths
        let normalized = parsed.toString();
        if (parsed.pathname === '/' && !parsed.search && !parsed.hash && normalized.endsWith('/')) {
          normalized = normalized.slice(0, -1);
        }
        return normalized;
      } catch {
        return val.trim();
      }
    }

    default:
      return val;
  }
}

/**
 * Determines whether an IP is private, link-local, loopback, or invalid.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip) return true;
  const clean = ip.trim();
  if (clean === '0.0.0.0' || clean === '127.0.0.1' || clean === 'localhost' || clean === '::1') return true;
  if (clean.startsWith('10.')) return true;
  if (clean.startsWith('192.168.')) return true;
  if (clean.startsWith('169.254.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean)) return true;
  return false;
}

export class GmailIocService {
  private threatIntelService: ThreatIntelService;

  constructor(threatIntelService?: ThreatIntelService) {
    this.threatIntelService = threatIntelService || new ThreatIntelService();
  }

  /**
   * Extracts raw indicators from a single GmailTriageRecord
   */
  public extractRawIocsFromRecord(record: GmailTriageRecord): Array<{ type: IOCType; value: string; timestamp: string }> {
    const iocs: Array<{ type: IOCType; value: string; timestamp: string }> = [];
    const timestamp = record.receivedAt || record.analyzedAt || new Date().toISOString();

    // 1. Originating IP
    if (record.originatingIp && !isPrivateOrReservedIp(record.originatingIp)) {
      iocs.push({
        type: 'ipv4',
        value: normalizeIocValue('ipv4', record.originatingIp),
        timestamp,
      });
    }

    // 2. Sender Domain
    if (record.sender?.fromDomain) {
      iocs.push({
        type: 'domain',
        value: normalizeIocValue('domain', record.sender.fromDomain),
        timestamp,
      });
    }

    // 3. Extracted Domains
    if (Array.isArray(record.extractedDomains)) {
      for (const dom of record.extractedDomains) {
        if (dom && typeof dom === 'string') {
          iocs.push({
            type: 'domain',
            value: normalizeIocValue('domain', dom),
            timestamp,
          });
        }
      }
    }

    // 4. Extracted URLs
    if (Array.isArray(record.extractedUrls)) {
      for (const u of record.extractedUrls) {
        if (u && typeof u === 'string') {
          iocs.push({
            type: 'url',
            value: normalizeIocValue('url', u),
            timestamp,
          });
        }
      }
    }

    // 5. Sender Email Address
    if (record.sender?.fromAddress) {
      iocs.push({
        type: 'email',
        value: normalizeIocValue('email', record.sender.fromAddress),
        timestamp,
      });
    }

    // 6. Attachment SHA-256 Hashes
    if (Array.isArray(record.attachments)) {
      for (const att of record.attachments) {
        if (att?.sha256) {
          iocs.push({
            type: 'hash_sha256',
            value: normalizeIocValue('hash_sha256', att.sha256),
            timestamp,
          });
        }
      }
    }

    return iocs;
  }

  /**
   * Deduplicates, normalizes, and enriches all IOCs from a collection of GmailTriageRecords.
   * Gracefully handles provider errors, timeouts, or missing keys with 'THREAT INTELLIGENCE UNAVAILABLE'.
   * ZERO GEMINI CALLS.
   */
  public async normalizeAndEnrichIocs(
    records: GmailTriageRecord[],
    customIntelService?: ThreatIntelService
  ): Promise<GmailNormalizedIOC[]> {
    const intelService = customIntelService || this.threatIntelService;

    // Deduplication map: key = `${type}:${value}`
    const iocMap = new Map<
      string,
      {
        type: IOCType;
        value: string;
        sourceMessageIds: Set<string>;
        firstSeen: string;
        lastSeen: string;
        occurrenceCount: number;
      }
    >();

    for (const record of records) {
      const rawList = this.extractRawIocsFromRecord(record);
      for (const item of rawList) {
        if (!item.value) continue;
        const key = `${item.type}:${item.value}`;
        const existing = iocMap.get(key);

        if (existing) {
          existing.sourceMessageIds.add(record.gmailMessageId);
          existing.occurrenceCount++;
          if (item.timestamp < existing.firstSeen) existing.firstSeen = item.timestamp;
          if (item.timestamp > existing.lastSeen) existing.lastSeen = item.timestamp;
        } else {
          iocMap.set(key, {
            type: item.type,
            value: item.value,
            sourceMessageIds: new Set([record.gmailMessageId]),
            firstSeen: item.timestamp,
            lastSeen: item.timestamp,
            occurrenceCount: 1,
          });
        }
      }
    }

    const uniqueItems = Array.from(iocMap.values());
    const results: GmailNormalizedIOC[] = [];

    // Process enrichment in bounded batches of 10 to avoid overwhelming external providers
    const BATCH_SIZE = 10;
    for (let i = 0; i < uniqueItems.length; i += BATCH_SIZE) {
      const chunk = uniqueItems.slice(i, i + BATCH_SIZE);
      const chunkPromises = chunk.map(async item => {
        const id = `GMAIL-IOC-${Buffer.from(`${item.type}:${item.value}`).toString('base64url').slice(0, 16)}`;
        const defanged = defangIndicator(item.type, item.value);

        let threatIntelResult: {
          reputation: IOCReputation;
          reputationScore: number;
          source: string;
          enrichmentStatus: IOCEnrichmentStatus;
          relatedThreats?: string[];
          maliciousCategory?: string;
        };

        try {
          const enriched = await intelService.enrichIoc(item.type, item.value, Array.from(item.sourceMessageIds));
          threatIntelResult = {
            reputation: enriched.reputation || 'UNKNOWN',
            reputationScore: enriched.reputationScore || 0,
            source: enriched.source || 'THREAT INTELLIGENCE UNAVAILABLE',
            enrichmentStatus: enriched.enrichmentStatus || 'THREAT INTELLIGENCE UNAVAILABLE',
            relatedThreats: enriched.relatedThreats,
            maliciousCategory: enriched.maliciousCategory,
          };
        } catch (err: any) {
          // Graceful degradation: never crash triage or campaign correlation
          threatIntelResult = {
            reputation: 'UNKNOWN',
            reputationScore: 0,
            source: 'THREAT INTELLIGENCE UNAVAILABLE',
            enrichmentStatus: 'THREAT INTELLIGENCE UNAVAILABLE',
          };
        }

        const normalized: GmailNormalizedIOC = {
          id,
          type: item.type,
          value: item.value,
          defangedValue: defanged,
          sourceMessageIds: Array.from(item.sourceMessageIds),
          occurrenceCount: item.occurrenceCount,
          firstSeen: item.firstSeen,
          lastSeen: item.lastSeen,
          threatIntel: threatIntelResult,
        };

        return normalized;
      });

      const chunkResults = await Promise.all(chunkPromises);
      results.push(...chunkResults);
    }

    // Sort: MALICIOUS first, then SUSPICIOUS, then by occurrenceCount descending
    const reputationRank: Record<IOCReputation, number> = {
      MALICIOUS: 4,
      SUSPICIOUS: 3,
      UNKNOWN: 2,
      BENIGN: 1,
    };

    results.sort((a, b) => {
      const repA = a.threatIntel?.reputation || 'UNKNOWN';
      const repB = b.threatIntel?.reputation || 'UNKNOWN';
      const diff = reputationRank[repB] - reputationRank[repA];
      if (diff !== 0) return diff;
      return b.occurrenceCount - a.occurrenceCount;
    });

    return results;
  }
}

export const gmailIocService = new GmailIocService();
