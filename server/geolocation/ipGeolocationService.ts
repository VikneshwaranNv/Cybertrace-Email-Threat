import { classifyIp, normalizeIp } from './ipClassifier';
import { GeoLocationData, CaseGeolocationSummary, DomainIntelligenceData } from './types';
import type { GeoLocationProvider } from './providers/GeoLocationProvider';
import { MaxMindProvider } from './providers/MaxMindProvider';
import { IpWhoIsProvider } from './providers/IpWhoIsProvider';
import { LiveGeoIpProvider } from './providers/LiveGeoIpProvider';
import { ForensicCacheProvider } from './providers/ForensicCacheProvider';
import { MockProvider } from './providers/MockProvider';
import { getGeoIpConfig, validateGeoIpConfig, isMaxMindConfigured } from './config';
import { InvestigationCompletePayload, ReceivedHop } from '../../src/types/forensics';

interface CacheEntry {
  data: GeoLocationData;
  expiresAt: number;
}

export interface IPGeolocationServiceOptions {
  primaryProvider?: GeoLocationProvider;
  secondaryProvider?: GeoLocationProvider;
  mockProvider?: MockProvider;
  cacheTtlMs?: number;
  provider?: string;
  env?: NodeJS.ProcessEnv;
}

export class IPGeolocationService {
  private primaryProvider: GeoLocationProvider;
  private secondaryProvider?: GeoLocationProvider;
  private baselineCache: ForensicCacheProvider;
  private mockProvider?: MockProvider;
  private cache: Map<string, CacheEntry> = new Map();
  private cacheTtlMs: number = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Factory method to dynamically instantiate either MaxMindProvider or IpWhoIsProvider
   * based on the GEOIP_PROVIDER environment variable, ensuring a clean fallback to ipwhois as default.
   */
  public static createProvider(
    providerName?: string,
    options?: {
      env?: NodeJS.ProcessEnv;
      maxMindOptions?: { accountId?: string; licenseKey?: string; timeoutMs?: number };
      ipWhoIsOptions?: { timeoutMs?: number; baseUrl?: string };
    }
  ): GeoLocationProvider {
    const env = options?.env || process.env;
    const raw = (providerName || env.GEOIP_PROVIDER || 'ipwhois').toLowerCase().trim();

    if (raw === 'maxmind') {
      return new MaxMindProvider(options?.maxMindOptions);
    }

    // Default implementation and clean fallback: IpWhoIsProvider
    return new IpWhoIsProvider(options?.ipWhoIsOptions);
  }

  /**
   * Factory method to dynamically create an IPGeolocationService instance.
   * Dynamically instantiates either MaxMindProvider or IpWhoIsProvider based on the
   * GEOIP_PROVIDER environment variable, ensuring a clean fallback to ipwhois as the default.
   */
  public static create(options?: IPGeolocationServiceOptions): IPGeolocationService {
    return new IPGeolocationService(options);
  }

  constructor(options?: IPGeolocationServiceOptions) {
    this.baselineCache = new ForensicCacheProvider();
    this.mockProvider = options?.mockProvider;

    const env = options?.env || process.env;
    const rawProvider = (options?.provider || env.GEOIP_PROVIDER || 'ipwhois').toLowerCase().trim();

    if (options?.primaryProvider) {
      this.primaryProvider = options.primaryProvider;
      this.secondaryProvider = options.secondaryProvider || new IpWhoIsProvider();
    } else if (rawProvider === 'mock') {
      this.primaryProvider = options?.mockProvider || new MockProvider();
      this.secondaryProvider = new IpWhoIsProvider();
    } else if (rawProvider === 'maxmind') {
      const validation = validateGeoIpConfig(env);
      if (!validation.valid) {
        console.warn(
          `[GeoIP] MaxMind provider selected, but credentials missing (${validation.errors.join(', ')}). Secondary provider (ipwhois) will handle lookups.`
        );
      }
      // Dynamically instantiate MaxMindProvider
      this.primaryProvider = new MaxMindProvider();
      // Ensure clean fallback to ipwhois as secondary provider
      this.secondaryProvider = new IpWhoIsProvider();
    } else {
      // Default: 'ipwhois' (clean fallback for empty, missing, or unrecognized values)
      // Dynamically instantiate IpWhoIsProvider as the primary default implementation
      this.primaryProvider = new IpWhoIsProvider();
      const maxmind = new MaxMindProvider();
      if (maxmind.isConfigured()) {
        this.secondaryProvider = maxmind;
      }
    }

    if (options?.cacheTtlMs) {
      this.cacheTtlMs = options.cacheTtlMs;
    }
  }

  getPrimaryProvider(): GeoLocationProvider {
    return this.mockProvider || this.primaryProvider;
  }

  getSecondaryProvider(): GeoLocationProvider | undefined {
    return this.secondaryProvider;
  }

  getPrimaryProviderName(): string {
    return this.mockProvider ? this.mockProvider.name : this.primaryProvider.name;
  }

  setMockProvider(provider: MockProvider) {
    this.mockProvider = provider;
  }

  clearMockProvider() {
    this.mockProvider = undefined;
  }

  clearCache() {
    this.cache.clear();
  }

  /**
   * Look up a single IP address with full RFC compliance and provider abstraction
   */
  async lookupIp(rawIp: string): Promise<GeoLocationData> {
    const ip = normalizeIp(rawIp);
    const classification = classifyIp(ip);

    if (!classification.isValid) {
      return {
        ip,
        version: 'IPv4',
        confidence: 0,
        isVpn: false,
        isProxy: false,
        isTor: false,
        isHosting: false,
        source: 'IP Validator',
        geolocatable: false,
        reason: 'INVALID_IP_SYNTAX',
        attributionNote: 'Invalid IP address syntax provided.',
      };
    }

    if (!classification.isPublic) {
      return {
        ip,
        version: classification.version === 'IPv6' ? 'IPv6' : 'IPv4',
        confidence: 0,
        isVpn: false,
        isProxy: false,
        isTor: false,
        isHosting: false,
        source: 'RFC IP Classification Engine',
        geolocatable: false,
        reason: 'PRIVATE_OR_RESERVED_IP',
        attributionNote:
          'Private, non-routable, or reserved loopback address. Not routable across the public Internet and cannot be geolocated to external infrastructure.',
      };
    }

    // Check in-memory cache
    const cached = this.cache.get(ip);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.data;
    }

    // If a mock provider is active (automated tests), query mock provider directly
    if (this.mockProvider) {
      const mockResult = await this.mockProvider.lookupIp(ip);
      if (mockResult) {
        this.cache.set(ip, { data: mockResult, expiresAt: Date.now() + this.cacheTtlMs });
        return mockResult;
      }
    }

    // Query primary provider (e.g. IpWhoIsProvider or MaxMindProvider based on GEOIP_PROVIDER)
    let resolvedData: GeoLocationData | null = null;
    try {
      resolvedData = await this.primaryProvider.lookupIp(ip);
    } catch (err: any) {
      console.warn(`Primary geolocation provider (${this.primaryProvider.name}) failed for ${ip}:`, err.message);
    }

    // If primary failed or returned null, try secondary provider
    if (!resolvedData && this.secondaryProvider) {
      try {
        resolvedData = await this.secondaryProvider.lookupIp(ip);
      } catch (err: any) {
        console.warn(`Secondary geolocation provider (${this.secondaryProvider.name}) failed for ${ip}:`, err.message);
      }
    }

    // If neither provider resolved, check baseline forensic cache for canonical cases
    if (!resolvedData) {
      const baseline = await this.baselineCache.lookupIp(ip);
      if (baseline) {
        resolvedData = baseline;
      }
    }

    if (resolvedData) {
      // Set attribution note
      if (!resolvedData.attributionNote) {
        resolvedData.attributionNote =
          'Approximate geolocation of observed network infrastructure. Does not establish physical location or identity of human sender.';
      }
      this.cache.set(ip, { data: resolvedData, expiresAt: Date.now() + this.cacheTtlMs });
      return resolvedData;
    }

    // Fallback unresolvable record without inventing coordinates
    const fallback: GeoLocationData = {
      ip,
      version: classification.version === 'IPv6' ? 'IPv6' : 'IPv4',
      confidence: 0,
      isVpn: false,
      isProxy: false,
      isTor: false,
      isHosting: false,
      source: 'Network Intelligence Resolution',
      geolocatable: false,
      reason: 'PROVIDER_UNAVAILABLE',
      attributionNote: 'Geolocation temporarily unavailable or IP not present in upstream databases. No synthetic coordinates created.',
    };

    this.cache.set(ip, { data: fallback, expiresAt: Date.now() + 60000 }); // short TTL for transient failures
    return fallback;
  }

  /**
   * Look up multiple IPs with strict deduplication
   */
  async lookupManyIps(ips: string[]): Promise<GeoLocationData[]> {
    const uniqueIps: string[] = [];
    const seen = new Set<string>();

    for (const raw of ips) {
      const clean = normalizeIp(raw);
      if (clean && !seen.has(clean)) {
        seen.add(clean);
        uniqueIps.push(clean);
      }
    }

    const results: GeoLocationData[] = [];
    for (const ip of uniqueIps) {
      const res = await this.lookupIp(ip);
      results.push(res);
    }

    return results;
  }

  /**
   * Extracts public routable IPs and header provenance from a case payload
   */
  extractCaseIpsWithProvenance(payload: InvestigationCompletePayload): Array<{
    ip: string;
    isOriginating: boolean;
    role: string;
    sourceHeader?: string;
    rawSnippet?: string;
    observedIn: 'RECEIVED_HEADER' | 'ORIGINATING_IP' | 'EXTRACTED_INFRASTRUCTURE' | 'BODY_EXTRACTION';
  }> {
    const records: Array<{
      ip: string;
      isOriginating: boolean;
      role: string;
      sourceHeader?: string;
      rawSnippet?: string;
      observedIn: 'RECEIVED_HEADER' | 'ORIGINATING_IP' | 'EXTRACTED_INFRASTRUCTURE' | 'BODY_EXTRACTION';
    }> = [];

    const seenIps = new Set<string>();
    const originatingIp = payload.headerAnalysis?.originatingIp;

    // 1. Process Received hops in order
    const hops: ReceivedHop[] = payload.headerAnalysis?.receivedHops || [];
    hops.forEach(h => {
      if (h.ip) {
        const clean = normalizeIp(h.ip);
        if (!seenIps.has(clean)) {
          seenIps.add(clean);
          records.push({
            ip: clean,
            isOriginating: clean === originatingIp || h.isOriginating,
            role: h.relayRole,
            sourceHeader: `Received Hop #${h.hopNumber}`,
            rawSnippet: h.fromHost ? `from ${h.fromHost} by ${h.byHost || 'unspecified'}` : undefined,
            observedIn: 'RECEIVED_HEADER',
          });
        }
      }
    });

    // 2. Ensure originating IP is included if not in hops
    if (originatingIp) {
      const cleanOrigin = normalizeIp(originatingIp);
      if (!seenIps.has(cleanOrigin)) {
        seenIps.add(cleanOrigin);
        records.push({
          ip: cleanOrigin,
          isOriginating: true,
          role: 'PROBABLE_SOURCE_INFRASTRUCTURE',
          sourceHeader: 'Originating Header / Earliest Reliable Envelope',
          observedIn: 'ORIGINATING_IP',
        });
      }
    }

    // 3. Process extracted IPs from body/headers
    const extractedIps = payload.evidence?.extractedIps || [];
    for (const raw of extractedIps) {
      const clean = normalizeIp(raw);
      if (!seenIps.has(clean)) {
        seenIps.add(clean);
        records.push({
          ip: clean,
          isOriginating: false,
          role: 'EXTRACTED_MESSAGE_INFRASTRUCTURE',
          sourceHeader: 'Message Content / MIME Telemetry',
          observedIn: 'BODY_EXTRACTION',
        });
      }
    }

    // 4. Process threat indicators matching IP types
    const threatIndicators = (payload as any).threatIndicators || [];
    for (const ti of threatIndicators) {
      if ((ti.type === 'ipv4' || ti.type === 'ipv6') && ti.value) {
        const clean = normalizeIp(ti.value);
        if (!seenIps.has(clean)) {
          seenIps.add(clean);
          records.push({
            ip: clean,
            isOriginating: false,
            role: 'THREAT_INDICATOR_INFRASTRUCTURE',
            sourceHeader: 'SOC IOC Evidence Ledger',
            observedIn: 'EXTRACTED_INFRASTRUCTURE',
          });
        }
      }
    }

    // 5. Fallback: Parse received headers directly if receivedHops were empty
    if (records.length === 0 && payload.evidence?.headers?.receivedHeaders) {
      const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
      for (const line of payload.evidence.headers.receivedHeaders) {
        const matches = line.match(ipRegex);
        if (matches) {
          for (const m of matches) {
            const clean = normalizeIp(m);
            if (!seenIps.has(clean)) {
              seenIps.add(clean);
              records.push({
                ip: clean,
                isOriginating: false,
                role: 'RECEIVED_HEADER_RELAY',
                sourceHeader: line.substring(0, 80),
                observedIn: 'RECEIVED_HEADER',
              });
            }
          }
        }
      }
    }

    return records;
  }

  /**
   * Generates comprehensive Case Geolocation Summary including domain intelligence
   */
  async resolveCaseGeolocations(payload: InvestigationCompletePayload): Promise<CaseGeolocationSummary> {
    const ipRecords = this.extractCaseIpsWithProvenance(payload);
    const geolocations: GeoLocationData[] = [];
    const timestamp = new Date().toISOString();

    for (const rec of ipRecords) {
      const geo = await this.lookupIp(rec.ip);
      const enriched: GeoLocationData = {
        ...geo,
        isOriginating: rec.isOriginating,
        infrastructureRole: rec.role,
        attributionNote: geo.geolocatable
          ? 'Approximate geolocation of observed network infrastructure. Does not establish physical location or identity of human sender.'
          : geo.attributionNote,
        evidenceProvenance: {
          sourceHeader: rec.sourceHeader,
          rawHeaderSnippet: rec.rawSnippet,
          lookupTimestamp: timestamp,
          observedIn: rec.observedIn,
        },
      };
      geolocations.push(enriched);
    }

    const originatingGeo = geolocations.find(g => g.isOriginating) || geolocations[0];

    // Build chronological observed sequence
    const observedSequence = geolocations.map((g, idx) => {
      const locationLabel = g.geolocatable
        ? `${g.city ? g.city + ', ' : ''}${g.region ? g.region + ', ' : ''}${g.country || 'Unknown'}`
        : g.reason === 'PRIVATE_OR_RESERVED_IP'
        ? 'Internal Non-Routable IP'
        : 'Unresolved Infrastructure';

      return {
        hopIndex: idx + 1,
        ip: g.ip,
        role: g.infrastructureRole || 'Observed Relay',
        geoSummary: locationLabel,
        geolocatable: g.geolocatable,
      };
    });

    // Domain Intelligence
    const senderDomain = payload.evidence?.headers?.fromDomain || 'unknown.domain';
    const associatedGeos = geolocations.filter(g => g.geolocatable);
    const asnList = Array.from(new Set(associatedGeos.map(g => g.asn).filter(Boolean) as string[]));
    const orgs = Array.from(new Set(associatedGeos.map(g => g.organization || g.isp).filter(Boolean) as string[]));

    const domainLocations = Array.from(
      new Set(associatedGeos.map(g => `${g.region ? g.region + ', ' : ''}${g.country || ''}`).filter(Boolean))
    );

    const domainSummary =
      domainLocations.length > 0
        ? `Observed infrastructure associated with domain '${senderDomain}' includes IPs geolocated approximately to ${domainLocations.join(
            '; '
          )}.`
        : `No external routable infrastructure observed for domain '${senderDomain}'.`;

    const domainIntelligence: DomainIntelligenceData = {
      domain: senderDomain,
      observedIps: geolocations.map(g => g.ip),
      associatedGeos,
      asnList,
      organizations: orgs,
      anonymizerStatus: {
        hasVpn: geolocations.some(g => g.isVpn),
        hasTor: geolocations.some(g => g.isTor),
        hasProxy: geolocations.some(g => g.isProxy),
        hasHosting: geolocations.some(g => g.isHosting),
      },
      confidence: originatingGeo ? originatingGeo.confidence : 50,
      summary: domainSummary,
    };

    return {
      caseId: payload.caseRecord.caseId,
      disclaimer:
        'IP geolocation provides an approximate location of network infrastructure. It does not identify a person’s exact physical location.',
      geolocations,
      originatingGeo,
      observedSequence,
      domainIntelligence,
      cachedAt: timestamp,
      provider: this.mockProvider ? this.mockProvider.name : this.primaryProvider.name,
    };
  }
}

// Export factory functions
/**
 * Factory function to dynamically create an IPGeolocationService instance.
 * Dynamically instantiates either MaxMindProvider or IpWhoIsProvider based on the
 * GEOIP_PROVIDER environment variable, ensuring a clean fallback to ipwhois as the default.
 */
export function createIPGeolocationService(options?: IPGeolocationServiceOptions): IPGeolocationService {
  return IPGeolocationService.create(options);
}

export function createGeoLocationService(options?: IPGeolocationServiceOptions): IPGeolocationService {
  return IPGeolocationService.create(options);
}

/**
 * Factory function to dynamically instantiate either MaxMindProvider or IpWhoIsProvider
 * based on the GEOIP_PROVIDER environment variable, ensuring a clean fallback to ipwhois as default.
 */
export function createGeoLocationProvider(
  providerName?: string,
  options?: {
    env?: NodeJS.ProcessEnv;
    maxMindOptions?: { accountId?: string; licenseKey?: string; timeoutMs?: number };
    ipWhoIsOptions?: { timeoutMs?: number; baseUrl?: string };
  }
): GeoLocationProvider {
  return IPGeolocationService.createProvider(providerName, options);
}

// Export singleton instance (created via factory)
export const ipGeolocationService = IPGeolocationService.create();
export { IPGeolocationService as GeoLocationService };
export type { GeoLocationProvider };
export { validateGeoIpConfig, getGeoIpConfig, isMaxMindConfigured } from './config';
