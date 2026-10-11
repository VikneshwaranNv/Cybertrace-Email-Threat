export interface GeoLocationData {
  ip: string;
  version: 'IPv4' | 'IPv6';
  country?: string | null;
  countryCode?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  timezone?: string | null;
  postalCode?: string | null;
  accuracyRadiusKm?: number | null;
  confidence: number; // 0 - 100
  asn?: string | null;
  organization?: string | null;
  isp?: string | null;
  connectionType?: 'hosting' | 'residential' | 'cellular' | 'corporate' | 'unknown' | null;
  isVpn: boolean;
  isProxy: boolean;
  isTor: boolean;
  isHosting: boolean;
  source: string; // e.g., "MaxMind GeoIP2", "ipwho.is", "Forensic Verified Cache", "Mock Provider"
  geolocatable: boolean;
  reason?:
    | 'PRIVATE_OR_RESERVED_IP'
    | 'INVALID_IP_SYNTAX'
    | 'PROVIDER_UNAVAILABLE'
    | 'PROVIDER_RATE_LIMIT'
    | 'NOT_FOUND'
    | 'LOW_CONFIDENCE'
    | 'LOOKUP_FAILED';
  // Forensic and backwards-compatibility fields
  isOriginating?: boolean;
  infrastructureRole?: string;
  attributionNote?: string;
  vpnTorProxy?: {
    isVpn: boolean;
    isTor: boolean;
    isProxy: boolean;
    isDatacenter: boolean;
  };
  evidenceProvenance?: {
    sourceHeader?: string;
    rawHeaderSnippet?: string;
    lookupTimestamp: string;
    observedIn: 'RECEIVED_HEADER' | 'ORIGINATING_IP' | 'EXTRACTED_INFRASTRUCTURE' | 'BODY_EXTRACTION';
  };
}

export interface DomainIntelligenceData {
  domain: string;
  observedIps: string[];
  associatedGeos: GeoLocationData[];
  asnList: string[];
  organizations: string[];
  anonymizerStatus: {
    hasVpn: boolean;
    hasTor: boolean;
    hasProxy: boolean;
    hasHosting: boolean;
  };
  confidence: number;
  summary: string;
}

export interface CaseGeolocationSummary {
  caseId: string;
  disclaimer: string;
  geolocations: GeoLocationData[];
  originatingGeo?: GeoLocationData;
  observedSequence: {
    hopIndex: number;
    ip: string;
    role: string;
    geoSummary: string;
    geolocatable: boolean;
  }[];
  domainIntelligence?: DomainIntelligenceData;
  cachedAt: string;
  provider: string;
}
