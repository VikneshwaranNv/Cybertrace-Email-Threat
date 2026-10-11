import { IOCType, IOCReputation, IOCEnrichmentStatus, NormalizedIOC } from '../../src/types/forensics';

export interface ThreatEnrichmentResult {
  reputation: IOCReputation;
  reputationScore: number;
  confidence: number;
  source: string;
  firstSeen?: string;
  lastSeen?: string;
  relatedThreats: string[];
  enrichmentStatus: IOCEnrichmentStatus;
  maliciousCategory?: string;
  rawDetails?: Record<string, any>;
}

export interface ThreatIntelProvider {
  id: string;
  name: string;
  isAvailable(): Promise<boolean> | boolean;
  canEnrich(type: IOCType): boolean;
  enrich(type: IOCType, value: string): Promise<ThreatEnrichmentResult | null>;
}

// 1. AbuseIPDB Provider (IP Reputation)
export class AbuseIPDBProvider implements ThreatIntelProvider {
  id = 'abuseipdb';
  name = 'AbuseIPDB Threat Intelligence';

  async isAvailable(): Promise<boolean> {
    return true;
  }

  canEnrich(type: IOCType): boolean {
    return type === 'ipv4' || type === 'ipv6';
  }

  async enrich(type: IOCType, value: string): Promise<ThreatEnrichmentResult | null> {
    if (!this.canEnrich(type)) return null;

    // Deterministic intelligence for known threat infrastructure
    if (value === '185.220.101.5') {
      return {
        reputation: 'MALICIOUS',
        reputationScore: 94,
        confidence: 95,
        source: 'AbuseIPDB Global Blacklist',
        firstSeen: '2024-02-14',
        lastSeen: '2026-09-04',
        relatedThreats: ['Tor Exit Node Anonymizer', 'Brute Force Relay', 'M365 Credential Proxy'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Tor Exit Node / Bulletproof Relay',
        rawDetails: { totalReports: 1420, abuseConfidenceScore: 94, countryCode: 'DE' },
      };
    }

    if (value === '194.165.16.88') {
      return {
        reputation: 'MALICIOUS',
        reputationScore: 88,
        confidence: 90,
        source: 'AbuseIPDB Network Telemetry',
        firstSeen: '2024-08-11',
        lastSeen: '2026-09-01',
        relatedThreats: ['HostKey Bulletproof VPS', 'AiTM Phishing Proxy', 'APT29 Activity Cluster'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Bulletproof Unmanaged Hosting',
        rawDetails: { totalReports: 830, abuseConfidenceScore: 88, countryCode: 'RU' },
      };
    }

    if (value === '197.210.64.12') {
      return {
        reputation: 'SUSPICIOUS',
        reputationScore: 78,
        confidence: 85,
        source: 'AbuseIPDB Telemetry',
        firstSeen: '2025-01-20',
        lastSeen: '2026-08-28',
        relatedThreats: ['FIN-7 Impersonation Infrastructure', 'Residential VPN Proxy'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Commercial Cellular Proxy / Diversion Relay',
        rawDetails: { totalReports: 420, abuseConfidenceScore: 78, countryCode: 'NG' },
      };
    }

    if (value === '198.51.100.45') {
      return {
        reputation: 'SUSPICIOUS',
        reputationScore: 72,
        confidence: 80,
        source: 'AbuseIPDB Telemetry',
        firstSeen: '2025-05-12',
        lastSeen: '2026-07-15',
        relatedThreats: ['Offshore Proxy Gateway', 'Wire Diversion Lure'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Encrypted Proxy Transit',
        rawDetails: { totalReports: 310, abuseConfidenceScore: 72, countryCode: 'PA' },
      };
    }

    if (value === '209.85.220.41' || value === '142.250.102.26') {
      return {
        reputation: 'BENIGN',
        reputationScore: 5,
        confidence: 98,
        source: 'AbuseIPDB Verified Enterprise Whitefeed',
        firstSeen: '2010-01-01',
        lastSeen: '2026-09-05',
        relatedThreats: [],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Authorized Google Workspace MX Relay',
        rawDetails: { totalReports: 0, abuseConfidenceScore: 0, isWhitelisted: true },
      };
    }

    return null;
  }
}

// 2. AlienVault OTX Provider (Domains, URLs, IPs)
export class AlienVaultOTXProvider implements ThreatIntelProvider {
  id = 'alienvault_otx';
  name = 'AlienVault OTX Open Threat Exchange';

  async isAvailable(): Promise<boolean> {
    return true;
  }

  canEnrich(type: IOCType): boolean {
    return type === 'domain' || type === 'url' || type === 'ipv4' || type === 'hash_sha256';
  }

  async enrich(type: IOCType, value: string): Promise<ThreatEnrichmentResult | null> {
    const val = value.toLowerCase();

    // Malicious domains
    if (val.includes('login-micros0ft-online.com') || val.includes('auth-office365-verify.com')) {
      return {
        reputation: 'MALICIOUS',
        reputationScore: 96,
        confidence: 98,
        source: 'AlienVault OTX Pulse: Midnight Harvest',
        firstSeen: '2025-03-01',
        lastSeen: '2026-09-02',
        relatedThreats: ['Midnight Harvest AiTM', 'Adversary-in-the-Middle', 'M365 Token Theft'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Typosquatting & Credential Harvester',
        rawDetails: { pulseCount: 18, tags: ['phishing', 'aitm', 'm365', 'apt29'] },
      };
    }

    if (val.includes('global-invoicing.net') || val.includes('wire-settlement-corp.com')) {
      return {
        reputation: 'MALICIOUS',
        reputationScore: 89,
        confidence: 92,
        source: 'AlienVault OTX Pulse: FIN-7 WireLure',
        firstSeen: '2024-11-12',
        lastSeen: '2026-08-30',
        relatedThreats: ['FIN-7 Financial Crime', 'Executive Impersonation', 'BEC Wire Diversion'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Lookalike Financial Domain',
        rawDetails: { pulseCount: 12, tags: ['bec', 'fin7', 'wire-fraud'] },
      };
    }

    // Malicious URLs
    if (val.includes('login-micros0ft-online.com') || val.includes('auth-office365-verify.com/login')) {
      return {
        reputation: 'MALICIOUS',
        reputationScore: 98,
        confidence: 96,
        source: 'AlienVault OTX Malicious URL Feed',
        firstSeen: '2025-03-01',
        lastSeen: '2026-09-02',
        relatedThreats: ['AiTM Token Interceptor', 'Phishing Landing Page'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Phishing Reverse Proxy',
      };
    }

    if (val.includes('wire-settlement-corp.com/remittance')) {
      return {
        reputation: 'MALICIOUS',
        reputationScore: 91,
        confidence: 93,
        source: 'AlienVault OTX Malicious URL Feed',
        firstSeen: '2024-11-12',
        lastSeen: '2026-08-30',
        relatedThreats: ['BEC Wire Transfer Request Form', 'FIN-7 Syndicate'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Fraudulent Payment Portal',
      };
    }

    // Benign enterprise domain
    if (val.includes('google.com') || val.includes('microsoft.com') || val.includes('apple.com')) {
      return {
        reputation: 'BENIGN',
        reputationScore: 0,
        confidence: 99,
        source: 'AlienVault OTX Top 1M Alexa/Tranco',
        firstSeen: '1998-09-04',
        lastSeen: '2026-09-05',
        relatedThreats: [],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Legitimate Global Service Provider',
      };
    }

    return null;
  }
}

// 3. VirusTotal Provider (File Hashes & URLs)
export class VirusTotalProvider implements ThreatIntelProvider {
  id = 'virustotal';
  name = 'VirusTotal Multi-Engine Scanner';

  async isAvailable(): Promise<boolean> {
    return true;
  }

  canEnrich(type: IOCType): boolean {
    return type === 'hash_sha256' || type === 'hash_md5' || type === 'url';
  }

  async enrich(type: IOCType, value: string): Promise<ThreatEnrichmentResult | null> {
    const val = value.toLowerCase();

    // Known malicious attachment hash for demo malware
    if (val.includes('e3b0c442') || val.includes('d5f8c3a1') || val.includes('malware') || val.includes('a789ef')) {
      return {
        reputation: 'MALICIOUS',
        reputationScore: 92,
        confidence: 94,
        source: 'VirusTotal 58/72 Detections',
        firstSeen: '2025-01-15',
        lastSeen: '2026-08-20',
        relatedThreats: ['Trojan.Downloader.Qakbot', 'VBA.Dropper.Agent', 'Script.Heuristic.Malware'],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Weaponized Document Loader',
        rawDetails: { positives: 58, total: 72, scanDate: '2026-08-20' },
      };
    }

    // Known benign attachment (PDF receipts / harmless text)
    if (val.includes('c893') || val.includes('benign') || val.includes('b472')) {
      return {
        reputation: 'BENIGN',
        reputationScore: 0,
        confidence: 96,
        source: 'VirusTotal 0/72 Clean',
        firstSeen: '2026-01-01',
        lastSeen: '2026-09-01',
        relatedThreats: [],
        enrichmentStatus: 'ENRICHED',
        maliciousCategory: 'Clean File',
        rawDetails: { positives: 0, total: 72, scanDate: '2026-09-01' },
      };
    }

    return null;
  }
}

// 4. Simulated Offline/Failing Provider for testing resilience
export class OfflineTestProvider implements ThreatIntelProvider {
  id = 'offline_provider';
  name = 'Offline Threat Intelligence Service';

  async isAvailable(): Promise<boolean> {
    return false;
  }

  canEnrich(): boolean {
    return true;
  }

  async enrich(): Promise<ThreatEnrichmentResult | null> {
    throw new Error('Connection refused: Threat Intelligence service is offline');
  }
}
