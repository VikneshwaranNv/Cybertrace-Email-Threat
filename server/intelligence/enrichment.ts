import { GeolocationResult } from '../../src/types/forensics';
import { classifyIp, normalizeIp } from '../geolocation/ipClassifier';
import { ipGeolocationService } from '../geolocation/ipGeolocationService';

interface IpGeoProfile {
  country: string;
  countryCode: string;
  region: string;
  city?: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  hostingProvider: string;
  isVpn: boolean;
  isTor: boolean;
  isProxy: boolean;
  isDatacenter: boolean;
  confidence: number;
}

// Deterministic realistic profile database for IP forensics
const KNOWN_PROFILES: Record<string, IpGeoProfile> = {
  // Demo Case 1: Legitimate Enterprise IP (Mountain View / Google Cloud)
  '209.85.220.41': {
    country: 'United States',
    countryCode: 'US',
    region: 'California',
    city: 'Mountain View',
    latitude: 37.422,
    longitude: -122.084,
    isp: 'Google LLC',
    asn: 'AS15169 Google LLC',
    hostingProvider: 'Google Enterprise Workspace MX',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isDatacenter: true,
    confidence: 96,
  },
  '142.250.102.26': {
    country: 'United States',
    countryCode: 'US',
    region: 'California',
    city: 'Los Angeles',
    latitude: 34.0522,
    longitude: -118.2437,
    isp: 'Google LLC',
    asn: 'AS15169 Google LLC',
    hostingProvider: 'Google Cloud Relay',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isDatacenter: true,
    confidence: 94,
  },
  // Demo Case 2: Suspicious Invoice / Payment wire diversion (Lagos / Offshore VPN relay)
  '197.210.64.12': {
    country: 'Nigeria',
    countryCode: 'NG',
    region: 'Lagos State',
    city: 'Lagos',
    latitude: 6.5244,
    longitude: 3.3792,
    isp: 'MTN Nigeria Communication Ltd',
    asn: 'AS29465 MTN Nigeria',
    hostingProvider: 'Commercial Cellular / Dynamic Broadband',
    isVpn: true,
    isTor: false,
    isProxy: true,
    isDatacenter: false,
    confidence: 84,
  },
  '198.51.100.45': {
    country: 'Panama',
    countryCode: 'PA',
    region: 'Panamá',
    city: 'Panama City',
    latitude: 8.9824,
    longitude: -79.5199,
    isp: 'Offshore Privacy Gateway Ltd',
    asn: 'AS57118 Offshore Relay',
    hostingProvider: 'Encrypted Proxy Transit',
    isVpn: true,
    isTor: false,
    isProxy: true,
    isDatacenter: true,
    confidence: 78,
  },
  // Demo Case 3: Phishing / Credential harvesting (Russian Federation / Bulletproof Hosting)
  '185.220.101.5': {
    country: 'Germany',
    countryCode: 'DE',
    region: 'Hesse',
    city: 'Frankfurt am Main',
    latitude: 50.1109,
    longitude: 8.6821,
    isp: 'Zwiebelfreunde e.V.',
    asn: 'AS208323 Tor Exit Infrastructure',
    hostingProvider: 'Tor Public Anonymization Relay',
    isVpn: false,
    isTor: true,
    isProxy: true,
    isDatacenter: true,
    confidence: 92,
  },
  '194.165.16.88': {
    country: 'Russian Federation',
    countryCode: 'RU',
    region: 'Moscow Oblast',
    city: 'Moscow',
    latitude: 55.7558,
    longitude: 37.6173,
    isp: 'Selectel / HostKey Cloud',
    asn: 'AS49505 HostKey Network',
    hostingProvider: 'Bulletproof Unmanaged VPS',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isDatacenter: true,
    confidence: 89,
  },
};

/**
 * Derives realistic geolocation and infrastructure telemetry for any IP
 */
export function enrichIpInfrastructure(rawIp: string, isOriginating = false): GeolocationResult {
  const ip = normalizeIp(rawIp);
  const classification = classifyIp(ip);

  if (!classification.isPublic) {
    return {
      ip,
      version: classification.version === 'IPv6' ? 'IPv6' : 'IPv4',
      isOriginating,
      country: 'Private Network',
      countryCode: 'XX',
      region: 'RFC 1918 / Loopback',
      city: undefined,
      latitude: 0,
      longitude: 0,
      isp: 'Non-Routable Address Space',
      asn: 'N/A',
      hostingProvider: 'Internal / Loopback Infrastructure',
      vpnTorProxy: {
        isVpn: false,
        isTor: false,
        isProxy: false,
        isDatacenter: false,
      },
      confidence: 0,
      geolocatable: false,
      reason: 'PRIVATE_OR_RESERVED_IP',
      infrastructureRole: isOriginating ? 'Originating Internal Host' : 'Internal MTA Hop',
      attributionNote:
        'Private or non-routable address space. Not routable across the public Internet and cannot be geolocated.',
    };
  }

  const profile = KNOWN_PROFILES[ip];

  if (profile) {
    return {
      ip,
      version: ip.includes(':') ? 'IPv6' : 'IPv4',
      isOriginating,
      country: profile.country,
      countryCode: profile.countryCode,
      region: profile.region,
      city: profile.city,
      latitude: profile.latitude,
      longitude: profile.longitude,
      isp: profile.isp,
      asn: profile.asn,
      hostingProvider: profile.hostingProvider,
      isVpn: profile.isVpn,
      isTor: profile.isTor,
      isProxy: profile.isProxy,
      isHosting: profile.isDatacenter,
      accuracyRadiusKm: 30,
      geolocatable: true,
      source: 'Forensic Baseline Profile',
      vpnTorProxy: {
        isVpn: profile.isVpn,
        isTor: profile.isTor,
        isProxy: profile.isProxy,
        isDatacenter: profile.isDatacenter,
      },
      confidence: profile.confidence,
      infrastructureRole: isOriginating ? 'Probable Originating Relay MTA' : 'Transit Relay / Intermediate MX',
      attributionNote:
        'Approximate geolocation of observed network infrastructure. Does not establish physical location or identity of human sender.',
    };
  }

  // For un-profiled public IPs in synchronous mode, do not invent coordinates
  return {
    ip,
    version: classification.version === 'IPv6' ? 'IPv6' : 'IPv4',
    isOriginating,
    country: 'Observed Public Carrier',
    countryCode: 'XX',
    region: 'Network Transit Region',
    city: undefined,
    latitude: 0,
    longitude: 0,
    isp: 'Observed Autonomous System',
    asn: 'AS-OBSERVED',
    hostingProvider: 'Observed Transit Infrastructure',
    isVpn: false,
    isProxy: false,
    isTor: false,
    isHosting: false,
    geolocatable: false,
    reason: 'UNRESOLVABLE',
    confidence: 40,
    vpnTorProxy: {
      isVpn: false,
      isTor: false,
      isProxy: false,
      isDatacenter: false,
    },
    infrastructureRole: isOriginating ? 'Probable Source Infrastructure' : 'MTA Routing Relay',
    attributionNote:
      'Approximate geolocation of observed network infrastructure. Live DFIR lookup required to resolve provider telemetry.',
  };
}

function formatGeoDataToResult(data: any, isOriginating: boolean): GeolocationResult {
  return {
    ip: data.ip,
    version: data.version,
    isOriginating,
    country: data.country || 'Unknown Country',
    countryCode: data.countryCode || 'XX',
    region: data.region || 'Unknown Region',
    city: data.city,
    latitude: data.latitude ?? 0,
    longitude: data.longitude ?? 0,
    timezone: data.timezone,
    postalCode: data.postalCode,
    accuracyRadiusKm: data.accuracyRadiusKm,
    isp: data.isp || data.organization || 'Unknown ISP',
    asn: data.asn || 'AS-UNKNOWN',
    organization: data.organization,
    connectionType: data.connectionType,
    hostingProvider: data.organization || data.isp || 'Network Infrastructure',
    isVpn: data.isVpn,
    isProxy: data.isProxy,
    isTor: data.isTor,
    isHosting: data.isHosting,
    source: data.source,
    geolocatable: Boolean(data.geolocatable),
    reason: data.reason,
    vpnTorProxy: data.vpnTorProxy || {
      isVpn: Boolean(data.isVpn),
      isTor: Boolean(data.isTor),
      isProxy: Boolean(data.isProxy),
      isDatacenter: Boolean(data.isHosting),
    },
    confidence: data.confidence,
    infrastructureRole: data.infrastructureRole || (isOriginating ? 'Probable Originating Relay MTA' : 'Transit Relay / Intermediate MX'),
    attributionNote: data.attributionNote || 'Approximate geolocation of observed network infrastructure.',
    evidenceProvenance: data.evidenceProvenance,
  };
}

export function enrichAllIps(ips: string[], originatingIp?: string): GeolocationResult[] {
  const results: GeolocationResult[] = [];
  const seen = new Set<string>();

  if (originatingIp) {
    seen.add(originatingIp);
    results.push(enrichIpInfrastructure(originatingIp, true));
  }

  for (const ip of ips) {
    if (!seen.has(ip)) {
      seen.add(ip);
      results.push(enrichIpInfrastructure(ip, false));
    }
  }

  return results;
}

export async function enrichAllIpsAsync(ips: string[], originatingIp?: string): Promise<GeolocationResult[]> {
  const results: GeolocationResult[] = [];
  const seen = new Set<string>();

  if (originatingIp) {
    const cleanOrigin = normalizeIp(originatingIp);
    seen.add(cleanOrigin);
    const data = await ipGeolocationService.lookupIp(cleanOrigin);
    results.push(formatGeoDataToResult(data, true));
  }

  for (const raw of ips) {
    const clean = normalizeIp(raw);
    if (clean && !seen.has(clean)) {
      seen.add(clean);
      const data = await ipGeolocationService.lookupIp(clean);
      results.push(formatGeoDataToResult(data, false));
    }
  }

  return results;
}
