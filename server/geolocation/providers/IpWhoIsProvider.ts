import { GeoLocationData } from '../types';
import { GeoLocationProvider } from './GeoLocationProvider';

export interface IpWhoIsOptions {
  timeoutMs?: number;
  baseUrl?: string;
}

/**
 * IpWhoIsProvider: Live public IP intelligence provider using the https://ipwho.is API.
 * Designed for students, researchers, and DFIR analysts who do not possess paid MaxMind credentials.
 * Receives a validated public routable IP and returns only data actually supplied by the upstream API.
 */
export class IpWhoIsProvider implements GeoLocationProvider {
  readonly name = 'ipwho.is';
  private timeoutMs: number;
  private baseUrl: string;

  constructor(options?: IpWhoIsOptions) {
    this.timeoutMs = options?.timeoutMs ?? 4000;
    this.baseUrl = options?.baseUrl ?? 'https://ipwho.is';
  }

  async lookupIp(ip: string): Promise<GeoLocationData | null> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      // API endpoint used: https://ipwho.is/{ip}
      const targetUrl = `${this.baseUrl}/${encodeURIComponent(ip)}`;
      const response = await fetch(targetUrl, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': 'MailForensicAI/2.7.0 (DFIR SOC Intelligence)',
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        console.warn(`[IpWhoIsProvider] HTTP error status ${response.status} for IP ${ip}`);
        return null;
      }

      const data = (await response.json()) as any;

      if (!data || typeof data !== 'object') {
        return null;
      }

      // Upstream unresolvable or reserved IP handling
      if (data.success === false) {
        return {
          ip,
          version: ip.includes(':') ? 'IPv6' : 'IPv4',
          country: null,
          countryCode: null,
          region: null,
          city: null,
          latitude: null,
          longitude: null,
          timezone: null,
          postalCode: null,
          asn: null,
          organization: null,
          isp: null,
          isVpn: false,
          isProxy: false,
          isTor: false,
          isHosting: false,
          accuracyRadiusKm: null,
          confidence: 0,
          source: 'ipwho.is',
          geolocatable: false,
          reason: 'NOT_FOUND',
          attributionNote: data.message || 'IP address not found in ipwho.is registry.',
          vpnTorProxy: {
            isVpn: false,
            isTor: false,
            isProxy: false,
            isDatacenter: false,
          },
        };
      }

      // Map only fields actually supplied by ipwho.is without inventing data
      const country = typeof data.country === 'string' && data.country.trim() ? data.country.trim() : null;
      const countryCode = typeof data.country_code === 'string' && data.country_code.trim() ? data.country_code.trim() : null;
      const region = typeof data.region === 'string' && data.region.trim() ? data.region.trim() : null;
      const city = typeof data.city === 'string' && data.city.trim() ? data.city.trim() : null;
      const latitude = typeof data.latitude === 'number' && !isNaN(data.latitude) ? data.latitude : null;
      const longitude = typeof data.longitude === 'number' && !isNaN(data.longitude) ? data.longitude : null;
      const timezone = typeof data.timezone?.id === 'string' && data.timezone.id.trim() ? data.timezone.id.trim() : null;
      const postalCode = typeof data.postal === 'string' && data.postal.trim() ? data.postal.trim() : null;

      const connection = data.connection || {};
      const rawAsn = connection.asn;
      const asn = rawAsn
        ? String(rawAsn).toUpperCase().startsWith('AS')
          ? String(rawAsn).toUpperCase()
          : `AS${rawAsn}`
        : null;
      const organization = typeof connection.org === 'string' && connection.org.trim() ? connection.org.trim() : null;
      const isp = typeof connection.isp === 'string' && connection.isp.trim() ? connection.isp.trim() : organization;

      // Security / anonymizer flags (if supplied by API)
      const security = data.security || {};
      const isVpn = Boolean(security.vpn);
      const isProxy = Boolean(security.proxy);
      const isTor = Boolean(security.tor);
      const isHosting = Boolean(security.hosting);

      // accuracyRadiusKm is not provided by the ipwho.is schema; return null per instructions
      const accuracyRadiusKm = null;

      // Compute confidence score based on verified resolution depth
      let confidence = 30;
      if (country) confidence += 20;
      if (region) confidence += 15;
      if (city) confidence += 15;
      if (latitude !== null && longitude !== null) confidence += 10;
      if (asn) confidence += 10;
      confidence = Math.min(100, Math.max(0, confidence));

      const hasCoordinates = latitude !== null && longitude !== null && !(latitude === 0 && longitude === 0);

      const connectionType = isHosting
        ? 'hosting'
        : isVpn || isProxy
        ? 'corporate'
        : 'residential';

      return {
        ip,
        version: data.type === 'IPv6' || ip.includes(':') ? 'IPv6' : 'IPv4',
        country,
        countryCode,
        region,
        city,
        latitude,
        longitude,
        timezone,
        postalCode,
        asn,
        organization,
        isp,
        isVpn,
        isProxy,
        isTor,
        isHosting,
        accuracyRadiusKm,
        confidence: hasCoordinates ? confidence : 0,
        source: 'ipwho.is',
        geolocatable: hasCoordinates,
        connectionType,
        vpnTorProxy: {
          isVpn,
          isTor,
          isProxy,
          isDatacenter: isHosting,
        },
        attributionNote:
          'Approximate geolocation of observed network infrastructure via ipwho.is. Does not identify a person’s exact physical location.',
      };
    } catch (err: any) {
      if (err.name === 'AbortError') {
        console.warn(`[IpWhoIsProvider] Request timed out after ${this.timeoutMs}ms for IP ${ip}`);
      } else {
        console.warn(`[IpWhoIsProvider] Request failed for IP ${ip}:`, err.message);
      }
      return null;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
