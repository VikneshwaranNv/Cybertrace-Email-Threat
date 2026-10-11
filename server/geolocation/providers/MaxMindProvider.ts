import { GeoLocationData } from '../types';
import { GeoLocationProvider } from './GeoLocationProvider';

export class MaxMindProvider implements GeoLocationProvider {
  readonly name = 'MaxMind GeoIP2';
  private accountId?: string;
  private licenseKey?: string;
  private timeoutMs: number;

  constructor(options?: { accountId?: string; licenseKey?: string; timeoutMs?: number }) {
    this.accountId = options?.accountId || process.env.GEOIP_ACCOUNT_ID;
    this.licenseKey = options?.licenseKey || process.env.GEOIP_LICENSE_KEY || process.env.MAXMIND_LICENSE_KEY;
    this.timeoutMs = options?.timeoutMs || 3500;
  }

  isConfigured(): boolean {
    return Boolean(this.accountId && this.licenseKey);
  }

  async lookupIp(ip: string): Promise<GeoLocationData | null> {
    if (!this.isConfigured()) {
      return null;
    }

    const authHeader = 'Basic ' + Buffer.from(`${this.accountId}:${this.licenseKey}`).toString('base64');
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`https://geoip.maxmind.com/geoip/v2.1/city/${encodeURIComponent(ip)}`, {
        method: 'GET',
        headers: {
          Authorization: authHeader,
          Accept: 'application/vnd.maxmind.com-city+json; charset=UTF-8; version=2.1',
          'User-Agent': 'MailForensicAI/2.7.0 (DFIR Threat Geolocation)',
        },
        signal: controller.signal,
      });

      if (response.status === 401 || response.status === 403) {
        console.warn('MaxMind authentication failure: invalid license key or account ID.');
        return null;
      }

      if (response.status === 429) {
        console.warn('MaxMind rate limit exceeded.');
        return null;
      }

      if (response.status === 404) {
        return {
          ip,
          version: ip.includes(':') ? 'IPv6' : 'IPv4',
          confidence: 0,
          isVpn: false,
          isProxy: false,
          isTor: false,
          isHosting: false,
          source: 'MaxMind GeoIP2 Web Service',
          geolocatable: false,
          reason: 'NOT_FOUND',
        };
      }

      if (!response.ok) {
        return null;
      }

      const data = (await response.json()) as any;

      const country = data.country?.names?.en || data.registered_country?.names?.en;
      const countryCode = data.country?.iso_code || data.registered_country?.iso_code;
      const region = data.subdivisions?.[0]?.names?.en;
      const city = data.city?.names?.en;
      const lat = data.location?.latitude;
      const lng = data.location?.longitude;
      const accuracyRadius = data.location?.accuracy_radius;
      const timezone = data.location?.time_zone;
      const postalCode = data.postal?.code;
      const asn = data.traits?.autonomous_system_number ? `AS${data.traits.autonomous_system_number}` : undefined;
      const org = data.traits?.autonomous_system_organization;
      const isp = data.traits?.isp || org;
      const isHosting = Boolean(data.traits?.is_hosting_provider);
      const isVpn = Boolean(data.traits?.is_anonymous_vpn);
      const isTor = Boolean(data.traits?.is_tor_exit_node);
      const isProxy = Boolean(data.traits?.is_public_proxy || data.traits?.is_residential_proxy);

      const hasCoordinates = typeof lat === 'number' && typeof lng === 'number';

      return {
        ip,
        version: ip.includes(':') ? 'IPv6' : 'IPv4',
        country,
        countryCode,
        region,
        city,
        latitude: lat,
        longitude: lng,
        timezone,
        postalCode,
        accuracyRadiusKm: accuracyRadius,
        confidence: hasCoordinates ? (city ? 88 : region ? 75 : 60) : 40,
        asn,
        organization: org,
        isp,
        connectionType: isHosting ? 'hosting' : 'residential',
        isVpn,
        isProxy,
        isTor,
        isHosting,
        source: 'MaxMind GeoIP2 Web Service',
        geolocatable: hasCoordinates,
        vpnTorProxy: {
          isVpn,
          isTor,
          isProxy,
          isDatacenter: isHosting,
        },
      };
    } catch (err: any) {
      if (err.name === 'AbortError') {
        console.warn(`MaxMind lookup timed out after ${this.timeoutMs}ms for IP ${ip}`);
      } else {
        console.warn(`MaxMind request error for IP ${ip}:`, err.message);
      }
      return null;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
