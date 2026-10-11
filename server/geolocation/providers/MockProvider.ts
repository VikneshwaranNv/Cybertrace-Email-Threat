import { GeoLocationData } from '../types';
import { GeoLocationProvider } from './GeoLocationProvider';

export type MockBehavior =
  | 'DEFAULT'
  | 'TIMEOUT'
  | 'RATE_LIMIT'
  | 'PROVIDER_UNAVAILABLE'
  | 'MISSING_CITY'
  | 'MISSING_COORDINATES'
  | 'LOW_CONFIDENCE'
  | 'VPN_DETECTED'
  | 'PROXY_DETECTED'
  | 'TOR_DETECTED'
  | 'HOSTING_DETECTED';

export class MockProvider implements GeoLocationProvider {
  readonly name = 'Mock Geolocation Provider (Automated Tests Only)';
  private behavior: MockBehavior = 'DEFAULT';
  private customFixtures: Map<string, GeoLocationData> = new Map();

  setBehavior(behavior: MockBehavior) {
    this.behavior = behavior;
  }

  setFixture(ip: string, data: GeoLocationData) {
    this.customFixtures.set(ip, data);
  }

  clearFixtures() {
    this.customFixtures.clear();
    this.behavior = 'DEFAULT';
  }

  async lookupIp(ip: string): Promise<GeoLocationData | null> {
    if (this.behavior === 'TIMEOUT') {
      throw new Error('PROVIDER_TIMEOUT: Upstream provider timed out after 3000ms');
    }

    if (this.behavior === 'RATE_LIMIT') {
      throw new Error('PROVIDER_RATE_LIMIT: HTTP 429 Too Many Requests');
    }

    if (this.behavior === 'PROVIDER_UNAVAILABLE') {
      throw new Error('PROVIDER_UNAVAILABLE: Connection refused or DNS failure');
    }

    if (this.customFixtures.has(ip)) {
      return this.customFixtures.get(ip)!;
    }

    const isV6 = ip.includes(':');

    if (this.behavior === 'MISSING_CITY') {
      return {
        ip,
        version: isV6 ? 'IPv6' : 'IPv4',
        country: 'India',
        countryCode: 'IN',
        region: 'Tamil Nadu',
        city: undefined, // Explicitly undefined
        latitude: 11.0,
        longitude: 77.0,
        accuracyRadiusKm: 100,
        confidence: 65,
        asn: 'AS55836',
        organization: 'National Transit Carrier',
        isp: 'National Transit Carrier',
        isVpn: false,
        isProxy: false,
        isTor: false,
        isHosting: false,
        source: 'Mock Provider (Missing City Test)',
        geolocatable: true,
      };
    }

    if (this.behavior === 'MISSING_COORDINATES') {
      return {
        ip,
        version: isV6 ? 'IPv6' : 'IPv4',
        country: 'Unknown Territory',
        countryCode: 'XX',
        region: undefined,
        city: undefined,
        latitude: undefined, // Explicitly undefined
        longitude: undefined,
        confidence: 30,
        asn: 'AS12345',
        organization: 'Unanchored AS',
        isp: 'Unanchored AS',
        isVpn: false,
        isProxy: false,
        isTor: false,
        isHosting: false,
        source: 'Mock Provider (Missing Coordinates Test)',
        geolocatable: false,
        reason: 'LOW_CONFIDENCE',
      };
    }

    if (this.behavior === 'LOW_CONFIDENCE') {
      return {
        ip,
        version: isV6 ? 'IPv6' : 'IPv4',
        country: 'Brazil',
        countryCode: 'BR',
        region: undefined,
        city: undefined,
        latitude: -14.235,
        longitude: -51.9253,
        accuracyRadiusKm: 500,
        confidence: 35, // Low confidence
        asn: 'AS28573',
        organization: 'Regional ISP',
        isp: 'Regional ISP',
        isVpn: false,
        isProxy: false,
        isTor: false,
        isHosting: false,
        source: 'Mock Provider (Low Confidence Test)',
        geolocatable: true,
      };
    }

    if (this.behavior === 'VPN_DETECTED') {
      return {
        ip,
        version: isV6 ? 'IPv6' : 'IPv4',
        country: 'Switzerland',
        countryCode: 'CH',
        region: 'Zurich',
        city: 'Zurich',
        latitude: 47.3769,
        longitude: 8.5417,
        accuracyRadiusKm: 25,
        confidence: 88,
        asn: 'AS9009',
        organization: 'Privacy VPN Provider AG',
        isp: 'Privacy Tunnel Networks',
        connectionType: 'corporate',
        isVpn: true,
        isProxy: true,
        isTor: false,
        isHosting: true,
        source: 'Mock Provider (VPN Test)',
        geolocatable: true,
        vpnTorProxy: {
          isVpn: true,
          isTor: false,
          isProxy: true,
          isDatacenter: true,
        },
      };
    }

    if (this.behavior === 'PROXY_DETECTED') {
      return {
        ip,
        version: isV6 ? 'IPv6' : 'IPv4',
        country: 'Panama',
        countryCode: 'PA',
        region: 'Panamá',
        city: 'Panama City',
        latitude: 8.9824,
        longitude: -79.5199,
        accuracyRadiusKm: 30,
        confidence: 82,
        asn: 'AS57118',
        organization: 'Offshore Proxy Network',
        isp: 'Offshore Proxy Network',
        connectionType: 'hosting',
        isVpn: false,
        isProxy: true,
        isTor: false,
        isHosting: true,
        source: 'Mock Provider (Proxy Test)',
        geolocatable: true,
        vpnTorProxy: {
          isVpn: false,
          isTor: false,
          isProxy: true,
          isDatacenter: true,
        },
      };
    }

    if (this.behavior === 'TOR_DETECTED') {
      return {
        ip,
        version: isV6 ? 'IPv6' : 'IPv4',
        country: 'Germany',
        countryCode: 'DE',
        region: 'Hesse',
        city: 'Frankfurt am Main',
        latitude: 50.1109,
        longitude: 8.6821,
        accuracyRadiusKm: 15,
        confidence: 90,
        asn: 'AS208323',
        organization: 'Tor Community Node',
        isp: 'Tor Community Node',
        connectionType: 'hosting',
        isVpn: false,
        isProxy: true,
        isTor: true,
        isHosting: true,
        source: 'Mock Provider (Tor Test)',
        geolocatable: true,
        vpnTorProxy: {
          isVpn: false,
          isTor: true,
          isProxy: true,
          isDatacenter: true,
        },
      };
    }

    if (this.behavior === 'HOSTING_DETECTED') {
      return {
        ip,
        version: isV6 ? 'IPv6' : 'IPv4',
        country: 'United States',
        countryCode: 'US',
        region: 'Virginia',
        city: 'Ashburn',
        latitude: 39.0438,
        longitude: -77.4874,
        accuracyRadiusKm: 20,
        confidence: 95,
        asn: 'AS16509',
        organization: 'Amazon.com, Inc.',
        isp: 'AWS EC2 Datacenter',
        connectionType: 'hosting',
        isVpn: false,
        isProxy: false,
        isTor: false,
        isHosting: true,
        source: 'Mock Provider (Hosting Test)',
        geolocatable: true,
        vpnTorProxy: {
          isVpn: false,
          isTor: false,
          isProxy: false,
          isDatacenter: true,
        },
      };
    }

    // Default valid resolution
    return {
      ip,
      version: isV6 ? 'IPv6' : 'IPv4',
      country: isV6 ? 'Ireland' : 'India',
      countryCode: isV6 ? 'IE' : 'IN',
      region: isV6 ? 'Leinster' : 'Tamil Nadu',
      city: isV6 ? 'Dublin' : 'Coimbatore',
      latitude: isV6 ? 53.3498 : 11.0168,
      longitude: isV6 ? -6.2603 : 76.9558,
      accuracyRadiusKm: isV6 ? 20 : 50,
      confidence: 85,
      asn: isV6 ? 'AS8075' : 'AS45528',
      organization: isV6 ? 'Microsoft Ireland' : 'Bharti Airtel Limited',
      isp: isV6 ? 'Microsoft Corp' : 'Airtel Broadband',
      connectionType: isV6 ? 'hosting' : 'residential',
      isVpn: false,
      isProxy: false,
      isTor: false,
      isHosting: isV6,
      source: 'Mock Geolocation Provider',
      geolocatable: true,
      vpnTorProxy: {
        isVpn: false,
        isTor: false,
        isProxy: false,
        isDatacenter: isV6,
      },
    };
  }
}
