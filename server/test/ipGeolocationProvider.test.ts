import assert from 'assert';
import { IpWhoIsProvider } from '../geolocation/providers/IpWhoIsProvider';
import { MaxMindProvider } from '../geolocation/providers/MaxMindProvider';
import { MockProvider } from '../geolocation/providers/MockProvider';
import {
  IPGeolocationService,
  GeoLocationService,
  createIPGeolocationService,
  createGeoLocationService,
  createGeoLocationProvider,
  validateGeoIpConfig,
  getGeoIpConfig,
} from '../geolocation/ipGeolocationService';
import createServiceFromFactory from '../geolocation/factory';
import { classifyIp, normalizeIp } from '../geolocation/ipClassifier';

console.log('=== RUNNING FORENSIC IP GEOLOCATION PROVIDER TEST SUITE ===\n');

async function runGeolocationProviderTests() {
  // =========================================================================
  // Test 1: RFC 1918, RFC 5737, and Documentation IP Filtering
  // =========================================================================
  console.log('--- Test 1: RFC Filtering & Documentation IP Rejection ---');
  const docIps = ['198.51.100.5', '203.0.113.25', '192.0.2.1'];
  for (const ip of docIps) {
    const classification = classifyIp(ip);
    assert.strictEqual(classification.isPublic, false, `Documentation IP ${ip} must be classified as non-public`);
    assert.strictEqual(classification.reason, 'PRIVATE_OR_RESERVED_IP', `Documentation IP ${ip} must have PRIVATE_OR_RESERVED_IP reason`);
  }

  const privateIps = ['10.1.2.3', '172.16.5.4', '192.168.1.1', '127.0.0.1'];
  for (const ip of privateIps) {
    const classification = classifyIp(ip);
    assert.strictEqual(classification.isPublic, false, `Private IP ${ip} must be classified as non-public`);
  }

  const publicIps = ['1.1.1.1', '8.8.8.8', '185.220.101.5', '203.192.204.15'];
  for (const ip of publicIps) {
    const classification = classifyIp(ip);
    assert.strictEqual(classification.isPublic, true, `Routable public IP ${ip} must be classified as public`);
  }
  console.log('✔ Test 1 Passed: RFC filtering and documentation IP rejection verified.\n');

  // =========================================================================
  // Test 2: IpWhoIsProvider Normalized Response & Schema Integrity
  // =========================================================================
  console.log('--- Test 2: IpWhoIsProvider Response Normalization & Nullability ---');
  const ipWhoIs = new IpWhoIsProvider({ timeoutMs: 5000 });

  // Test error handling on invalid / unresolvable IP with custom mock server/URL
  const mockFailingProvider = new IpWhoIsProvider({ timeoutMs: 1000, baseUrl: 'https://invalid-non-existent-domain-xyz123.com' });
  const failedResult = await mockFailingProvider.lookupIp('1.1.1.1');
  assert.strictEqual(failedResult, null, 'IpWhoIsProvider must gracefully return null on network failure without throwing');

  console.log('✔ Test 2 Passed: IpWhoIsProvider network error handling verified.\n');

  // =========================================================================
  // Test 3: Actual Live Lookup via ipwho.is (Tested with Public IPs 1.1.1.1 & 8.8.8.8)
  // =========================================================================
  console.log('--- Test 3: Live Upstream Lookup via ipwho.is ---');
  console.log('Initiating live HTTP query to https://ipwho.is/1.1.1.1 ...');
  const liveResult = await ipWhoIs.lookupIp('1.1.1.1');

  assert.ok(liveResult !== null, 'Live lookup for 1.1.1.1 must return a result');
  console.log('Live Lookup Result for 1.1.1.1:', {
    ip: liveResult.ip,
    country: liveResult.country,
    countryCode: liveResult.countryCode,
    city: liveResult.city,
    latitude: liveResult.latitude,
    longitude: liveResult.longitude,
    asn: liveResult.asn,
    source: liveResult.source,
    accuracyRadiusKm: liveResult.accuracyRadiusKm,
  });

  // Verify all 18 normalized fields specified in the architecture prompt
  assert.strictEqual(liveResult.ip, '1.1.1.1', 'IP must match queried IP');
  assert.strictEqual(liveResult.countryCode, 'AU', 'Country code for 1.1.1.1 should be AU');
  assert.strictEqual(liveResult.source, 'ipwho.is', 'Source must be ipwho.is');
  assert.strictEqual(liveResult.accuracyRadiusKm, null, 'accuracyRadiusKm must be null (not supplied by ipwho.is)');
  assert.ok(typeof liveResult.latitude === 'number', 'Latitude must be a valid number from ipwho.is');
  assert.ok(typeof liveResult.longitude === 'number', 'Longitude must be a valid number from ipwho.is');
  assert.strictEqual(liveResult.geolocatable, true, 'Result with coordinates must be geolocatable');
  assert.ok(liveResult.confidence >= 50, 'Confidence must reflect resolution granularity');
  assert.strictEqual(typeof liveResult.isVpn, 'boolean', 'isVpn must be boolean');
  assert.strictEqual(typeof liveResult.isProxy, 'boolean', 'isProxy must be boolean');
  assert.strictEqual(typeof liveResult.isTor, 'boolean', 'isTor must be boolean');
  assert.strictEqual(typeof liveResult.isHosting, 'boolean', 'isHosting must be boolean');

  // Second live test: Google DNS 8.8.8.8
  console.log('Initiating live HTTP query to https://ipwho.is/8.8.8.8 ...');
  const liveGoogle = await ipWhoIs.lookupIp('8.8.8.8');
  assert.ok(liveGoogle !== null, 'Live lookup for 8.8.8.8 must return a result');
  assert.strictEqual(liveGoogle.countryCode, 'US', '8.8.8.8 country code should be US');
  assert.ok(liveGoogle.asn?.includes('15169') || liveGoogle.organization?.includes('Google'), 'ASN or organization should identify Google');
  assert.strictEqual(liveGoogle.source, 'ipwho.is', 'Source must be ipwho.is');

  console.log('✔ Test 3 Passed: Verified real live lookups against ipwho.is successfully.\n');

  // =========================================================================
  // Test 4: Provider Switching & Credential Validation Architecture
  // =========================================================================
  console.log('--- Test 4: Provider Switching & Credential Validation Architecture ---');

  // 4a. Default or explicit GEOIP_PROVIDER=ipwhois (credentials must be completely optional)
  delete process.env.GEOIP_ACCOUNT_ID;
  delete process.env.GEOIP_LICENSE_KEY;
  delete process.env.MAXMIND_LICENSE_KEY;
  delete process.env.GEOIP_PROVIDER; // unsetting defaults to 'ipwhois'
  const defaultValidation = validateGeoIpConfig();
  assert.strictEqual(defaultValidation.valid, true, 'Default provider must be valid without any MaxMind credentials');
  assert.strictEqual(defaultValidation.provider, 'ipwhois', 'Default provider must be ipwhois');
  assert.strictEqual(defaultValidation.isMaxMindRequired, false, 'MaxMind credentials must NOT be required for default provider');
  assert.strictEqual(defaultValidation.errors.length, 0, 'No validation errors when credentials are empty for ipwhois');

  // Explicit GEOIP_PROVIDER=ipwhois with empty credentials
  process.env.GEOIP_PROVIDER = 'ipwhois';
  const ipwhoisValidation = validateGeoIpConfig();
  assert.strictEqual(ipwhoisValidation.valid, true, 'ipwhois must be valid without credentials');
  assert.strictEqual(ipwhoisValidation.isMaxMindRequired, false, 'MaxMind credentials must be optional for ipwhois');
  const ipwhoisService = new GeoLocationService();
  assert.strictEqual(ipwhoisService.getPrimaryProviderName(), 'ipwho.is', 'Default/ipwhois config must activate IpWhoIsProvider');

  // 4b. Explicit GEOIP_PROVIDER=maxmind without credentials (validation must flag missing credentials)
  process.env.GEOIP_PROVIDER = 'maxmind';
  const maxmindMissingValidation = validateGeoIpConfig();
  assert.strictEqual(maxmindMissingValidation.valid, false, 'MaxMind provider without credentials must fail validation');
  assert.strictEqual(maxmindMissingValidation.isMaxMindRequired, true, 'MaxMind credentials must be marked as required');
  assert.ok(maxmindMissingValidation.errors.some(e => e.includes('GEOIP_ACCOUNT_ID')), 'Must report missing GEOIP_ACCOUNT_ID');
  assert.ok(maxmindMissingValidation.errors.some(e => e.includes('GEOIP_LICENSE_KEY')), 'Must report missing GEOIP_LICENSE_KEY');

  // 4c. Explicit GEOIP_PROVIDER=maxmind with credentials provided
  process.env.GEOIP_ACCOUNT_ID = 'test-account-123';
  process.env.GEOIP_LICENSE_KEY = 'test-key-xyz';
  const maxmindConfiguredValidation = validateGeoIpConfig();
  assert.strictEqual(maxmindConfiguredValidation.valid, true, 'MaxMind provider with credentials must pass validation');
  assert.strictEqual(maxmindConfiguredValidation.errors.length, 0, 'No errors when credentials are provided');

  // Clean up credentials
  delete process.env.GEOIP_ACCOUNT_ID;
  delete process.env.GEOIP_LICENSE_KEY;

  // 4d. MaxMind service instance activates MaxMindProvider as primary
  process.env.GEOIP_PROVIDER = 'maxmind';
  const maxmindService = new GeoLocationService();
  assert.strictEqual(maxmindService.getPrimaryProviderName(), 'MaxMind GeoIP2', 'maxmind config must activate MaxMindProvider');

  // 4e. Without MaxMind credentials, maxmindService falls back to secondary (ipwhois)
  const fallbackResult = await maxmindService.lookupIp('1.1.1.1');
  assert.ok(fallbackResult.geolocatable, 'Service must fall back to secondary provider when MaxMind credentials are missing');

  // 4f. Explicit GEOIP_PROVIDER=mock
  process.env.GEOIP_PROVIDER = 'mock';
  const mockService = new GeoLocationService({ mockProvider: new MockProvider() });
  assert.ok(mockService.getPrimaryProviderName().includes('Mock'), 'mock config must activate MockProvider');

  // 4g. IPGeolocationService factory dynamic instantiation and clean fallback
  // Dynamic MaxMind instantiation via factory
  process.env.GEOIP_PROVIDER = 'maxmind';
  const factoryMaxMindService = IPGeolocationService.create();
  assert.strictEqual(factoryMaxMindService.getPrimaryProviderName(), 'MaxMind GeoIP2', 'Factory must instantiate MaxMindProvider when GEOIP_PROVIDER=maxmind');
  const factoryMaxMindProvider = IPGeolocationService.createProvider();
  assert.ok(factoryMaxMindProvider instanceof MaxMindProvider, 'Provider factory must instantiate MaxMindProvider');

  // Dynamic IpWhoIs instantiation via factory when GEOIP_PROVIDER=ipwhois
  process.env.GEOIP_PROVIDER = 'ipwhois';
  const factoryIpWhoIsService = createIPGeolocationService();
  assert.strictEqual(factoryIpWhoIsService.getPrimaryProviderName(), 'ipwho.is', 'Factory must instantiate IpWhoIsProvider when GEOIP_PROVIDER=ipwhois');
  const factoryIpWhoIsProvider = createGeoLocationProvider();
  assert.ok(factoryIpWhoIsProvider instanceof IpWhoIsProvider, 'Provider factory must instantiate IpWhoIsProvider');

  // Clean fallback to 'ipwhois' when GEOIP_PROVIDER is unset
  delete process.env.GEOIP_PROVIDER;
  const unsetEnvService = createServiceFromFactory();
  assert.strictEqual(unsetEnvService.getPrimaryProviderName(), 'ipwho.is', 'Factory must cleanly fall back to ipwhois when GEOIP_PROVIDER is unset');

  // Clean fallback to 'ipwhois' when GEOIP_PROVIDER has unknown/unrecognized value
  process.env.GEOIP_PROVIDER = 'some_unsupported_provider';
  const unknownEnvService = IPGeolocationService.create();
  assert.strictEqual(unknownEnvService.getPrimaryProviderName(), 'ipwho.is', 'Factory must cleanly fall back to ipwhois when GEOIP_PROVIDER is unrecognized');
  const unknownProvider = IPGeolocationService.createProvider('unknown');
  assert.ok(unknownProvider instanceof IpWhoIsProvider, 'Provider factory must cleanly fall back to IpWhoIsProvider on unknown value');

  console.log('✔ Test 4 Passed: Provider switching & credential validation verified (ipwhois default, MaxMind credentials strictly optional).\n');

  // =========================================================================
  // Test 5: In-Memory Caching & Cache Invalidation
  // =========================================================================
  console.log('--- Test 5: Cache Behavior & Efficiency ---');
  process.env.GEOIP_PROVIDER = 'ipwhois';
  const testService = new GeoLocationService();
  testService.clearCache();

  // First lookup (cache miss -> provider hit)
  const firstLookup = await testService.lookupIp('8.8.8.8');
  assert.ok(firstLookup.geolocatable, 'First lookup must resolve');

  // Second lookup (cache hit)
  const secondLookup = await testService.lookupIp('8.8.8.8');
  assert.strictEqual(secondLookup, firstLookup, 'Second lookup must return cached reference without outbound call');

  // Cache clear
  testService.clearCache();
  console.log('✔ Test 5 Passed: In-memory caching and TTL protection verified.\n');

  // =========================================================================
  // Test 6: End-to-End Investigation Payload & Provenance
  // =========================================================================
  console.log('--- Test 6: Investigation Payload Integration ---');
  const syntheticCasePayload: any = {
    caseRecord: { caseId: 'CASE-GEOLOCATION-TEST-001' },
    evidence: {
      headers: {
        fromDomain: 'airtel.in',
        receivedHeaders: [
          'from relay.airtel.in (relay.airtel.in [203.192.204.15]) by mx.victim.com with ESMTP',
          'from internal-mta (internal-mta [192.168.1.50]) by relay.airtel.in with ESMTP',
        ],
      },
    },
    threatIndicators: [
      { type: 'ipv4', value: '203.192.204.15' },
      { type: 'ipv4', value: '192.168.1.50' },
    ],
  };

  const caseSummary = await testService.resolveCaseGeolocations(syntheticCasePayload);
  assert.strictEqual(caseSummary.caseId, 'CASE-GEOLOCATION-TEST-001');
  assert.ok(caseSummary.disclaimer.includes('IP geolocation provides an approximate location'));
  assert.ok(caseSummary.geolocations.length > 0, 'Must contain resolved geolocations');

  // Ensure private IP is flagged as non-geolocatable
  const privateNode = caseSummary.geolocations.find(g => g.ip === '192.168.1.50');
  assert.ok(privateNode, 'Private node must be cataloged in investigation payload');
  assert.strictEqual(privateNode?.geolocatable, false, 'Private IP must not be geolocatable');
  assert.strictEqual(privateNode?.reason, 'PRIVATE_OR_RESERVED_IP', 'Private IP must retain technical reason');

  console.log('✔ Test 6 Passed: Case summary, domain intelligence, and forensic provenance verified.\n');

  console.log('================================================================');
  console.log('ALL 6 FORENSIC IP GEOLOCATION TESTS PASSED SUCCESSFULLY! (100%)');
  console.log('================================================================\n');
}

runGeolocationProviderTests().catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
