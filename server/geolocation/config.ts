/**
 * Geolocation Configuration & Credential Validation
 * 
 * Rules:
 * 1. GEOIP_PROVIDER defaults to 'ipwhois' (free public provider, no API key or credentials required).
 * 2. GEOIP_ACCOUNT_ID and GEOIP_LICENSE_KEY are OPTIONAL when using 'ipwhois'.
 * 3. MaxMind credentials are required ONLY when GEOIP_PROVIDER=maxmind.
 * 4. Do not validate or require MaxMind credentials for the 'ipwhois' or 'mock' providers.
 */

export type GeoIpProviderType = 'ipwhois' | 'maxmind' | 'mock';

export interface GeoIpConfigValidation {
  valid: boolean;
  provider: GeoIpProviderType;
  errors: string[];
  isMaxMindRequired: boolean;
  isConfigured: boolean;
}

export interface GeoIpConfig {
  provider: GeoIpProviderType;
  accountId: string | null;
  licenseKey: string | null;
  isValid: boolean;
  errors: string[];
}

/**
 * Validates the current or provided environment for GeoIP configuration.
 */
export function validateGeoIpConfig(env: NodeJS.ProcessEnv = process.env): GeoIpConfigValidation {
  const rawProvider = (env.GEOIP_PROVIDER || 'ipwhois').toLowerCase().trim();
  const provider: GeoIpProviderType =
    rawProvider === 'maxmind' || rawProvider === 'mock' ? rawProvider : 'ipwhois';

  // For default 'ipwhois' or 'mock', MaxMind credentials are NEVER required or validated.
  if (provider === 'ipwhois' || provider === 'mock') {
    return {
      valid: true,
      provider,
      errors: [],
      isMaxMindRequired: false,
      isConfigured: true,
    };
  }

  // provider === 'maxmind' -> MaxMind credentials are required only in this mode.
  const errors: string[] = [];
  const accountId = env.GEOIP_ACCOUNT_ID?.trim();
  const licenseKey = (env.GEOIP_LICENSE_KEY || env.MAXMIND_LICENSE_KEY)?.trim();

  if (!accountId) {
    errors.push('GEOIP_ACCOUNT_ID is required when GEOIP_PROVIDER=maxmind');
  }
  if (!licenseKey) {
    errors.push('GEOIP_LICENSE_KEY is required when GEOIP_PROVIDER=maxmind');
  }

  return {
    valid: errors.length === 0,
    provider: 'maxmind',
    errors,
    isMaxMindRequired: true,
    isConfigured: errors.length === 0,
  };
}

/**
 * Retrieves the normalized GeoIP configuration.
 */
export function getGeoIpConfig(env: NodeJS.ProcessEnv = process.env): GeoIpConfig {
  const validation = validateGeoIpConfig(env);
  return {
    provider: validation.provider,
    accountId: env.GEOIP_ACCOUNT_ID?.trim() || null,
    licenseKey: (env.GEOIP_LICENSE_KEY || env.MAXMIND_LICENSE_KEY)?.trim() || null,
    isValid: validation.valid,
    errors: validation.errors,
  };
}

/**
 * Checks if MaxMind credentials exist and are non-empty.
 */
export function isMaxMindConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  const accountId = env.GEOIP_ACCOUNT_ID?.trim();
  const licenseKey = (env.GEOIP_LICENSE_KEY || env.MAXMIND_LICENSE_KEY)?.trim();
  return Boolean(accountId && licenseKey);
}
