import {
  IPGeolocationService,
  createIPGeolocationService,
  createGeoLocationService,
  createGeoLocationProvider,
} from './ipGeolocationService';
import type { IPGeolocationServiceOptions } from './ipGeolocationService';
import type { GeoLocationProvider } from './providers/GeoLocationProvider';
import { MaxMindProvider } from './providers/MaxMindProvider';
import { IpWhoIsProvider } from './providers/IpWhoIsProvider';

/**
 * Geolocation Factory Module
 *
 * Dynamically instantiates either the MaxMindProvider or the IpWhoIsProvider
 * based on the 'GEOIP_PROVIDER' environment variable, ensuring a clean fallback
 * to 'ipwhois' as the default implementation.
 */

export {
  IPGeolocationService,
  createIPGeolocationService,
  createGeoLocationService,
  createGeoLocationProvider,
  MaxMindProvider,
  IpWhoIsProvider,
};
export type { IPGeolocationServiceOptions, GeoLocationProvider };

export default createIPGeolocationService;
