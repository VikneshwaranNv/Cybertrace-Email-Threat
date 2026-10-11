import { IpWhoIsProvider } from './IpWhoIsProvider';

/**
 * LiveGeoIpProvider: Alias for IpWhoIsProvider.
 * Maintained for backward-compatibility with prior imports.
 */
export class LiveGeoIpProvider extends IpWhoIsProvider {
  override readonly name = 'ipwho.is';
}
