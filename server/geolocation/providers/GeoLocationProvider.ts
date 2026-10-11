import { GeoLocationData } from '../types';

export interface GeoLocationProvider {
  readonly name: string;
  lookupIp(ip: string): Promise<GeoLocationData | null>;
}
