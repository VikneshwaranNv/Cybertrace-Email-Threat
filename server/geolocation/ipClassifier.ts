import net from 'net';

export interface IpClassification {
  isValid: boolean;
  isPublic: boolean;
  version: 'IPv4' | 'IPv6' | 'INVALID';
  reason?: 'PRIVATE_OR_RESERVED_IP' | 'INVALID_IP_SYNTAX';
  description?: string;
}

/**
 * Parses IPv4 into 32-bit unsigned number for CIDR checks
 */
function ipv4ToNumber(ip: string): number {
  const parts = ip.split('.').map(n => parseInt(n, 10));
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inIpv4Range(ipNum: number, baseIp: string, prefixLen: number): boolean {
  const baseNum = ipv4ToNumber(baseIp);
  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  return (ipNum & mask) === (baseNum & mask);
}

/**
 * Classifies an IP address into valid/public vs private/reserved/invalid.
 * Rejects non-routable addresses per RFC 1918, RFC 3927, RFC 5737, RFC 6598, etc.
 */
export function classifyIp(rawIp: string): IpClassification {
  if (!rawIp || typeof rawIp !== 'string') {
    return { isValid: false, isPublic: false, version: 'INVALID', reason: 'INVALID_IP_SYNTAX', description: 'Empty or non-string IP' };
  }

  // Trim brackets and whitespace (e.g. [203.0.113.1] from Received headers)
  const cleanIp = rawIp.trim().replace(/^\[|\]$/g, '');

  const ipType = net.isIP(cleanIp);
  if (ipType === 0) {
    return {
      isValid: false,
      isPublic: false,
      version: 'INVALID',
      reason: 'INVALID_IP_SYNTAX',
      description: `String '${cleanIp}' does not conform to valid IPv4 or IPv6 syntax.`,
    };
  }

  if (ipType === 4) {
    const ipNum = ipv4ToNumber(cleanIp);

    // Private and Reserved IPv4 Ranges
    const isLoopback = inIpv4Range(ipNum, '127.0.0.0', 8); // 127.0.0.0/8
    const isPrivateA = inIpv4Range(ipNum, '10.0.0.0', 8); // 10.0.0.0/8
    const isPrivateB = inIpv4Range(ipNum, '172.16.0.0', 12); // 172.16.0.0/12
    const isPrivateC = inIpv4Range(ipNum, '192.168.0.0', 16); // 192.168.0.0/16
    const isLinkLocal = inIpv4Range(ipNum, '169.254.0.0', 16); // 169.254.0.0/16
    const isCarrierNat = inIpv4Range(ipNum, '100.64.0.0', 10); // 100.64.0.0/10
    const isCurrentNet = inIpv4Range(ipNum, '0.0.0.0', 8); // 0.0.0.0/8
    const isTestNet1 = inIpv4Range(ipNum, '192.0.2.0', 24); // 192.0.2.0/24 (TEST-NET-1)
    const isTestNet2 = inIpv4Range(ipNum, '198.51.100.0', 24); // 198.51.100.0/24 (TEST-NET-2)
    const isTestNet3 = inIpv4Range(ipNum, '203.0.113.0', 24); // 203.0.113.0/24 (TEST-NET-3)
    const isBenchmark = inIpv4Range(ipNum, '198.18.0.0', 15); // 198.18.0.0/15
    const isMulticast = inIpv4Range(ipNum, '224.0.0.0', 4); // 224.0.0.0/4
    const isReserved = inIpv4Range(ipNum, '240.0.0.0', 4); // 240.0.0.0/4
    const isBroadcast = cleanIp === '255.255.255.255';

    if (
      isLoopback ||
      isPrivateA ||
      isPrivateB ||
      isPrivateC ||
      isLinkLocal ||
      isCarrierNat ||
      isCurrentNet ||
      isTestNet1 ||
      isTestNet2 ||
      isTestNet3 ||
      isBenchmark ||
      isMulticast ||
      isReserved ||
      isBroadcast
    ) {
      return {
        isValid: true,
        isPublic: false,
        version: 'IPv4',
        reason: 'PRIVATE_OR_RESERVED_IP',
        description: `IPv4 address ${cleanIp} falls within private, reserved, or non-routable address space.`,
      };
    }

    return {
      isValid: true,
      isPublic: true,
      version: 'IPv4',
    };
  }

  // IPv6 checks
  const lowerIp = cleanIp.toLowerCase();
  const isV6Loopback = lowerIp === '::1';
  const isV6Unspecified = lowerIp === '::';
  const isV6LinkLocal = lowerIp.startsWith('fe80:');
  const isV6UniqueLocal = lowerIp.startsWith('fc') || lowerIp.startsWith('fd');
  const isV6Multicast = lowerIp.startsWith('ff');
  const isV6Doc = lowerIp.startsWith('2001:db8:');

  if (isV6Loopback || isV6Unspecified || isV6LinkLocal || isV6UniqueLocal || isV6Multicast || isV6Doc) {
    return {
      isValid: true,
      isPublic: false,
      version: 'IPv6',
      reason: 'PRIVATE_OR_RESERVED_IP',
      description: `IPv6 address ${cleanIp} falls within private, loopback, or non-routable address space.`,
    };
  }

  return {
    isValid: true,
    isPublic: true,
    version: 'IPv6',
  };
}

/**
 * Normalizes an IP string (removes surrounding brackets and whitespace)
 */
export function normalizeIp(ip: string): string {
  if (!ip) return '';
  return ip.trim().replace(/^\[|\]$/g, '');
}
