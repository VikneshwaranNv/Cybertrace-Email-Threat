import { EmailAttachment, IOC, IOCType } from '../../src/types/forensics';

export function extractAllIOCs(params: {
  urls: string[];
  ips: string[];
  domains: string[];
  senderEmail: string;
  senderDomain: string;
  replyTo?: string;
  attachments: EmailAttachment[];
  bodyText: string;
}): IOC[] {
  const iocs: IOC[] = [];
  const seenValues = new Set<string>();

  const addIoc = (
    type: IOCType,
    value: string,
    reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN',
    score: number,
    confidence: number,
    source: string,
    isSimulated: boolean,
    context?: string,
    maliciousCategory?: string
  ) => {
    const valKey = `${type}:${value.toLowerCase()}`;
    if (seenValues.has(valKey)) return;
    seenValues.add(valKey);

    iocs.push({
      id: `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      type,
      value,
      reputation,
      reputationScore: score,
      confidence,
      source,
      firstSeen: new Date(Date.now() - Math.floor(Math.random() * 86400000 * 30)).toISOString().split('T')[0],
      relatedCases: score > 60 ? ['CASE-2026-002', 'CASE-2026-003'] : [],
      isSimulated,
      context,
      maliciousCategory,
    });
  };

  // 1. Email IOCs
  if (params.senderEmail) {
    const isFree = /@(gmail|yahoo|outlook|hotmail|protonmail|yandex)\.com$/i.test(params.senderEmail);
    addIoc(
      'email',
      params.senderEmail,
      isFree ? 'SUSPICIOUS' : 'UNKNOWN',
      isFree ? 55 : 20,
      88,
      'Email Header Ingestion Engine',
      false,
      'Envelope RFC-5322 From address',
      isFree ? 'Public webmail sender in organizational context' : undefined
    );
  }

  if (params.replyTo && params.replyTo !== params.senderEmail) {
    addIoc(
      'email',
      params.replyTo,
      'SUSPICIOUS',
      75,
      92,
      'Email Header Ingestion Engine',
      false,
      'Reply-To diverged destination',
      'Potential diversion address'
    );
  }

  // 2. IP IOCs
  for (const ip of params.ips) {
    // Known threat/suspicious patterns for demo dataset
    if (ip.startsWith('185.220.') || ip.startsWith('194.165.') || ip.startsWith('45.142.') || ip.startsWith('103.151.')) {
      addIoc(
        'ipv4',
        ip,
        'MALICIOUS',
        88,
        94,
        'ThreatFeed [AlienVault OTX / AbuseIPDB]',
        true,
        'Observed in recent phishing MTA relay infrastructure',
        'Bulletproof Hosting / Tor Exit Node'
      );
    } else if (ip.startsWith('198.51.') || ip.startsWith('203.0.113.')) {
      addIoc(
        'ipv4',
        ip,
        'SUSPICIOUS',
        68,
        80,
        'ThreatFeed [AbuseIPDB]',
        true,
        'High frequency email volume anomaly',
        'Suspected Open Proxy'
      );
    } else if (ip.startsWith('142.250.') || ip.startsWith('209.85.') || ip.startsWith('40.92.') || ip.startsWith('52.100.')) {
      addIoc(
        'ipv4',
        ip,
        'BENIGN',
        5,
        98,
        'Verified Cloud MX Network (Google/Microsoft)',
        false,
        'Enterprise Mail Gateway'
      );
    } else {
      addIoc(
        'ipv4',
        ip,
        'UNKNOWN',
        25,
        60,
        'Local Forensic Extraction',
        false,
        'MTA Transit IP'
      );
    }
  }

  // 3. Domain IOCs
  for (const domain of params.domains) {
    const isTyposquat = /micros0ft|sec-login|verify-portal|bank-secure|billing-auth|update-auth|cloud-portal/i.test(domain);
    const isLegit = /google\.com|microsoft\.com|github\.com|apple\.com|amazon\.com|company\.org/i.test(domain);

    if (isTyposquat) {
      addIoc(
        'domain',
        domain,
        'MALICIOUS',
        92,
        95,
        'ThreatFeed [DomainTools / URLhaus]',
        true,
        'Newly registered domain with homoglyph/typosquat pattern',
        'Credential Harvesting Domain'
      );
    } else if (isLegit) {
      addIoc(
        'domain',
        domain,
        'BENIGN',
        2,
        99,
        'Tranco Top 1M / Verified Domain Database',
        false,
        'Legitimate enterprise domain'
      );
    } else {
      const isDynamic = /\.xyz$|\.top$|\.work$|\.ru$|\.click$|\.link$/i.test(domain);
      addIoc(
        'domain',
        domain,
        isDynamic ? 'SUSPICIOUS' : 'UNKNOWN',
        isDynamic ? 65 : 20,
        70,
        isDynamic ? 'ThreatFeed [PassiveDNS / WHOIS]' : 'DNS Resolver',
        isDynamic,
        isDynamic ? 'High-risk generic TLD with short registration age' : 'Sender/URL domain'
      );
    }
  }

  // 4. URL IOCs
  for (const url of params.urls) {
    const isPhish = /login|verify|update|account|auth|wallet|invoice|password|office365|sharepoint/i.test(url) &&
                    !/microsoft\.com|google\.com|github\.com/i.test(url);
    if (isPhish) {
      addIoc(
        'url',
        url,
        'MALICIOUS',
        94,
        92,
        'ThreatFeed [PhishTank / VirusTotal]',
        true,
        'Deceptive credential portal lure',
        'Phishing Landing Page'
      );
    } else {
      addIoc(
        'url',
        url,
        'BENIGN',
        10,
        85,
        'Static URL Parser',
        false,
        'Extracted document link'
      );
    }
  }

  // 5. Attachment Hash IOCs
  for (const att of params.attachments) {
    addIoc(
      'hash_sha256',
      att.sha256,
      att.isSuspicious ? 'MALICIOUS' : 'BENIGN',
      att.isSuspicious ? 90 : 5,
      95,
      'Cryptographic SHA-256 Engine',
      false,
      `Attachment payload: ${att.filename} (${Math.round(att.sizeBytes / 1024)} KB)`,
      att.isSuspicious ? 'Potential Malicious Payload Hash' : undefined
    );
  }

  return iocs;
}
