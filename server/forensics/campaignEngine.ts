import {
  CampaignMatch,
  HeaderAnalysis,
  NormalizedIOC,
  RiskLevel,
  CaseRecord,
} from '../../src/types/forensics';

interface KnownCampaignProfile {
  campaignId: string;
  campaignCode: string;
  name: string;
  threatActorGroup: string;
  domains: string[];
  ips: string[];
  hashes: string[];
  urlPatterns: RegExp[];
  senderPatterns: RegExp[];
  replyToPatterns: RegExp[];
  subjectKeywords: string[];
  authAnomalies: string[];
  previousCases: string[];
  firstObserved: string;
  lastObserved: string;
  campaignDescription: string;
  severity: RiskLevel;
  timelineHistory: Array<{ date: string; event: string; sourceCase?: string }>;
}

const KNOWN_CAMPAIGNS: KnownCampaignProfile[] = [
  {
    campaignId: 'CAMP-0042',
    campaignCode: 'CAMPAIGN-0042 (FIN-7 WireLure)',
    name: 'FIN-7 WireLure Syndicate',
    threatActorGroup: 'FIN-7 / Carbanak Financial Group',
    domains: ['global-invoicing.net', 'wire-settlement-corp.com', 'vendor-payments.xyz', 'fin-billing.top'],
    ips: ['197.210.64.12', '198.51.100.45', '45.142.214.9'],
    hashes: ['a789ef4123bca0123456789abcdef0123456789abcdef0123456789abcdef012'],
    urlPatterns: [/invoice/i, /remittance/i, /swift-payment/i, /wire-confirm/i],
    senderPatterns: [/billing/i, /accounting/i, /treasury/i, /cfo/i, /finance/i],
    replyToPatterns: [/gmail\.com/i, /protonmail\.com/i, /finance-office/i],
    subjectKeywords: ['urgent payment', 'revised invoice', 'wire instruction', 'remittance advice', 'overdue invoice', 'updated bank details'],
    authAnomalies: ['replyToMismatch', 'returnPathMismatch', 'spfFail'],
    previousCases: ['CASE-2026-002', 'CASE-2025-889', 'CASE-2025-714'],
    firstObserved: '2024-11-12',
    lastObserved: '2026-08-30',
    campaignDescription: 'Targeted Business Email Compromise (BEC) ring executing executive impersonation and wire diversion against finance departments.',
    severity: 'HIGH',
    timelineHistory: [
      { date: '2024-11-12', event: 'First observed lookalike domain registration: global-invoicing.net' },
      { date: '2025-04-03', event: 'Spearphishing wave detected against manufacturing supply-chain CFOs', sourceCase: 'CASE-2025-714' },
      { date: '2025-11-19', event: 'Switch to Nigerian cellular proxy relay infrastructure (197.210.64.12)', sourceCase: 'CASE-2025-889' },
      { date: '2026-08-30', event: 'Fraudulent remittance portal detected on wire-settlement-corp.com', sourceCase: 'CASE-2026-002' },
    ],
  },
  {
    campaignId: 'CAMP-0089',
    campaignCode: 'CAMPAIGN-0089 (Midnight Harvest)',
    name: 'Midnight Harvest M365 PhishNet',
    threatActorGroup: 'APT29 / Midnight Blizzard Imitator',
    domains: ['login-micros0ft-online.com', 'auth-office365-verify.com', 'security-update-portal.org', 'cloud-verify.net'],
    ips: ['185.220.101.5', '194.165.16.88', '103.151.125.10'],
    hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    urlPatterns: [/login/i, /auth/i, /verify/i, /account-reset/i, /session/i],
    senderPatterns: [/security/i, /admin/i, /no-reply/i, /microsoft/i, /it-support/i],
    replyToPatterns: [/sec-review/i, /support-desk/i],
    subjectKeywords: ['security alert', 'password expiration', 'unauthorized sign-in', 'action required: verify', 'session suspended'],
    authAnomalies: ['spfFail', 'dkimFail', 'displaySpoofing', 'punycodeHomograph'],
    previousCases: ['CASE-2026-003', 'CASE-2026-012', 'CASE-2025-942'],
    firstObserved: '2025-03-01',
    lastObserved: '2026-09-02',
    campaignDescription: 'Adversary-in-the-Middle (AiTM) spear-phishing campaign deploying reverse proxies to harvest corporate session tokens and bypass MFA.',
    severity: 'CRITICAL',
    timelineHistory: [
      { date: '2025-03-01', event: 'Initial bulletproof host registration in Germany (185.220.101.5)' },
      { date: '2025-08-14', event: 'AiTM reverse proxy templates deployed spoofing Microsoft 365 identity portals', sourceCase: 'CASE-2025-942' },
      { date: '2026-02-18', event: 'Tor exit node routing integration observed in transit hops', sourceCase: 'CASE-2026-012' },
      { date: '2026-09-02', event: 'Active phishing wave targeting defense contractor executives', sourceCase: 'CASE-2026-003' },
    ],
  },
  {
    campaignId: 'CAMP-0015',
    campaignCode: 'CAMPAIGN-0015 (QakLocker Dropper)',
    name: 'QakLocker Loader Ecosystem',
    threatActorGroup: 'TA577 / BlackCat Affiliate',
    domains: ['cdn-delivery-package.com', 'secure-download-drive.net', 'file-share-hub.xyz'],
    ips: ['185.190.140.22', '45.154.255.8', '91.240.118.50'],
    hashes: ['d5f8c3a10987654321fedcba0123456789abcdef0123456789abcdef01234567'],
    urlPatterns: [/download/i, /attachment/i, /shared-doc/i, /dropbox/i],
    senderPatterns: [/shipping/i, /dhl/i, /fedex/i, /legal/i],
    replyToPatterns: [/shipping-desk/i],
    subjectKeywords: ['shipment detained', 'court summons', 'attached contract', 'order receipt'],
    authAnomalies: ['spfFail', 'messageIdAnomaly'],
    previousCases: ['CASE-2025-630', 'CASE-2025-512'],
    firstObserved: '2024-06-18',
    lastObserved: '2026-07-21',
    campaignDescription: 'Malspam distributing weaponized ISO/ZIP containers containing OneNote or script loaders executing secondary ransomware payloads.',
    severity: 'CRITICAL',
    timelineHistory: [
      { date: '2024-06-18', event: 'Initial weaponized OneNote delivery campaign detected' },
      { date: '2025-01-10', event: 'Shift to ISO archive container bypass technique', sourceCase: 'CASE-2025-512' },
      { date: '2025-09-28', event: 'Distribution surge via compromised Polish mail relays', sourceCase: 'CASE-2025-630' },
    ],
  },
];

export function correlateCampaignDNA(params: {
  subject: string;
  fromDomain: string;
  fromAddress: string;
  replyTo?: string;
  ips: string[];
  domains: string[];
  urls: string[];
  hashes?: string[];
  headerAnalysis: HeaderAnalysis;
  iocs: NormalizedIOC[];
  otherCases?: CaseRecord[];
}): CampaignMatch[] {
  const matches: CampaignMatch[] = [];

  const lowerSubj = (params.subject || '').toLowerCase();
  const lowerFromDomain = (params.fromDomain || '').toLowerCase();
  const lowerFromAddress = (params.fromAddress || '').toLowerCase();
  const lowerDomains = (params.domains || []).map(d => d.toLowerCase());
  const allHashes = (params.hashes || []).map(h => h.toLowerCase());

  for (const camp of KNOWN_CAMPAIGNS) {
    let score = 0;
    const sharedInfrastructure: string[] = [];
    const sharedIocs: string[] = [];
    const observedCorrelation: string[] = [];
    const aiInference: string[] = [];
    const matchingFeatures: string[] = [];
    const missingFeatures: string[] = [];

    const matchingIndicators = {
      domains: [] as string[],
      ips: [] as string[],
      urls: [] as string[],
      senderPatterns: [] as string[],
      replyToPatterns: [] as string[],
      subjectStructure: [] as string[],
      languagePatterns: [] as string[],
      htmlCharacteristics: [] as string[],
      infrastructure: [] as string[],
      authenticationAnomalies: [] as string[],
    };

    // 1. Check Sender Infrastructure & IPs (weight: 25%)
    for (const ip of params.ips || []) {
      if (camp.ips.includes(ip)) {
        score += 25;
        matchingIndicators.ips.push(ip);
        matchingIndicators.infrastructure.push(`Known Campaign Transit/C2 IP: ${ip}`);
        sharedInfrastructure.push(`IP: ${ip}`);
        sharedIocs.push(`IPv4: ${ip}`);
        observedCorrelation.push(`Direct infrastructure IP match: ${ip} overlaps with historical ${camp.name} telemetry`);
      }
    }

    // 2. Check Sender Domains & Referenced Domains (weight: 25%)
    for (const d of lowerDomains) {
      if (camp.domains.includes(d)) {
        score += 25;
        matchingIndicators.domains.push(d);
        sharedIocs.push(`Domain: ${d}`);
        observedCorrelation.push(`Observed domain match: '${d}' registered/controlled by ${camp.threatActorGroup}`);
      } else if (camp.domains.some(cd => cd.includes(d) || d.includes(cd))) {
        score += 12;
        matchingIndicators.domains.push(`Fuzzy lookalike: ${d}`);
        aiInference.push(`Domain '${d}' exhibits lexical and structural likeness to campaign cluster '${camp.campaignId}'`);
      }
    }
    if (camp.domains.includes(lowerFromDomain)) {
      score += 15;
      observedCorrelation.push(`Envelope sender domain '${lowerFromDomain}' is a confirmed ${camp.name} indicator`);
    }

    // 3. Check File Hashes (weight: 25%)
    for (const hash of allHashes) {
      if (camp.hashes.some(ch => ch.toLowerCase() === hash || hash.includes(ch.substring(0, 16)))) {
        score += 25;
        sharedIocs.push(`SHA-256: ${hash}`);
        observedCorrelation.push(`Cryptographic attachment hash '${hash.substring(0, 16)}...' matches known payload in ${camp.name}`);
      }
    }

    // 4. Check Subject Keywords & Language Patterns (weight: 15%)
    for (const kw of camp.subjectKeywords) {
      if (lowerSubj.includes(kw)) {
        score += 8;
        matchingIndicators.subjectStructure.push(`Keyword: "${kw}"`);
        aiInference.push(`Subject lure pattern "${kw}" matches social engineering lure archetype for ${camp.name}`);
      }
    }

    // 5. Check Sender Persona & Reply-To Patterns (weight: 10%)
    for (const sp of camp.senderPatterns) {
      if (sp.test(lowerFromAddress) || sp.test(lowerFromDomain)) {
        score += 8;
        matchingIndicators.senderPatterns.push(`Sender pattern: ${sp.source}`);
        aiInference.push(`Sender handle matches spoofed persona taxonomy typical of ${camp.threatActorGroup}`);
      }
    }
    if (params.replyTo) {
      for (const rp of camp.replyToPatterns) {
        if (rp.test(params.replyTo)) {
          score += 8;
          matchingIndicators.replyToPatterns.push(`Reply-To pattern: ${params.replyTo}`);
          observedCorrelation.push(`Reply-To redirection to '${params.replyTo}' matches campaign diversion tactic`);
        }
      }
    }

    // 6. Check Authentication Characteristics & Header Fingerprints (weight: 15%)
    if (camp.authAnomalies.includes('replyToMismatch') && params.headerAnalysis.inconsistencies.replyToMismatch) {
      score += 8;
      matchingIndicators.authenticationAnomalies.push('Reply-To envelope redirection pattern');
      observedCorrelation.push('Header verification: RFC-5322 From diverges from Reply-To destination');
    }
    if (camp.authAnomalies.includes('spfFail') && params.headerAnalysis.spf.status === 'FAIL') {
      score += 5;
      matchingIndicators.authenticationAnomalies.push('Sender SPF envelope rejection');
      observedCorrelation.push('Authentication: SPF validation failed for originating envelope host');
    }
    if (camp.authAnomalies.includes('displaySpoofing') && params.headerAnalysis.inconsistencies.displaySpoofing) {
      score += 8;
      matchingIndicators.authenticationAnomalies.push('Display name impersonation anomaly');
      observedCorrelation.push('Header verification: Display name masquerades as trusted corporate brand');
    }

    // 7. Check Cross-Case Correlations from existing case history
    const relatedInvestigations = [...camp.previousCases];
    if (params.otherCases && params.otherCases.length > 0) {
      for (const other of params.otherCases) {
        if (
          other.relatedCampaign === camp.campaignId ||
          (other.emailSubject && camp.subjectKeywords.some(kw => other.emailSubject.toLowerCase().includes(kw)))
        ) {
          if (!relatedInvestigations.includes(other.caseNumber)) {
            relatedInvestigations.push(other.caseNumber);
          }
        }
      }
    }

    // Populate matching and missing features
    if (matchingIndicators.domains.length > 0) matchingFeatures.push(`Targeted domain overlap: ${matchingIndicators.domains.join(', ')}`);
    if (matchingIndicators.ips.length > 0) matchingFeatures.push(`Shared infrastructure IP(s): ${matchingIndicators.ips.join(', ')}`);
    if (matchingIndicators.subjectStructure.length > 0) matchingFeatures.push(`Linguistic keyword match: ${matchingIndicators.subjectStructure.join(', ')}`);
    if (matchingIndicators.authenticationAnomalies.length > 0) matchingFeatures.push(`Authentication anomaly profile: ${matchingIndicators.authenticationAnomalies.join('; ')}`);

    if (matchingIndicators.domains.length === 0) missingFeatures.push('No direct campaign domain matches observed');
    if (matchingIndicators.ips.length === 0) missingFeatures.push('No overlap with known campaign C2 or relay IP blocks');
    if (params.headerAnalysis.spf.status === 'PASS') missingFeatures.push('Message demonstrated valid SPF (untypical for spoofed variant)');

    const finalSimilarity = Math.min(96, Math.max(0, score));

    // CRITICAL: "Do NOT claim two emails belong to the same campaign without supporting evidence."
    // Only return when there is genuine supporting forensic evidence (similarity >= 30%)
    if (finalSimilarity >= 30 && (observedCorrelation.length > 0 || matchingIndicators.domains.length > 0 || matchingIndicators.ips.length > 0)) {
      const confidenceLevel: 'Low' | 'Medium' | 'High' =
        finalSimilarity >= 75 ? 'High' : finalSimilarity >= 50 ? 'Medium' : 'Low';
      const campaignConfidence = Math.min(95, Math.round(finalSimilarity * 0.95));

      const attributionNotice = `Statistical similarity only (${finalSimilarity}% feature overlap). Observed indicators match patterns historically associated with ${camp.threatActorGroup}. Does not establish definitive legal attribution or confirm human operator identity.`;

      // Timeline of campaign
      const campaignTimeline = [
        ...camp.timelineHistory,
        {
          date: new Date().toISOString().split('T')[0],
          event: `Current email investigation correlated (${finalSimilarity}% similarity to ${camp.name})`,
        },
      ];

      matches.push({
        campaignId: camp.campaignId,
        campaignCode: camp.campaignCode,
        name: camp.name,
        threatActorGroup: camp.threatActorGroup,
        similarityScore: finalSimilarity,
        similarityPercentage: finalSimilarity,
        campaignConfidence,
        confidence: confidenceLevel,
        relatedInvestigations,
        sharedInfrastructure,
        sharedIocs,
        campaignTimeline,
        observedCorrelation,
        aiInference,
        matchingFeatures,
        missingFeatures,
        attributionNotice,
        matchingIndicators,
        previousRelatedCases: relatedInvestigations,
        firstObserved: camp.firstObserved,
        lastObserved: camp.lastObserved,
        campaignDescription: camp.campaignDescription,
        severity: camp.severity,
      });
    }
  }

  matches.sort((a, b) => b.similarityScore - a.similarityScore);
  return matches;
}
