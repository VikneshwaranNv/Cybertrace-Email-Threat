import { BulkTriageItem, MailType, RiskLevel, ThreatClassification } from '../../src/types/forensics';

/**
 * Deterministic Synthetic Generator for 6,000+ Triage Emails
 * Designed for prototype validation and instant live demonstration without uploading gigabytes of real EMLs.
 * Strictly labels every generated telemetry entry as DEMO / SIMULATED DATA.
 */
export function generateSyntheticDemoBatch(targetCount = 6250): BulkTriageItem[] {
  const items: BulkTriageItem[] = [];
  const batchId = 'BATCH-DEMO-2026';

  // 173 unique routable public IPs (RFC compliant, synthetic public prefixes)
  const uniqueIps: { ip: string; asn: string; country: string; city: string }[] = [];
  for (let i = 1; i <= 173; i++) {
    const ip = `185.220.101.${i}`;
    const asns = ['AS13335 (Cloudflare)', 'AS15169 (Google)', 'AS8075 (Microsoft)', 'AS16509 (Amazon AWS)', 'AS44050 (HostKey)', 'AS204957 (DataCamp)'];
    const countries = ['United States', 'Germany', 'Netherlands', 'United Kingdom', 'Singapore', 'Australia', 'France'];
    const cities = ['Frankfurt', 'Amsterdam', 'Washington', 'London', 'Singapore', 'Sydney', 'Paris'];
    uniqueIps.push({
      ip,
      asn: asns[i % asns.length],
      country: countries[i % countries.length],
      city: cities[i % cities.length],
    });
  }

  // Pre-defined Coordinated Campaigns
  const campaignBlueprints = [
    {
      id: 'CAMP-001',
      name: 'Operation GhostWire (Executive BEC & Wire Diversion)',
      code: 'CP-2026-01',
      threatCategory: 'BUSINESS_EMAIL_COMPROMISE' as ThreatClassification,
      riskScore: 92,
      riskLevel: 'CRITICAL' as RiskLevel,
      mailType: 'COMPANY' as MailType,
      senders: ['cfo-office@global-holdings-ltd.com', 'treasury@executive-funds.net', 'finance-approval@holdings-corp.org'],
      subjectTemplates: [
        'URGENT: Executive Wire Transfer Authorization #W-{NUM}',
        'STRICTLY CONFIDENTIAL: Acquisition Closing Wire Approval #{NUM}',
        'Immediate Processing Required: Foreign Sub-Ledger Transfer #{NUM}',
      ],
      bodySnippet: 'Please confirm immediate release of wire instruction for overseas partner. Audit documentation attached.',
      reasons: ['Reply-To header diverts to unaligned external domain', 'Display name executive impersonation pattern', 'Urgent wire transfer semantics'],
      ipIndices: [0, 1, 2, 3],
      targetDomain: 'swift-wire-clearance.net',
      targetCount: 125,
    },
    {
      id: 'CAMP-002',
      name: 'DarkHarvest M365 (AiTM Credential Harvester Wave)',
      code: 'CP-2026-02',
      threatCategory: 'CREDENTIAL_HARVESTING' as ThreatClassification,
      riskScore: 88,
      riskLevel: 'CRITICAL' as RiskLevel,
      mailType: 'COMPANY' as MailType,
      senders: ['security-alert@microsoft-365-tenant.com', 'admin@login-mfa-verify.net', 'no-reply@portal-tenant-auth.org'],
      subjectTemplates: [
        'Microsoft Security Alert: Password Expiry Notification for User #{NUM}',
        'Action Required: Re-authenticate Office 365 Tenant Session #{NUM}',
        'Security Notice: Suspicious Login Attempt Blocked (#{NUM})',
      ],
      bodySnippet: 'Your session has expired due to multi-factor policy update. Please verify your credentials at the secure portal.',
      reasons: ['Direct link to punycode / typosquatted login domain', 'Credential harvesting semantics', 'DMARC alignment failed'],
      ipIndices: [4, 5, 6, 7, 8],
      targetDomain: 'login-microsoft-portal.xyz',
      targetCount: 340,
    },
    {
      id: 'CAMP-003',
      name: 'InvoiceLocker (Ransomware ZIP/ISO Dropper)',
      code: 'CP-2026-03',
      threatCategory: 'SUSPICIOUS_ATTACHMENT' as ThreatClassification,
      riskScore: 82,
      riskLevel: 'HIGH' as RiskLevel,
      mailType: 'COMPANY' as MailType,
      senders: ['billing@fastline-logistics-corp.com', 'invoices@freight-accounting-service.org'],
      subjectTemplates: [
        'OVERDUE NOTICE: Outstanding Invoice #INV-2026-{NUM}',
        'Remittance Advice & Receipt Confirmation #{NUM}',
        'Account Statement Overdue - Final Demand #{NUM}',
      ],
      bodySnippet: 'Attached invoice contains the itemized billing details. Please review macro instructions to reconcile.',
      reasons: ['High-risk executable ZIP / macro attachment', 'Suspicious outbound payment lure', 'SPF validation failure'],
      ipIndices: [9, 10, 11],
      targetDomain: 'freight-accounting-docs.org',
      targetCount: 195,
    },
    {
      id: 'CAMP-004',
      name: 'PhishPayroll (Direct Deposit Diversion Lure)',
      code: 'CP-2026-04',
      threatCategory: 'PHISHING' as ThreatClassification,
      riskScore: 74,
      riskLevel: 'HIGH' as RiskLevel,
      mailType: 'COMPANY' as MailType,
      senders: ['human-resources@adp-portal-benefits.com', 'payroll@workday-selfservice-portal.net'],
      subjectTemplates: [
        'Employee Self-Service: Update Banking Information for Pay Period #{NUM}',
        'HR Notice: Important Changes to W-2 Tax Withholding ({NUM})',
        'Direct Deposit Verification Incomplete for Account #{NUM}',
      ],
      bodySnippet: 'To prevent delay in your next paycheck, submit direct deposit verification in the employee payroll portal.',
      reasons: ['Domain impersonates HR service provider', 'Contains credential lure hyperlinks', 'Timezone transit anomaly'],
      ipIndices: [12, 13, 14, 15],
      targetDomain: 'adp-workday-benefits-auth.com',
      targetCount: 280,
    },
    {
      id: 'CAMP-005',
      name: 'DocuSpoof AiTM (Token Interception Lure)',
      code: 'CP-2026-05',
      threatCategory: 'MALICIOUS_LINK' as ThreatClassification,
      riskScore: 86,
      riskLevel: 'CRITICAL' as RiskLevel,
      mailType: 'COMPANY' as MailType,
      senders: ['dse@docusign-secure-document.org', 'esignature@docs-auth-verification.net'],
      subjectTemplates: [
        'DocuSign: Please review and sign Confidential ND&A Agreement #{NUM}',
        'Completed: Executive Employment Contract for Review #{NUM}',
        'DocuSign Notification: Signature Required on Purchase Agreement #{NUM}',
      ],
      bodySnippet: 'You have been requested to electronically sign this document. Click below to review and authenticate with your corporate ID.',
      reasons: ['Hyperlink points to known adversary reverse-proxy', 'Spoofed DocuSign envelope headers', 'High-confidence AiTM pattern'],
      ipIndices: [16, 17, 18, 19],
      targetDomain: 'docusign-secure-gateway.net',
      targetCount: 160,
    },
  ];

  let currentId = 1;

  // 1. Generate Coordinated Campaign Emails (~1,100 emails)
  for (const c of campaignBlueprints) {
    for (let i = 0; i < c.targetCount; i++) {
      const triageId = `TRIAGE-${String(currentId).padStart(5, '0')}`;
      const numStr = String(1000 + i);
      const subTemplate = c.subjectTemplates[i % c.subjectTemplates.length];
      const subject = subTemplate.replace('{NUM}', numStr);
      const sender = c.senders[i % c.senders.length];
      const fromDomain = sender.split('@')[1];
      const ipObj = uniqueIps[c.ipIndices[i % c.ipIndices.length]];

      items.push({
        triageId,
        batchId,
        emailSubject: subject,
        fromAddress: sender,
        fromDomain,
        toAddresses: [`employee.${(i % 80) + 1}@enterprise-soc.local`],
        date: new Date(Date.now() - (i * 90000 + 3600000)).toISOString(),
        rawSha256: `a1b2c3d4e5f6${String(currentId).padStart(6, '0')}` + '0'.repeat(52),
        sizeBytes: 3500 + (i * 37) % 8000,
        hasAttachments: c.threatCategory === 'SUSPICIOUS_ATTACHMENT',
        attachmentNames: c.threatCategory === 'SUSPICIOUS_ATTACHMENT' ? [`Invoice_${numStr}.zip`] : [],
        mailClassification: {
          mailType: c.mailType,
          mailTypeConfidence: 88,
          mailTypeReasons: ['Corporate business workflow terminology', 'Enterprise gateway headers observed'],
        },
        riskScore: c.riskScore - (i % 7),
        riskLevel: c.riskLevel,
        threatCategory: c.threatCategory,
        riskReasons: c.reasons,
        originatingIp: ipObj.ip,
        originatingAsn: ipObj.asn,
        originatingCountry: ipObj.country,
        originatingCity: ipObj.city,
        extractedIps: [ipObj.ip],
        extractedDomains: [fromDomain, c.targetDomain],
        extractedUrls: [`https://${c.targetDomain}/verify?id=${numStr}`],
        campaignId: c.id,
        campaignName: c.name,
        campaignCode: c.code,
        isPromoted: false,
      });
      currentId++;
    }
  }

  // 2. Generate Benign Enterprise Company Traffic (~2,650 emails)
  const corpDomains = ['acme-corp.com', 'internal-soc.local', 'cloud-logistics.com', 'legal-advisors.net', 'partners.corp'];
  const corpSubjects = [
    'Weekly Sprint Planning & Retrospective Agenda',
    'Quarterly Financial Statement Review & Sync',
    'IT Maintenance Window: Scheduled Database Patching',
    'SOC Incident Metrics & Threat Intel Summary',
    'Client Architecture Review: Architecture Document v3',
    'Vendor Security Assessment Checklist Completed',
  ];

  for (let i = 0; i < 2300 && currentId <= targetCount; i++) {
    const triageId = `TRIAGE-${String(currentId).padStart(5, '0')}`;
    const fromDomain = corpDomains[i % corpDomains.length];
    const sender = `colleague.${(i % 120) + 1}@${fromDomain}`;
    const ipObj = uniqueIps[20 + (i % 40)];

    items.push({
      triageId,
      batchId,
      emailSubject: corpSubjects[i % corpSubjects.length] + ` (Ref #${i + 100})`,
      fromAddress: sender,
      fromDomain,
      toAddresses: [`analyst@internal-soc.local`],
      date: new Date(Date.now() - (i * 120000 + 7200000)).toISOString(),
      rawSha256: `b2c3d4e5f6a1${String(currentId).padStart(6, '0')}` + '1'.repeat(52),
      sizeBytes: 4200 + (i * 29) % 6000,
      hasAttachments: i % 4 === 0,
      attachmentNames: i % 4 === 0 ? [`Report_${i + 100}.pdf`] : [],
      mailClassification: {
        mailType: 'COMPANY',
        mailTypeConfidence: 94,
        mailTypeReasons: [
          `Transmitted from enterprise domain '@${fromDomain}'`,
          'Legal confidentiality disclaimer detected in signature block',
          'Routed through enterprise email security gateway',
        ],
      },
      riskScore: 10 + (i % 15),
      riskLevel: 'LOW',
      threatCategory: 'LEGITIMATE',
      riskReasons: ['SPF/DKIM/DMARC authentication passed', 'No anomalous external hyperlinks', 'Standard internal SMTP transit'],
      originatingIp: ipObj.ip,
      originatingAsn: ipObj.asn,
      originatingCountry: ipObj.country,
      originatingCity: ipObj.city,
      extractedIps: [ipObj.ip],
      extractedDomains: [fromDomain],
      extractedUrls: [],
      isPromoted: false,
    });
    currentId++;
  }

  // 3. Generate Benign Personal 1-to-1 Emails (~1,450 emails)
  const personalWebmails = ['gmail.com', 'yahoo.com', 'outlook.com', 'icloud.com'];
  const personalSubjects = [
    'Quick question about our weekend meetup',
    'Photos from family gathering last Saturday',
    'Dinner reservation confirmation for Friday night',
    'Checking in on how your week is going',
    'Book recommendation we talked about yesterday',
  ];

  for (let i = 0; i < 1400 && currentId <= targetCount; i++) {
    const triageId = `TRIAGE-${String(currentId).padStart(5, '0')}`;
    const fromDomain = personalWebmails[i % personalWebmails.length];
    const sender = `friend.${(i % 150) + 1}@${fromDomain}`;
    const ipObj = uniqueIps[60 + (i % 40)];

    items.push({
      triageId,
      batchId,
      emailSubject: personalSubjects[i % personalSubjects.length],
      fromAddress: sender,
      fromDomain,
      toAddresses: [`analyst.personal@gmail.com`],
      date: new Date(Date.now() - (i * 150000 + 10800000)).toISOString(),
      rawSha256: `c3d4e5f6a1b2${String(currentId).padStart(6, '0')}` + '2'.repeat(52),
      sizeBytes: 2100 + (i * 19) % 3000,
      hasAttachments: false,
      attachmentNames: [],
      mailClassification: {
        mailType: 'PERSONAL',
        mailTypeConfidence: 89,
        mailTypeReasons: [
          `Consumer webmail domain (@${fromDomain}) observed`,
          'Conversational greeting/sign-off without automated broadcast markers',
          'Absence of marketing or bulk tracking headers',
        ],
      },
      riskScore: 8 + (i % 12),
      riskLevel: 'LOW',
      threatCategory: 'LEGITIMATE',
      riskReasons: ['Valid DKIM signature from consumer provider', 'Standard peer-to-peer SMTP transit'],
      originatingIp: ipObj.ip,
      originatingAsn: ipObj.asn,
      originatingCountry: ipObj.country,
      originatingCity: ipObj.city,
      extractedIps: [ipObj.ip],
      extractedDomains: [fromDomain],
      extractedUrls: [],
      isPromoted: false,
    });
    currentId++;
  }

  // 4. Generate Spam / Bulk Marketing Emails (~1,000 emails)
  const spamSenders = ['deals@retail-promos.com', 'newsletter@daily-tech-digest.org', 'offers@global-discounts-club.net', 'alerts@flights-booking-weekly.com'];
  const spamSubjects = [
    'EXCLUSIVE: 50% Off Annual Subscription Ends Tonight!',
    'Your Weekly Tech Digest & Developer Highlights',
    'Special Summer Flight Deals Selected For You',
    'Limited Time Offer: Upgrade your cloud plan today',
  ];

  for (let i = 0; i < 1000 && currentId <= targetCount; i++) {
    const triageId = `TRIAGE-${String(currentId).padStart(5, '0')}`;
    const sender = spamSenders[i % spamSenders.length];
    const fromDomain = sender.split('@')[1];
    const ipObj = uniqueIps[100 + (i % 40)];

    const isSuspiciousSpam = i % 7 === 0;
    const riskScore = isSuspiciousSpam ? 62 : 28 + (i % 15);
    const riskLevel: RiskLevel = isSuspiciousSpam ? 'HIGH' : 'LOW';

    items.push({
      triageId,
      batchId,
      emailSubject: spamSubjects[i % spamSubjects.length] + ` (#${i + 500})`,
      fromAddress: sender,
      fromDomain,
      toAddresses: [`subscriber.${(i % 200) + 1}@enterprise-soc.local`],
      date: new Date(Date.now() - (i * 180000 + 14400000)).toISOString(),
      rawSha256: `d4e5f6a1b2c3${String(currentId).padStart(6, '0')}` + '3'.repeat(52),
      sizeBytes: 8500 + (i * 43) % 12000,
      hasAttachments: false,
      attachmentNames: [],
      mailClassification: {
        mailType: 'SPAM',
        mailTypeConfidence: 96,
        mailTypeReasons: [
          'List-Unsubscribe header present',
          "Precedence header set to 'bulk'",
          'Transmitted via commercial bulk marketing ESP service',
          'Contains promotional opt-out / preference management terminology',
        ],
      },
      riskScore,
      riskLevel,
      threatCategory: isSuspiciousSpam ? 'PHISHING' : 'LEGITIMATE',
      riskReasons: isSuspiciousSpam
        ? ['Bulk marketing stream contains redirect URL with low domain reputation', 'Precedence: bulk with altered return-path']
        : ['Standard commercial newsletter mailing list', 'Unsubscribe header verified'],
      originatingIp: ipObj.ip,
      originatingAsn: ipObj.asn,
      originatingCountry: ipObj.country,
      originatingCity: ipObj.city,
      extractedIps: [ipObj.ip],
      extractedDomains: [fromDomain, 'track-metrics-click.com'],
      extractedUrls: [`https://track-metrics-click.com/redirect?u=${i + 500}`],
      isPromoted: false,
    });
    currentId++;
  }

  // 5. Fill remaining up to targetCount (~400 emails) as Unknown / Truncated Anomalous
  while (currentId <= targetCount) {
    const triageId = `TRIAGE-${String(currentId).padStart(5, '0')}`;
    const ipObj = uniqueIps[140 + (currentId % 33)];
    const isMedium = currentId % 3 === 0;

    items.push({
      triageId,
      batchId,
      emailSubject: currentId % 2 === 0 ? '(No Subject - Diagnostic Ping)' : 'Automated Diagnostic Delivery Status',
      fromAddress: `daemon-service@sub-${currentId % 20}.net`,
      fromDomain: `sub-${currentId % 20}.net`,
      toAddresses: ['postmaster@internal-soc.local'],
      date: new Date(Date.now() - (currentId * 100000)).toISOString(),
      rawSha256: `e5f6a1b2c3d4${String(currentId).padStart(6, '0')}` + '4'.repeat(52),
      sizeBytes: 800 + (currentId % 900),
      hasAttachments: false,
      attachmentNames: [],
      mailClassification: {
        mailType: 'UNKNOWN',
        mailTypeConfidence: 45,
        mailTypeReasons: ['Insufficient technical headers or content markers to definitively attribute mail category.'],
      },
      riskScore: isMedium ? 45 : 22,
      riskLevel: isMedium ? 'MEDIUM' : 'LOW',
      threatCategory: 'LEGITIMATE',
      riskReasons: ['Automated relay without verifiable SPF policy', 'Minimal message envelope'],
      originatingIp: ipObj.ip,
      originatingAsn: ipObj.asn,
      originatingCountry: ipObj.country,
      originatingCity: ipObj.city,
      extractedIps: [ipObj.ip],
      extractedDomains: [`sub-${currentId % 20}.net`],
      extractedUrls: [],
      isPromoted: false,
    });
    currentId++;
  }

  return items;
}
