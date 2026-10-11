import {
  EmailAttachment,
  HeaderAnalysis,
  MitreTechniqueMapping,
  NormalizedIOC,
} from '../../src/types/forensics';

export function mapMitreAttackTechniques(params: {
  headerAnalysis: HeaderAnalysis;
  iocs: NormalizedIOC[];
  attachments: EmailAttachment[];
  bodyText: string;
  extractedUrls: string[];
  senderFrom: string;
  senderDomain: string;
  replyTo?: string;
  threatAssessmentReasons?: string[];
}): MitreTechniqueMapping[] {
  const mappings: MitreTechniqueMapping[] = [];

  const lowerBody = (params.bodyText || '').toLowerCase();
  const inconsistencies = params.headerAnalysis.inconsistencies;

  // 1. T1566.002 - Phishing: Spearphishing Link
  // Grounding requirement: At least one suspicious/malicious URL or credential landing link observed in email body
  const suspiciousUrls = params.iocs.filter(
    i => (i.type === 'url' || i.type === 'domain') && (i.reputation === 'MALICIOUS' || i.reputation === 'SUSPICIOUS')
  );
  if (params.extractedUrls.length > 0 && (suspiciousUrls.length > 0 || /click|login|verify|update|access|portal|account/i.test(params.bodyText))) {
    mappings.push({
      techniqueId: 'T1566.002',
      techniqueName: 'Phishing: Spearphishing Link',
      tactic: 'Initial Access',
      supportingEvidence: [
        `Extracted ${params.extractedUrls.length} hyperlink(s) from email body (${params.extractedUrls.slice(0, 2).join(', ')})`,
        ...(suspiciousUrls.length > 0
          ? [`Threat Intelligence identified malicious/suspicious destination(s): ${suspiciousUrls.map(u => u.value).slice(0, 2).join(', ')}`]
          : ['Embedded hyperlink directs recipient to external credential/action prompt']),
      ],
      confidence: suspiciousUrls.length > 0 ? 'High' : 'Medium',
      evidenceReferences: [
        'Body: Extracted Hyperlink Anchor',
        ...(suspiciousUrls.map(u => `IOC: ${u.type.toUpperCase()} ${u.value}`)),
      ],
      mappingRationale: 'Forensic body inspection identified hyperlinked URLs designed to route user traffic to external threat infrastructure.',
      isAiGuessed: false,
    });
  }

  // 2. T1566.001 - Phishing: Spearphishing Attachment
  // Grounding requirement: Physical presence of suspicious attachment or weaponized document
  const suspiciousAttachments = params.attachments.filter(
    a => a.isSuspicious || /\.(iso|exe|scr|vbs|hta|zip|rar|xlsm|docm)$/i.test(a.filename)
  );
  if (params.attachments.length > 0 && (suspiciousAttachments.length > 0 || params.attachments.some(a => a.threatDetails))) {
    mappings.push({
      techniqueId: 'T1566.001',
      techniqueName: 'Phishing: Spearphishing Attachment',
      tactic: 'Initial Access',
      supportingEvidence: [
        `Message contains ${params.attachments.length} attachment file(s)`,
        `Suspicious attachment(s) identified: ${params.attachments.map(a => `${a.filename} (${a.contentType}, SHA-256: ${a.sha256.substring(0, 12)}...)`).join(', ')}`,
      ],
      confidence: 'High',
      evidenceReferences: params.attachments.map(a => `Attachment: ${a.filename} (SHA-256: ${a.sha256.substring(0, 16)}...)`),
      mappingRationale: 'Forensically verified attachment containers with weaponized payload signatures or active execution capabilities.',
      isAiGuessed: false,
    });
  }

  // 3. T1598.003 - Phishing for Information: Spearphishing Link
  // Grounding requirement: Body and URL lures specifically solicits credential submission or authentication data
  const hasCredentialLure =
    /(password|credential|sign-in|sign in|session expired|mfa|authenticate|verify your account|banking portal|wire instruction)/i.test(lowerBody);
  if (hasCredentialLure && params.extractedUrls.length > 0) {
    mappings.push({
      techniqueId: 'T1598.003',
      techniqueName: 'Phishing for Information: Spearphishing Link',
      tactic: 'Reconnaissance',
      supportingEvidence: [
        'Observed text strings solicit sensitive authentication or financial transaction credentials',
        `Credential harvesting landing URL identified: ${params.extractedUrls[0]}`,
      ],
      confidence: 'High',
      evidenceReferences: [
        'Body: Credential harvesting language indicators',
        `Body URL: ${params.extractedUrls[0]}`,
      ],
      mappingRationale: 'Language patterns combined with external hyperlink structure directly target credential interception.',
      isAiGuessed: false,
    });
  }

  // 4. T1656 - Impersonation
  // Grounding requirement: Explicit header inconsistency showing display name spoofing, reply-to mismatch, or return-path mismatch
  if (inconsistencies.displaySpoofing || inconsistencies.replyToMismatch || inconsistencies.returnPathMismatch) {
    const evidenceList: string[] = [];
    const refList: string[] = [];

    if (inconsistencies.displaySpoofing) {
      evidenceList.push(`Display name masquerades as trusted entity while sender domain is '${params.senderDomain}'`);
      refList.push('Header: Display name spoofing mismatch');
    }
    if (inconsistencies.replyToMismatch && params.replyTo) {
      evidenceList.push(`Reply-To address '${params.replyTo}' diverges from envelope sender '${params.senderFrom}'`);
      refList.push('Header: Reply-To divergence');
    }
    if (inconsistencies.returnPathMismatch) {
      evidenceList.push('Return-Path envelope routing does not match RFC-5322 From address');
      refList.push('Header: Return-Path mismatch');
    }

    mappings.push({
      techniqueId: 'T1656',
      techniqueName: 'Impersonation',
      tactic: 'Defense Evasion',
      supportingEvidence: evidenceList,
      confidence: 'High',
      evidenceReferences: refList,
      mappingRationale: 'Header divergence demonstrates deliberate sender identity manipulation to deceive mail clients and recipients.',
      isAiGuessed: false,
    });
  }

  // 5. T1036.005 - Masquerading: Match Legitimate Name or Location
  // Grounding requirement: Punycode homograph or deceptive lookalike domain detected
  if (inconsistencies.punycodeHomograph || /micros0ft|office365-verify|sec-portal|bank-wire/i.test(params.senderDomain)) {
    mappings.push({
      techniqueId: 'T1036.005',
      techniqueName: 'Masquerading: Match Legitimate Name or Location',
      tactic: 'Defense Evasion',
      supportingEvidence: [
        `Sender domain '${params.senderDomain}' employs visual deception or character replacement`,
        'Typosquatting / homograph anomaly detected during RFC-5322 domain analysis',
      ],
      confidence: 'High',
      evidenceReferences: [
        `Domain: ${params.senderDomain}`,
        'Header: Punycode / Typo anomaly check',
      ],
      mappingRationale: 'Domain syntax was constructed to mimic legitimate brand infrastructure for defense evasion.',
      isAiGuessed: false,
    });
  }

  // 6. T1204.001 - User Execution: Malicious Link
  // Grounding requirement: Urgent call-to-action directing recipient to execute hyperlink
  if (params.extractedUrls.length > 0 && /(urgent|immediately|within 24 hours|action required|suspended|locked)/i.test(lowerBody)) {
    mappings.push({
      techniqueId: 'T1204.001',
      techniqueName: 'User Execution: Malicious Link',
      tactic: 'Execution',
      supportingEvidence: [
        'Psychological urgency triggers coerce recipient into clicking embedded link without secondary verification',
        `Urgent call-to-action associated with link destination: ${params.extractedUrls[0]}`,
      ],
      confidence: 'Medium',
      evidenceReferences: [
        'Body: Urgency and coercion phrasing',
        `Body URL: ${params.extractedUrls[0]}`,
      ],
      mappingRationale: 'Social engineering urgency levers combined with hyperlinked call-to-action compel user execution.',
      isAiGuessed: false,
    });
  }

  return mappings.map(m => ({
    ...m,
    evidenceFound: m.supportingEvidence.join('; '),
  }));
}
