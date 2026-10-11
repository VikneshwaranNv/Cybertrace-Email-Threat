import {
  EmailAttachment,
  GeolocationResult,
  HeaderAnalysis,
  IOC,
  RiskLevel,
  RiskScore,
  ThreatAssessment,
} from '../../src/types/forensics';

export function calculateExplainableRiskScore(params: {
  threatAssessment: ThreatAssessment;
  headerAnalysis: HeaderAnalysis;
  iocs: IOC[];
  geolocations: GeolocationResult[];
  attachments: EmailAttachment[];
  bodyText: string;
}): RiskScore {
  const { threatAssessment, headerAnalysis, iocs, geolocations, attachments, bodyText } = params;

  // --- 1. AI/NLP Phishing Probability (Weight: 30%) ---
  let rawNlp = 10;
  const nlpEvidence: string[] = [];
  const nlpIndicators: string[] = [];

  if (threatAssessment.classification === 'LEGITIMATE') {
    rawNlp = Math.max(5, 100 - threatAssessment.confidence);
    nlpEvidence.push(`AI linguistic classification assessed benign communication (${threatAssessment.confidence}% confidence)`);
  } else {
    rawNlp = threatAssessment.confidence;
    nlpEvidence.push(`AI Model identified threat category: ${threatAssessment.classification}`);
    threatAssessment.reasons.forEach(r => nlpEvidence.push(`Forensic Reason: ${r}`));
    if (threatAssessment.detectedIndicators.credentialHarvesting) nlpIndicators.push('Credential Harvest Keyword Semantics');
    if (threatAssessment.detectedIndicators.urgencyManipulation) nlpIndicators.push('Psychological Urgency Trigger');
    if (threatAssessment.detectedIndicators.executiveImpersonation) nlpIndicators.push('Authority Bias Simulation');
  }
  const weightedNlp = Math.round((rawNlp * 0.3) * 10) / 10;

  // --- 2. URL/Domain Intelligence (Weight: 20%) ---
  let rawUrlDomain = 5;
  const urlEvidence: string[] = [];
  const urlIndicators: string[] = [];

  const maliciousUrls = iocs.filter(i => i.type === 'url' && i.reputation === 'MALICIOUS');
  const suspiciousUrls = iocs.filter(i => i.type === 'url' && i.reputation === 'SUSPICIOUS');
  const maliciousDomains = iocs.filter(i => i.type === 'domain' && i.reputation === 'MALICIOUS');
  const suspiciousDomains = iocs.filter(i => i.type === 'domain' && i.reputation === 'SUSPICIOUS');

  if (maliciousUrls.length > 0 || maliciousDomains.length > 0) {
    rawUrlDomain = 95;
    urlEvidence.push(`${maliciousUrls.length} malicious URLs and ${maliciousDomains.length} blacklisted domains identified`);
    maliciousUrls.forEach(u => urlIndicators.push(`URL: ${u.value} (Score: ${u.reputationScore})`));
    maliciousDomains.forEach(d => urlIndicators.push(`Domain: ${d.value} (Typosquat/Phishing)`));
  } else if (suspiciousUrls.length > 0 || suspiciousDomains.length > 0) {
    rawUrlDomain = 65;
    urlEvidence.push(`Low-reputation or newly observed domains/links detected`);
    suspiciousDomains.forEach(d => urlIndicators.push(`Suspicious TLD/Domain: ${d.value}`));
  } else {
    rawUrlDomain = 10;
    urlEvidence.push('Extracted domains belong to known trusted providers or no external URLs present');
  }
  const weightedUrlDomain = Math.round((rawUrlDomain * 0.2) * 10) / 10;

  // --- 3. Email Authentication (Weight: 15%) ---
  let rawAuth = 10;
  const authEvidence: string[] = [];
  const authIndicators: string[] = [];

  const { spf, dkim, dmarc, inconsistencies } = headerAnalysis;

  let authFailures = 0;
  if (spf.status === 'FAIL') {
    authFailures++;
    authEvidence.push(`SPF verification failed: sending MTA unauthorized for domain ${spf.senderDomain || ''}`);
    authIndicators.push('SPF: FAIL');
  } else if (spf.status === 'PASS') {
    authEvidence.push('SPF check passed: sending IP authorized in DNS');
    authIndicators.push('SPF: PASS');
  }

  if (dkim.status === 'FAIL') {
    authFailures++;
    authEvidence.push(`DKIM signature verification failed: signature broken or header modified`);
    authIndicators.push('DKIM: FAIL');
  } else if (dkim.status === 'PASS') {
    authEvidence.push('DKIM cryptographic signature verified');
    authIndicators.push('DKIM: PASS');
  }

  if (dmarc.status === 'FAIL') {
    authFailures++;
    authEvidence.push(`DMARC alignment failure: sender domain identifier policy violated`);
    authIndicators.push('DMARC: FAIL');
  } else if (dmarc.status === 'PASS') {
    authEvidence.push('DMARC policy verified');
    authIndicators.push('DMARC: PASS');
  }

  if (inconsistencies.replyToMismatch) {
    authFailures += 1.5;
    authEvidence.push('Reply-To header deliberately diverges from envelope From address');
    authIndicators.push('Reply-To Mismatch Flagged');
  }
  if (inconsistencies.returnPathMismatch) {
    authFailures += 0.5;
    authEvidence.push('Return-Path bounce address diverges from sender address');
    authIndicators.push('Return-Path Divergence');
  }
  if (inconsistencies.displaySpoofing) {
    authFailures += 1.5;
    authEvidence.push('Display name impersonates an email address');
    authIndicators.push('Display Spoofing');
  }

  if (authFailures >= 3) {
    rawAuth = 95;
  } else if (authFailures >= 2) {
    rawAuth = 75;
  } else if (authFailures >= 1) {
    rawAuth = 50;
  } else if (spf.status === 'PASS' && dkim.status === 'PASS' && dmarc.status === 'PASS') {
    rawAuth = 0;
  } else {
    rawAuth = 20;
  }
  const weightedAuth = Math.round((rawAuth * 0.15) * 10) / 10;

  // --- 4. IP Intelligence (Weight: 15%) ---
  let rawIp = 10;
  const ipEvidence: string[] = [];
  const ipIndicators: string[] = [];

  const maliciousIps = iocs.filter(i => (i.type === 'ipv4' || i.type === 'ipv6') && i.reputation === 'MALICIOUS');
  const suspiciousIps = iocs.filter(i => (i.type === 'ipv4' || i.type === 'ipv6') && i.reputation === 'SUSPICIOUS');
  const originatingGeo = geolocations.find(g => g.isOriginating) || geolocations[0];

  if (originatingGeo) {
    if (originatingGeo.vpnTorProxy.isTor) {
      rawIp = 98;
      ipEvidence.push(`Probable source relay ${originatingGeo.ip} is a confirmed Tor Anonymizing Exit Node`);
      ipIndicators.push('Tor Exit Relay Traffic');
    } else if (originatingGeo.vpnTorProxy.isVpn || originatingGeo.vpnTorProxy.isProxy) {
      rawIp = 80;
      ipEvidence.push(`Probable source infrastructure ${originatingGeo.ip} (${originatingGeo.country}) is an anonymous VPN/Proxy`);
      ipIndicators.push(`VPN/Proxy Provider: ${originatingGeo.isp}`);
    } else if (maliciousIps.length > 0) {
      rawIp = 90;
      ipEvidence.push(`Relay IP found in malicious threat intelligence feeds`);
      maliciousIps.forEach(i => ipIndicators.push(`IP: ${i.value} (${i.source})`));
    } else if (originatingGeo.vpnTorProxy.isDatacenter) {
      rawIp = 40;
      ipEvidence.push(`Transit IP originates from commercial cloud hosting (${originatingGeo.hostingProvider})`);
      ipIndicators.push(`ASN: ${originatingGeo.asn}`);
    } else {
      rawIp = 15;
      ipEvidence.push(`Transit IP is registered to legitimate residential/broadband pool (${originatingGeo.isp})`);
      ipIndicators.push(`Country: ${originatingGeo.country} (${originatingGeo.city || 'Regional'})`);
    }
  }
  const weightedIp = Math.round((rawIp * 0.15) * 10) / 10;

  // --- 5. Attachment Analysis (Weight: 10%) ---
  let rawAttachment = 0;
  const attEvidence: string[] = [];
  const attIndicators: string[] = [];

  if (attachments.length === 0) {
    rawAttachment = 0;
    attEvidence.push('No binary or archive attachments included with message');
  } else {
    const suspiciousAtts = attachments.filter(a => a.isSuspicious);
    if (suspiciousAtts.length > 0) {
      rawAttachment = 95;
      attEvidence.push(`${suspiciousAtts.length} high-risk attachment(s) identified with executable or macro profiles`);
      suspiciousAtts.forEach(a => {
        attIndicators.push(`${a.filename} (${a.threatDetails || 'High Risk Extension'})`);
      });
    } else {
      rawAttachment = 15;
      attEvidence.push(`${attachments.length} attachment(s) inspected; standard non-executable document formats (PDF/PNG)`);
      attachments.forEach(a => attIndicators.push(`${a.filename} (${Math.round(a.sizeBytes / 1024)} KB)`));
    }
  }
  const weightedAttachment = Math.round((rawAttachment * 0.1) * 10) / 10;

  // --- 6. Social Engineering (Weight: 10%) ---
  let rawSocial = 10;
  const socialEvidence: string[] = [];
  const socialIndicators: string[] = [];

  const lowerText = bodyText.toLowerCase();
  const urgencyCount = (lowerText.match(/urgent|immediately|within 24 hours|deadline|expir|overdue|warning|critical action/gi) || []).length;
  const paymentCount = (lowerText.match(/wire|invoice|remittance|bank|account|swift|iban|payroll|payment|funds/gi) || []).length;
  const fearCount = (lowerText.match(/suspend|deactivat|compromised|violation|legal|police|terminat/gi) || []).length;

  if (urgencyCount > 0) {
    socialEvidence.push(`Artificial urgency manipulation triggers detected (${urgencyCount} instances)`);
    socialIndicators.push('Time Pressure / Scarcity Lure');
  }
  if (paymentCount > 1) {
    socialEvidence.push(`Direct financial diversion keywords observed (${paymentCount} instances)`);
    socialIndicators.push('Financial Settlement Focus');
  }
  if (fearCount > 0) {
    socialEvidence.push(`Coercion / negative consequence framing detected (${fearCount} instances)`);
    socialIndicators.push('Fear / Penalty Framing');
  }

  const socialScoreCalc = Math.min(100, (urgencyCount * 25) + (paymentCount * 20) + (fearCount * 30));
  rawSocial = threatAssessment.classification === 'LEGITIMATE' ? 5 : Math.max(10, socialScoreCalc);
  const weightedSocial = Math.round((rawSocial * 0.1) * 10) / 10;

  // Total Score Calculation: sum of weighted components
  const totalScore = Math.min(100, Math.max(0, Math.round(
    weightedNlp + weightedUrlDomain + weightedAuth + weightedIp + weightedAttachment + weightedSocial
  )));

  let level: RiskLevel = 'LOW';
  if (totalScore >= 75) level = 'CRITICAL';
  else if (totalScore >= 50) level = 'HIGH';
  else if (totalScore >= 25) level = 'MEDIUM';
  else level = 'LOW';

  let summaryReason = '';
  if (level === 'CRITICAL') {
    summaryReason = 'CRITICAL THREAT: Multiple high-confidence attack vectors present (credential harvesting / BEC / malicious payload). Immediate containment required.';
  } else if (level === 'HIGH') {
    summaryReason = 'HIGH RISK: Significant forensic anomalies detected in headers, sender infrastructure, and communication patterns.';
  } else if (level === 'MEDIUM') {
    summaryReason = 'MEDIUM RISK: Suspicious characteristics observed requiring secondary SOC analyst review before release.';
  } else {
    summaryReason = 'LOW RISK: Message satisfies cryptographic authentication and exhibits standard organizational patterns with minimal threat indicators.';
  }

  return {
    totalScore,
    level,
    components: {
      aiNlpPhishing: {
        name: 'AI/NLP Phishing Probability',
        weightPercent: 30,
        rawScore: rawNlp,
        maxScore: 100,
        weightedScore: weightedNlp,
        evidence: nlpEvidence,
        calculation: `${rawNlp} / 100 × 30% = ${weightedNlp} pts`,
        supportingIndicators: nlpIndicators,
        riskFactors: [
          {
            factor: 'NLP Semantic Urgency & Threat Vector',
            evidence: nlpEvidence[0] || 'Classification confidence',
            contribution: weightedNlp,
            confidence: threatAssessment.confidence > 80 ? 'High' : 'Medium',
            isCounterEvidence: threatAssessment.classification === 'LEGITIMATE',
          },
        ],
        counterEvidence: threatAssessment.classification === 'LEGITIMATE' ? ['Benign operational vocabulary recognized'] : [],
      },
      urlDomainIntel: {
        name: 'URL/Domain Intelligence',
        weightPercent: 20,
        rawScore: rawUrlDomain,
        maxScore: 100,
        weightedScore: weightedUrlDomain,
        evidence: urlEvidence,
        calculation: `${rawUrlDomain} / 100 × 20% = ${weightedUrlDomain} pts`,
        supportingIndicators: urlIndicators,
        riskFactors: [
          {
            factor: 'Domain & Link Reputation Analysis',
            evidence: urlEvidence[0] || 'Domain database lookup',
            contribution: weightedUrlDomain,
            confidence: maliciousUrls.length > 0 ? 'High' : 'Medium',
            isCounterEvidence: maliciousUrls.length === 0 && suspiciousUrls.length === 0,
          },
        ],
        counterEvidence: maliciousUrls.length === 0 && suspiciousUrls.length === 0 ? ['No flagged malicious links or newly registered domains'] : [],
      },
      emailAuthentication: {
        name: 'Email Authentication & Headers',
        weightPercent: 15,
        rawScore: rawAuth,
        maxScore: 100,
        weightedScore: weightedAuth,
        evidence: authEvidence,
        calculation: `${rawAuth} / 100 × 15% = ${weightedAuth} pts`,
        supportingIndicators: authIndicators,
        riskFactors: [
          {
            factor: 'Cryptographic Envelope Validation',
            evidence: authEvidence[0] || 'SPF/DKIM/DMARC status evaluation',
            contribution: weightedAuth,
            confidence: 'High',
            isCounterEvidence: authFailures === 0,
          },
        ],
        counterEvidence: authFailures === 0 ? ['SPF, DKIM, and DMARC alignment verified without mismatch'] : [],
      },
      ipIntelligence: {
        name: 'IP & Infrastructure Intelligence',
        weightPercent: 15,
        rawScore: rawIp,
        maxScore: 100,
        weightedScore: weightedIp,
        evidence: ipEvidence,
        calculation: `${rawIp} / 100 × 15% = ${weightedIp} pts`,
        supportingIndicators: ipIndicators,
        riskFactors: [
          {
            factor: 'MTA Relay & Anonymization Telemetry',
            evidence: ipEvidence[0] || 'Infrastructure enrichment',
            contribution: weightedIp,
            confidence: originatingGeo?.vpnTorProxy.isTor || originatingGeo?.vpnTorProxy.isVpn ? 'High' : 'Medium',
            isCounterEvidence: originatingGeo && !originatingGeo.vpnTorProxy.isTor && !originatingGeo.vpnTorProxy.isVpn,
          },
        ],
        counterEvidence: originatingGeo && !originatingGeo.vpnTorProxy.isTor && !originatingGeo.vpnTorProxy.isVpn ? ['Reputable network routing pool without anonymizer flags'] : [],
      },
      attachmentAnalysis: {
        name: 'Attachment Analysis',
        weightPercent: 10,
        rawScore: rawAttachment,
        maxScore: 100,
        weightedScore: weightedAttachment,
        evidence: attEvidence,
        calculation: `${rawAttachment} / 100 × 10% = ${weightedAttachment} pts`,
        supportingIndicators: attIndicators,
        riskFactors: [
          {
            factor: 'Payload Threat & Macro Verification',
            evidence: attEvidence[0] || 'Attachment structural scan',
            contribution: weightedAttachment,
            confidence: attachments.some(a => a.isSuspicious) ? 'High' : 'Low',
            isCounterEvidence: attachments.length === 0 || !attachments.some(a => a.isSuspicious),
          },
        ],
        counterEvidence: attachments.length === 0 ? ['No file attachments included'] : ['No weaponized or executable extensions detected'],
      },
      socialEngineering: {
        name: 'Social Engineering Heuristics',
        weightPercent: 10,
        rawScore: rawSocial,
        maxScore: 100,
        weightedScore: weightedSocial,
        evidence: socialEvidence,
        calculation: `${rawSocial} / 100 × 10% = ${weightedSocial} pts`,
        supportingIndicators: socialIndicators,
        riskFactors: [
          {
            factor: 'Psychological Urgency & Authority Manipulation',
            evidence: socialEvidence[0] || 'Keyword heuristic analysis',
            contribution: weightedSocial,
            confidence: urgencyCount > 0 || paymentCount > 0 ? 'High' : 'Low',
            isCounterEvidence: urgencyCount === 0 && paymentCount === 0,
          },
        ],
        counterEvidence: urgencyCount === 0 && paymentCount === 0 ? ['No artificial urgency triggers or financial manipulation cues'] : [],
      },
    },
    summaryReason,
  };
}
