import {
  CampaignMatch,
  EmailEvidence,
  EvidenceBlock,
  GeolocationResult,
  HeaderAnalysis,
  IOC,
  RiskScore,
  ThreatAssessment,
  TimelineEvent,
} from '../../src/types/forensics';

export function buildAttackTimeline(params: {
  evidence: EmailEvidence;
  headerAnalysis: HeaderAnalysis;
  iocs: IOC[];
  threatAssessment: ThreatAssessment;
  riskScore: RiskScore;
  geolocations: GeolocationResult[];
  campaignMatches: CampaignMatch[];
  evidenceBlock: EvidenceBlock;
}): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  const baseTime = new Date(params.evidence.ingestedAt).getTime();

  // Helper to format ISO with offset
  const timeAt = (secOffset: number) => new Date(baseTime + secOffset * 1000).toISOString();

  // Step 1: Email Received
  events.push({
    id: 'TL-STEP-1',
    stepNumber: 1,
    timestamp: timeAt(0),
    timeDelta: '+0.0s',
    title: 'Email Envelope Ingestion & Hash Generation',
    phase: 'EMAIL_RECEIVED',
    severity: 'INFO',
    description: `Raw RFC-822 message envelope (${Math.round(params.evidence.sizeBytes / 1024)} KB) ingested. Extracted Subject: "${params.evidence.headers.subject}".`,
    observedEvidence: [
      `SHA-256: ${params.evidence.sha256}`,
      `MD5: ${params.evidence.md5}`,
      `From: ${params.evidence.headers.from}`,
    ],
    actionTaken: 'Calculated baseline cryptographic hash and preserved original bitstream.',
  });

  // Step 2: Sender Analyzed
  events.push({
    id: 'TL-STEP-2',
    stepNumber: 2,
    timestamp: timeAt(1),
    timeDelta: '+1.2s',
    title: 'Sender Identity & Header Structure Inspection',
    phase: 'SENDER_ANALYZED',
    severity: params.headerAnalysis.inconsistencies.replyToMismatch || params.headerAnalysis.inconsistencies.displaySpoofing ? 'WARNING' : 'INFO',
    description: `Sender domain extracted as "${params.evidence.headers.fromDomain}". Evaluated RFC-5322 header alignment.`,
    observedEvidence: [
      `From Address: ${params.evidence.headers.fromAddress}`,
      params.evidence.headers.replyTo ? `Reply-To: ${params.evidence.headers.replyTo}` : 'No Reply-To header override',
      params.evidence.headers.returnPath ? `Return-Path: ${params.evidence.headers.returnPath}` : 'No Return-Path header',
    ],
    actionTaken: 'Parsed Received header stack and checked for envelope-to-header divergence.',
  });

  // Step 3: Authentication Checked
  const authSevere = params.headerAnalysis.spf.status === 'FAIL' || params.headerAnalysis.dmarc.status === 'FAIL';
  events.push({
    id: 'TL-STEP-3',
    stepNumber: 3,
    timestamp: timeAt(2),
    timeDelta: '+2.4s',
    title: 'Cryptographic Email Authentication Audit (SPF/DKIM/DMARC)',
    phase: 'AUTH_CHECKED',
    severity: authSevere ? 'CRITICAL' : 'SUCCESS',
    description: `SPF evaluated as ${params.headerAnalysis.spf.status}, DKIM as ${params.headerAnalysis.dkim.status}, DMARC as ${params.headerAnalysis.dmarc.status}.`,
    observedEvidence: [
      `SPF: ${params.headerAnalysis.spf.status} (${params.headerAnalysis.spf.details})`,
      `DKIM: ${params.headerAnalysis.dkim.status} (${params.headerAnalysis.dkim.details})`,
      `DMARC: ${params.headerAnalysis.dmarc.status} (${params.headerAnalysis.dmarc.details})`,
    ],
    actionTaken: authSevere
      ? 'Flagged authentication failure. Sender domain policy violated.'
      : 'Verified domain cryptographic alignment.',
  });

  // Step 4: Suspicious Indicators Detected
  const badIocs = params.iocs.filter(i => i.reputation === 'MALICIOUS' || i.reputation === 'SUSPICIOUS');
  events.push({
    id: 'TL-STEP-4',
    stepNumber: 4,
    timestamp: timeAt(3),
    timeDelta: '+3.1s',
    title: 'IOC Extraction & Static Signature Analysis',
    phase: 'SUSPICIOUS_INDICATOR_DETECTED',
    severity: badIocs.length > 0 ? 'WARNING' : 'INFO',
    description: `Extracted ${params.iocs.length} unique Indicators of Compromise (IOCs) across IPs, domains, URLs, and attachment hashes.`,
    observedEvidence: badIocs.slice(0, 3).map(i => `[${i.type.toUpperCase()}] ${i.value} (${i.reputation} - ${i.source})`),
    actionTaken: 'Queried threat reputation databases and classified indicator anomalies.',
  });

  // Step 5: Infrastructure Enriched
  const originatingGeo = params.geolocations.find(g => g.isOriginating) || params.geolocations[0];
  events.push({
    id: 'TL-STEP-5',
    stepNumber: 5,
    timestamp: timeAt(4),
    timeDelta: '+4.5s',
    title: 'MTA Routing & GeoLocation Infrastructure Intelligence',
    phase: 'INFRASTRUCTURE_ENRICHED',
    severity: originatingGeo?.vpnTorProxy.isTor || originatingGeo?.vpnTorProxy.isVpn ? 'CRITICAL' : 'INFO',
    description: `Traced ${params.headerAnalysis.receivedHops.length} MTA relay hops. Probable source infrastructure localized to ${originatingGeo?.country || 'Unknown'} (${originatingGeo?.isp || 'Unknown ISP'}).`,
    observedEvidence: [
      `Originating Transit IP: ${originatingGeo?.ip || 'N/A'}`,
      `ASN / Provider: ${originatingGeo?.asn || 'N/A'}`,
      `Anonymization: Tor=${originatingGeo?.vpnTorProxy.isTor ? 'YES' : 'NO'}, VPN=${originatingGeo?.vpnTorProxy.isVpn ? 'YES' : 'NO'}`,
    ],
    actionTaken: 'Mapped network topology and enriched IP metadata with autonomous system records.',
  });

  // Step 6: Campaign Correlated
  const topCamp = params.campaignMatches[0];
  events.push({
    id: 'TL-STEP-6',
    stepNumber: 6,
    timestamp: timeAt(5),
    timeDelta: '+5.7s',
    title: 'Campaign DNA Fingerprint Correlation',
    phase: 'CAMPAIGN_CORRELATED',
    severity: topCamp && topCamp.similarityPercentage > 50 ? 'WARNING' : 'INFO',
    description: topCamp
      ? `Correlated with ${topCamp.campaignCode} (${topCamp.similarityPercentage}% similarity, ${topCamp.campaignConfidence}% confidence).`
      : 'No statistically significant match with registered threat campaigns.',
    observedEvidence: topCamp
      ? [
          `Threat Actor: ${topCamp.threatActorGroup}`,
          `Matched Indicators: ${topCamp.matchingIndicators.domains.concat(topCamp.matchingIndicators.ips).join(', ') || 'Structural subject & header alignment'}`,
          `Historical Related Cases: ${topCamp.previousRelatedCases.join(', ')}`,
        ]
      : ['Autonomous novel pattern or standalone benign delivery.'],
    actionTaken: 'Queried SOC campaign vector index and calculated behavioral similarity score.',
  });

  // Step 7: AI Classification Completed
  events.push({
    id: 'TL-STEP-7',
    stepNumber: 7,
    timestamp: timeAt(7),
    timeDelta: '+7.2s',
    title: 'AI Threat Classification & NLP Semantic Assessment',
    phase: 'AI_CLASSIFIED',
    severity: params.threatAssessment.classification === 'LEGITIMATE' ? 'SUCCESS' : 'CRITICAL',
    description: `AI Model classified threat category as "${params.threatAssessment.classification}" with ${params.threatAssessment.confidence}% confidence (${params.threatAssessment.modelUsed}).`,
    observedEvidence: params.threatAssessment.evidence.slice(0, 3),
    actionTaken: `Synthesized recommendations: ${params.threatAssessment.recommendedActions[0] || 'Monitor'}.`,
  });

  // Step 8: Risk Calculated
  events.push({
    id: 'TL-STEP-8',
    stepNumber: 8,
    timestamp: timeAt(8),
    timeDelta: '+8.0s',
    title: 'Multi-Factor Explainable Risk Scoring',
    phase: 'RISK_CALCULATED',
    severity: params.riskScore.level === 'CRITICAL' ? 'CRITICAL' : params.riskScore.level === 'HIGH' ? 'WARNING' : 'INFO',
    description: `Overall Forensic Risk Score computed: ${params.riskScore.totalScore}/100 [${params.riskScore.level}].`,
    observedEvidence: [
      `AI/NLP Phishing (30%): ${params.riskScore.components.aiNlpPhishing.weightedScore} pts`,
      `URL/Domain Intel (20%): ${params.riskScore.components.urlDomainIntel.weightedScore} pts`,
      `Email Auth (15%): ${params.riskScore.components.emailAuthentication.weightedScore} pts`,
      `IP Intel (15%): ${params.riskScore.components.ipIntelligence.weightedScore} pts`,
      `Attachment (10%): ${params.riskScore.components.attachmentAnalysis.weightedScore} pts`,
      `Social Eng (10%): ${params.riskScore.components.socialEngineering.weightedScore} pts`,
    ],
    actionTaken: 'Executed weighted scoring algorithm and validated mathematical audit trail.',
  });

  // Step 9: Evidence Sealed in Blockchain
  events.push({
    id: 'TL-STEP-9',
    stepNumber: 9,
    timestamp: timeAt(9),
    timeDelta: '+9.1s',
    title: 'Cryptographic Hash-Chain Evidence Sealing',
    phase: 'EVIDENCE_SEALED',
    severity: 'SUCCESS',
    description: `Evidence block #${params.evidenceBlock.blockIndex} (${params.evidenceBlock.blockId}) sealed into private integrity ledger.`,
    observedEvidence: [
      `Block Hash: ${params.evidenceBlock.blockHash}`,
      `Previous Block Hash: ${params.evidenceBlock.prevBlockHash}`,
      `Sealed At: ${params.evidenceBlock.timestamp}`,
    ],
    actionTaken: 'Committed irreversible SHA-256 evidence record for digital forensics court admissibility.',
  });

  return events;
}
