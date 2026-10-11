import { Type } from '@google/genai';
import { ThreatAssessment, ThreatClassification } from '../../src/types/forensics';
import {
  getGeminiClient,
  isGeminiAvailable,
  recordGeminiQuotaExceeded,
  isQuotaExceededError,
} from './geminiClient';

/**
 * Deterministic Forensic Heuristic Engine (Fallback when GEMINI_API_KEY is not set or network unavailable)
 */
export function analyzeEmailHeuristically(params: {
  subject: string;
  from: string;
  fromDomain: string;
  replyTo?: string;
  bodyText: string;
  urls: string[];
  attachments: { filename: string; isSuspicious: boolean }[];
  authStatus: { spf: string; dkim: string; dmarc: string };
  inconsistencies: { replyToMismatch: boolean; returnPathMismatch: boolean; displaySpoofing: boolean };
}): ThreatAssessment {
  const lowerBody = (params.bodyText || '').toLowerCase();
  const lowerSubject = (params.subject || '').toLowerCase();

  // Observed facts directly from headers and body
  const observedEvidence: string[] = [];
  const counterEvidence: string[] = [];
  const aiInference: string[] = [];
  const riskFactors: string[] = [];

  // Pattern checks
  const hasUrgency = /urgent|immediate|within 24 hours|account suspended|wire transfer|overdue|action required|verify your account|security alert/i.test(
    lowerSubject + ' ' + lowerBody
  );
  const hasPayment = /invoice|wire|bank|routing|account details|beneficiary|payment instruction|transfer funds|payroll|ach/i.test(
    lowerSubject + ' ' + lowerBody
  );
  const hasCredLure = /password|login|credentials|portal|office365|microsoft 365|verify identity|session expired|reset password/i.test(
    lowerSubject + ' ' + lowerBody
  );
  const hasExecRole = /ceo|cfo|chief executive|president|managing director|board of directors/i.test(
    params.from + ' ' + lowerBody
  );

  const hasPhishUrl = params.urls.some(u => /login|verify|update|auth|secure|sharepoint/i.test(u) && !u.includes('google.com') && !u.includes('microsoft.com'));
  const hasBadAttachment = params.attachments.some(a => a.isSuspicious);

  // Document directly observed facts
  if (params.replyTo) {
    observedEvidence.push(`Explicit Reply-To header present: '${params.replyTo}' vs sender domain '${params.fromDomain}'.`);
  }
  if (params.urls.length > 0) {
    observedEvidence.push(`${params.urls.length} distinct URL hyperlinks extracted from message body.`);
  }
  if (params.attachments.length > 0) {
    observedEvidence.push(`Message carries ${params.attachments.length} attachment(s): ${params.attachments.map(a => a.filename).join(', ')}.`);
  }
  observedEvidence.push(`Authentication envelope states SPF='${params.authStatus.spf}', DKIM='${params.authStatus.dkim}', DMARC='${params.authStatus.dmarc}'.`);

  // Document counter-evidence
  if (params.authStatus.spf === 'PASS') {
    counterEvidence.push('Observed SPF verification passed for transmitting MTA.');
  }
  if (params.authStatus.dkim === 'PASS') {
    counterEvidence.push('Cryptographic DKIM signature reported valid by recipient gateway.');
  }
  if (params.attachments.length === 0) {
    counterEvidence.push('No executable payloads or attachment files detected.');
  }
  if (!params.inconsistencies.replyToMismatch) {
    counterEvidence.push('Reply-To header is either absent or domain-aligned with From address.');
  }

  let classification: ThreatClassification = 'LEGITIMATE';
  let confidence = 88;
  const reasons: string[] = [];
  const recommendedActions: string[] = [];

  const detected = {
    phishing: false,
    spoofing: false,
    impersonation: false,
    bec: false,
    credentialHarvesting: false,
    paymentDiversion: false,
    maliciousLinks: false,
    suspiciousAttachments: false,
    socialEngineering: false,
    executiveImpersonation: false,
    urgencyManipulation: false,
  };

  // Evaluate Threat Vectors
  if (params.inconsistencies.displaySpoofing || (params.authStatus.spf === 'FAIL' && hasExecRole)) {
    detected.spoofing = true;
    detected.impersonation = true;
    riskFactors.push('Sender Identity Deception: Display name disguises underlying transmitting identity or domain.');
    aiInference.push('Probable display-name impersonation targeting executive authority recognition.');
  }

  if (params.inconsistencies.replyToMismatch && hasPayment) {
    classification = 'BUSINESS_EMAIL_COMPROMISE';
    detected.bec = true;
    detected.paymentDiversion = true;
    detected.socialEngineering = true;
    confidence = 94;
    reasons.push('Reply-To divergence paired with urgent fund transfer instructions indicates a Business Email Compromise (BEC) wire diversion.');
    riskFactors.push('Financial Wire Redirection: Reply-To routes replies to an unaligned external mailbox while soliciting payments.');
    aiInference.push('High probability of financial fraud via social engineering wire diversion tactic.');
    recommendedActions.push('Contact intended recipient/counterparty via out-of-band verified phone number.');
    recommendedActions.push('Alert corporate treasury and suspend pending wire transfers to designated accounts.');
    recommendedActions.push('Block sender address and target domain on enterprise email security gateway.');
  } else if (hasCredLure && (hasPhishUrl || params.authStatus.spf === 'FAIL' || params.authStatus.dmarc === 'FAIL')) {
    classification = 'CREDENTIAL_HARVESTING';
    detected.phishing = true;
    detected.credentialHarvesting = true;
    detected.maliciousLinks = hasPhishUrl;
    confidence = 96;
    reasons.push('Deceptive security notification designed to direct victims to an illegitimate external credential-harvesting portal.');
    riskFactors.push('Credential Interception: Body contains urgency lure paired with suspicious authentication portal URLs.');
    aiInference.push('Model hypothesis: Attacker infrastructure deployed to harvest enterprise single sign-on (SSO) credentials.');
    recommendedActions.push('Blacklist extracted URLs and domains on perimeter proxy and DNS resolvers.');
    recommendedActions.push('Purge identical messages from all employee inboxes via Microsoft 365 / Google Workspace eDiscovery.');
    recommendedActions.push('Force password resets and terminate active sessions for any user who interacted with links.');
  } else if (hasBadAttachment) {
    classification = 'SUSPICIOUS_ATTACHMENT';
    detected.suspiciousAttachments = true;
    detected.phishing = true;
    confidence = 92;
    reasons.push('Message contains suspicious or weaponized attachment payload with executable or macro characteristics.');
    riskFactors.push('Malicious Payload Delivery: Attachment extension or packaging matches known initial access dropper profiles.');
    aiInference.push('Payload characteristics indicate initial access dropper or macro execution vector.');
    recommendedActions.push('Submit attachment hash to automated malware sandbox for dynamic detonation analysis.');
    recommendedActions.push('Quarantine message and inspect endpoint EDR logs on recipient workstation.');
  } else if (params.authStatus.spf === 'PASS' && params.authStatus.dkim === 'PASS' && !hasPhishUrl && !hasBadAttachment && !params.inconsistencies.replyToMismatch) {
    classification = 'LEGITIMATE';
    confidence = 95;
    reasons.push('Email exhibits valid cryptographic signatures, authorized SPF envelope, and standard operational terminology.');
    aiInference.push('Communication conforms to standard benign business exchange patterns.');
    recommendedActions.push('No incident response action required. Message verified authentic.');
  } else {
    // General high suspicion
    if (hasUrgency) {
      detected.urgencyManipulation = true;
      detected.socialEngineering = true;
      reasons.push('Artificial time-pressure heuristics detected in email content.');
      riskFactors.push('Urgency Manipulation: Language creates synthetic crisis requiring immediate unverified action.');
    }
    classification = hasPhishUrl ? 'PHISHING' : 'SPOOFING';
    confidence = 79;
    aiInference.push('Indicators match suspicious unverified relay patterns.');
    recommendedActions.push('Review sender IP transit record and request secondary verification.');
  }

  if (hasUrgency) detected.urgencyManipulation = true;
  if (hasExecRole) detected.executiveImpersonation = true;

  const urgencyLevel = classification === 'LEGITIMATE' ? 'LOW' : confidence > 90 ? 'CRITICAL' : 'HIGH';

  return {
    classification,
    confidence: Math.max(0, Math.min(100, confidence)),
    reasons: reasons.length > 0 ? reasons : ['Pattern heuristics match automated threat profile.'],
    evidence: observedEvidence,
    observedEvidence,
    aiInference,
    riskFactors,
    counterEvidence,
    attributionAssessment: 'Statistical similarity only. Does not constitute definitive legal or physical attribution to any specific human actor or nation-state entity.',
    attributionConfidence: 65,
    recommendedActions: recommendedActions.length > 0 ? recommendedActions : ['Quarantine message and review mail server logs.'],
    detectedIndicators: detected,
    urgencyLevel,
    executiveSummary: `${classification} threat identified with ${confidence}% confidence based on envelope analysis and indicator correlation.`,
    modelUsed: 'Forensic Deterministic Heuristic Engine (Offline Safety Mode)',
    isAiAssisted: false,
  };
}

/**
 * Runs AI Threat Analysis with Gemini 3.8 Flash, or falls back gracefully
 */
export async function analyzeEmailWithAI(params: {
  subject: string;
  from: string;
  fromDomain: string;
  to: string[];
  replyTo?: string;
  returnPath?: string;
  bodyText: string;
  urls: string[];
  ips: string[];
  domains: string[];
  attachments: { filename: string; isSuspicious: boolean }[];
  authStatus: { spf: string; dkim: string; dmarc: string };
  inconsistencies: { replyToMismatch: boolean; returnPathMismatch: boolean; displaySpoofing: boolean };
}, options?: { skipAi?: boolean; isDemo?: boolean }): Promise<ThreatAssessment> {
  // If skipAi requested, or during demo seed, or Gemini is in quota cooldown, immediately use heuristic engine
  if (options?.skipAi || options?.isDemo || !isGeminiAvailable()) {
    const fallback = analyzeEmailHeuristically(params);
    if (!isGeminiAvailable() && process.env.GEMINI_API_KEY) {
      fallback.executiveSummary += ' (Deterministic forensic fallback active during API quota cooldown)';
    }
    return fallback;
  }

  const gemini = getGeminiClient();
  if (!gemini) {
    return analyzeEmailHeuristically(params);
  }

  const prompt = `
You are a senior SOC analyst and digital forensics expert inspecting a suspicious email for Smart India Hackathon 2026.
Analyze the following email metadata and content strictly from a digital forensics perspective:

Subject: ${params.subject}
From: ${params.from}
From Domain: ${params.fromDomain}
To: ${params.to.join(', ')}
Reply-To: ${params.replyTo || 'None'}
Return-Path: ${params.returnPath || 'None'}
SPF Status: ${params.authStatus.spf}
DKIM Status: ${params.authStatus.dkim}
DMARC Status: ${params.authStatus.dmarc}
Extracted URLs: ${JSON.stringify(params.urls)}
Extracted IPs: ${JSON.stringify(params.ips)}
Extracted Domains: ${JSON.stringify(params.domains)}
Attachments: ${JSON.stringify(params.attachments)}
Reply-To Mismatch: ${params.inconsistencies.replyToMismatch}
Return-Path Mismatch: ${params.inconsistencies.returnPathMismatch}
Display Spoofing: ${params.inconsistencies.displaySpoofing}

Email Body Content:
"""
${params.bodyText.substring(0, 4000)}
"""

CRITICAL INSTRUCTIONS:
1. Strict Separation:
   - observedEvidence MUST contain ONLY directly observed, factual fragments extracted from the headers, body, attachments, or transport metadata.
   - aiInference MUST contain your analytical hypotheses, probabilistic models, and behavioral conclusions.
   - counterEvidence MUST contain any observed facts that argue AGAINST a malicious conclusion (e.g. valid SPF, professional tone, lack of links).
   - riskFactors MUST contain categorized threat risk factors justified by specific evidence.
2. Attribution Guardrail:
   - DO NOT make definitive legal or physical attribution claims (e.g., do NOT state "This was sent by APT28").
   - State attribution purely as "Consistent with patterns associated with..." or "Statistical similarity only".
3. Confidence MUST be a bounded integer between 0 and 100.
4. Classify into exactly one of: PHISHING, BUSINESS_EMAIL_COMPROMISE, EXECUTIVE_IMPERSONATION, CREDENTIAL_HARVESTING, PAYMENT_DIVERSION, MALICIOUS_LINK, SUSPICIOUS_ATTACHMENT, SPOOFING, LEGITIMATE.
`;

  try {
    const response = await gemini.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            classification: {
              type: Type.STRING,
              description: 'One of PHISHING, BUSINESS_EMAIL_COMPROMISE, EXECUTIVE_IMPERSONATION, CREDENTIAL_HARVESTING, PAYMENT_DIVERSION, MALICIOUS_LINK, SUSPICIOUS_ATTACHMENT, SPOOFING, LEGITIMATE',
            },
            confidence: {
              type: Type.INTEGER,
              description: 'Confidence percentage from 0 to 100',
            },
            reasons: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Forensic reasons for this determination',
            },
            observedEvidence: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Strictly observed factual evidence directly extracted from headers, body, or transport envelope',
            },
            aiInference: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Analytical deductions, behavioral interpretations, and probabilistic threat hypotheses',
            },
            riskFactors: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Categorized threat risk factors with specific evidence justifications',
            },
            counterEvidence: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Observed factors that argue against malice or indicate legitimate origin',
            },
            attributionAssessment: {
              type: Type.STRING,
              description: 'Statistical attribution statement strictly avoiding definitive human or state claims',
            },
            attributionConfidence: {
              type: Type.INTEGER,
              description: 'Attribution confidence between 0 and 100',
            },
            recommendedActions: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Concrete actions SOC analysts and incident response teams should execute immediately',
            },
            detectedIndicators: {
              type: Type.OBJECT,
              properties: {
                phishing: { type: Type.BOOLEAN },
                spoofing: { type: Type.BOOLEAN },
                impersonation: { type: Type.BOOLEAN },
                bec: { type: Type.BOOLEAN },
                credentialHarvesting: { type: Type.BOOLEAN },
                paymentDiversion: { type: Type.BOOLEAN },
                maliciousLinks: { type: Type.BOOLEAN },
                suspiciousAttachments: { type: Type.BOOLEAN },
                socialEngineering: { type: Type.BOOLEAN },
                executiveImpersonation: { type: Type.BOOLEAN },
                urgencyManipulation: { type: Type.BOOLEAN },
              },
              required: [
                'phishing',
                'spoofing',
                'impersonation',
                'bec',
                'credentialHarvesting',
                'paymentDiversion',
                'maliciousLinks',
                'suspiciousAttachments',
                'socialEngineering',
                'executiveImpersonation',
                'urgencyManipulation',
              ],
            },
            urgencyLevel: {
              type: Type.STRING,
              description: 'LOW, MEDIUM, HIGH, or CRITICAL',
            },
            executiveSummary: {
              type: Type.STRING,
              description: 'High level executive summary of the threat incident',
            },
          },
          required: [
            'classification',
            'confidence',
            'reasons',
            'observedEvidence',
            'aiInference',
            'riskFactors',
            'counterEvidence',
            'attributionAssessment',
            'attributionConfidence',
            'recommendedActions',
            'detectedIndicators',
            'urgencyLevel',
            'executiveSummary',
          ],
        },
      },
    });

    const parsedJson = JSON.parse(response.text || '{}');
    const observed = parsedJson.observedEvidence || [];
    const inference = parsedJson.aiInference || [];
    const risks = parsedJson.riskFactors || [];
    const counter = parsedJson.counterEvidence || [];

    return {
      classification: (parsedJson.classification || 'PHISHING') as ThreatClassification,
      confidence: Math.max(0, Math.min(100, parsedJson.confidence ?? 85)),
      reasons: parsedJson.reasons || [],
      evidence: observed.length > 0 ? observed : parsedJson.reasons || [],
      observedEvidence: observed,
      aiInference: inference,
      riskFactors: risks,
      counterEvidence: counter,
      attributionAssessment:
        parsedJson.attributionAssessment ||
        'Consistent with observed threat patterns; statistical similarity only, non-definitive.',
      attributionConfidence: Math.max(0, Math.min(100, parsedJson.attributionConfidence ?? 65)),
      recommendedActions: parsedJson.recommendedActions || [],
      detectedIndicators: parsedJson.detectedIndicators || {
        phishing: true,
        spoofing: false,
        impersonation: false,
        bec: false,
        credentialHarvesting: false,
        paymentDiversion: false,
        maliciousLinks: false,
        suspiciousAttachments: false,
        socialEngineering: true,
        executiveImpersonation: false,
        urgencyManipulation: true,
      },
      urgencyLevel: (parsedJson.urgencyLevel || 'HIGH') as any,
      executiveSummary: parsedJson.executiveSummary || 'AI forensic threat evaluation concluded.',
      modelUsed: 'gemini-3.8-flash (Google GenAI)',
      isAiAssisted: true,
    };
  } catch (error) {
    if (isQuotaExceededError(error)) {
      recordGeminiQuotaExceeded(error);
    } else {
      console.warn(
        '[Gemini Analyzer] AI evaluation unavailable (' +
          ((error as any)?.message || 'network/timeout') +
          '), invoking deterministic heuristic fallback.'
      );
    }
    const fallback = analyzeEmailHeuristically(params);
    fallback.executiveSummary += ' (Deterministic heuristic fallback engine active)';
    return fallback;
  }
}

