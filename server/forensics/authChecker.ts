import { AuthStatus, AuthVerificationType, HeaderAnalysis, ReceivedHop } from '../../src/types/forensics';
import { classifyIp } from '../geolocation/ipClassifier';

export function analyzeHeaders(
  receivedHeaders: string[],
  headers: {
    from: string;
    fromAddress: string;
    fromDomain: string;
    fromName?: string;
    replyTo?: string;
    returnPath?: string;
    messageId?: string;
    date?: string;
    rawSource?: string;
  }
): HeaderAnalysis {
  const hops: ReceivedHop[] = [];
  const inconsistencies: {
    replyToMismatch: boolean;
    returnPathMismatch: boolean;
    messageIdAnomaly: boolean;
    displaySpoofing: boolean;
    punycodeHomograph: boolean;
    timezoneAnomaly: boolean;
    notes: string[];
  } = {
    replyToMismatch: false,
    returnPathMismatch: false,
    messageIdAnomaly: false,
    displaySpoofing: false,
    punycodeHomograph: false,
    timezoneAnomaly: false,
    notes: [],
  };

  // Received headers are ordered top to bottom in RFC-822 (Hop N down to Hop 1)
  // Reversing gives chronological hops (1 = initial ingestion/relay, N = recipient MX)
  const reversed = [...receivedHeaders].reverse();
  let prevTimestamp: Date | null = null;

  reversed.forEach((rec, idx) => {
    const hopNumber = idx + 1;
    const isChronologicalFirst = hopNumber === 1;
    const isChronologicalLast = hopNumber === reversed.length;

    // Extract 'from' host
    const fromMatch = rec.match(/from\s+([^\s;()]+)(?:\s+\(([^)]+)\))?/i);
    const fromHost = fromMatch ? fromMatch[1] : undefined;

    // Extract 'by' host
    const byMatch = rec.match(/by\s+([^\s;()]+)/i);
    const byHost = byMatch ? byMatch[1] : undefined;

    // Extract IP address inside brackets [x.x.x.x]
    const ipMatch = rec.match(/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/);
    const ip = ipMatch ? ipMatch[1] : undefined;

    // Extract timestamp after semicolon
    const semiIdx = rec.lastIndexOf(';');
    let timestamp: string | undefined = undefined;
    let delaySeconds: number | undefined = undefined;
    let isSuspicious = false;
    let flagReason: string | undefined = undefined;

    if (semiIdx !== -1) {
      const rawDateStr = rec.substring(semiIdx + 1).trim();
      const parsedDate = new Date(rawDateStr);
      if (!isNaN(parsedDate.getTime())) {
        timestamp = parsedDate.toISOString();
        if (prevTimestamp) {
          const diffMs = parsedDate.getTime() - prevTimestamp.getTime();
          delaySeconds = Math.max(0, Math.round(diffMs / 1000));
          if (diffMs < -30000) {
            isSuspicious = true;
            flagReason = `Time inversion detected: hop timestamp is ${Math.abs(Math.round(diffMs / 1000))}s before previous hop`;
            inconsistencies.timezoneAnomaly = true;
            inconsistencies.notes.push(`Chronological anomaly between hop ${hopNumber - 1} and ${hopNumber}`);
          } else if (delaySeconds > 86400) {
            isSuspicious = true;
            flagReason = `Excessive transit delay (${Math.round(delaySeconds / 3600)}h)`;
          }
        }
        prevTimestamp = parsedDate;
      }
    }

    // Check for suspicious untrusted MTA markers
    if (fromHost && (fromHost.includes('unknown') || fromHost.includes('dynamic') || fromHost.includes('pool'))) {
      isSuspicious = true;
      flagReason = flagReason ? `${flagReason}; Dynamic/unregistered host ${fromHost}` : `Dynamic or unregistered host name: ${fromHost}`;
    }

    const isPrivateIp = ip ? !classifyIp(ip).isPublic : false;

    // Distinguish relay roles strictly per Priority 3
    let relayRole: ReceivedHop['relayRole'] = 'OBSERVED_RELAY';
    let hopConfidence = 85;
    let attributionReasoning = 'Intermediate transit relay observed in message transport headers.';

    if (isChronologicalLast && reversed.length > 1) {
      relayRole = 'INTERNAL_RECEIVER';
      hopConfidence = 98;
      attributionReasoning = 'Recipient boundary mail exchange (MX) server responsible for local delivery.';
    } else if (isChronologicalFirst) {
      if (isPrivateIp) {
        relayRole = 'INFERRED_ORIGIN';
        hopConfidence = 60;
        attributionReasoning = 'Internal non-routable private IP recorded at initial client submission. Origin network inferred.';
      } else {
        relayRole = 'PROBABLE_SOURCE_INFRASTRUCTURE';
        hopConfidence = isSuspicious ? 68 : 88;
        attributionReasoning = 'Earliest routable external envelope transit point. Represents probable sending infrastructure, not verified human identity.';
      }
    } else if (idx === 1 && hops[0]?.ip && !classifyIp(hops[0].ip).isPublic) {
      relayRole = 'EARLIEST_RELIABLE_RELAY';
      hopConfidence = 86;
      attributionReasoning = 'First public routable internet relay following private submission boundary.';
    }

    hops.push({
      hopNumber,
      fromHost,
      byHost,
      ip,
      timestamp,
      delaySeconds,
      isOriginating: isChronologicalFirst,
      isSuspicious,
      flagReason,
      relayRole,
      confidence: hopConfidence,
      attributionReasoning,
    });
  });

  // Originating IP detection and Earliest Reliable Relay
  let originatingIp: string | undefined = undefined;
  let originatingHost: string | undefined = undefined;
  let earliestReliableRelay: { ip: string; host: string; confidence: number } | undefined = undefined;
  let probableSourceInfrastructure: { ip: string; host: string; confidence: number } | undefined = undefined;

  const publicHops = hops.filter(h => h.ip && classifyIp(h.ip).isPublic);

  if (publicHops.length > 0) {
    const firstPublic = publicHops[0];
    originatingIp = firstPublic.ip;
    originatingHost = firstPublic.fromHost;
    earliestReliableRelay = {
      ip: firstPublic.ip!,
      host: firstPublic.fromHost || firstPublic.ip!,
      confidence: firstPublic.confidence,
    };
    probableSourceInfrastructure = {
      ip: firstPublic.ip!,
      host: firstPublic.fromHost || firstPublic.ip!,
      confidence: firstPublic.confidence,
    };
  } else if (hops[0]?.ip) {
    originatingIp = hops[0].ip;
    originatingHost = hops[0].fromHost;
    probableSourceInfrastructure = {
      ip: hops[0].ip,
      host: hops[0].fromHost || hops[0].ip,
      confidence: hops[0].confidence,
    };
  }

  // --- SPF, DKIM, DMARC Forensic Verification (Priority 2) ---
  // Inspect Authentication-Results or Received-SPF or X-Authentication-Results
  const rawLower = (headers.rawSource || '').toLowerCase();

  // 1. SPF: Distinguish header-reported vs unverified
  let spfStatus: AuthStatus = 'NOT_VERIFIED';
  let spfVerificationType: AuthVerificationType = 'UNVERIFIED';
  let spfDetails = 'No SPF authentication records or Authentication-Results headers present in message envelope.';
  const spfMatch = rawLower.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i);
  const receivedSpfMatch = rawLower.match(/received-spf:\s*(pass|fail|softfail|neutral|none)/i);

  if (spfMatch || receivedSpfMatch) {
    spfVerificationType = 'HEADER_REPORTED';
    const rawStatus = (spfMatch ? spfMatch[1] : receivedSpfMatch![1]).toLowerCase();
    if (rawStatus === 'pass') {
      spfStatus = 'PASS';
      spfDetails = 'Header-reported result (Authentication-Results header): Recipient MTA evaluated sending host as authorized in sender DNS SPF record.';
    } else {
      spfStatus = 'FAIL';
      spfDetails = `Header-reported result (Authentication-Results header): SPF evaluation returned '${rawStatus}'. Sending host not authorized in domain DNS policy.`;
    }
  }

  // 2. DKIM: Distinguish header-reported vs unverified
  let dkimStatus: AuthStatus = 'NOT_VERIFIED';
  let dkimVerificationType: AuthVerificationType = 'UNVERIFIED';
  let dkimDetails = 'No DKIM signature verification headers located in message envelope.';
  const dkimMatch = rawLower.match(/dkim=(pass|fail|none|neutral|temperror|permerror)/i);
  const hasDkimSig = rawLower.includes('dkim-signature:');

  if (dkimMatch) {
    dkimVerificationType = 'HEADER_REPORTED';
    const rawStatus = dkimMatch[1].toLowerCase();
    if (rawStatus === 'pass') {
      dkimStatus = 'PASS';
      dkimDetails = 'Header-reported result (Authentication-Results header): Cryptographic body and header signature reported valid against sender domain public key.';
    } else {
      dkimStatus = 'FAIL';
      dkimDetails = `Header-reported result (Authentication-Results header): DKIM verification returned '${rawStatus}'. Signature validation or canonicalization failed.`;
    }
  } else if (hasDkimSig) {
    dkimStatus = 'NOT_VERIFIED';
    dkimVerificationType = 'UNVERIFIED';
    dkimDetails = 'DKIM-Signature header is present in message envelope, but independent local DNS key resolution was not conducted and no Authentication-Results header was recorded.';
  }

  // 3. DMARC: Distinguish header-reported vs unverified
  let dmarcStatus: AuthStatus = 'NOT_VERIFIED';
  let dmarcVerificationType: AuthVerificationType = 'UNVERIFIED';
  let dmarcDetails = 'No DMARC policy validation record published or evaluated.';
  const dmarcMatch = rawLower.match(/dmarc=(pass|fail|none|temperror|permerror)/i);

  if (dmarcMatch) {
    dmarcVerificationType = 'HEADER_REPORTED';
    const rawStatus = dmarcMatch[1].toLowerCase();
    if (rawStatus === 'pass') {
      dmarcStatus = 'PASS';
      dmarcDetails = 'Header-reported result (Authentication-Results header): Sender domain identifier alignment passed DMARC policy.';
    } else {
      dmarcStatus = 'FAIL';
      dmarcDetails = `Header-reported result (Authentication-Results header): DMARC policy evaluation returned '${rawStatus}'. Identifier alignment failed.`;
    }
  }

  // --- Inconsistency Analysis ---

  // Check Reply-To mismatch
  if (headers.replyTo) {
    const replyMatch = headers.replyTo.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (replyMatch && replyMatch[1]) {
      const replyDomain = replyMatch[1].toLowerCase();
      if (headers.fromDomain && replyDomain !== headers.fromDomain) {
        inconsistencies.replyToMismatch = true;
        inconsistencies.notes.push(
          `Reply-To domain (${replyDomain}) does not align with From domain (${headers.fromDomain}) — potential redirect or wire diversion vector.`
        );
      }
    }
  }

  // Check Return-Path mismatch
  if (headers.returnPath) {
    const returnMatch = headers.returnPath.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (returnMatch && returnMatch[1]) {
      const returnDomain = returnMatch[1].toLowerCase();
      if (headers.fromDomain && returnDomain !== headers.fromDomain) {
        inconsistencies.returnPathMismatch = true;
        inconsistencies.notes.push(
          `Return-Path envelope bounce sender (${returnDomain}) diverges from From header (${headers.fromDomain}).`
        );
      }
    }
  }

  // Check Message-ID anomalies
  if (!headers.messageId) {
    inconsistencies.messageIdAnomaly = true;
    inconsistencies.notes.push('RFC compliance violation: Message-ID header is entirely absent from message.');
  } else {
    const msgIdDomain = headers.messageId.split('@')[1]?.replace(/>.*$/, '').trim().toLowerCase();
    if (msgIdDomain && headers.fromDomain && !msgIdDomain.includes(headers.fromDomain) && !headers.fromDomain.includes(msgIdDomain)) {
      inconsistencies.messageIdAnomaly = true;
      inconsistencies.notes.push(
        `Message-ID host (${msgIdDomain}) does not align with sender domain (${headers.fromDomain}).`
      );
    }
  }

  // Check Display Name Spoofing
  if (headers.fromName) {
    const emailInsideName = headers.fromName.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    if (emailInsideName && emailInsideName[0].toLowerCase() !== headers.fromAddress.toLowerCase()) {
      inconsistencies.displaySpoofing = true;
      inconsistencies.notes.push(
        `Display Name Spoofing: Display name contains '${emailInsideName[0]}' disguising actual envelope sender '${headers.fromAddress}'.`
      );
    }
  }

  // Check Punycode / Homograph
  if (headers.fromDomain.includes('xn--') || (headers.fromDomain.includes('0') && headers.fromDomain.includes('o'))) {
    if (headers.fromDomain.includes('xn--')) {
      inconsistencies.punycodeHomograph = true;
      inconsistencies.notes.push(`Internationalized Punycode homograph domain detected in sender (${headers.fromDomain}).`);
    }
  }

  // Origin Confidence calculation
  let originConfidence = 85;
  if (hops.length === 0) originConfidence -= 40;
  if (hops.some(h => h.isSuspicious)) originConfidence -= 25;
  if (spfStatus === 'FAIL') originConfidence -= 20;
  if (dkimStatus === 'FAIL') originConfidence -= 15;
  if (hops.length >= 3 && !hops.some(h => h.isSuspicious) && spfStatus === 'PASS') originConfidence = 95;
  originConfidence = Math.max(15, Math.min(99, originConfidence));

  let originReliabilityExplanation = '';
  if (originConfidence >= 80) {
    originReliabilityExplanation = 'High reliability: Multi-hop transit trace is internally consistent with sequential timestamps and valid header structure.';
  } else if (originConfidence >= 50) {
    originReliabilityExplanation = 'Moderate reliability: Envelope relays are partially reconstructed with minor inconsistencies or unverified authentication headers.';
  } else {
    originReliabilityExplanation = 'Low reliability: Fragmented or forged Received headers detected; probable source infrastructure cannot be verified with high confidence.';
  }

  const originAttributionNotice =
    'Probable source infrastructure based on envelope transit trace. Does not establish exact physical location or definitive human actor identity.';

  return {
    receivedHops: hops,
    originatingIp,
    originatingHost,
    inferredOriginatingHop: hops.find(h => h.relayRole === 'PROBABLE_SOURCE_INFRASTRUCTURE') || hops[0],
    earliestReliableRelay,
    probableSourceInfrastructure,
    originAttributionNotice,
    spf: {
      status: spfStatus,
      details: spfDetails,
      senderDomain: headers.fromDomain,
      clientIp: originatingIp,
      verificationType: spfVerificationType,
      attributionNotice: 'Header-reported SPF result from receiving gateway Authentication-Results header. Unverified external state.',
    },
    dkim: {
      status: dkimStatus,
      details: dkimDetails,
      domain: headers.fromDomain,
      verificationType: dkimVerificationType,
      attributionNotice: 'Unverified / Header-reported DKIM signature. Does not guarantee sender authenticity without live DNS key validation.',
    },
    dmarc: {
      status: dmarcStatus,
      details: dmarcDetails,
      domain: headers.fromDomain,
      verificationType: dmarcVerificationType,
      attributionNotice: 'Header-reported DMARC evaluation from message envelope.',
    },
    inconsistencies,
    originConfidence,
    originReliabilityExplanation,
  };
}
