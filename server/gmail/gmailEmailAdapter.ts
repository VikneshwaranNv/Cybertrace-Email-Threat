import { parseRawEmail } from '../forensics/parser';
import { EmailEvidence } from '../../src/types/forensics';
import { GmailRawMessage } from './gmailApiService';

export interface GmailForensicEvidence {
  gmailMessageId: string;
  threadId: string;
  labelIds: string[];
  snippet?: string;
  sizeEstimate?: number;
  rawEml: string;
  evidence: EmailEvidence;
}

/**
 * Forensic adapter converting Gmail API raw message payload into CyberTrace EmailEvidence.
 * Reuses the existing parseRawEmail() without duplicating or altering any forensic parsing logic.
 *
 * Guaranteed Properties:
 * - Unaltered RFC-822 content is passed directly to the forensic parser.
 * - CRLF line breaks, multipart MIME boundaries, headers, and attachments are preserved verbatim.
 * - Cryptographic hashes (SHA-256 / MD5) are computed on the raw bytes.
 */
export function adaptGmailRawToForensics(
  gmailMessage: GmailRawMessage,
  caseIdPrefix = 'GMAIL'
): GmailForensicEvidence {
  if (!gmailMessage || !gmailMessage.rawEml) {
    throw new Error('Invalid Gmail message: missing raw RFC-822 content');
  }

  const caseId = `${caseIdPrefix}-${gmailMessage.id}`;
  const evidence = parseRawEmail(gmailMessage.rawEml, caseId);

  return {
    gmailMessageId: gmailMessage.id,
    threadId: gmailMessage.threadId,
    labelIds: gmailMessage.labelIds || [],
    snippet: gmailMessage.snippet,
    sizeEstimate: gmailMessage.sizeEstimate,
    rawEml: gmailMessage.rawEml,
    evidence,
  };
}

/**
 * Direct Base64URL-to-Evidence conversion helper.
 * Decodes the raw Base64URL string into standard RFC-822 and parses it via parseRawEmail().
 */
export function adaptBase64UrlToEvidence(
  base64UrlRaw: string,
  messageId = 'MSG-RAW',
  caseId = 'GMAIL-CASE'
): EmailEvidence {
  if (!base64UrlRaw || typeof base64UrlRaw !== 'string') {
    throw new Error('Missing or invalid Base64URL content');
  }

  const rawEml = Buffer.from(base64UrlRaw, 'base64url').toString('utf8');
  if (!rawEml || rawEml.trim().length === 0) {
    throw new Error('Decoded Base64URL payload resulted in empty RFC-822 content');
  }

  return parseRawEmail(rawEml, `${caseId}-${messageId}`);
}
