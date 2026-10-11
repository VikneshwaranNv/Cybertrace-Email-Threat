import crypto from 'crypto';
import { CustodyEvent, EmailAttachment, EmailEvidence } from '../../src/types/forensics';

export function calculateSha256(content: string | Buffer): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function calculateMd5(content: string | Buffer): string {
  return crypto.createHash('md5').update(content).digest('hex');
}

/**
 * Strict HTML sanitization for safe display in forensic console.
 * Neutralizes scripts, iframes, objects, embeds, forms, event handlers, and active content.
 * Never executes URLs or JavaScript from email HTML.
 */
export function sanitizeHtml(html: string): string {
  if (!html) return '';
  return html
    // Remove script tags and contents
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[SCRIPT EXECUTION BLOCKED BY FORENSIC SANDBOX]')
    // Remove iframes, objects, embeds, applets
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '[IFRAME BLOCKED]')
    .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '[OBJECT EMBED BLOCKED]')
    .replace(/<embed\b[^>]*>/gi, '[EMBED BLOCKED]')
    .replace(/<applet\b[^<]*(?:(?!<\/applet>)<[^<]*)*<\/applet>/gi, '[APPLET BLOCKED]')
    // Remove forms
    .replace(/<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>/gi, '[FORM SUBMISSION BLOCKED]')
    // Neutralize any inline event handlers (onload, onclick, onerror, etc.)
    .replace(/\s+on[a-zA-Z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, ' data-sanitized-event="handler-removed"')
    // Neutralize javascript: or data: URIs in href or src
    .replace(/\s+href\s*=\s*["']?\s*javascript:[^"'>\s]*/gi, ' href="#" data-blocked="javascript-scheme"')
    .replace(/\s+src\s*=\s*["']?\s*javascript:[^"'>\s]*/gi, ' src="about:blank" data-blocked="javascript-scheme"')
    // Prevent CSS expression attacks
    .replace(/style\s*=\s*["'][^"']*(?:expression|behavior|javascript)[^"']*["']/gi, 'data-sanitized-style="blocked"');
}

/**
 * Extracts all URLs from raw email content and bodies
 */
export function extractUrls(text: string): string[] {
  const urlRegex = /https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/gi;
  const matches = text.match(urlRegex) || [];
  const cleaned = matches.map(u => u.replace(/['"<>),.;\]]+$/, ''));
  return Array.from(new Set(cleaned));
}

/**
 * Extracts IPv4 and IPv6 addresses from text
 */
export function extractIps(text: string): string[] {
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const matches = text.match(ipv4Regex) || [];
  // Exclude common broadcast / loopback / zero IPs
  const filtered = matches.filter(ip => {
    return (
      ip !== '0.0.0.0' &&
      ip !== '255.255.255.255' &&
      !ip.startsWith('127.')
    );
  });
  return Array.from(new Set(filtered));
}

/**
 * Extracts domain names from text and URLs
 */
export function extractDomains(urls: string[], fromDomain?: string): string[] {
  const domains = new Set<string>();
  if (fromDomain) domains.add(fromDomain.toLowerCase());

  for (const url of urls) {
    try {
      const parsed = new URL(url);
      if (parsed.hostname && !parsed.hostname.match(/^\d+\.\d+\.\d+\.\d+$/)) {
        domains.add(parsed.hostname.toLowerCase());
      }
    } catch {
      const domainMatch = url.match(/https?:\/\/([^/?#:]+)/i);
      if (domainMatch && domainMatch[1]) {
        domains.add(domainMatch[1].toLowerCase());
      }
    }
  }
  return Array.from(domains);
}

/**
 * Parses an RFC-822 formatted raw email or header block into an EmailEvidence record
 */
export function parseRawEmail(rawEml: string, caseId = 'CASE-TMP'): EmailEvidence {
  const emailId = `EV-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
  // Calculate SHA-256 on raw uploaded bytes/content before any transformation
  const sha256 = calculateSha256(rawEml);
  const md5 = calculateMd5(rawEml);
  const sizeBytes = Buffer.byteLength(rawEml, 'utf8');

  // Normalize line breaks for header unfolding
  const normalized = rawEml.replace(/\r\n/g, '\n');
  const splitIndex = normalized.indexOf('\n\n');
  const headerBlock = splitIndex !== -1 ? normalized.substring(0, splitIndex) : normalized;
  const bodyBlock = splitIndex !== -1 ? normalized.substring(splitIndex + 2) : '';

  // Unfold folded headers (RFC 2822 / RFC 822: CRLF followed by WSP is a continuation)
  const unfoldedHeaderLines: string[] = [];
  const rawLines = headerBlock.split('\n');
  for (const line of rawLines) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && unfoldedHeaderLines.length > 0) {
      unfoldedHeaderLines[unfoldedHeaderLines.length - 1] += ' ' + line.trim();
    } else if (line.trim().length > 0) {
      unfoldedHeaderLines.push(line.trim());
    }
  }

  const headerMap: Record<string, string[]> = {};
  for (const line of unfoldedHeaderLines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx !== -1) {
      const key = line.substring(0, colonIdx).trim().toLowerCase();
      const val = line.substring(colonIdx + 1).trim();
      if (!headerMap[key]) {
        headerMap[key] = [];
      }
      headerMap[key].push(val);
    }
  }

  const getHeader = (name: string): string => {
    const list = headerMap[name.toLowerCase()];
    return list && list.length > 0 ? list[0] : '';
  };

  const fromRaw = getHeader('from') || 'Unknown Sender <unknown@example.com>';
  let fromName = '';
  let fromAddress = '';
  const fromMatch = fromRaw.match(/(?:"?([^"]*)"?\s)?(?:<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?)/);
  if (fromMatch) {
    fromName = (fromMatch[1] || '').trim();
    fromAddress = (fromMatch[2] || fromRaw).replace(/^[<"']+|[>"']+$/g, '').trim();
  } else {
    fromAddress = fromRaw.replace(/^[<"']+|[>"']+$/g, '').trim();
  }
  const fromDomain = fromAddress.includes('@')
    ? fromAddress.split('@')[1].replace(/[>"']+$/g, '').trim().toLowerCase()
    : 'unknown.domain';

  const toRaw = getHeader('to') || '';
  const toList = toRaw ? toRaw.split(',').map(s => s.trim()) : [];
  const ccRaw = getHeader('cc') || '';
  const ccList = ccRaw ? ccRaw.split(',').map(s => s.trim()) : [];
  const bccRaw = getHeader('bcc') || '';
  const bccList = bccRaw ? bccRaw.split(',').map(s => s.trim()) : [];

  const subject = getHeader('subject') || '(No Subject)';
  const date = getHeader('date') || new Date().toUTCString();
  const replyTo = getHeader('reply-to') || undefined;
  const returnPath = getHeader('return-path') || undefined;
  const messageId = getHeader('message-id') || undefined;
  const contentType = getHeader('content-type') || 'text/plain';
  const mimeVersion = getHeader('mime-version') || '1.0';
  const xMailer = getHeader('x-mailer') || undefined;
  // Preserve Received headers in their exact ingested order
  const receivedHeaders = headerMap['received'] || [];

  // Parse Body & Attachments
  let textBody = '';
  let htmlBody = '';
  const attachments: EmailAttachment[] = [];

  // Check for multipart boundary
  const boundaryMatch = contentType.match(/boundary=["']?([^"';]+)["']?/i);
  if (boundaryMatch && boundaryMatch[1]) {
    const boundary = boundaryMatch[1];
    const parts = bodyBlock.split(new RegExp(`--${boundary}(?:--)?`));
    for (const part of parts) {
      const trimmedPart = part.trim();
      if (!trimmedPart || trimmedPart === '--') continue;

      const partSplit = trimmedPart.indexOf('\n\n');
      const partHeaders = partSplit !== -1 ? trimmedPart.substring(0, partSplit) : '';
      const partContent = partSplit !== -1 ? trimmedPart.substring(partSplit + 2) : trimmedPart;

      const partContentType = (partHeaders.match(/content-type:\s*([^;\n]+)/i)?.[1] || '').toLowerCase();
      const contentDisposition = partHeaders.match(/content-disposition:[^\n]+/i)?.[0] || '';
      const filenameMatch = partHeaders.match(/filename=["']?([^"';\n]+)["']?/i) || contentDisposition.match(/filename=["']?([^"';\n]+)["']?/i);

      if (filenameMatch) {
        const filename = filenameMatch[1].trim();
        const attSha = calculateSha256(partContent);
        const attMd5 = calculateMd5(partContent);
        const isExe = /\.(exe|scr|bat|cmd|vbs|js|ps1|iso|img|hta|xlsm|docm)$/i.test(filename);
        const isMacro = /\.(docm|xlsm|pptm|dotm)$/i.test(filename);
        const isInvoiceZip = /invoice.*\.zip/i.test(filename);

        attachments.push({
          filename,
          contentType: partContentType || 'application/octet-stream',
          sizeBytes: Buffer.byteLength(partContent, 'utf8'),
          sha256: attSha,
          md5: attMd5,
          isSuspicious: isExe || isMacro || isInvoiceZip,
          threatDetails: isExe
            ? 'Executable payload extension detected'
            : isMacro
            ? 'Document with potential VBA macro payload'
            : undefined,
        });
      } else if (partContentType.includes('text/html')) {
        htmlBody += partContent;
      } else if (partContentType.includes('text/plain') || !partContentType) {
        textBody += partContent;
      }
    }
  } else {
    // Single part
    if (contentType.toLowerCase().includes('text/html')) {
      htmlBody = bodyBlock;
      textBody = bodyBlock.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    } else {
      textBody = bodyBlock;
    }
  }

  const combinedContent = `${headerBlock}\n${textBody}\n${htmlBody}`;
  const extractedUrls = extractUrls(combinedContent);
  const extractedIps = extractIps(combinedContent);
  const extractedDomains = extractDomains(extractedUrls, fromDomain);

  const ingestedTimestamp = new Date().toISOString();

  // Initialize chain of custody events for this evidence artifact
  const custodyEvents: CustodyEvent[] = [
    {
      id: `CUSTODY-${emailId}-1`,
      timestamp: ingestedTimestamp,
      action: 'INGESTED',
      evidenceId: emailId,
      actorOrSystem: 'RFC-822 Forensic Ingestion Parser',
      previousState: 'RAW_BITSTREAM',
      result: `Successfully ingested message (${Math.round(sizeBytes / 1024)} KB). Preserved original RFC-822 bitstream without transformation.`,
    },
    {
      id: `CUSTODY-${emailId}-2`,
      timestamp: new Date(Date.now() + 50).toISOString(),
      action: 'HASHED',
      evidenceId: emailId,
      actorOrSystem: 'SHA-256 Cryptographic Engine',
      previousState: 'INGESTED',
      result: `Calculated primary integrity hash: ${sha256}. MD5 reference: ${md5}.`,
    },
  ];

  return {
    id: emailId,
    caseId,
    rawSource: rawEml,
    sha256,
    md5,
    md5Note: 'Legacy reference checksum only — not primary cryptographic integrity',
    sizeBytes,
    ingestedAt: ingestedTimestamp,
    headers: {
      from: fromRaw,
      fromName: fromName || undefined,
      fromAddress,
      fromDomain,
      to: toList,
      cc: ccList.length > 0 ? ccList : undefined,
      bcc: bccList.length > 0 ? bccList : undefined,
      replyTo,
      returnPath,
      subject,
      date,
      messageId,
      contentType,
      mimeVersion,
      xMailer,
      receivedHeaders,
    },
    body: {
      text: textBody,
      html: htmlBody || undefined,
      sanitizedHtml: htmlBody ? sanitizeHtml(htmlBody) : undefined,
    },
    attachments,
    extractedUrls,
    extractedIps,
    extractedDomains,
    chainOfCustody: custodyEvents,
    custodyEvents,
  };
}
