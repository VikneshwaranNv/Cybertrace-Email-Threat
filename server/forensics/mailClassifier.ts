import { MailType, MailTypeClassification } from '../../src/types/forensics';

interface MailClassificationInput {
  fromAddress: string;
  fromDomain: string;
  fromName?: string;
  subject: string;
  bodyText: string;
  headers: {
    receivedHeaders?: string[];
    replyTo?: string;
    returnPath?: string;
    messageId?: string;
    xMailer?: string;
    [key: string]: any;
  };
  authStatus?: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
  hasListHeaders?: boolean;
}

const COMMON_CONSUMER_WEBMAIL_DOMAINS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'yahoo.co.uk',
  'yahoo.co.in',
  'ymail.com',
  'hotmail.com',
  'outlook.com',
  'live.com',
  'msn.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'aol.com',
  'zoho.com',
  'proton.me',
  'protonmail.com',
  'mail.com',
  'gmx.com',
  'yandex.com',
]);

const BULK_MARKETING_MAILER_PATTERNS = [
  /mailchimp/i,
  /sendgrid/i,
  /constantcontact/i,
  /marketo/i,
  /hubspot/i,
  /salesforce/i,
  /activecampaign/i,
  /klaviyo/i,
  /campaignmonitor/i,
  /sparkpost/i,
  /sendinblue/i,
  /brevo/i,
  /mailgun/i,
  /subscribers/i,
  /newsletter/i,
  /promo/i,
  /marketing/i,
];

const CORPORATE_DISCLAIMER_PATTERNS = [
  /this (message|email) (and any attachments )?(is|are) confidential/i,
  /intended solely for the use of the (individual|entity)/i,
  /any unauthorized review, use, disclosure, or distribution is prohibited/i,
  /if you are not the intended recipient/i,
  /please notify the sender immediately and delete/i,
  /registered office.*company registration/i,
  /privilege.*confidential/i,
];

const SPAM_MARKETING_LURE_PATTERNS = [
  /unsubscribe/i,
  /opt[- ]out/i,
  /view in browser/i,
  /special offer|limited time deal|act now|exclusive discount|free trial/i,
  /manage preferences|update email preferences/i,
  /privacy policy.*terms of service/i,
];

/**
 * Evidence-based Mail Type Classification
 * Evaluates whether an email represents:
 * - COMPANY: enterprise communication, internal/B2B traffic, business workflows
 * - PERSONAL: direct 1-to-1 conversational communication
 * - SPAM: mass marketing, unsolicited promotional, newsletter campaigns
 * - UNKNOWN: ambiguous, truncated, or non-conforming message headers
 */
export function classifyMailType(input: MailClassificationInput): MailTypeClassification {
  const domain = (input.fromDomain || '').toLowerCase();
  const body = input.bodyText || '';
  const subject = input.subject || '';
  const headers = input.headers || {};
  const reasons: string[] = [];

  let companyScore = 0;
  let personalScore = 0;
  let spamScore = 0;

  // 1. Evaluate Bulk / Marketing Header Indicators (Strong SPAM indicators)
  const listUnsubscribe = headers['list-unsubscribe'] || headers['List-Unsubscribe'];
  const precedence = (headers['precedence'] || headers['Precedence'] || '').toLowerCase();
  const listId = headers['list-id'] || headers['List-Id'];
  const feedbackId = headers['feedback-id'] || headers['Feedback-Id'];
  const xMailer = (headers.xMailer || headers['x-mailer'] || '').toLowerCase();

  if (listUnsubscribe) {
    spamScore += 45;
    reasons.push('List-Unsubscribe header present');
  }
  if (precedence === 'bulk' || precedence === 'list') {
    spamScore += 35;
    reasons.push(`Precedence header set to '${precedence}'`);
  }
  if (listId || feedbackId) {
    spamScore += 30;
    reasons.push('Mailing list identifier present (List-ID / Feedback-ID)');
  }
  if (BULK_MARKETING_MAILER_PATTERNS.some(p => p.test(xMailer) || p.test(domain))) {
    spamScore += 35;
    reasons.push('Transmitted via commercial bulk marketing ESP service');
  }

  // Check body for marketing/unsubscribe text
  const matchesSpamText = SPAM_MARKETING_LURE_PATTERNS.filter(p => p.test(body)).length;
  if (matchesSpamText >= 2) {
    spamScore += 25;
    reasons.push('Contains promotional opt-out / preference management terminology');
  }

  // 2. Evaluate Corporate / Enterprise Indicators (Strong COMPANY indicators)
  const isConsumerDomain = COMMON_CONSUMER_WEBMAIL_DOMAINS.has(domain);
  const hasCorpDisclaimer = CORPORATE_DISCLAIMER_PATTERNS.some(p => p.test(body));

  if (!isConsumerDomain && domain.includes('.') && domain !== 'unknown.domain') {
    companyScore += 15;
    reasons.push(`Transmitted from non-consumer domain '@${domain}'`);
  }

  if (hasCorpDisclaimer) {
    companyScore += 40;
    reasons.push('Legal confidentiality disclaimer detected in signature block');
  }

  // Enterprise gateway and collaboration routing
  const receivedChain = (headers.receivedHeaders || []).join(' ').toLowerCase();
  if (
    /exchange|proofpoint|mimecast|ironport|barracuda|symantec|microsoft-enterprise/i.test(receivedChain)
  ) {
    companyScore += 35;
    reasons.push('Routed through enterprise email security gateway (Exchange/Proofpoint/Mimecast)');
  }

  // Business subject / workflow patterns
  if (
    /invoice|statement|quarterly|wire|purchase order|contract|agreement|meeting agenda|project sync|rfp|soc audit|board meeting/i.test(
      subject
    )
  ) {
    companyScore += 20;
    reasons.push('Subject reflects structured corporate business workflow');
  }

  // 3. Evaluate Personal / Conversational Indicators (Strong PERSONAL indicators)
  if (isConsumerDomain) {
    personalScore += 25;
    reasons.push(`Consumer webmail domain (@${domain}) observed`);
  }

  // Personal conversational markers
  const isShortOrConversational =
    body.length < 1500 &&
    /(^(hi|hello|hey|dear|thanks|cheers|best|talk soon|see you|regards)\b)/im.test(body) &&
    !hasCorpDisclaimer &&
    !listUnsubscribe;

  if (isShortOrConversational) {
    personalScore += 35;
    reasons.push('Conversational greeting/sign-off without automated broadcast markers');
  }

  // Direct In-Reply-To / References without bulk headers
  if ((headers['in-reply-to'] || headers['references']) && !listUnsubscribe) {
    personalScore += 25;
    reasons.push('Direct conversational thread (In-Reply-To header present)');
  }

  // 4. Resolve Classification & Confidence
  const scores = [
    { type: 'SPAM' as MailType, score: spamScore },
    { type: 'COMPANY' as MailType, score: companyScore },
    { type: 'PERSONAL' as MailType, score: personalScore },
  ].sort((a, b) => b.score - a.score);

  const top = scores[0];
  const second = scores[1];

  // Ambiguity / insufficient signal threshold
  if (top.score < 25) {
    return {
      mailType: 'UNKNOWN',
      mailTypeConfidence: 40,
      mailTypeReasons: ['Insufficient technical headers or content markers to definitively attribute mail category.'],
    };
  }

  // Relative margin calculation
  const margin = top.score - second.score;
  let confidence = Math.min(95, Math.max(55, top.score + Math.round(margin * 0.5)));

  // If listUnsubscribe was present, it is virtually never a Personal email
  if (listUnsubscribe && top.type === 'PERSONAL') {
    return {
      mailType: 'SPAM',
      mailTypeConfidence: 80,
      mailTypeReasons: ['Explicit bulk unsubscribe header overrides personal webmail address.'],
    };
  }

  return {
    mailType: top.type,
    mailTypeConfidence: confidence,
    mailTypeReasons: reasons.slice(0, 4),
  };
}
