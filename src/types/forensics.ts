/**
 * Type definitions for AI-Powered Email Threat Detection, GeoLocation
 * and Forensic Intelligence Platform (SIH 2026 Problem 26106)
 */

export type AuthStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'NOT_VERIFIED';

export type AuthVerificationType = 'HEADER_REPORTED' | 'INDEPENDENTLY_VERIFIED' | 'UNVERIFIED';

export type CustodyAction =
  | 'INGESTED'
  | 'HASHED'
  | 'ANALYZED'
  | 'ENRICHED'
  | 'REVIEWED'
  | 'REPORTED';

export interface CustodyEvent {
  id: string;
  timestamp: string;
  action: CustodyAction;
  evidenceId: string;
  actorOrSystem: string;
  previousState: string;
  result: string;
}

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatClassification =
  | 'PHISHING'
  | 'BUSINESS_EMAIL_COMPROMISE'
  | 'EXECUTIVE_IMPERSONATION'
  | 'CREDENTIAL_HARVESTING'
  | 'PAYMENT_DIVERSION'
  | 'MALICIOUS_LINK'
  | 'SUSPICIOUS_ATTACHMENT'
  | 'SPOOFING'
  | 'LEGITIMATE';

export type CaseStatus =
  | 'OPEN'
  | 'IN_PROGRESS'
  | 'ESCALATED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
  | 'UNDER_INVESTIGATION'
  | 'CONTAINED'
  | 'CLOSED';

export type CasePriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type IOCType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'hash_sha256' | 'hash_md5' | 'email';

export type IOCReputation = 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';

export type IOCEnrichmentStatus =
  | 'ENRICHED'
  | 'THREAT INTELLIGENCE UNAVAILABLE'
  | 'PENDING'
  | 'CACHED'
  | 'ERROR';

export interface EmailAttachment {
  filename: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  md5: string;
  isSuspicious: boolean;
  threatDetails?: string;
}

export interface EmailEvidence {
  id: string;
  caseId: string;
  rawSource: string;
  sha256: string;
  md5: string;
  md5Note: string; // "Legacy reference checksum only — not primary cryptographic integrity"
  sizeBytes: number;
  ingestedAt: string;
  headers: {
    from: string;
    fromName?: string;
    fromAddress: string;
    fromDomain: string;
    to: string[];
    cc?: string[];
    bcc?: string[];
    replyTo?: string;
    returnPath?: string;
    subject: string;
    date: string;
    messageId?: string;
    contentType?: string;
    mimeVersion?: string;
    xMailer?: string;
    receivedHeaders: string[];
  };
  body: {
    text: string;
    html?: string;
    sanitizedHtml?: string;
  };
  attachments: EmailAttachment[];
  extractedUrls: string[];
  extractedIps: string[];
  extractedDomains: string[];
  custodyEvents: CustodyEvent[];
  chainOfCustody?: CustodyEvent[];
}

export interface ReceivedHop {
  hopNumber: number;
  fromHost?: string;
  byHost?: string;
  ip?: string;
  protocol?: string;
  timestamp?: string;
  delaySeconds?: number;
  isOriginating: boolean;
  isSuspicious: boolean;
  flagReason?: string;
  relayRole:
    | 'OBSERVED_RELAY'
    | 'EARLIEST_RELIABLE_RELAY'
    | 'PROBABLE_SOURCE_INFRASTRUCTURE'
    | 'INFERRED_ORIGIN'
    | 'INTERNAL_RECEIVER';
  confidence: number;
  attributionReasoning: string;
}

export interface HeaderAnalysis {
  receivedHops: ReceivedHop[];
  originatingIp?: string;
  originatingHost?: string;
  inferredOriginatingHop?: ReceivedHop;
  earliestReliableRelay?: { ip: string; host: string; confidence: number };
  probableSourceInfrastructure?: { ip: string; host: string; confidence: number };
  originAttributionNotice: string;
  spf: {
    status: AuthStatus;
    details: string;
    clientIp?: string;
    senderDomain?: string;
    verificationType: AuthVerificationType;
    attributionNotice?: string;
  };
  dkim: {
    status: AuthStatus;
    details: string;
    domain?: string;
    selector?: string;
    verificationType: AuthVerificationType;
    attributionNotice?: string;
  };
  dmarc: {
    status: AuthStatus;
    details: string;
    disposition?: string;
    domain?: string;
    verificationType: AuthVerificationType;
    attributionNotice?: string;
  };
  inconsistencies: {
    replyToMismatch: boolean;
    returnPathMismatch: boolean;
    messageIdAnomaly: boolean;
    displaySpoofing: boolean;
    punycodeHomograph: boolean;
    timezoneAnomaly: boolean;
    notes: string[];
  };
  originConfidence: number; // 0 - 100%
  originReliabilityExplanation: string;
}

export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  reputation: IOCReputation;
  reputationScore: number; // 0 - 100
  confidence: number; // 0 - 100%
  source: string;
  firstSeen: string;
  lastSeen?: string;
  relatedThreats?: string[];
  relatedEvidenceReferences?: string[];
  timestamp?: string;
  enrichmentStatus?: IOCEnrichmentStatus;
  relatedCases: string[];
  isSimulated: boolean; // clearly distinguishes live vs simulated
  maliciousCategory?: string;
  context?: string;
  rawThreatData?: Record<string, any>;
}

export type NormalizedIOC = IOC;

export interface MitreTechniqueMapping {
  techniqueId: string; // e.g. "T1566.001", "T1566.002", "T1598.003", "T1656", "T1586.002", "T1204.001", "T1204.002"
  techniqueName: string; // e.g. "Spearphishing Attachment", "Spearphishing Link"
  tactic: string; // "Initial Access" | "Reconnaissance" | "Execution" | "Defense Evasion" | "Credential Access"
  supportingEvidence: string[]; // Strict list of actual observed artifacts
  evidenceFound?: string; // Human-readable aggregate of supporting evidence
  confidence: 'Low' | 'Medium' | 'High' | number;
  evidenceReferences: string[]; // IDs/labels connecting directly to headers, URLs, attachments, etc.
  mappingRationale: string;
  isAiGuessed: false; // strictly grounded, NEVER claimed solely on AI guess
}

export interface GeolocationResult {
  ip: string;
  version?: 'IPv4' | 'IPv6';
  isOriginating: boolean;
  country: string;
  countryCode: string;
  region: string;
  city?: string;
  latitude: number;
  longitude: number;
  timezone?: string;
  postalCode?: string;
  accuracyRadiusKm?: number;
  isp: string;
  asn: string;
  organization?: string;
  connectionType?: 'hosting' | 'residential' | 'cellular' | 'corporate' | 'unknown' | string;
  hostingProvider: string;
  isVpn?: boolean;
  isProxy?: boolean;
  isTor?: boolean;
  isHosting?: boolean;
  source?: string;
  geolocatable?: boolean;
  reason?: string;
  vpnTorProxy: {
    isVpn: boolean;
    isTor: boolean;
    isProxy: boolean;
    isDatacenter: boolean;
  };
  confidence: number; // 0 - 100%
  infrastructureRole: string; // e.g. "Direct Relay Host", "Target MX Receiver", "Probable Relay"
  attributionNote: string; // "Probable source infrastructure. Geolocation indicates network transit point, not confirmed human actor identity."
  evidenceProvenance?: {
    sourceHeader?: string;
    rawHeaderSnippet?: string;
    lookupTimestamp: string;
    observedIn: 'RECEIVED_HEADER' | 'ORIGINATING_IP' | 'EXTRACTED_INFRASTRUCTURE' | 'BODY_EXTRACTION';
  };
}

export interface DomainNetworkIntelligence {
  domain: string;
  observedIps: string[];
  associatedGeos: GeolocationResult[];
  asnList: string[];
  organizations: string[];
  anonymizerStatus: {
    hasVpn: boolean;
    hasTor: boolean;
    hasProxy: boolean;
    hasHosting: boolean;
  };
  confidence: number;
  summary: string;
}

export interface RiskComponent {
  name: string;
  weightPercent: number; // e.g. 30 for 30%
  rawScore: number; // 0 - 100
  maxScore: number; // Maximum possible raw score (usually 100)
  weightedScore: number; // rawScore * (weightPercent / 100)
  evidence: string[];
  calculation: string;
  supportingIndicators: string[];
  riskFactors?: Array<{
    factor: string;
    evidence: string;
    contribution: number;
    confidence: 'Low' | 'Medium' | 'High';
    isCounterEvidence?: boolean;
  }>;
  counterEvidence?: string[];
}

export interface RiskScore {
  totalScore: number; // 0 - 100
  level: RiskLevel;
  components: {
    aiNlpPhishing: RiskComponent; // 30%
    urlDomainIntel: RiskComponent; // 20%
    emailAuthentication: RiskComponent; // 15%
    ipIntelligence: RiskComponent; // 15%
    attachmentAnalysis: RiskComponent; // 10%
    socialEngineering: RiskComponent; // 10%
  };
  summaryReason: string;
}

export interface ThreatAssessment {
  classification: ThreatClassification;
  confidence: number; // 0 - 100%
  reasons: string[];
  evidence: string[];
  observedEvidence: string[]; // Strict separation: directly observed facts
  aiInference: string[]; // Strict separation: model-generated conclusions
  riskFactors: string[];
  counterEvidence: string[];
  attributionAssessment: string; // e.g. "Statistical similarity only; human attribution cannot be established"
  attributionConfidence: number; // 0 - 100%
  recommendedActions: string[];
  detectedIndicators: {
    phishing: boolean;
    spoofing: boolean;
    impersonation: boolean;
    bec: boolean;
    credentialHarvesting: boolean;
    paymentDiversion: boolean;
    maliciousLinks: boolean;
    suspiciousAttachments: boolean;
    socialEngineering: boolean;
    executiveImpersonation: boolean;
    urgencyManipulation: boolean;
  };
  urgencyLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  executiveSummary: string;
  modelUsed: string;
  isAiAssisted: boolean;
}

export interface CampaignMatch {
  campaignId: string;
  campaignCode: string; // e.g. "CAMPAIGN-0042"
  name: string;
  threatActorGroup: string;
  similarityScore: number; // 0 - 100
  similarityPercentage: number; // alias for backward compatibility
  campaignConfidence: number; // 0 - 100%
  confidence: 'Low' | 'Medium' | 'High';
  relatedInvestigations: string[]; // e.g. ['CASE-2026-002', 'CASE-2026-003']
  sharedInfrastructure: string[]; // e.g. ["IP: 197.210.64.12", "ASN: AS29465"]
  sharedIocs: string[]; // e.g. ["Domain: global-invoicing.net", "URL: http://..."]
  campaignTimeline: Array<{
    date: string;
    event: string;
    sourceCase?: string;
  }>;
  observedCorrelation: string[]; // STRICT separation: factual observed matches
  aiInference: string[]; // STRICT separation: AI probabilistic clustering hypotheses
  matchingFeatures: string[]; // Explicit matching features
  missingFeatures: string[]; // Explicit counter-indicators/missing features
  attributionNotice: string; // Explicit notice separating campaign similarity from human attribution
  matchingIndicators: {
    domains: string[];
    ips: string[];
    urls: string[];
    senderPatterns: string[];
    replyToPatterns: string[];
    subjectStructure: string[];
    languagePatterns: string[];
    htmlCharacteristics: string[];
    infrastructure: string[];
    authenticationAnomalies: string[];
  };
  previousRelatedCases: string[];
  firstObserved: string;
  lastObserved: string;
  campaignDescription: string;
  severity: RiskLevel;
}

export type GraphNodeType =
  | 'Email'
  | 'Sender'
  | 'Domain'
  | 'IP'
  | 'URL'
  | 'Hash'
  | 'IOC'
  | 'Campaign'
  | 'Technique'
  | 'email'
  | 'sender'
  | 'reply_to'
  | 'domain'
  | 'url'
  | 'ip'
  | 'asn'
  | 'hosting'
  | 'campaign'
  | 'case';

export type GraphEdgeType =
  | 'SENT_FROM'
  | 'CONTAINS'
  | 'RESOLVES_TO'
  | 'REDIRECTS_TO'
  | 'MATCHES'
  | 'CORRELATED_WITH'
  | 'USES_TECHNIQUE'
  | 'sent from'
  | 'replies to'
  | 'resolves to'
  | 'hosted by'
  | 'related to'
  | 'observed in'
  | 'shares infrastructure with';

export interface GraphNode {
  id: string;
  label: string;
  type: GraphNodeType;
  subType?: string;
  risk?: RiskLevel;
  properties: Record<string, any>;
  evidenceReferences?: string[]; // Evidence references connecting node to forensic artifact
  evidenceDetails?: string; // Human-readable forensic evidence string revealed on click
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: GraphEdgeType;
  relationship?: string;
  evidence: string; // Mandatory supporting evidence
  evidenceReference: string; // Mandatory evidence reference ID/label
  confidence?: number;
}

export interface InvestigationGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AnalystNote {
  id: string;
  author: string;
  timestamp: string;
  content: string;
}

export interface CaseHistoryItem {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  details: string;
  previousValue?: string;
  newValue?: string;
}

export interface TimelineEvent {
  id: string;
  stepNumber: number;
  timestamp: string;
  timeDelta: string;
  title: string;
  phase:
    | 'EMAIL_RECEIVED'
    | 'SENDER_ANALYZED'
    | 'AUTH_CHECKED'
    | 'SUSPICIOUS_INDICATOR_DETECTED'
    | 'INFRASTRUCTURE_ENRICHED'
    | 'CAMPAIGN_CORRELATED'
    | 'AI_CLASSIFIED'
    | 'RISK_CALCULATED'
    | 'EVIDENCE_SEALED';
  severity: 'INFO' | 'WARNING' | 'CRITICAL' | 'SUCCESS';
  description: string;
  observedEvidence: string[];
  actionTaken?: string;
  analystNotes?: string;
}

export interface EvidenceBlock {
  blockIndex: number;
  blockId: string;
  evidenceId: string;
  caseId?: string;
  timestamp: string;
  emailSha256: string;
  analysisSha256: string;
  prevBlockHash: string;
  blockHash: string;
  nonce?: number;
  previousHash?: string; // Standard alias
  currentHash?: string; // Standard alias
  ledgerType?: string; // "Private tamper-evident hash-chain demonstration"
  metadata: {
    investigator: string;
    action: string;
    clientFingerprint: string;
    toolVersion: string;
  };
  isTampered?: boolean;
}

export interface LedgerVerificationResult {
  isValid: boolean;
  statusMessage: string;
  totalBlocks: number;
  verifiedAt: string;
  invalidBlockIndex?: number;
  brokenLinkDetails?: {
    blockIndex: number;
    expectedHash: string;
    actualHash: string;
    reason: string;
  };
}

export interface CaseRecord {
  caseId: string;
  caseNumber: string; // e.g. "CASE-2026-001"
  title: string;
  severity: RiskLevel;
  priority: CasePriority;
  classification: ThreatClassification;
  status: CaseStatus;
  createdAt: string;
  updatedAt: string;
  analyst: string;
  assignedTo: string;
  assignedAnalystId?: string;
  assignedAnalystName?: string;
  lastUpdatedBy?: string;
  ownerId?: string;
  ownerEmail?: string;
  isPublicDemo?: boolean;
  authorizedUsers?: string[];
  tags: string[];
  notes: AnalystNote[];
  history: CaseHistoryItem[];
  relatedCampaign?: string;
  evidenceCount: number;
  riskScore: number;
  emailSubject: string;
  fromAddress: string;
  originatingGeo?: GeolocationResult;
  geolocations?: GeolocationResult[];
}

export interface ForensicReportSection {
  title: string;
  sectionNumber: number;
  content: string;
  details?: Record<string, any>;
  evidenceReferences?: string[];
  isAiGenerated?: boolean;
}

export interface ForensicReportData {
  reportId: string;
  generatedAt: string;
  analyst: string;
  organization: string;
  caseRecord: CaseRecord;
  evidence: EmailEvidence;
  headerAnalysis: HeaderAnalysis;
  iocs: IOC[];
  threatAssessment: ThreatAssessment;
  riskScore: RiskScore;
  geolocations: GeolocationResult[];
  campaignMatches: CampaignMatch[];
  mitreMappings: MitreTechniqueMapping[];
  attackTimeline: TimelineEvent[];
  evidenceBlock: EvidenceBlock;
  ledgerStatus: LedgerVerificationResult;
  custodyEvents?: CustodyEvent[];
  investigativeAssessment: string;
  observedEvidenceSummary?: string[];
  analyticalConclusionsSummary?: string[];
  recommendedActions: string[];
  limitations: string[];
  evidenceIntegrityNotice: string;
  auditInformation: string;
  legalDisclaimer: string;
  disclaimers?: {
    attribution?: string;
    geolocation?: string;
    aiInference?: string;
    integrity?: string;
    custody?: string;
    tamperEvidentLedger?: string;
    demonstrationIntelligence?: string;
    legalDisclaimer?: string;
  };
  sections?: {
    executiveSummary: string;
    observedEvidence: string[];
    authenticationAudit: string[];
    enrichmentFindings: string[];
    aiAnalysis: string[];
    blockchainSealingStatus: string;
    chainOfCustodySummary: string[];
  };
  structuredSections?: ForensicReportSection[];
}

export interface InvestigationCompletePayload {
  caseRecord: CaseRecord;
  evidence: EmailEvidence;
  headerAnalysis: HeaderAnalysis;
  iocs: IOC[];
  threatAssessment: ThreatAssessment;
  riskScore: RiskScore;
  geolocations: GeolocationResult[];
  originatingGeo?: GeolocationResult;
  domainIntelligence?: DomainNetworkIntelligence;
  campaignMatches: CampaignMatch[];
  mitreMappings: MitreTechniqueMapping[];
  attackTimeline: TimelineEvent[];
  graphData: InvestigationGraphData;
  investigationGraph?: InvestigationGraphData;
  evidenceBlock: EvidenceBlock;
  custodyEvents: CustodyEvent[];
}

export type EvidenceTag = 'OBSERVED EVIDENCE' | 'AI INFERENCE' | 'THREAT INTELLIGENCE' | 'DEMO/SIMULATED DATA';

export interface CopilotEvidenceReference {
  refId: string;
  label: string;
  targetSection: 'headers' | 'iocs' | 'risk' | 'campaign' | 'attachments' | 'body' | 'ledger' | 'timeline';
  targetId?: string;
  category: EvidenceTag;
  description: string;
}

export interface CopilotQueryResponse {
  conclusion: string;
  keyEvidence: string[];
  riskImpact: string;
  confidence: 'Low' | 'Medium' | 'High';
  limitations: string[];
  evidenceReferences: CopilotEvidenceReference[];
  queryTimestamp: string;
  modelUsed: string;
}

export interface CopilotQueryRequest {
  question: string;
  caseId?: string;
  payload?: InvestigationCompletePayload;
}

// ============================================================================
// BULK EMAIL FORENSIC TRIAGE & CAMPAIGN CORRELATION MODELS
// ============================================================================

export type MailType = 'PERSONAL' | 'COMPANY' | 'SPAM' | 'UNKNOWN';

export interface MailTypeClassification {
  mailType: MailType;
  mailTypeConfidence: number; // 0 - 100%
  mailTypeReasons: string[];
}

export interface BulkTriageItem {
  triageId: string;
  batchId: string;
  emailSubject: string;
  fromAddress: string;
  fromDomain: string;
  toAddresses: string[];
  date: string;
  rawSha256: string;
  sizeBytes: number;
  hasAttachments: boolean;
  attachmentNames: string[];
  rawSource?: string; // Optional cached raw MIME string
  
  // Independent Mail Type
  mailClassification: MailTypeClassification;

  // Existing Deterministic Risk Score
  riskScore: number; // 0 - 100
  riskLevel: RiskLevel; // 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  threatCategory: ThreatClassification;
  riskReasons: string[];

  // Infrastructure & Network
  originatingIp?: string;
  originatingAsn?: string;
  originatingCountry?: string;
  originatingCity?: string;
  extractedIps: string[];
  extractedDomains: string[];
  extractedUrls: string[];

  // Campaign Cluster Association
  campaignId?: string;
  campaignName?: string;
  campaignCode?: string;

  // Status
  isPromoted: boolean;
  promotedCaseId?: string;

  // Optional AI Deep Analysis
  aiDeepAnalysis?: {
    analyzedAt: string;
    model: string;
    assessment: ThreatAssessment;
  };
}

export interface BulkCampaignCluster {
  campaignId: string;
  campaignName: string;
  campaignCode: string;
  threatLevel: RiskLevel;
  totalEmails: number;
  sampleSubjects: string[];
  senderDomains: string[];
  originatingIps: string[];
  asns: string[];
  sharedIocs: string[];
  attackTechnique: string;
  clusterRationale: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface BulkTriageMetrics {
  totalEmails: number;
  mailTypes: {
    PERSONAL: number;
    COMPANY: number;
    SPAM: number;
    UNKNOWN: number;
  };
  riskLevels: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  campaignClustersCount: number;
  uniquePublicIpsCount: number;
  uniqueDomainsCount: number;
  promotedCount: number;
}

export interface BulkTriageSession {
  sessionId: string;
  createdAt: string;
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'CANCELLED' | 'ERROR';
  totalCount: number;
  processedCount: number;
  failedCount: number;
  progressPercent: number;
  isDemo: boolean;
  errorMessage?: string;
  metrics: BulkTriageMetrics;
}

export interface BulkIndicatorItem {
  indicator: string;
  type: IOCType;
  frequency: number;
  reputation?: IOCReputation;
  country?: string;
  asn?: string;
  associatedCampaigns: string[];
  sampleTriageIds: string[];
}

// =========================================================================
// GMAIL MONITORING & TRIAGE TYPES (PHASE 5)
// =========================================================================

export interface SafeGmailStatus {
  connected: boolean;
  gmailEmail?: string;
  connectedAt?: string;
}

export interface GmailMessageSummaryItem {
  id: string;
  threadId: string;
}

export interface GmailTriageRecord {
  gmailMessageId: string;
  userId: string;
  threadId?: string;
  sender: {
    raw: string;
    fromAddress: string;
    fromDomain: string;
    fromName?: string;
  };
  recipients: string[];
  subject: string;
  receivedAt?: string;
  mailClassification: {
    mailType: 'COMPANY' | 'PERSONAL' | 'SPAM' | 'UNKNOWN';
    confidence: number;
    reasons: string[];
  };
  threatClassification: string;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threatIndicators: {
    detected: Record<string, boolean>;
    reasons: string[];
    riskFactors: string[];
  };
  originatingIp?: string | null;
  extractedDomains: string[];
  extractedUrls: string[];
  attachments: Array<{
    filename: string;
    contentType: string;
    sizeBytes: number;
    sha256: string;
    isSuspicious: boolean;
    threatDetails?: string;
  }>;
  authStatus: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
  forensicSha256: string;
  forensicMd5: string;
  analyzedAt: string;
  triageStatus: 'SAFE' | 'SUSPICIOUS' | 'PHISHING_OR_MALICIOUS' | 'NEEDS_REVIEW';
  alreadyTriaged?: boolean;
}

export interface GmailRawMessagePayload {
  id: string;
  threadId: string;
  labelIds?: string[];
  sizeEstimate?: number;
  snippet?: string;
  rawEml: string;
  sha256: string;
  md5: string;
}

export type GmailSyncStatus = 'IDLE' | 'SYNCING' | 'TRIAGING' | 'COMPLETED' | 'FAILED';

export interface GmailSyncResult {
  success: boolean;
  status: GmailSyncStatus;
  isInitialSync: boolean;
  historyReset: boolean;
  historyId: string | null;
  messagesDiscovered: number;
  messagesTriaged: number;
  lastSyncStartedAt?: string;
  lastSyncCompletedAt?: string;
  error?: string;
  errorCode?: string;
}

export interface GmailSyncStatusState {
  userId: string;
  historyId: string | null;
  status: GmailSyncStatus;
  lastSyncStartedAt?: string;
  lastSyncCompletedAt?: string;
  lastError?: string | null;
  lastErrorCode?: string | null;
  messagesDiscovered: number;
  messagesTriaged: number;
  updatedAt: string;
  lastHistoryResetAt?: string | null;
}

export interface GmailPromotionResponse {
  success: boolean;
  caseId: string;
  caseNumber: string;
  alreadyPromoted: boolean;
  promotedAt: string;
  caseRecord: {
    caseId: string;
    caseNumber: string;
    title: string;
    severity: RiskLevel;
    priority: string;
    status: CaseStatus;
    riskScore: number;
    createdAt: string;
    analyst: string;
    ownerId: string;
    tags: string[];
  };
}

// =========================================================================
// GMAIL THREAT INTEL & CAMPAIGN CORRELATION TYPES (PHASE 7)
// =========================================================================

export interface GmailNormalizedIOC {
  id: string;
  type: IOCType;
  value: string;
  defangedValue: string;
  sourceMessageIds: string[];
  occurrenceCount: number;
  firstSeen: string;
  lastSeen: string;
  threatIntel?: {
    reputation: IOCReputation;
    reputationScore: number;
    source: string;
    enrichmentStatus: IOCEnrichmentStatus;
    relatedThreats?: string[];
    maliciousCategory?: string;
  };
}

export interface GmailCampaignSummary {
  campaignId: string;
  campaignName: string;
  campaignCode: string;
  threatLevel: RiskLevel;
  relatedMessageIds: string[];
  totalMessages: number;
  highestMessageRisk: number;
  campaignRiskScore: number;
  campaignRiskLevel: RiskLevel;
  threatCategory: string;
  sampleSubjects: string[];
  senderAddresses: string[];
  originatingIps: string[];
  sharedIocs: GmailNormalizedIOC[];
  correlationReasons: string[];
  threatIntelFindings: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface GmailCampaignDetailResponse {
  campaign: GmailCampaignSummary;
  messages: GmailTriageRecord[];
}

// =========================================================================
// SOC DASHBOARD & ANALYST OPERATIONS TYPES (PHASE 8)
// =========================================================================

export interface SocDashboardSummaryMetrics {
  totalMonitoredMessages: number;
  totalTriagedMessages: number;
  totalThreats: number;
  criticalThreats: number;
  highThreats: number;
  mediumThreats: number;
  lowThreats: number;
  activeCampaigns: number;
  totalIocs: number;
  promotedCases: number;
}

export interface SocRiskDistributionItem {
  level: RiskLevel;
  count: number;
}

export interface SocThreatCategoryItem {
  category: string;
  count: number;
}

export interface SocTopCampaignItem {
  campaignId: string;
  campaignName?: string;
  riskScore: number;
  riskLevel: RiskLevel;
  messageCount: number;
  category: string;
  findings: string[];
  reasons: string[];
}

export interface SocRecentThreatItem {
  gmailMessageId: string;
  subject: string;
  sender: string;
  riskScore: number;
  riskLevel: RiskLevel;
  classification: string;
  campaignId: string | null;
  analyzedAt: string;
}

export interface SocDashboardSummaryResponse {
  summary: SocDashboardSummaryMetrics;
  riskDistribution: SocRiskDistributionItem[];
  threatCategories: SocThreatCategoryItem[];
  topCampaigns: SocTopCampaignItem[];
  recentThreats: SocRecentThreatItem[];
  generatedAt: string;
}

// ── Real-Time Threat Alerts (Phase 11) ──────────────────────────────────────
export interface AlertEvent {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  caseId?: string;
  threatType?: string;
  source: 'GMAIL_SYNC' | 'BULK_TRIAGE' | 'CASE_PIPELINE' | 'SYSTEM';
}

// ── Threat Hunting Query Engine (Phase 12) ──────────────────────────────────
export interface HuntQuery {
  q?: string;
  iocType?: IOCType;
  riskLevels?: RiskLevel[];
  threatTypes?: ThreatClassification[];
  fromDate?: string;
  toDate?: string;
  minRiskScore?: number;
  maxRiskScore?: number;
  limit?: number;
}

export interface IOCHit {
  value: string;
  defangedValue: string;
  type: IOCType;
  reputation: IOCReputation;
  caseCount: number;
  caseIds: string[];
}

export interface CampaignLink {
  campaignId: string;
  name: string;
  threatCategory: string;
  caseCount: number;
  caseIds: string[];
  riskScore: number;
}

export interface HuntResult {
  query: HuntQuery;
  cases: CaseRecord[];
  iocHits: IOCHit[];
  campaignLinks: CampaignLink[];
  totalMatches: number;
  durationMs: number;
}



