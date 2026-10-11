import {
  AnalystNote,
  CaseHistoryItem,
  CasePriority,
  CaseRecord,
  CaseStatus,
  ForensicReportData,
  ForensicReportSection,
  InvestigationCompletePayload,
} from '../../src/types/forensics';
import { analyzeEmailWithAI } from '../ai/geminiAnalyzer';
import { evidenceLedger } from '../blockchain/evidenceLedger';
import { ALL_DEMO_CASES } from '../demo/demoCases';
import { analyzeHeaders } from '../forensics/authChecker';
import { correlateCampaignDNA } from '../forensics/campaignEngine';
import { buildInvestigationGraph } from '../forensics/graphEngine';
import { mapMitreAttackTechniques } from '../forensics/mitreAttackEngine';
import { calculateSha256, parseRawEmail } from '../forensics/parser';
import { calculateExplainableRiskScore } from '../forensics/riskEngine';
import { buildAttackTimeline } from '../forensics/timelineBuilder';
import { enrichAllIps, enrichAllIpsAsync } from '../intelligence/enrichment';
import { ipGeolocationService } from '../geolocation/ipGeolocationService';
import { threatIntelService } from '../intelligence/threatIntelService';

class CaseService {
  private cases: Map<string, CaseRecord> = new Map();
  private payloads: Map<string, InvestigationCompletePayload> = new Map();
  private initialized = false;

  public async initialize() {
    if (this.initialized) return;
    this.initialized = true;

    // Seed the 3 demonstration cases
    for (const demo of ALL_DEMO_CASES) {
      const status: CaseStatus =
        demo.caseId === 'CASE-2026-001'
          ? 'RESOLVED'
          : demo.caseId === 'CASE-2026-002'
          ? 'ESCALATED'
          : 'IN_PROGRESS';

      const priority: CasePriority =
        demo.caseId === 'CASE-2026-003'
          ? 'CRITICAL'
          : demo.caseId === 'CASE-2026-002'
          ? 'HIGH'
          : 'LOW';

      await this.processEmail(demo.rawEmail, {
        caseId: demo.caseId,
        caseNumber: demo.caseNumber,
        title: demo.title,
        analyst: demo.analyst,
        customStatus: status,
        customPriority: priority,
        isPublicDemo: true,
        ownerId: 'usr-analyst-01',
        ownerEmail: 'analyst@soc.internal',
        authorizedUsers: ['usr-analyst-01', 'usr-analyst-02', 'usr-admin-01'],
        tags:
          demo.caseId === 'CASE-2026-003'
            ? ['AiTM', 'Credential Harvesting', 'M365', 'Tor-Relay']
            : demo.caseId === 'CASE-2026-002'
            ? ['BEC', 'Wire Diversion', 'Executive Impersonation']
            : ['Internal', 'Authorized Relay', 'Benign'],
      });
    }
  }

  public async processEmail(
    rawEmail: string,
    options?: {
      caseId?: string;
      caseNumber?: string;
      title?: string;
      analyst?: string;
      customStatus?: CaseStatus;
      customPriority?: CasePriority;
      tags?: string[];
      assignedTo?: string;
      ownerId?: string;
      ownerEmail?: string;
      isPublicDemo?: boolean;
      authorizedUsers?: string[];
    }
  ): Promise<InvestigationCompletePayload> {
    const caseId = options?.caseId || `CASE-2026-${String(this.cases.size + 1).padStart(3, '0')}`;
    const caseNumber = options?.caseNumber || caseId;
    const analyst = options?.analyst || 'SOC Analyst';

    // 1. Parse Email
    const evidence = parseRawEmail(rawEmail, caseId);

    // 2. Header Forensics
    const headerAnalysis = analyzeHeaders(evidence.headers.receivedHeaders, {
      from: evidence.headers.from,
      fromAddress: evidence.headers.fromAddress,
      fromDomain: evidence.headers.fromDomain,
      fromName: evidence.headers.fromName,
      replyTo: evidence.headers.replyTo,
      returnPath: evidence.headers.returnPath,
      messageId: evidence.headers.messageId,
      date: evidence.headers.date,
      rawSource: rawEmail,
    });

    // 3. IOC Extraction & Threat Intelligence Enrichment (Provider Abstraction)
    const receivedHopsIps = headerAnalysis.receivedHops.map(h => h.ip).filter(Boolean) as string[];
    const iocs = await threatIntelService.extractAndEnrichAll({
      urls: evidence.extractedUrls,
      ips: evidence.extractedIps,
      domains: evidence.extractedDomains,
      senderEmail: evidence.headers.fromAddress,
      senderDomain: evidence.headers.fromDomain,
      replyTo: evidence.headers.replyTo,
      attachments: evidence.attachments,
      bodyText: evidence.body.text,
      receivedHopsIps,
    });

    // 4. Geolocation and Infrastructure Enrichment
    const geolocations = await enrichAllIpsAsync(evidence.extractedIps, headerAnalysis.originatingIp);

    // 5. AI Threat Detection (Gemini 3.8 Flash or deterministic heuristic)
    const threatAssessment = await analyzeEmailWithAI({
      subject: evidence.headers.subject,
      from: evidence.headers.from,
      fromDomain: evidence.headers.fromDomain,
      to: evidence.headers.to,
      replyTo: evidence.headers.replyTo,
      returnPath: evidence.headers.returnPath,
      bodyText: evidence.body.text,
      urls: evidence.extractedUrls,
      ips: evidence.extractedIps,
      domains: evidence.extractedDomains,
      attachments: evidence.attachments,
      authStatus: {
        spf: headerAnalysis.spf.status,
        dkim: headerAnalysis.dkim.status,
        dmarc: headerAnalysis.dmarc.status,
      },
      inconsistencies: headerAnalysis.inconsistencies,
    }, { isDemo: options?.isPublicDemo });

    // 6. Explainable Risk Score
    const riskScore = calculateExplainableRiskScore({
      threatAssessment,
      headerAnalysis,
      iocs,
      geolocations,
      attachments: evidence.attachments,
      bodyText: evidence.body.text,
    });

    // 7. MITRE ATT&CK Mapping (Evidence-Grounded)
    const mitreMappings = mapMitreAttackTechniques({
      headerAnalysis,
      iocs,
      attachments: evidence.attachments,
      bodyText: evidence.body.text,
      extractedUrls: evidence.extractedUrls,
      senderFrom: evidence.headers.fromAddress,
      senderDomain: evidence.headers.fromDomain,
      replyTo: evidence.headers.replyTo,
    });

    // 8. Campaign DNA Correlation
    const existingCases = this.getAllCases();
    const campaignMatches = correlateCampaignDNA({
      subject: evidence.headers.subject,
      fromDomain: evidence.headers.fromDomain,
      fromAddress: evidence.headers.fromAddress,
      replyTo: evidence.headers.replyTo,
      ips: evidence.extractedIps,
      domains: evidence.extractedDomains,
      urls: evidence.extractedUrls,
      hashes: evidence.attachments.map(a => a.sha256).filter(Boolean),
      headerAnalysis,
      iocs,
      otherCases: existingCases,
    });

    // 9. Seal Evidence Block in Blockchain Hash-Chain
    const analysisHash = calculateSha256(
      JSON.stringify({
        threatAssessmentClassification: threatAssessment.classification,
        riskScoreTotal: riskScore.totalScore,
        headerAnalysisConfidence: headerAnalysis.originConfidence,
        iocsCount: iocs.length,
        mitreCount: mitreMappings.length,
      })
    );

    const evidenceBlock = evidenceLedger.appendEvidence({
      evidenceId: evidence.id,
      caseId,
      emailSha256: evidence.sha256,
      analysisSha256: analysisHash,
      investigator: analyst,
      action: 'EVIDENCE_INGESTION_AND_CRYPTOGRAPHIC_SEALING',
    });

    // 10. Attack Timeline Narrative
    const attackTimeline = buildAttackTimeline({
      evidence,
      headerAnalysis,
      iocs,
      threatAssessment,
      riskScore,
      geolocations,
      campaignMatches,
      evidenceBlock,
    });

    // 11. Investigation Relationship Graph
    const graphData = buildInvestigationGraph({
      caseId,
      emailSubject: evidence.headers.subject,
      senderAddress: evidence.headers.fromAddress,
      fromDomain: evidence.headers.fromDomain,
      replyTo: evidence.headers.replyTo,
      rawSha256: evidence.sha256,
      iocs,
      geolocations,
      campaignMatches,
      mitreMappings,
      overallRisk: riskScore.level,
    });

    // 12. Determine Priority & Status
    const defaultPriority: CasePriority =
      options?.customPriority ||
      (riskScore.level === 'CRITICAL'
        ? 'CRITICAL'
        : riskScore.level === 'HIGH'
        ? 'HIGH'
        : riskScore.level === 'MEDIUM'
        ? 'MEDIUM'
        : 'LOW');

    const defaultStatus: CaseStatus =
      options?.customStatus ||
      (riskScore.level === 'LOW'
        ? 'RESOLVED'
        : riskScore.level === 'CRITICAL'
        ? 'ESCALATED'
        : 'OPEN');

    const initialHistoryItem: CaseHistoryItem = {
      id: `HIST-${Date.now().toString(36)}-1`,
      timestamp: evidence.ingestedAt,
      actor: analyst,
      action: 'CASE_CREATED',
      details: `Case registered and ingested into forensic custody with initial risk score ${riskScore.totalScore}/100 (${riskScore.level}).`,
      newValue: defaultStatus,
    };

    // 13. Store Case Record
    const caseRecord: CaseRecord = {
      caseId,
      caseNumber,
      title: options?.title || evidence.headers.subject,
      severity: riskScore.level,
      priority: defaultPriority,
      classification: threatAssessment.classification,
      status: defaultStatus,
      createdAt: evidence.ingestedAt,
      updatedAt: new Date().toISOString(),
      analyst,
      assignedTo: options?.assignedTo || analyst,
      ownerId: options?.ownerId || 'usr-analyst-01',
      ownerEmail: options?.ownerEmail || 'analyst@soc.internal',
      isPublicDemo: options?.isPublicDemo ?? false,
      authorizedUsers: options?.authorizedUsers || (options?.ownerId ? [options.ownerId] : ['usr-analyst-01']),
      tags: options?.tags || [threatAssessment.classification, riskScore.level],
      notes: [
        {
          id: `NOTE-${Date.now().toString(36)}-1`,
          author: analyst,
          timestamp: evidence.ingestedAt,
          content: `Automated forensic triage completed. Cryptographic hash-chain evidence sealed at block #${evidenceBlock.blockIndex}.`,
        },
      ],
      history: [initialHistoryItem],
      relatedCampaign: campaignMatches[0]?.campaignCode,
      evidenceCount: 1 + evidence.attachments.length,
      riskScore: riskScore.totalScore,
      emailSubject: evidence.headers.subject,
      fromAddress: evidence.headers.fromAddress,
      originatingGeo: geolocations.find(g => g.isOriginating) || geolocations[0],
      geolocations,
    };

    const originatingGeo = geolocations.find(g => g.isOriginating) || geolocations[0];

    const payload: InvestigationCompletePayload = {
      caseRecord,
      evidence,
      headerAnalysis,
      iocs,
      threatAssessment,
      riskScore,
      geolocations,
      originatingGeo,
      campaignMatches,
      mitreMappings,
      attackTimeline,
      graphData,
      evidenceBlock,
      custodyEvents: evidence.custodyEvents,
    };

    // Domain Network Intelligence
    const associatedGeos = geolocations.filter(g => g.geolocatable);
    const domainLocations = Array.from(
      new Set(associatedGeos.map(g => `${g.region ? g.region + ', ' : ''}${g.country || ''}`).filter(Boolean))
    );
    payload.domainIntelligence = {
      domain: evidence.headers.fromDomain || 'unknown.domain',
      observedIps: geolocations.map(g => g.ip),
      associatedGeos,
      asnList: Array.from(new Set(associatedGeos.map(g => g.asn).filter(Boolean) as string[])),
      organizations: Array.from(new Set(associatedGeos.map(g => g.organization || g.isp).filter(Boolean) as string[])),
      anonymizerStatus: {
        hasVpn: geolocations.some(g => g.isVpn || g.vpnTorProxy?.isVpn),
        hasTor: geolocations.some(g => g.isTor || g.vpnTorProxy?.isTor),
        hasProxy: geolocations.some(g => g.isProxy || g.vpnTorProxy?.isProxy),
        hasHosting: geolocations.some(g => g.isHosting || g.vpnTorProxy?.isDatacenter),
      },
      confidence: originatingGeo ? originatingGeo.confidence : 50,
      summary:
        domainLocations.length > 0
          ? `Observed infrastructure associated with domain '${evidence.headers.fromDomain}' includes IPs geolocated approximately to ${domainLocations.join('; ')}.`
          : `No external routable infrastructure observed for domain '${evidence.headers.fromDomain}'.`,
    };

    this.cases.set(caseId, caseRecord);
    this.payloads.set(caseId, payload);

    return payload;
  }

  public getAllCases(): CaseRecord[] {
    return Array.from(this.cases.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  /**
   * Evaluates if an authenticated user has permission to access a specific case
   * - ADMIN: Oversight on all cases
   * - Public Demo: Allowed for all authenticated users
   * - Owner / Collaborator: Allowed for the specific analyst
   */
  public canUserAccessCase(
    user: { id?: string; userId?: string; role: string; email?: string },
    caseId: string
  ): { allowed: boolean; reason?: string; caseFound: boolean } {
    const c = this.cases.get(caseId);
    if (!c) {
      return { allowed: false, caseFound: false, reason: 'Case not found' };
    }

    if (user.role === 'ADMIN' || user.role === 'AUDITOR') {
      return { allowed: true, caseFound: true };
    }

    if (c.isPublicDemo) {
      return { allowed: true, caseFound: true };
    }

    const currentUserId = user.userId || user.id;
    if (currentUserId && c.ownerId && c.ownerId === currentUserId) {
      return { allowed: true, caseFound: true };
    }

    if (user.email && c.ownerEmail && c.ownerEmail.toLowerCase() === user.email.toLowerCase()) {
      return { allowed: true, caseFound: true };
    }

    if (currentUserId && c.authorizedUsers && c.authorizedUsers.includes(currentUserId)) {
      return { allowed: true, caseFound: true };
    }

    return {
      allowed: false,
      caseFound: true,
      reason: 'Forbidden: You do not have permission to access this case',
    };
  }

  /**
   * Evaluates if an authenticated user has permission to mutate a specific case (status, priority, assignment, notes).
   * - AUDITOR: Strictly read-only; mutations are forbidden.
   * - ADMIN: Oversight on all cases.
   * - Owner / Collaborator: Permitted for their authorized cases.
   */
  public canUserMutateCase(
    user: { id?: string; userId?: string; role: string; email?: string },
    caseId: string
  ): { allowed: boolean; reason?: string; caseFound: boolean } {
    const c = this.cases.get(caseId);
    if (!c) {
      return { allowed: false, caseFound: false, reason: 'Case not found' };
    }

    if (user.role === 'AUDITOR') {
      return {
        allowed: false,
        caseFound: true,
        reason: 'Forbidden: Auditor role is strictly read-only',
      };
    }

    return this.canUserAccessCase(user, caseId);
  }

  /**
   * Retrieves case list scoped strictly to what the user is authorized to see
   */
  public getCasesForUser(user: { id?: string; userId?: string; role: string; email?: string }): CaseRecord[] {
    const allCases = this.getAllCases();
    if (user.role === 'ADMIN' || user.role === 'AUDITOR') {
      return allCases;
    }

    const currentUserId = user.userId || user.id;
    return allCases.filter(c => {
      if (c.isPublicDemo) return true;
      if (currentUserId && c.ownerId === currentUserId) return true;
      if (user.email && c.ownerEmail && c.ownerEmail.toLowerCase() === user.email.toLowerCase()) return true;
      if (currentUserId && c.authorizedUsers && c.authorizedUsers.includes(currentUserId)) return true;
      return false;
    });
  }

  /**
   * Retrieves full investigation payload with access authorization enforcement
   */
  public getCasePayloadForUser(
    user: { id?: string; userId?: string; role: string; email?: string },
    caseId: string
  ): { status: 'NOT_FOUND' | 'FORBIDDEN' | 'ALLOWED'; payload?: InvestigationCompletePayload } {
    const access = this.canUserAccessCase(user, caseId);
    if (!access.caseFound) {
      return { status: 'NOT_FOUND' };
    }
    if (!access.allowed) {
      return { status: 'FORBIDDEN' };
    }

    const payload = this.payloads.get(caseId);
    if (!payload) {
      return { status: 'NOT_FOUND' };
    }
    return { status: 'ALLOWED', payload };
  }

  public getCasePayload(caseId: string): InvestigationCompletePayload | undefined {
    return this.payloads.get(caseId);
  }

  public getCaseById(caseId: string): InvestigationCompletePayload | undefined {
    return this.payloads.get(caseId);
  }

  public updateCaseStatus(caseId: string, status: CaseStatus, actor = 'Analyst'): boolean {
    const c = this.cases.get(caseId);
    if (!c) return false;
    const prevStatus = c.status;
    c.status = status;
    c.updatedAt = new Date().toISOString();
    c.lastUpdatedBy = actor;

    const historyItem: CaseHistoryItem = {
      id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: c.updatedAt,
      actor,
      action: 'STATUS_CHANGED',
      details: `Case status changed from ${prevStatus} to ${status}.`,
      previousValue: prevStatus,
      newValue: status,
    };
    c.history = c.history || [];
    c.history.push(historyItem);

    const p = this.payloads.get(caseId);
    if (p) {
      p.caseRecord.status = status;
      p.caseRecord.updatedAt = c.updatedAt;
      p.caseRecord.lastUpdatedBy = actor;
      p.caseRecord.history = c.history;
    }
    return true;
  }

  public updateCasePriority(caseId: string, priority: CasePriority, actor = 'Analyst'): CaseRecord | null {
    const c = this.cases.get(caseId);
    if (!c) return null;

    const prevPriority = c.priority || (c.severity as any) || 'MEDIUM';
    const now = new Date().toISOString();

    if (priority !== prevPriority) {
      c.history = c.history || [];
      c.history.push({
        id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        actor,
        action: 'PRIORITY_CHANGED',
        details: `Case operational priority changed from ${prevPriority} to ${priority}.`,
        previousValue: prevPriority,
        newValue: priority,
      });
      c.priority = priority;
    }

    c.updatedAt = now;
    c.lastUpdatedBy = actor;

    const p = this.payloads.get(caseId);
    if (p) {
      p.caseRecord = { ...c };
    }

    return c;
  }

  public updateCaseAssignment(
    caseId: string,
    assignment: {
      assignedTo: string;
      assignedAnalystId?: string;
      assignedAnalystName?: string;
      actor?: string;
    }
  ): CaseRecord | null {
    const c = this.cases.get(caseId);
    if (!c) return null;

    const actor = assignment.actor || 'Analyst';
    const prevAssigned = c.assignedTo || c.analyst;
    const now = new Date().toISOString();

    c.history = c.history || [];
    c.history.push({
      id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: now,
      actor,
      action: 'ASSIGNMENT_CHANGED',
      details: `Case reassigned from ${prevAssigned} to ${assignment.assignedTo}.`,
      previousValue: prevAssigned,
      newValue: assignment.assignedTo,
    });

    c.assignedTo = assignment.assignedTo;
    if (assignment.assignedAnalystId) {
      c.assignedAnalystId = assignment.assignedAnalystId;
      c.authorizedUsers = c.authorizedUsers || [];
      if (!c.authorizedUsers.includes(assignment.assignedAnalystId)) {
        c.authorizedUsers.push(assignment.assignedAnalystId);
      }
    }
    if (assignment.assignedAnalystName) {
      c.assignedAnalystName = assignment.assignedAnalystName;
    }
    c.updatedAt = now;
    c.lastUpdatedBy = actor;

    const p = this.payloads.get(caseId);
    if (p) {
      p.caseRecord = { ...c };
    }

    return c;
  }

  public getCaseRecord(caseId: string): CaseRecord | null {
    const c = this.cases.get(caseId);
    return c ? { ...c } : null;
  }

  public getCaseHistory(caseId: string): CaseHistoryItem[] | null {
    const c = this.cases.get(caseId);
    return c ? [...(c.history || [])] : null;
  }

  public updateCaseManagement(
    caseId: string,
    update: {
      status?: CaseStatus;
      priority?: CasePriority;
      assignedTo?: string;
      tags?: string[];
      newNote?: string;
      actor?: string;
    }
  ): CaseRecord | null {
    const c = this.cases.get(caseId);
    if (!c) return null;

    const actor = update.actor || c.analyst;
    const now = new Date().toISOString();

    if (update.status && update.status !== c.status) {
      const prevStatus = c.status;
      c.status = update.status;
      c.history.push({
        id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        actor,
        action: 'STATUS_CHANGED',
        details: `Case status changed from ${prevStatus} to ${update.status}.`,
        previousValue: prevStatus,
        newValue: update.status,
      });
    }

    if (update.priority && update.priority !== c.priority) {
      c.history.push({
        id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        actor,
        action: 'PRIORITY_CHANGED',
        details: `Case priority changed from ${c.priority} to ${update.priority}.`,
        previousValue: c.priority,
        newValue: update.priority,
      });
      c.priority = update.priority;
    }

    if (update.assignedTo && update.assignedTo !== c.assignedTo) {
      c.history.push({
        id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        actor,
        action: 'ASSIGNMENT_CHANGED',
        details: `Case reassigned to ${update.assignedTo}.`,
        previousValue: c.assignedTo,
        newValue: update.assignedTo,
      });
      c.assignedTo = update.assignedTo;
    }

    if (update.tags) {
      c.tags = update.tags;
      c.history.push({
        id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        actor,
        action: 'TAGS_UPDATED',
        details: `Tags updated: ${update.tags.join(', ')}`,
      });
    }

    if (update.newNote && update.newNote.trim()) {
      const noteContent = update.newNote.trim().slice(0, 5000);
      const note: AnalystNote = {
        id: `NOTE-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        author: actor,
        timestamp: now,
        content: noteContent,
      };
      c.notes = c.notes || [];
      c.notes.push(note);
      c.history.push({
        id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        actor,
        action: 'NOTE_ADDED',
        details: `Analyst note appended by ${actor}.`,
      });
    }

    c.updatedAt = now;
    c.lastUpdatedBy = actor;

    const p = this.payloads.get(caseId);
    if (p) {
      p.caseRecord = { ...c };
    }

    return c;
  }

  public addAnalystNote(caseId: string, author: string, content: string): AnalystNote | null {
    const c = this.cases.get(caseId);
    if (!c) return null;

    const sanitized = (content || '').trim().slice(0, 5000);
    if (!sanitized) return null;

    const now = new Date().toISOString();
    const note: AnalystNote = {
      id: `NOTE-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      author,
      timestamp: now,
      content: sanitized,
    };

    c.notes = c.notes || [];
    c.notes.push(note);
    c.updatedAt = now;
    c.lastUpdatedBy = author;

    c.history = c.history || [];
    c.history.push({
      id: `HIST-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: now,
      actor: author,
      action: 'NOTE_ADDED',
      details: `Analyst note appended: "${sanitized.substring(0, 50)}${sanitized.length > 50 ? '...' : ''}"`,
    });

    const p = this.payloads.get(caseId);
    if (p) {
      p.caseRecord = { ...c };
    }

    return note;
  }

  /**
   * Generates a professional 18-section forensic examination report.
   * Strictly adheres to anti-hallucination standards:
   * Insufficient evidence notice provided whenever data does not exist.
   * AI conclusions clearly demarcated.
   */
  public generateReport(caseId: string): ForensicReportData | null {
    const p = this.payloads.get(caseId);
    if (!p) return null;

    const ledgerStatus = evidenceLedger.verifyIntegrity();
    const INSUFFICIENT_EVIDENCE = 'Insufficient evidence available to answer this question.';

    // Construct the 18 specific forensic sections
    const structuredSections: ForensicReportSection[] = [
      // 1. Case Information
      {
        sectionNumber: 1,
        title: 'Case Information',
        content: `Case Number: ${p.caseRecord.caseNumber}\nCase ID: ${p.caseRecord.caseId}\nStatus: ${p.caseRecord.status}\nPriority: ${p.caseRecord.priority}\nAssigned Analyst: ${p.caseRecord.assignedTo}\nClassification: ${p.caseRecord.classification}\nCreated At: ${p.caseRecord.createdAt}\nUpdated At: ${p.caseRecord.updatedAt}`,
        details: {
          caseNumber: p.caseRecord.caseNumber,
          status: p.caseRecord.status,
          priority: p.caseRecord.priority,
          analyst: p.caseRecord.assignedTo,
          tags: p.caseRecord.tags,
        },
        isAiGenerated: false,
      },
      // 2. Executive Summary
      {
        sectionNumber: 2,
        title: 'Executive Summary',
        content: p.threatAssessment.executiveSummary || `Investigation of incoming message "${p.evidence.headers.subject}" completed. Deterministic risk assessment evaluates overall threat at ${p.riskScore.totalScore}/100 (${p.riskScore.level}). Evidence has been preserved under tamper-evident blockchain hash-chain verification.`,
        isAiGenerated: false,
      },
      // 3. Deterministic Risk Score
      {
        sectionNumber: 3,
        title: 'Deterministic Risk Score',
        content: `Deterministic Score: ${p.riskScore.totalScore} / 100\nThreat Level: ${p.riskScore.level}\nUrgency: ${p.threatAssessment.urgencyLevel}\nMathematical Formulation: Weighted composite of 6 independent forensic vectors.`,
        details: {
          totalScore: p.riskScore.totalScore,
          level: p.riskScore.level,
        },
        isAiGenerated: false,
      },
      // 4. Risk Factor Breakdown
      {
        sectionNumber: 4,
        title: 'Risk Factor Breakdown',
        content: (Array.isArray(p.riskScore.components)
          ? p.riskScore.components
          : Object.entries(p.riskScore.components || {}).map(([key, c]: [string, any]) => ({
              name: c.name || key,
              weight: c.weightPercent || c.weight || 0,
              weightedScore: c.weightedScore || 0,
              rawScore: c.rawScore || 0,
              description: c.calculation || (Array.isArray(c.evidence) ? c.evidence.join('; ') : ''),
            }))
        )
          .map(
            (c: any) =>
              `• ${c.name} (Weight ${c.weight}%): Contributed ${c.weightedScore} pts (Raw: ${c.rawScore}/100) — ${c.description}`
          )
          .join('\n'),
        details: { components: p.riskScore.components },
        isAiGenerated: false,
      },
      // 5. Email Metadata
      {
        sectionNumber: 5,
        title: 'Email Metadata',
        content: `Subject: ${p.evidence.headers.subject || INSUFFICIENT_EVIDENCE}\nFrom: ${p.evidence.headers.from || INSUFFICIENT_EVIDENCE}\nFrom Address: ${p.evidence.headers.fromAddress || INSUFFICIENT_EVIDENCE}\nFrom Domain: ${p.evidence.headers.fromDomain || INSUFFICIENT_EVIDENCE}\nTo: ${p.evidence.headers.to || INSUFFICIENT_EVIDENCE}\nDate: ${p.evidence.headers.date || INSUFFICIENT_EVIDENCE}\nMessage-ID: ${p.evidence.headers.messageId || INSUFFICIENT_EVIDENCE}\nReturn-Path: ${p.evidence.headers.returnPath || INSUFFICIENT_EVIDENCE}\nReply-To: ${p.evidence.headers.replyTo || 'None specified in headers'}`,
        isAiGenerated: false,
      },
      // 6. Header Analysis
      {
        sectionNumber: 6,
        title: 'Header Analysis',
        content: `Transit Hop Count: ${p.headerAnalysis.receivedHops.length}\nOriginating IP: ${p.headerAnalysis.originatingIp || INSUFFICIENT_EVIDENCE}\nOrigin Confidence: ${p.headerAnalysis.originConfidence}%\nInconsistencies:\n• Display Spoofing: ${p.headerAnalysis.inconsistencies.displaySpoofing ? 'DETECTED' : 'None'}\n• Reply-To Mismatch: ${p.headerAnalysis.inconsistencies.replyToMismatch ? 'DETECTED' : 'None'}\n• Return-Path Mismatch: ${p.headerAnalysis.inconsistencies.returnPathMismatch ? 'DETECTED' : 'None'}\n• Homograph/Punycode: ${p.headerAnalysis.inconsistencies.punycodeHomograph ? 'DETECTED' : 'None'}`,
        details: p.headerAnalysis.inconsistencies,
        isAiGenerated: false,
      },
      // 7. Authentication Results
      {
        sectionNumber: 7,
        title: 'Authentication Results',
        content: `SPF Status: ${p.headerAnalysis.spf.status} (${p.headerAnalysis.spf.details})\nDKIM Status: ${p.headerAnalysis.dkim.status} (${p.headerAnalysis.dkim.details})\nDMARC Status: ${p.headerAnalysis.dmarc.status} (${p.headerAnalysis.dmarc.details})\nDisposition: ${p.headerAnalysis.dmarc.disposition || 'None'}`,
        details: {
          spf: p.headerAnalysis.spf,
          dkim: p.headerAnalysis.dkim,
          dmarc: p.headerAnalysis.dmarc,
        },
        isAiGenerated: false,
      },
      // 8. Transit/Received Chain
      {
        sectionNumber: 8,
        title: 'Transit / Received Chain',
        content: p.headerAnalysis.receivedHops.length > 0
          ? p.headerAnalysis.receivedHops
              .map(
                (h, idx) =>
                  `[Hop #${h.hopNumber}] By: ${h.byHost || 'Unknown'} | From: ${h.fromHost || 'Unknown'} | IP: ${h.ip || 'Unknown'} | Time: ${h.timestamp || 'Unknown'}`
              )
              .join('\n')
          : INSUFFICIENT_EVIDENCE,
        isAiGenerated: false,
      },
      // 9. IOC Findings
      {
        sectionNumber: 9,
        title: 'IOC Findings',
        content: p.iocs.length > 0
          ? p.iocs
              .map(
                i =>
                  `• [${i.type.toUpperCase()}] ${i.value} | Status: ${i.reputation} | Source: ${i.source} | Confidence: ${i.confidence}%`
              )
              .join('\n')
          : 'No suspicious IOCs identified in message.',
        details: { iocsCount: p.iocs.length },
        isAiGenerated: false,
      },
      // 10. Threat Intelligence
      {
        sectionNumber: 10,
        title: 'Threat Intelligence',
        content: p.iocs.some(i => i.enrichmentStatus === 'ENRICHED')
          ? p.iocs
              .filter(i => i.enrichmentStatus === 'ENRICHED')
              .map(
                i =>
                  `• ${i.value} (${i.type}): ${i.source} reports ${i.reputation}. Related threats: ${i.relatedThreats?.join(', ') || 'None'}`
              )
              .join('\n')
          : 'THREAT INTELLIGENCE UNAVAILABLE — No external intelligence feeds responded or indicator was not indexed in threat registries.',
        isAiGenerated: false,
      },
      // 11. MITRE ATT&CK Mappings
      {
        sectionNumber: 11,
        title: 'MITRE ATT&CK Mappings',
        content: p.mitreMappings.length > 0
          ? p.mitreMappings
              .map(
                m =>
                  `• [${m.techniqueId}] ${m.techniqueName} (${m.tactic})\n  - Evidence: ${m.supportingEvidence.join('; ')}\n  - Confidence: ${m.confidence}\n  - References: ${m.evidenceReferences.join(', ')}`
              )
              .join('\n\n')
          : 'No MITRE ATT&CK techniques justified by current forensic evidence.',
        details: { techniques: p.mitreMappings },
        isAiGenerated: false,
      },
      // 12. Campaign Correlation
      {
        sectionNumber: 12,
        title: 'Campaign Correlation',
        content: p.campaignMatches.length > 0
          ? p.campaignMatches
              .map(
                c =>
                  `Campaign: ${c.name} (${c.campaignCode})\nThreat Group: ${c.threatActorGroup}\nSimilarity Score: ${c.similarityScore}%\nConfidence: ${c.confidence}\nObserved Correlation:\n${c.observedCorrelation.map(o => `  • ${o}`).join('\n') || '  • None'}\nAI Inference:\n${c.aiInference.map(a => `  • ${a}`).join('\n') || '  • None'}\nAttribution Notice: ${c.attributionNotice}`
              )
              .join('\n\n')
          : 'No correlating threat campaign cluster identified in threat intelligence baseline.',
        isAiGenerated: false,
      },
      // 13. Investigation Timeline
      {
        sectionNumber: 13,
        title: 'Investigation Timeline',
        content: p.attackTimeline
          .map(
            t =>
              `[Step ${t.stepNumber}] ${t.timestamp} (${t.timeDelta}): ${t.title} [${t.phase}] — ${t.description}`
          )
          .join('\n'),
        isAiGenerated: false,
      },
      // 14. Evidence References
      {
        sectionNumber: 14,
        title: 'Evidence References',
        content: `1. Header: RFC-5322 From (${p.evidence.headers.from})\n2. Header: Received trace hops (${p.headerAnalysis.receivedHops.length} hops)\n3. Body: Raw MIME plain text and HTML containers (${p.evidence.body.text.length} chars)\n4. Attachments: ${p.evidence.attachments.length} attachment file(s)\n5. Ledger Block: Index #${p.evidenceBlock.blockIndex} (Hash: ${p.evidenceBlock.blockHash.substring(0, 16)}...)`,
        isAiGenerated: false,
      },
      // 15. AI Investigation Conclusion (Clearly Labeled)
      {
        sectionNumber: 15,
        title: 'AI Investigation Conclusion',
        content: `[AI-GENERATED INFERENCE — NOT LEGAL PROOF]\nModel: ${p.threatAssessment.modelUsed}\nConclusion: ${p.threatAssessment.attributionAssessment}\n\nKey Inferred Indicators:\n• Urgency Level: ${p.threatAssessment.urgencyLevel}\n• Classification: ${p.threatAssessment.classification}\n• Confidence: ${p.threatAssessment.confidence}%\n\nNote: All AI conclusions are probabilistic inferences and must be cross-verified with deterministic cryptographic evidence.`,
        isAiGenerated: true,
      },
      // 16. Limitations
      {
        sectionNumber: 16,
        title: 'Limitations',
        content: `1. Geolocation reflects network routing, intermediate MTA hops, or VPN relays, not the verified physical coordinate of the human operator.\n2. Threat intelligence feeds provide historical observation telemetry and may exhibit latency relative to newly registered zero-day domains.\n3. AI reasoning serves as an analyst copilot and does not substitute for forensic confirmation.`,
        isAiGenerated: false,
      },
      // 17. SHA-256 Evidence Integrity
      {
        sectionNumber: 17,
        title: 'SHA-256 Evidence Integrity',
        content: `Raw Email MIME SHA-256: ${p.evidence.sha256}\nLegacy MD5 Reference: ${p.evidence.md5}\nAnalysis State SHA-256: ${p.evidenceBlock.analysisSha256}\nCryptographic Sealing Hash: ${p.evidenceBlock.blockHash}\nPrevious Block Hash: ${p.evidenceBlock.prevBlockHash}`,
        isAiGenerated: false,
      },
      // 18. Audit Information
      {
        sectionNumber: 18,
        title: 'Audit Information',
        content: `Chain Status: ${ledgerStatus.isValid ? 'VALID & UNTAMPERED' : 'TAMPER DETECTED'}\nTotal Ledger Blocks: ${ledgerStatus.totalBlocks}\nSealed At Block: #${p.evidenceBlock.blockIndex}\nSealing Investigator: ${p.evidenceBlock.metadata.investigator}\nVerification Timestamp: ${ledgerStatus.verifiedAt}`,
        isAiGenerated: false,
      },
    ];

    const observedEvidenceSummary: string[] = [
      `Original raw artifact SHA-256: ${p.evidence.sha256} (MD5 legacy reference: ${p.evidence.md5})`,
      `Message envelope: From '${p.evidence.headers.from}', Subject '${p.evidence.headers.subject}', Date '${p.evidence.headers.date}'`,
      `Received transit chain contains ${p.headerAnalysis.receivedHops.length} hops with earliest external relay ${p.headerAnalysis.originatingIp || 'Internal'}`,
      `Header-reported Authentication: SPF=${p.headerAnalysis.spf.status}, DKIM=${p.headerAnalysis.dkim.status}, DMARC=${p.headerAnalysis.dmarc.status}`,
      `Extracted IOC counts: ${p.iocs.filter(i => i.type === 'url').length} URLs, ${p.iocs.filter(i => i.type === 'ipv4').length} IPs, ${p.iocs.filter(i => i.type === 'domain').length} domains, ${p.evidence.attachments.length} attachments`,
    ];

    const analyticalConclusionsSummary: string[] = [
      `Threat classification: ${p.threatAssessment.classification} (Evaluated confidence: ${p.threatAssessment.confidence}%)`,
      `Deterministic risk score: ${p.riskScore.totalScore}/100 (${p.riskScore.level}) calculated from 6 weighted risk components`,
      `Inferred originating infrastructure: ${p.geolocations[0]?.ip || 'Unknown'} (${p.geolocations[0]?.country || 'Unknown'}, ASN ${p.geolocations[0]?.asn || 'Unknown'})`,
      p.campaignMatches[0]
        ? `Statistical campaign pattern match: ${p.campaignMatches[0].name} (${p.campaignMatches[0].similarityScore}% feature similarity; non-definitive attribution)`
        : 'No correlating threat campaign cluster identified in threat intelligence baseline',
    ];

    return {
      reportId: `REP-${caseId}-${Date.now().toString(36).toUpperCase()}`,
      generatedAt: new Date().toISOString(),
      analyst: p.caseRecord.analyst,
      organization: 'Smart India Hackathon 2026 - Cyber Forensics Unit (Problem 26106)',
      caseRecord: p.caseRecord,
      evidence: p.evidence,
      headerAnalysis: p.headerAnalysis,
      iocs: p.iocs,
      threatAssessment: p.threatAssessment,
      riskScore: p.riskScore,
      geolocations: p.geolocations,
      campaignMatches: p.campaignMatches,
      mitreMappings: p.mitreMappings,
      attackTimeline: p.attackTimeline,
      evidenceBlock: p.evidenceBlock,
      ledgerStatus,
      custodyEvents: p.custodyEvents,
      investigativeAssessment: `Digital forensic examination confirms the target message presents a ${p.riskScore.level} security threat (${p.riskScore.totalScore}/100 Risk Score) classified as ${p.threatAssessment.classification}. Originating infrastructure has been traced across ${p.headerAnalysis.receivedHops.length} relay hops to autonomous system ${p.geolocations[0]?.asn || 'unassigned'}. Cryptographic integrity sealed in blockchain ledger at block #${p.evidenceBlock.blockIndex}.`,
      observedEvidenceSummary,
      analyticalConclusionsSummary,
      recommendedActions: p.threatAssessment.recommendedActions,
      limitations: [
        'Geolocation reflects network routing and transit relays, not physical coordinates of the human sender.',
        'Threat intelligence is bounded by registry reporting schedules and available provider telemetry.',
        'AI conclusions represent probabilistic inference rather than judicial certainty.',
      ],
      evidenceIntegrityNotice:
        'Cryptographic SHA-256 hash digests permanently lock raw MIME byte streams and analysis records into an immutable blockchain ledger block.',
      auditInformation: `Sealed in Evidence Ledger at Block #${p.evidenceBlock.blockIndex} by ${p.evidenceBlock.metadata.investigator}. Ledger verification status: ${ledgerStatus.isValid ? 'VERIFIED_VALID' : 'INTEGRITY_BREACH'}.`,
      legalDisclaimer:
        'DISCLAIMER: Geolocation data reflects approximate infrastructure routing and transit relays, not the physical location of the human sender. AI-assisted analysis provides probabilistic threat assessment based on observed indicators and does not constitute definitive judicial proof. Cryptographic SHA-256 hashes establish mathematical integrity of the evidence record at time of custody ingestion.',
      disclaimers: {
        geolocation: 'Geolocation is approximate and reflects infrastructure routing, CDN proxies, or VPN tunnels, not physical human sender coordinates.',
        aiInference: 'AI analysis represents probabilistic inference and heuristic modeling, not definitive legal attribution or absolute proof.',
        integrity: 'Cryptographic SHA-256 hashes establish raw byte and payload integrity at time of ingestion into the forensic ledger.',
        custody: 'Chain of custody log records sequential handling events with ISO-8601 timestamps and operator signatures to satisfy evidentiary standards.',
      },
      structuredSections,
    };
  }
}

export const caseService = new CaseService();
