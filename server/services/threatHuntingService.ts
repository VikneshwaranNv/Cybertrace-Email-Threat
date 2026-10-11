import {
  CaseRecord,
  RiskLevel,
  ThreatClassification,
  IOCType,
  IOCReputation,
} from "../../src/types/forensics";
import { caseService } from "./caseService";
import { UserPublicProfile } from "../auth/types";
import { defangIndicator } from "../gmail/gmailIocService";

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

export function refangIndicator(value: string): string {
  if (!value) return "";
  return value
    .trim()
    .replace(/^hxxps:\/\//i, "https://")
    .replace(/^hxxp:\/\//i, "http://")
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\[@\]/g, "@")
    .replace(/\(@\)/g, "@")
    .replace(/\[:\]/g, ":");
}

export class ThreatHuntingService {
  private static instance: ThreatHuntingService;

  private constructor() {}

  public static getInstance(): ThreatHuntingService {
    if (!ThreatHuntingService.instance) {
      ThreatHuntingService.instance = new ThreatHuntingService();
    }
    return ThreatHuntingService.instance;
  }

  public hunt(user: { id?: string; userId?: string; role: string; email: string; name?: string }, query: HuntQuery): HuntResult {
    const start = performance.now();
    const accessibleCases = caseService.getCasesForUser(user);

    const rawQ = (query.q || "").trim();
    const normalizedQ = refangIndicator(rawQ).toLowerCase();
    const limit = Math.max(1, Math.min(query.limit || 50, 100));

    const matchedCases: { caseRecord: CaseRecord; score: number }[] = [];
    const iocHitMap = new Map<string, { ioc: any; caseIds: Set<string> }>();
    const campaignMap = new Map<string, { name: string; category: string; riskScore: number; caseIds: Set<string> }>();

    for (const c of accessibleCases) {
      // 1. Risk Level Filter
      if (query.riskLevels && query.riskLevels.length > 0) {
        if (!query.riskLevels.includes(c.severity)) continue;
      }

      // 2. Threat Classification Filter
      if (query.threatTypes && query.threatTypes.length > 0) {
        if (!query.threatTypes.includes(c.classification)) continue;
      }

      // 3. Min/Max Risk Score Filter
      if (query.minRiskScore !== undefined && c.riskScore < query.minRiskScore) continue;
      if (query.maxRiskScore !== undefined && c.riskScore > query.maxRiskScore) continue;

      // 4. Date Range Filter
      if (query.fromDate && new Date(c.createdAt) < new Date(query.fromDate)) continue;
      if (query.toDate && new Date(c.createdAt) > new Date(query.toDate)) continue;

      // 5. Query matching & relevance scoring
      let relevanceScore = 0;
      const payload = caseService.getCasePayload(c.caseId);

      if (normalizedQ) {
        let matched = false;
        const cNum = (c.caseNumber || "").toLowerCase();
        const cTitle = (c.title || "").toLowerCase();
        const cClass = (c.classification || "").toLowerCase();
        const cAssignee = (c.assignedTo || "").toLowerCase();

        if (cNum === normalizedQ || cTitle === normalizedQ) {
          relevanceScore += 100;
          matched = true;
        } else if (cTitle.includes(normalizedQ) || cNum.includes(normalizedQ)) {
          relevanceScore += 50;
          matched = true;
        }

        if (cClass.includes(normalizedQ)) {
          relevanceScore += 30;
          matched = true;
        }

        if (cAssignee.includes(normalizedQ)) {
          relevanceScore += 20;
          matched = true;
        }

        // Search notes
        if (c.notes) {
          for (const n of c.notes) {
            if (n.content.toLowerCase().includes(normalizedQ)) {
              relevanceScore += 25;
              matched = true;
              break;
            }
          }
        }

        // Search payload evidence & IOCs
        if (payload) {
          const subj = (payload.evidence?.headers?.subject || "").toLowerCase();
          const from = (payload.evidence?.headers?.from || "").toLowerCase();
          const fromDomain = (payload.evidence?.headers?.fromDomain || "").toLowerCase();

          if (subj.includes(normalizedQ)) {
            relevanceScore += 40;
            matched = true;
          }
          if (from.includes(normalizedQ) || fromDomain.includes(normalizedQ)) {
            relevanceScore += 45;
            matched = true;
          }

          if (payload.iocs) {
            for (const ioc of payload.iocs) {
              const val = (ioc.value || "").toLowerCase();
              if (val === normalizedQ) {
                relevanceScore += 90;
                matched = true;
              } else if (val.includes(normalizedQ)) {
                relevanceScore += 35;
                matched = true;
              }
            }
          }
        }

        if (!matched) continue;
      } else {
        // No search string -> score by risk score
        relevanceScore = c.riskScore;
      }

      matchedCases.push({ caseRecord: c, score: relevanceScore });

      // Collect IOCs and Campaigns from matched cases
      if (payload) {
        if (payload.iocs) {
          for (const ioc of payload.iocs) {
            if (query.iocType && ioc.type !== query.iocType) continue;
            const existing = iocHitMap.get(ioc.value);
            if (existing) {
              existing.caseIds.add(c.caseId);
            } else {
              iocHitMap.set(ioc.value, { ioc, caseIds: new Set([c.caseId]) });
            }
          }
        }

        if (payload.campaignMatches) {
          for (const cmp of payload.campaignMatches) {
            const existing = campaignMap.get(cmp.campaignId);
            if (existing) {
              existing.caseIds.add(c.caseId);
            } else {
              campaignMap.set(cmp.campaignId, {
                name: cmp.name || cmp.campaignId,
                category: cmp.threatActorGroup || "Unknown",
                riskScore: cmp.similarityScore || 75,
                caseIds: new Set([c.caseId]),
              });
            }
          }
        }
      }
    }

    // Sort cases by highest relevance score first
    matchedCases.sort((a, b) => b.score - a.score);

    const paginatedCases = matchedCases.slice(0, limit).map((m) => m.caseRecord);

    const iocHits: IOCHit[] = Array.from(iocHitMap.values())
      .map(({ ioc, caseIds }) => ({
        value: ioc.value,
        defangedValue: defangIndicator(ioc.type, ioc.value),
        type: ioc.type,
        reputation: ioc.reputation || "SUSPICIOUS",
        caseCount: caseIds.size,
        caseIds: Array.from(caseIds),
      }))
      .sort((a, b) => b.caseCount - a.caseCount)
      .slice(0, 30);

    const campaignLinks: CampaignLink[] = Array.from(campaignMap.entries())
      .map(([campaignId, val]) => ({
        campaignId,
        name: val.name,
        threatCategory: val.category,
        caseCount: val.caseIds.size,
        caseIds: Array.from(val.caseIds),
        riskScore: val.riskScore,
      }))
      .sort((a, b) => b.caseCount - a.caseCount)
      .slice(0, 15);

    const durationMs = Math.round((performance.now() - start) * 100) / 100;

    return {
      query,
      cases: paginatedCases,
      iocHits,
      campaignLinks,
      totalMatches: matchedCases.length,
      durationMs,
    };
  }

  public lookupIoc(user: { id?: string; userId?: string; role: string; email: string; name?: string }, iocValue: string): IOCHit | null {
    const cleanVal = refangIndicator(iocValue);
    const result = this.hunt(user, { q: cleanVal });
    const hit = result.iocHits.find((h) => h.value.toLowerCase() === cleanVal.toLowerCase());
    return hit || null;
  }
}

export const threatHuntingService = ThreatHuntingService.getInstance();