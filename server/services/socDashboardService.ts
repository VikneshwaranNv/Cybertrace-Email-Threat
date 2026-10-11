import {
  SocDashboardSummaryMetrics,
  SocDashboardSummaryResponse,
  SocRiskDistributionItem,
  SocThreatCategoryItem,
  SocTopCampaignItem,
  SocRecentThreatItem,
} from '../../src/types/forensics';
import { GmailTriageRegistry, gmailTriageRegistry } from '../gmail/gmailTriageRegistry';
import { GmailCampaignService, gmailCampaignService } from '../gmail/gmailCampaignService';
import { GmailPromotionRegistry, gmailPromotionRegistry } from '../gmail/gmailCasePromotionService';
import { GmailSyncRegistry, gmailSyncRegistry } from '../gmail/gmailSyncRegistry';
import { caseService as defaultCaseService } from './caseService';

export class SocDashboardService {
  private triageRegistry: GmailTriageRegistry;
  private campaignService: GmailCampaignService;
  private promotionRegistry: GmailPromotionRegistry;
  private syncRegistry: GmailSyncRegistry;
  private caseService: typeof defaultCaseService;

  constructor(options?: {
    triageRegistry?: GmailTriageRegistry;
    campaignService?: GmailCampaignService;
    promotionRegistry?: GmailPromotionRegistry;
    syncRegistry?: GmailSyncRegistry;
    caseService?: typeof defaultCaseService;
  }) {
    this.triageRegistry = options?.triageRegistry || gmailTriageRegistry;
    this.campaignService = options?.campaignService || gmailCampaignService;
    this.promotionRegistry = options?.promotionRegistry || gmailPromotionRegistry;
    this.syncRegistry = options?.syncRegistry || gmailSyncRegistry;
    this.caseService = options?.caseService || defaultCaseService;
  }

  /**
   * Aggregates a comprehensive SOC dashboard summary strictly scoped to the authenticated user.
   *
   * Security & Design Guarantees:
   * 1. Multi-tenant isolation: Scoped strictly to `user.userId`.
   * 2. Zero Gemini API calls: Operates 100% deterministically from in-memory registries.
   * 3. Zero raw email exposure: Never returns raw RFC-822 MIME bodies.
   * 4. Zero secret exposure: Never returns OAuth tokens, refresh tokens, or API credentials.
   * 5. Clean empty states: Returns accurate zero counts and empty arrays when no data exists.
   */
  public async getDashboardSummary(user: {
    userId: string;
    role?: string;
    email?: string;
  }): Promise<SocDashboardSummaryResponse> {
    const emptyResponse = (timestamp: string): SocDashboardSummaryResponse => ({
      summary: {
        totalMonitoredMessages: 0,
        totalTriagedMessages: 0,
        totalThreats: 0,
        criticalThreats: 0,
        highThreats: 0,
        mediumThreats: 0,
        lowThreats: 0,
        activeCampaigns: 0,
        totalIocs: 0,
        promotedCases: 0,
      },
      riskDistribution: [
        { level: 'CRITICAL', count: 0 },
        { level: 'HIGH', count: 0 },
        { level: 'MEDIUM', count: 0 },
        { level: 'LOW', count: 0 },
      ],
      threatCategories: [],
      topCampaigns: [],
      recentThreats: [],
      generatedAt: timestamp,
    });

    const now = new Date().toISOString();

    if (!user || !user.userId || typeof user.userId !== 'string') {
      return emptyResponse(now);
    }

    const userId = user.userId.trim();
    if (!userId) {
      return emptyResponse(now);
    }

    // 1. In-memory triaged records for authenticated user
    const records = this.triageRegistry.getAllForUser(userId);

    // 2. Sync telemetry for authenticated user
    const syncState = this.syncRegistry.get(userId);
    const totalMonitoredMessages = syncState
      ? Math.max(syncState.messagesDiscovered, records.length)
      : records.length;
    const totalTriagedMessages = records.length;

    // 3. Risk calculations
    const criticalThreats = records.filter(r => r.riskLevel === 'CRITICAL').length;
    const highThreats = records.filter(r => r.riskLevel === 'HIGH').length;
    const mediumThreats = records.filter(r => r.riskLevel === 'MEDIUM').length;
    const lowThreats = records.filter(r => r.riskLevel === 'LOW').length;
    const totalThreats = criticalThreats + highThreats + mediumThreats;

    // 4. Threat campaigns and IOCs for authenticated user
    const { campaigns, iocs } = await this.campaignService.getCampaignsForUser(userId);
    const activeCampaigns = campaigns.length;
    const totalIocs = iocs.length;

    // 5. Promoted DFIR cases for authenticated user
    const promotions = this.promotionRegistry.getAllForUser(userId);
    const promotedCases = promotions.length;

    // 6. Risk Distribution
    const riskDistribution: SocRiskDistributionItem[] = [
      { level: 'CRITICAL', count: criticalThreats },
      { level: 'HIGH', count: highThreats },
      { level: 'MEDIUM', count: mediumThreats },
      { level: 'LOW', count: lowThreats },
    ];

    // 7. Threat Categories Aggregation
    const categoryMap = new Map<string, number>();
    for (const c of campaigns) {
      if (c.threatCategory) {
        categoryMap.set(
          c.threatCategory,
          (categoryMap.get(c.threatCategory) || 0) + (c.totalMessages || 1)
        );
      }
    }

    // Fallback/enrichment from triaged records if campaigns are empty or categories underrepresented
    if (categoryMap.size === 0) {
      for (const r of records) {
        if (
          r.threatClassification &&
          r.threatClassification !== 'LEGITIMATE' &&
          r.threatClassification !== 'BENIGN'
        ) {
          categoryMap.set(
            r.threatClassification,
            (categoryMap.get(r.threatClassification) || 0) + 1
          );
        }
      }
    }

    const threatCategories: SocThreatCategoryItem[] = Array.from(categoryMap.entries())
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count);

    // 8. Priority Campaigns (Bounded to top 5, sorted highest risk score first)
    const topCampaigns: SocTopCampaignItem[] = campaigns.slice(0, 5).map(c => ({
      campaignId: c.campaignId,
      campaignName: c.campaignName,
      riskScore: c.campaignRiskScore,
      riskLevel: c.campaignRiskLevel,
      messageCount: c.totalMessages,
      category: c.threatCategory,
      findings: c.threatIntelFindings || [],
      reasons: c.correlationReasons || [],
    }));

    // 9. Recent Threats (Bounded to top 15, newest first)
    const messageToCampaignId = new Map<string, string>();
    for (const c of campaigns) {
      for (const mid of c.relatedMessageIds) {
        messageToCampaignId.set(mid, c.campaignId);
      }
    }

    const sortedRecords = [...records].sort((a, b) => {
      const dateA = a.analyzedAt ? new Date(a.analyzedAt).getTime() : 0;
      const dateB = b.analyzedAt ? new Date(b.analyzedAt).getTime() : 0;
      return dateB - dateA;
    });

    const recentThreats: SocRecentThreatItem[] = sortedRecords.slice(0, 15).map(r => ({
      gmailMessageId: r.gmailMessageId,
      subject: r.subject || '(No Subject)',
      sender: r.sender?.fromAddress || r.sender?.raw || 'Unknown',
      riskScore: r.riskScore,
      riskLevel: r.riskLevel,
      classification: r.threatClassification || 'UNKNOWN',
      campaignId: messageToCampaignId.get(r.gmailMessageId) || null,
      analyzedAt: r.analyzedAt,
    }));

    const summary: SocDashboardSummaryMetrics = {
      totalMonitoredMessages,
      totalTriagedMessages,
      totalThreats,
      criticalThreats,
      highThreats,
      mediumThreats,
      lowThreats,
      activeCampaigns,
      totalIocs,
      promotedCases,
    };

    return {
      summary,
      riskDistribution,
      threatCategories,
      topCampaigns,
      recentThreats,
      generatedAt: now,
    };
  }
}

export const socDashboardService = new SocDashboardService();
