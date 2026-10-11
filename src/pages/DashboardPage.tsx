import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  FileSearch,
  CheckCircle2,
  Activity,
  ArrowRight,
  Shield,
  Clock,
  Layers,
  Flame,
  Globe,
  Database,
  ExternalLink,
  RefreshCw,
  Filter,
  Mail,
  FolderKanban,
  Fingerprint,
  AlertCircle,
  BookOpen,
  Sparkles,
  Zap,
  Link2,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from 'recharts';
import {
  CaseRecord,
  InvestigationCompletePayload,
  SocDashboardSummaryResponse,
  RiskLevel,
} from '../types/forensics';
import { PageId } from '../components/Sidebar';
import { ThreatIntensityHeatMap } from '../components/ThreatIntensityHeatMap';
import { fetchSocDashboardSummary } from '../services/api';

interface DashboardPageProps {
  cases: CaseRecord[];
  activeCase?: InvestigationCompletePayload | null;
  activePayload?: InvestigationCompletePayload | null;
  onNavigate: (page: PageId) => void;
  onSelectCase: (caseId: string) => void;
  onQuickIngest?: () => void;
  onLoadScenario?: (type: 'LEGITIMATE' | 'BEC' | 'PHISHING') => void;
  onOpenGuide?: () => void;
}

function defangObservable(val: string): string {
  if (!val) return '';
  return val
    .replace(/https:\/\//gi, 'hxxps://')
    .replace(/http:\/\//gi, 'hxxp://')
    .replace(/\./g, '[.]');
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  cases,
  activeCase,
  activePayload: propPayload,
  onNavigate,
  onSelectCase,
  onQuickIngest,
  onLoadScenario,
  onOpenGuide,
}) => {
  const currentPayload = activeCase || propPayload || null;

  // Live SOC Telemetry State
  const [dashboardData, setDashboardData] = useState<SocDashboardSummaryResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState<'ALL' | RiskLevel>('ALL');

  const loadDashboardData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchSocDashboardSummary();
      setDashboardData(data);
    } catch (err: any) {
      console.error('[Dashboard] Failed to fetch live SOC summary:', err);
      setError(err?.message || 'Failed to load live SOC dashboard telemetry');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Derived counts from live summary (falling back to 0s cleanly)
  const summary = dashboardData?.summary || {
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
  };

  // Formal Cases Counts
  const totalCasesCount = cases.length;
  const criticalCases = cases.filter(c => c.severity === 'CRITICAL');
  const highCases = cases.filter(c => c.severity === 'HIGH');
  const mediumCases = cases.filter(c => c.severity === 'MEDIUM');
  const lowCases = cases.filter(c => c.severity === 'LOW');

  // 1. Live Risk Distribution Data (Recharts Pie)
  const rawRiskData = [
    { name: 'Critical', value: summary.criticalThreats, color: '#DC2626' },
    { name: 'High Risk', value: summary.highThreats, color: '#F59E0B' },
    { name: 'Medium Risk', value: summary.mediumThreats, color: '#2563EB' },
    { name: 'Safe / Low', value: summary.lowThreats, color: '#16A34A' },
  ];
  const hasRiskData = rawRiskData.some(r => r.value > 0);
  const liveRiskDistribution = hasRiskData
    ? rawRiskData.filter(r => r.value > 0)
    : [{ name: 'No Data Yet', value: 1, color: '#CBD5E1' }];

  // 2. Live Threat Categories Data (Recharts Bar)
  const rawCategories = dashboardData?.threatCategories || [];
  const palette = ['#DC2626', '#F59E0B', '#2563EB', '#7C3AED', '#0D9488', '#E11D48'];
  const threatCategoriesData = rawCategories.map((c, idx) => ({
    category: c.category.replace(/_/g, ' '),
    count: c.count,
    fill: palette[idx % palette.length],
  }));

  // 3. Filtered Recent Threats
  const recentThreats = dashboardData?.recentThreats || [];
  const filteredThreats = recentThreats.filter(t => {
    if (riskFilter === 'ALL') return true;
    return t.riskLevel === riskFilter;
  });

  return (
    <div id="soc-dashboard-view" className="space-y-8 pb-16 font-sans max-w-7xl mx-auto">
      {/* 1. Executive Operations Header & 1-Click Demo Scenarios */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5">
          <div className="space-y-1.5 max-w-2xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 font-semibold text-xs border border-emerald-200">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                SOC Engines Active
              </span>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 font-semibold border border-blue-200">
                Deterministic Triage
              </span>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-600 font-semibold border border-slate-200">
                SIH Problem 26106
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              SOC Threat Operations
            </h1>
            <p className="text-sm text-slate-600 leading-relaxed">
              Autonomous email threat forensics and incident response. Deterministically verifies RFC-822 headers, inspects authentication (SPF/DKIM/DMARC), correlates campaigns, and seals evidence in an immutable ledger.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 flex-shrink-0">
            <button
              id="dashboard-refresh-btn"
              onClick={loadDashboardData}
              disabled={isLoading}
              className="inline-flex items-center gap-2 px-3.5 py-2.5 rounded-xl border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs sm:text-sm font-medium transition-colors cursor-pointer"
              title="Refresh live SOC telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-blue-600' : ''}`} />
              <span>Refresh</span>
            </button>

            {onOpenGuide && (
              <button
                onClick={onOpenGuide}
                className="inline-flex items-center gap-2 px-3.5 py-2.5 rounded-xl border border-blue-200 bg-blue-50/60 hover:bg-blue-100 text-blue-700 text-xs sm:text-sm font-semibold transition-colors cursor-pointer"
                title="Platform Architecture & Guide"
              >
                <BookOpen className="w-4 h-4 text-blue-600" />
                <span>Guide</span>
              </button>
            )}
          </div>
        </div>

        {/* 1-Click Test Scenarios Bar */}
        {onLoadScenario && (
          <div className="mt-5 pt-4 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-600">
              <Zap className="w-3.5 h-3.5 text-amber-500 flex-shrink-0" />
              <span>1-Click Test Scenarios:</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => onLoadScenario('LEGITIMATE')}
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-200 text-xs font-semibold transition-colors cursor-pointer"
                title="Verified Corporate Support Memo (SPF/DKIM/DMARC pass)"
              >
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span>Clean Corporate Memo</span>
              </button>

              <button
                onClick={() => onLoadScenario('BEC')}
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 text-xs font-semibold transition-colors cursor-pointer"
                title="Executive BEC Wire Transfer Fraud (Reply-To mismatch)"
              >
                <span className="w-2 h-2 rounded-full bg-amber-500" />
                <span>Executive Wire Fraud (BEC)</span>
              </button>

              <button
                onClick={() => onLoadScenario('PHISHING')}
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-50 hover:bg-red-100 text-red-800 border border-red-200 text-xs font-semibold transition-colors cursor-pointer"
                title="Credential Harvester (Fake M365 Login)"
              >
                <span className="w-2 h-2 rounded-full bg-red-500" />
                <span>Credential Phishing</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Error Alert if any */}
      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-semibold">Telemetry Loading Error: </span>
            <span>{error}</span>
          </div>
          <button
            onClick={loadDashboardData}
            className="text-xs font-semibold text-red-700 hover:underline cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* 2. Top Summary KPI Metric Cards (4 Streamlined Cards) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Active Threats */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex flex-col justify-between hover:border-amber-300 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-amber-700 uppercase tracking-wider">
              Active Threats
            </span>
            <div className="w-9 h-9 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-extrabold text-slate-900">
              {summary.totalThreats}
            </div>
            <div className="flex items-center gap-1.5 text-xs text-slate-500 mt-1">
              <span className="font-bold text-red-600">{summary.criticalThreats + summary.highThreats} Critical/High</span>
              <span>•</span>
              <span>{summary.totalTriagedMessages} evaluated</span>
            </div>
          </div>
        </div>

        {/* Card 2: Monitored Messages */}
        <div
          onClick={() => onNavigate('gmail-monitor')}
          className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex flex-col justify-between hover:border-blue-300 hover:shadow-xs transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-blue-700 uppercase tracking-wider">
              Monitored Messages
            </span>
            <div className="w-9 h-9 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center group-hover:scale-105 transition-transform">
              <Mail className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-extrabold text-slate-900">
              {summary.totalMonitoredMessages}
            </div>
            <p className="text-xs text-slate-500 mt-1">Gmail inbox live synchronization</p>
          </div>
        </div>

        {/* Card 3: Correlated Campaigns */}
        <div
          onClick={() => onNavigate('campaign-dna')}
          className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex flex-col justify-between hover:border-purple-300 hover:shadow-xs transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-purple-700 uppercase tracking-wider">
              Threat Campaigns
            </span>
            <div className="w-9 h-9 rounded-xl bg-purple-50 text-purple-600 flex items-center justify-center group-hover:scale-105 transition-transform">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-extrabold text-slate-900">
              {summary.activeCampaigns}
            </div>
            <p className="text-xs text-slate-500 mt-1">{summary.totalIocs} correlated IOCs across clusters</p>
          </div>
        </div>

        {/* Card 4: Forensic Cases */}
        <div
          onClick={() => onNavigate('cases')}
          className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex flex-col justify-between hover:border-emerald-300 hover:shadow-xs transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-700 uppercase tracking-wider">
              Forensic Cases
            </span>
            <div className="w-9 h-9 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center group-hover:scale-105 transition-transform">
              <FolderKanban className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-extrabold text-slate-900">
              {totalCasesCount}
            </div>
            <p className="text-xs text-slate-500 mt-1">{summary.promotedCases} sealed in blockchain ledger</p>
          </div>
        </div>
      </div>

      {/* 4. Visual Component: Global Threat Intensity Heat Map */}
      <ThreatIntensityHeatMap
        cases={cases}
        activeCase={currentPayload}
        onSelectCase={onSelectCase}
        onNavigateToCase={caseId => {
          onSelectCase(caseId);
          onNavigate('investigation');
        }}
      />

      {/* 5. Key Charts: Severity Distribution & Threat Category Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Risk Distribution Chart (5 cols) */}
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Threat Severity Breakdown
              </h3>
              <p className="text-xs text-slate-500">
                Proportion of monitored emails by automated risk classification
              </p>
            </div>
            <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-2 py-1 rounded-md">
              {summary.totalTriagedMessages} Analyzed
            </span>
          </div>

          <div className="h-64 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={liveRiskDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={hasRiskData ? 3 : 0}
                  dataKey="value"
                >
                  {liveRiskDistribution.map((entry, index) => (
                    <Cell key={`risk-cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFFFF',
                    borderColor: '#E2E8F0',
                    borderRadius: '8px',
                    boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                    fontSize: '12px',
                    color: '#0F172A',
                  }}
                />
                <Legend
                  wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }}
                  formatter={value => <span className="text-slate-700">{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {!hasRiskData && (
            <p className="text-xs text-center text-slate-400">
              No triaged emails yet. Connect Gmail or triage emails to populate risk breakdown.
            </p>
          )}
        </div>

        {/* Threat Attack Categories Bar Chart (7 cols) */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Primary Threat Categories
              </h3>
              <p className="text-xs text-slate-500">
                Detected attack methodologies across triaged emails and campaigns
              </p>
            </div>
            <span className="text-xs font-semibold text-blue-600 bg-blue-50 px-2.5 py-1 rounded-lg">
              {threatCategoriesData.length} Identified
            </span>
          </div>

          {threatCategoriesData.length === 0 ? (
            <div className="h-64 flex flex-col items-center justify-center text-center p-6 border border-dashed border-slate-200 rounded-xl">
              <ShieldAlert className="w-8 h-8 text-slate-300 mb-2" />
              <p className="text-sm font-semibold text-slate-700">No Threat Categories Recorded</p>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Categories are automatically classified as emails are analyzed and correlated into attack waves.
              </p>
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threatCategoriesData} layout="vertical">
                  <XAxis type="number" stroke="#94A3B8" fontSize={11} allowDecimals={false} />
                  <YAxis
                    dataKey="category"
                    type="category"
                    stroke="#64748B"
                    fontSize={11}
                    width={150}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      borderColor: '#E2E8F0',
                      borderRadius: '8px',
                      boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                      fontSize: '12px',
                      color: '#0F172A',
                    }}
                  />
                  <Bar dataKey="count" name="Observed In Incidents" radius={[0, 6, 6, 0]}>
                    {threatCategoriesData.map((entry, index) => (
                      <Cell key={`cat-cell-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* 6. Priority Campaigns Section */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-3 border-b border-slate-200">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-slate-900">Priority Threat Campaigns</h2>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-purple-100 text-purple-800 font-semibold border border-purple-200">
                Highest Risk First
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Correlated multi-message adversary clusters clustered by shared infrastructure and indicators
            </p>
          </div>
          <button
            onClick={() => onNavigate('campaign-dna')}
            className="text-xs font-semibold text-purple-600 hover:text-purple-700 inline-flex items-center gap-1 cursor-pointer self-start sm:self-center"
          >
            <span>View campaign intelligence</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {(!dashboardData?.topCampaigns || dashboardData.topCampaigns.length === 0) ? (
          <div className="text-center py-10 space-y-3">
            <div className="w-12 h-12 rounded-full bg-purple-50 text-purple-500 mx-auto flex items-center justify-center">
              <Layers className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-slate-800">No Active Campaigns Detected</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Multi-signal clustering evaluates shared public IPs, domains, and payload hashes across your monitored Gmail messages.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {dashboardData.topCampaigns.map(c => {
              const badgeClass =
                c.riskLevel === 'CRITICAL'
                  ? 'bg-red-100 text-red-700 border-red-200'
                  : c.riskLevel === 'HIGH'
                  ? 'bg-amber-100 text-amber-800 border-amber-200'
                  : 'bg-blue-100 text-blue-700 border-blue-200';

              return (
                <div
                  key={c.campaignId}
                  onClick={() => onNavigate('gmail-monitor')}
                  className="p-4 rounded-xl border border-slate-200 hover:border-purple-400 hover:bg-purple-50/20 flex flex-col justify-between gap-3 cursor-pointer transition-all group"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-purple-700 bg-purple-50 px-2 py-0.5 rounded-md border border-purple-100">
                        {c.campaignId}
                      </span>
                      <span className={`text-xs px-2.5 py-0.5 rounded-md font-bold border ${badgeClass}`}>
                        {c.riskLevel} — {c.riskScore}/100
                      </span>
                    </div>

                    <h4 className="text-sm font-semibold text-slate-900 group-hover:text-purple-700 transition-colors">
                      {c.campaignName || c.campaignId}
                    </h4>

                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <span className="font-medium text-slate-700">{c.messageCount} related messages</span>
                      <span>•</span>
                      <span className="capitalize">{c.category.replace(/_/g, ' ')}</span>
                    </div>

                    {c.reasons && c.reasons.length > 0 && (
                      <div className="space-y-1 pt-1 border-t border-slate-100">
                        <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                          Correlation Rationale:
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {c.reasons.slice(0, 2).map((r, rIdx) => (
                            <span
                              key={rIdx}
                              className="text-[11px] bg-slate-100 text-slate-700 px-2 py-0.5 rounded-md font-medium"
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center justify-between text-xs text-purple-600 font-semibold pt-2 border-t border-slate-100">
                    <span>Inspect campaign in Monitor</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 7. Recent Threats Queue */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-slate-200">
          <div>
            <h2 className="text-lg font-bold text-slate-900">
              Recent Triaged Threats
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Live queue of analyzed emails with deterministic verdicts and safe defanged observables
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-xs font-semibold text-slate-600">Filter:</span>
            <div className="inline-flex rounded-lg border border-slate-200 p-0.5 bg-slate-50 text-xs">
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(lvl => (
                <button
                  key={lvl}
                  onClick={() => setRiskFilter(lvl)}
                  className={`px-2.5 py-1 rounded-md font-semibold transition-colors cursor-pointer ${
                    riskFilter === lvl
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-500 hover:text-slate-800'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>
        </div>

        {filteredThreats.length === 0 ? (
          <div className="text-center py-10 space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-100 text-slate-400 mx-auto flex items-center justify-center">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-slate-800">
              {riskFilter === 'ALL' ? 'No threats triaged yet' : `No ${riskFilter} threats detected`}
            </h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Synchronize Gmail or upload email headers to run automated deterministic forensic triage.
            </p>
            <button
              onClick={() => onNavigate('gmail-monitor')}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg text-xs font-semibold cursor-pointer inline-flex items-center gap-1.5"
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Go to Gmail Monitor</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider bg-slate-50/50">
                  <th className="py-2.5 px-3">Time</th>
                  <th className="py-2.5 px-3">Subject</th>
                  <th className="py-2.5 px-3">Sender (Defanged)</th>
                  <th className="py-2.5 px-3">Risk Level</th>
                  <th className="py-2.5 px-3">Classification</th>
                  <th className="py-2.5 px-3">Campaign</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredThreats.map((t, idx) => {
                  const badgeClass =
                    t.riskLevel === 'CRITICAL'
                      ? 'bg-red-100 text-red-700 border-red-200'
                      : t.riskLevel === 'HIGH'
                      ? 'bg-amber-100 text-amber-800 border-amber-200'
                      : t.riskLevel === 'MEDIUM'
                      ? 'bg-blue-100 text-blue-700 border-blue-200'
                      : 'bg-green-100 text-green-700 border-green-200';

                  const dateStr = t.analyzedAt
                    ? new Date(t.analyzedAt).toLocaleDateString(undefined, {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })
                    : 'Recent';

                  return (
                    <tr key={t.gmailMessageId || idx} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-3 text-slate-500 font-mono whitespace-nowrap">
                        {dateStr}
                      </td>
                      <td className="py-3 px-3 max-w-xs font-medium text-slate-900 truncate">
                        {t.subject}
                      </td>
                      <td className="py-3 px-3 text-slate-600 font-mono select-all truncate max-w-xs">
                        {defangObservable(t.sender)}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-md font-bold border ${badgeClass}`}>
                          {t.riskLevel} ({t.riskScore})
                        </span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 font-medium">
                          {t.classification}
                        </span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        {t.campaignId ? (
                          <span
                            onClick={() => onNavigate('gmail-monitor')}
                            className="font-mono text-purple-700 bg-purple-50 px-2 py-0.5 rounded-md border border-purple-100 hover:bg-purple-100 cursor-pointer"
                          >
                            {t.campaignId}
                          </span>
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={() => onNavigate('gmail-monitor')}
                          className="text-blue-600 hover:text-blue-800 font-semibold inline-flex items-center gap-1 cursor-pointer"
                        >
                          <span>Inspect</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 8. Formal Case Investigations Queue */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-3 border-b border-slate-200">
          <div>
            <h2 className="text-lg font-bold text-slate-900">
              Formal Case Investigations Queue
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Select any email case to inspect evidence, headers, and recommended defensive actions.
            </p>
          </div>
          <button
            onClick={() => onNavigate('cases')}
            className="text-xs font-semibold text-blue-600 hover:text-blue-700 inline-flex items-center gap-1 cursor-pointer self-start sm:self-center"
          >
            <span>View all cases in detail</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {cases.length === 0 ? (
          <div className="text-center py-10 space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-100 text-slate-400 mx-auto flex items-center justify-center">
              <FileSearch className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-slate-800">No cases ingested yet</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Get started by uploading or pasting an email header to run forensic analysis.
            </p>
            {onQuickIngest && (
              <button
                onClick={onQuickIngest}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg text-xs font-semibold cursor-pointer"
              >
                + Analyze First Email
              </button>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {cases.slice(0, 5).map(c => {
              const severityBadge =
                c.severity === 'CRITICAL'
                  ? 'bg-red-100 text-red-700 border-red-200'
                  : c.severity === 'HIGH'
                  ? 'bg-amber-100 text-amber-800 border-amber-200'
                  : c.severity === 'MEDIUM'
                  ? 'bg-blue-100 text-blue-700 border-blue-200'
                  : 'bg-green-100 text-green-700 border-green-200';

              return (
                <div
                  key={c.caseId}
                  onClick={() => {
                    onSelectCase(c.caseId);
                    onNavigate('investigation');
                  }}
                  className="p-4 rounded-xl border border-slate-200 hover:border-blue-400 hover:bg-slate-50/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer transition-all group"
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2.5 py-1 rounded-md text-xs font-bold border ${severityBadge}`}
                    >
                      {c.severity}
                    </span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-900">
                          {c.caseNumber}
                        </span>
                        <span className="text-slate-400">•</span>
                        <span className="text-xs text-slate-500 font-medium">
                          Risk {c.riskScore} / 100
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-800 mt-0.5 group-hover:text-blue-600 transition-colors">
                        {c.title}
                      </h4>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-xs self-end sm:self-center">
                    <span className="px-2.5 py-1 rounded-md bg-slate-100 text-slate-700 font-medium">
                      {c.status}
                    </span>
                    <span className="text-blue-600 font-semibold inline-flex items-center gap-1 group-hover:translate-x-0.5 transition-transform">
                      Inspect <ArrowRight className="w-3.5 h-3.5" />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
