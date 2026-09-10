import type { AlertStatus, DetectionSeverity } from '@/types/api'

/** Adapter-layer shapes the dashboard UI renders against. Deliberately
 * decoupled from both the raw demo data (demoData.ts) and any future
 * real API response shape — whichever one currently backs
 * `dashboardService.ts` just needs to produce these. See that file's
 * own docstring for the demo/real-data boundary.
 */

export interface DashboardMetrics {
  totalAlerts: number
  criticalAlerts: number
  openInvestigations: number
  eventsToday: number
}

export interface ThreatActivityPoint {
  /** ISO timestamp for the bucket start. */
  timestamp: string
  critical: number
  high: number
  medium: number
  low: number
}

export interface RecentAlertSummary {
  id: string
  title: string
  ruleId: string
  severity: DetectionSeverity
  status: AlertStatus
  occurredAt: string
}

export interface SeverityCount {
  severity: DetectionSeverity
  count: number
}

export interface MitreActivityEntry {
  techniqueId: string
  name: string
  tactic: string
  detectionCount: number
  sourceRuleId: string
}

export interface DashboardOverview {
  metrics: DashboardMetrics
  activity: ThreatActivityPoint[]
  recentAlerts: RecentAlertSummary[]
  severityDistribution: SeverityCount[]
  mitreActivity: MitreActivityEntry[]
}
