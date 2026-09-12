import type { AlertStatus, DetectionSeverity } from '@/types/api'

/** Adapter-layer shapes the live command-center dashboard renders
 * against. As of Step 12C these are produced exclusively by
 * deriveXxx.ts functions operating on REAL GET /events / GET /alerts
 * responses (see useDashboardData.ts) — no demo/fake/mock data source
 * exists anywhere in the frontend tree (the old dashboardService.ts
 * and demoData.ts were deleted in Step 12C, not merely unused).
 */

export interface ThreatActivityPoint {
  /** ISO timestamp for the bucket start. */
  timestamp: string
  critical: number
  high: number
  medium: number
  low: number
}

/** One row in the Active Threats panel. `mitre` is null when
 * `rule_id` has no entry in the static MITRE registry (see
 * mitreRegistry.ts) — never a fabricated mapping.
 */
export interface ActiveThreatSummary {
  id: string
  title: string
  ruleId: string
  severity: DetectionSeverity
  status: AlertStatus
  firstSeen: string
  lastSeen: string
  mitre: { techniqueId: string; name: string } | null
}

export interface SeverityCount {
  severity: DetectionSeverity
  count: number
}

/** Aggregated from Alert.rule_id in the currently-retrieved (bounded)
 * alert page only — see deriveMitreActivity.ts's own docstring for why
 * this is never a global total.
 */
export interface MitreActivityEntry {
  techniqueId: string
  name: string
  tactic: string
  detectionCount: number
  sourceRuleId: string
}

/** One row in the Live Event Stream. Field set is a strict subset of
 * SecurityEventRead — only what the backend schema actually provides.
 */
export interface LiveEventSummary {
  id: string
  eventType: string
  source: string
  hostname: string | null
  username: string | null
  sourceIp: string | null
  timestamp: string
}

/** A coarse, three-stage simplification of AlertStatus for the
 * Investigation Activity panel (brief §14) — derived purely from the
 * alert status already present in the bounded GET /alerts response,
 * never from a per-alert /investigation request.
 */
export type InvestigationStage = 'new' | 'investigating' | 'resolved'

export interface InvestigationStageGroup {
  stage: InvestigationStage
  label: string
  alerts: ActiveThreatSummary[]
}

/** See deriveThreatPulse.ts for the exact, documented formula. Never a
 * numeric "threat score" — a discrete, explainable activity state.
 */
export type ThreatPulseState = 'quiet' | 'guarded' | 'elevated' | 'active' | 'critical'
