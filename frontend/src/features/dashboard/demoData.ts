import type { DashboardOverview, RecentAlertSummary, ThreatActivityPoint } from './types'

/**
 * ============================================================
 * FRONTEND DEMO DATA — NOT LIVE BACKEND DATA
 * ============================================================
 *
 * AMNIX's backend currently exposes only single-resource lookups for
 * alerts/events (GET /alerts/{id}, GET /events/{id}) — there is no
 * list/pagination endpoint yet (verified by direct inspection of
 * backend/app/api/alerts.py and backend/app/api/events.py during Step
 * 12A discovery), so a "Total Alerts" count, a "Recent Alerts" feed, a
 * time-series activity chart, and a severity breakdown cannot be
 * computed from real data without inventing a backend endpoint —
 * something this step explicitly must not do (see brief §34).
 *
 * Everything in this file is therefore clearly isolated, frontend-only
 * demo data — see dashboardService.ts for the one function that would
 * need to change to swap this for a real API call once a list endpoint
 * exists. Detection rule_ids and MITRE technique mappings used below
 * are copied verbatim from the REAL backend registries (see
 * backend/app/mitre/registry.py) — nothing here invents a rule or a
 * technique mapping that doesn't already exist in the backend.
 */

const RULE_TITLES: Record<string, string> = {
  brute_force_authentication: 'Brute Force Authentication',
  suspicious_powershell_execution: 'Suspicious PowerShell Execution',
  encoded_powershell_command: 'Encoded PowerShell Command',
}

function hoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()
}

export const DEMO_METRICS = {
  totalAlerts: 128,
  criticalAlerts: 7,
  openInvestigations: 4,
  eventsToday: 3_842,
}

export const DEMO_RECENT_ALERTS: RecentAlertSummary[] = [
  {
    id: 'demo-alert-1',
    title: RULE_TITLES.brute_force_authentication,
    ruleId: 'brute_force_authentication',
    severity: 'critical',
    status: 'new',
    occurredAt: hoursAgo(0.03),
  },
  {
    id: 'demo-alert-2',
    title: RULE_TITLES.suspicious_powershell_execution,
    ruleId: 'suspicious_powershell_execution',
    severity: 'high',
    status: 'new',
    occurredAt: hoursAgo(0.13),
  },
  {
    id: 'demo-alert-3',
    title: RULE_TITLES.encoded_powershell_command,
    ruleId: 'encoded_powershell_command',
    severity: 'high',
    status: 'investigating',
    occurredAt: hoursAgo(0.28),
  },
  {
    id: 'demo-alert-4',
    title: RULE_TITLES.brute_force_authentication,
    ruleId: 'brute_force_authentication',
    severity: 'medium',
    status: 'acknowledged',
    occurredAt: hoursAgo(1.1),
  },
  {
    id: 'demo-alert-5',
    title: RULE_TITLES.suspicious_powershell_execution,
    ruleId: 'suspicious_powershell_execution',
    severity: 'medium',
    status: 'investigating',
    occurredAt: hoursAgo(2.4),
  },
  {
    id: 'demo-alert-6',
    title: RULE_TITLES.brute_force_authentication,
    ruleId: 'brute_force_authentication',
    severity: 'low',
    status: 'resolved',
    occurredAt: hoursAgo(5.8),
  },
]

export const DEMO_ACTIVITY: ThreatActivityPoint[] = Array.from({ length: 24 }, (_, hour) => {
  const t = 23 - hour
  // A deterministic, plausible-looking curve (busier during working
  // hours) rather than random noise every render -- purely cosmetic,
  // never presented as a measurement.
  const base = Math.max(0, Math.round(6 + 5 * Math.sin((hour / 23) * Math.PI)))
  return {
    timestamp: hoursAgo(t),
    critical: Math.round(base * 0.08),
    high: Math.round(base * 0.2),
    medium: Math.round(base * 0.35),
    low: Math.round(base * 0.37),
  }
})

export const DEMO_MITRE_ACTIVITY = [
  { techniqueId: 'T1110', name: 'Brute Force', tactic: 'Credential Access', detectionCount: 41, sourceRuleId: 'brute_force_authentication' },
  {
    techniqueId: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    detectionCount: 23,
    sourceRuleId: 'suspicious_powershell_execution',
  },
  {
    techniqueId: 'T1027.010',
    name: 'Obfuscated Files or Information: Command Obfuscation',
    tactic: 'Stealth',
    detectionCount: 9,
    sourceRuleId: 'encoded_powershell_command',
  },
]

export const DEMO_OVERVIEW: DashboardOverview = {
  metrics: DEMO_METRICS,
  activity: DEMO_ACTIVITY,
  recentAlerts: DEMO_RECENT_ALERTS,
  severityDistribution: [
    { severity: 'critical', count: 7 },
    { severity: 'high', count: 22 },
    { severity: 'medium', count: 51 },
    { severity: 'low', count: 48 },
  ],
  mitreActivity: DEMO_MITRE_ACTIVITY,
}
