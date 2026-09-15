/**
 * Step 12W: pure, side-effect-free derivations for the Incident Response
 * Console. Every function here takes REAL, already-fetched backend data
 * (AlertRead[], CaseRead, CaseAuditResponse[], CaseNoteResponse[],
 * TimelineEntry[], CopilotAuditResponse[]) and returns a derived view --
 * never a database query, never a fetch, never an invented field. Kept
 * as pure functions (not hooks/components) specifically so they can be
 * unit-tested directly against hand-built fixtures without mounting
 * React or mocking network calls.
 *
 * Architectural note on WHY investigation/Copilot data is scoped to one
 * "focused" alert rather than merged across every alert linked to a
 * case: GET /alerts/{id}/investigation and GET /alerts/{id}/copilot/
 * audits are both alert-scoped endpoints with no bulk/batch variant.
 * Looping either across every linked alert on page load would be
 * exactly the N+1 pattern Step 12U/12V's own discovery reports warned
 * against. The Console instead lets the analyst pick ONE alert to
 * inspect at a time (see useIncidentConsole.ts) -- every function below
 * that accepts investigation/Copilot data is written to accept "not yet
 * loaded" (undefined) as a normal, honest state, never a fabricated
 * empty-means-nothing-exists assumption.
 *
 * Step 13B: buildIncidentTimeline()/IncidentTimelineEntry are also reused
 * verbatim by CaseTimelinePanel (features/cases/components) for
 * CaseDetailPage's own Case Investigation Timeline -- per that step's
 * own explicit instruction ("do NOT create two different timeline
 * implementations"), this file is the one, shared source of truth for
 * assembling a Case's timeline, not Console-exclusive.
 */

import { compareAlertPriority } from '@/features/alerts/priority'
import { getMitreTechniquesForRule, type MitreTechnique } from '@/features/dashboard/mitreRegistry'
import { CASE_AUDIT_ACTION_LABEL, categoryForAuditAction } from '@/features/cases/caseAuditPresentation'
import type {
  AlertRead,
  AlertStatus,
  CaseAuditResponse,
  CaseNoteResponse,
  CaseRead,
  CopilotAuditRequestType,
  CopilotAuditResponse,
  DetectionSeverity,
  TimelineEntry,
} from '@/types/api'

/** Exhaustive over all 4 CopilotAuditRequestType values (an object index
 * signature, not a two-way ternary) so a future case-scoped audit ever
 * reaching this Console timeline is labeled correctly by construction,
 * rather than silently falling into an "else" branch meant for a
 * different request type. In the Console's own current wiring this only
 * ever receives alert-scoped ('ask'/'follow_up') rows (see
 * buildIncidentTimeline's own `focusedAlertCopilotAudits` param), but the
 * type itself is shared with the Case-scoped Copilot audit trail.
 */
export const COPILOT_AUDIT_TITLE_BY_REQUEST_TYPE: Record<CopilotAuditRequestType, string> = {
  ask: 'Copilot asked',
  follow_up: 'Copilot follow-up asked',
  case_brief: 'Case investigation brief generated',
  case_follow_up: 'Case Copilot follow-up asked',
}

// ---------------------------------------------------------------------------
// Evidence grouping (Phase "EVIDENCE GROUPING")
// ---------------------------------------------------------------------------

export type EvidenceGroupName = 'Authentication' | 'PowerShell' | 'Process Creation' | 'Network' | 'Other'

export const EVIDENCE_GROUP_ORDER: EvidenceGroupName[] = ['Authentication', 'PowerShell', 'Process Creation', 'Network', 'Other']

/** Generic, event_type-substring classification -- never a rule-specific
 * or alert-specific special case, exactly as required.
 */
export function classifyEventType(eventType: string): EvidenceGroupName {
  const t = eventType.toLowerCase()
  if (t.includes('auth')) return 'Authentication'
  if (t.includes('powershell')) return 'PowerShell'
  if (t.includes('process')) return 'Process Creation'
  if (t.includes('network') || t.includes('connection') || t.includes('dns') || t.includes('traffic')) return 'Network'
  return 'Other'
}

export function groupEvidenceByType(timeline: TimelineEntry[]): Map<EvidenceGroupName, TimelineEntry[]> {
  const groups = new Map<EvidenceGroupName, TimelineEntry[]>()
  for (const entry of timeline) {
    const group = classifyEventType(entry.event_type)
    const list = groups.get(group) ?? []
    list.push(entry)
    groups.set(group, list)
  }
  return groups
}

// ---------------------------------------------------------------------------
// Detection snapshot (Overview panel)
// ---------------------------------------------------------------------------

export interface DetectionSnapshot {
  linkedAlertCount: number
  highestSeverity: DetectionSeverity | null
  distinctRuleCount: number
  distinctEventCount: number
}

const SEVERITY_RANK: Record<DetectionSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 }

export function deriveDetectionSnapshot(alerts: AlertRead[]): DetectionSnapshot {
  if (alerts.length === 0) {
    return { linkedAlertCount: 0, highestSeverity: null, distinctRuleCount: 0, distinctEventCount: 0 }
  }
  const highestSeverity = alerts.reduce<DetectionSeverity>(
    (max, a) => (SEVERITY_RANK[a.severity] > SEVERITY_RANK[max] ? a.severity : max),
    alerts[0].severity,
  )
  return {
    linkedAlertCount: alerts.length,
    highestSeverity,
    distinctRuleCount: new Set(alerts.map((a) => a.rule_id)).size,
    distinctEventCount: new Set(alerts.flatMap((a) => a.source_event_ids)).size,
  }
}

// ---------------------------------------------------------------------------
// Alert grouping (Alert panel)
// ---------------------------------------------------------------------------

export function groupAlertsBySeverity(alerts: AlertRead[]): Record<DetectionSeverity, AlertRead[]> {
  const groups: Record<DetectionSeverity, AlertRead[]> = { critical: [], high: [], medium: [], low: [] }
  for (const alert of alerts) groups[alert.severity].push(alert)
  for (const severity of Object.keys(groups) as DetectionSeverity[]) groups[severity].sort(compareAlertPriority)
  return groups
}

// ---------------------------------------------------------------------------
// MITRE coverage grouped by tactic (MITRE panel)
// ---------------------------------------------------------------------------

export function groupMitreByTactic(alerts: AlertRead[]): Map<string, MitreTechnique[]> {
  const byTactic = new Map<string, MitreTechnique[]>()
  const seenTechniqueIds = new Set<string>()
  for (const alert of alerts) {
    for (const technique of getMitreTechniquesForRule(alert.rule_id)) {
      if (seenTechniqueIds.has(technique.techniqueId)) continue
      seenTechniqueIds.add(technique.techniqueId)
      const list = byTactic.get(technique.tactic) ?? []
      list.push(technique)
      byTactic.set(technique.tactic, list)
    }
  }
  return byTactic
}

// ---------------------------------------------------------------------------
// Participating detection rules (Detection panel)
// ---------------------------------------------------------------------------

export interface RuleParticipation {
  ruleId: string
  alerts: AlertRead[]
  hasObservedEvidence: boolean
}

export function deriveParticipatingRules(alerts: AlertRead[]): RuleParticipation[] {
  const byRule = new Map<string, AlertRead[]>()
  for (const alert of alerts) {
    const list = byRule.get(alert.rule_id) ?? []
    list.push(alert)
    byRule.set(alert.rule_id, list)
  }
  return Array.from(byRule.entries()).map(([ruleId, ruleAlerts]) => ({
    ruleId,
    alerts: ruleAlerts,
    hasObservedEvidence: ruleAlerts.some((a) => Object.keys(a.evidence).length > 0),
  }))
}

// ---------------------------------------------------------------------------
// Audit grouping by day (Audit panel)
// ---------------------------------------------------------------------------

export interface AuditDayGroup {
  label: 'Today' | 'Yesterday' | 'Older'
  items: CaseAuditResponse[]
}

function startOfDay(date: Date): number {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime()
}

/** Grouped purely by the real created_at timestamp already on each
 * audit row -- `now` is injectable so this stays deterministically
 * testable rather than depending on the wall clock at test-run time.
 */
export function groupAuditsByDay(audits: CaseAuditResponse[], now: Date = new Date()): AuditDayGroup[] {
  const today = startOfDay(now)
  const yesterday = today - 24 * 60 * 60 * 1000

  const groups: Record<'Today' | 'Yesterday' | 'Older', CaseAuditResponse[]> = { Today: [], Yesterday: [], Older: [] }
  for (const audit of audits) {
    const day = startOfDay(new Date(audit.created_at))
    if (day === today) groups.Today.push(audit)
    else if (day === yesterday) groups.Yesterday.push(audit)
    else groups.Older.push(audit)
  }

  return (['Today', 'Yesterday', 'Older'] as const).filter((label) => groups[label].length > 0).map((label) => ({ label, items: groups[label] }))
}

// ---------------------------------------------------------------------------
// Incident health (derived counts only -- no score, no percentage)
// ---------------------------------------------------------------------------

export interface IncidentHealth {
  linkedAlerts: number
  openAlerts: number
  investigatingAlerts: number
  resolvedAlerts: number
  escalatedAlerts: number
  notesAdded: number
  /** Scoped to whichever single alert is currently focused -- see this
   * module's own top-of-file note on why Copilot data is never merged
   * across every linked alert. */
  focusedAlertCopilotConversations: number
  timelineEvents: number
}

/** "Open" = new or acknowledged (not yet actively worked) -- AlertStatus
 * has no literal "open" value, so this is a documented, honest mapping,
 * not a backend field.
 */
const OPEN_STATUSES: ReadonlySet<AlertStatus> = new Set(['new', 'acknowledged'])

export function deriveIncidentHealth(input: {
  alerts: AlertRead[]
  notes: CaseNoteResponse[]
  focusedAlertCopilotAudits: CopilotAuditResponse[] | undefined
  timelineEventCount: number
}): IncidentHealth {
  return {
    linkedAlerts: input.alerts.length,
    openAlerts: input.alerts.filter((a) => OPEN_STATUSES.has(a.status)).length,
    investigatingAlerts: input.alerts.filter((a) => a.status === 'investigating').length,
    resolvedAlerts: input.alerts.filter((a) => a.status === 'resolved').length,
    escalatedAlerts: input.alerts.filter((a) => a.status === 'escalated').length,
    notesAdded: input.notes.length,
    focusedAlertCopilotConversations: input.focusedAlertCopilotAudits?.length ?? 0,
    timelineEvents: input.timelineEventCount,
  }
}

// ---------------------------------------------------------------------------
// Investigation progress checklist (read-only, no percentage)
// ---------------------------------------------------------------------------

export interface InvestigationProgressItem {
  key: string
  label: string
  complete: boolean
}

export function deriveInvestigationProgress(input: {
  caseItem: CaseRead
  alerts: AlertRead[]
  notes: CaseNoteResponse[]
  audits: CaseAuditResponse[]
  /** undefined = not yet fetched (no focused alert selected, or still
   * loading) -- deliberately distinct from an empty array, which would
   * mean "fetched, and genuinely zero". */
  focusedAlertTimeline: TimelineEntry[] | undefined
  focusedAlertCopilotAudits: CopilotAuditResponse[] | undefined
}): InvestigationProgressItem[] {
  const items: InvestigationProgressItem[] = [
    { key: 'detection-linked', label: 'Detection linked', complete: input.alerts.length > 0 },
    {
      key: 'evidence-available',
      label: 'Evidence available',
      complete: input.alerts.some((a) => Object.keys(a.evidence).length > 0 || a.source_event_ids.length > 0),
    },
    { key: 'timeline-available', label: 'Timeline available', complete: Boolean(input.focusedAlertTimeline && input.focusedAlertTimeline.length > 0) },
    { key: 'mitre-mapped', label: 'MITRE mapped', complete: input.alerts.some((a) => getMitreTechniquesForRule(a.rule_id).length > 0) },
    { key: 'analyst-assigned', label: 'Analyst assigned', complete: input.caseItem.owner_id !== null },
    {
      key: 'copilot-consulted',
      label: 'Copilot consulted',
      complete: Boolean(input.focusedAlertCopilotAudits && input.focusedAlertCopilotAudits.length > 0),
    },
    { key: 'notes-recorded', label: 'Notes recorded', complete: input.notes.length > 0 },
    { key: 'audit-history-present', label: 'Audit history present', complete: input.audits.length > 0 },
  ]
  if (input.caseItem.status === 'CLOSED') {
    items.push({
      key: 'closure-reason-present',
      label: 'Closure reason present',
      complete: Boolean(input.caseItem.closure_reason && input.caseItem.closure_reason.trim().length > 0),
    })
  }
  return items
}

// ---------------------------------------------------------------------------
// Next recommended actions (deterministic only -- never AI-generated)
// ---------------------------------------------------------------------------

export interface Recommendation {
  key: string
  text: string
  /** Real SPA navigation target, when the action requires leaving this page. */
  href?: string
  /** In-page scroll target (an element id already rendered on this same page). */
  scrollToId?: string
}

export function deriveRecommendations(input: { caseItem: CaseRead; alerts: AlertRead[]; notes: CaseNoteResponse[] }): Recommendation[] {
  const recommendations: Recommendation[] = []

  if (input.caseItem.owner_id === null) {
    recommendations.push({ key: 'no-owner', text: 'No owner assigned to this case.', href: `/cases/${input.caseItem.id}` })
  }
  if (input.notes.length === 0) {
    recommendations.push({ key: 'no-notes', text: 'No notes recorded yet.', scrollToId: 'console-notes' })
  }
  if (input.caseItem.status === 'OPEN') {
    recommendations.push({ key: 'still-open', text: 'Case is still OPEN -- begin investigating.', href: `/cases/${input.caseItem.id}` })
  }
  if (input.alerts.length === 0) {
    recommendations.push({ key: 'no-alerts', text: 'No alerts linked to this case yet.', href: `/cases/${input.caseItem.id}` })
  }
  const unresolvedCritical = input.alerts.find((a) => a.severity === 'critical' && a.status !== 'resolved')
  if (unresolvedCritical) {
    recommendations.push({
      key: 'critical-unresolved',
      text: `Critical alert "${unresolvedCritical.title}" is unresolved.`,
      href: `/alerts/${unresolvedCritical.id}`,
    })
  }
  return recommendations
}

// ---------------------------------------------------------------------------
// Incident timeline (the centerpiece merge)
// ---------------------------------------------------------------------------

export type IncidentTimelineCategory = 'Alerts' | 'Investigation' | 'Notes' | 'Audit' | 'Copilot' | 'Status' | 'Owner'

export interface IncidentTimelineEntry {
  id: string
  timestamp: string
  category: IncidentTimelineCategory
  title: string
  description: string | null
  /** A real user UUID, or null when the source genuinely has no actor
   * field (Copilot audits, system-observed telemetry) -- never a
   * fabricated name or a guessed actor.
   */
  actor: string | null
  /** Step 13B §4/§8: a real, already-existing SPA route this entry can
   * navigate to (an Alert or an Event, via the entry's own real
   * related_alert_id/event_id) -- undefined when the source has no
   * legitimate single navigation target (a Note; a Copilot audit, which
   * is only ever meaningful in the context of its already-visible
   * focused alert). Never a synthesized Case route: Event->Case has no
   * authoritative direct path (see Step 12Y's own discovery).
   */
  navigateTo?: string
}

function summarizeTimelineEntry(entry: TimelineEntry): string {
  const parts: string[] = []
  if (entry.hostname) parts.push(entry.hostname)
  if (entry.username) parts.push(entry.username)
  if (entry.process_name) parts.push(entry.process_name)
  if (entry.source_ip) parts.push(entry.source_ip)
  return parts.length > 0 ? parts.join(' · ') : entry.source
}

/**
 * Merges every REAL, already-fetched source into one chronological
 * timeline. `focusedAlertTimeline`/`focusedAlertCopilotAudits` are
 * optional and, when present, are scoped to exactly one alert (see this
 * module's top-of-file architectural note) -- never looped across every
 * linked alert. There is deliberately no "Investigation Started" entry
 * type: no backend event records that (Step 12U's own discovery
 * confirmed viewing Investigation is never audited), so inventing one
 * here would be a fabricated timeline entry. What real investigation
 * activity this timeline CAN show is the focused alert's own actual
 * SecurityEvent timestamps, under the "Investigation" category.
 */
export function buildIncidentTimeline(input: {
  audits: CaseAuditResponse[]
  notes: CaseNoteResponse[]
  focusedAlertTimeline?: TimelineEntry[]
  focusedAlertCopilotAudits?: CopilotAuditResponse[]
}): IncidentTimelineEntry[] {
  const entries: IncidentTimelineEntry[] = []

  for (const audit of input.audits) {
    entries.push({
      id: `audit-${audit.id}`,
      timestamp: audit.created_at,
      category: categoryForAuditAction(audit.action),
      title: CASE_AUDIT_ACTION_LABEL[audit.action] ?? audit.action,
      description:
        audit.previous_value || audit.new_value
          ? [audit.previous_value ? `from "${audit.previous_value}"` : null, audit.new_value ? `to "${audit.new_value}"` : null]
              .filter(Boolean)
              .join(' ')
          : null,
      actor: audit.actor_user_id,
      navigateTo: audit.related_alert_id ? `/alerts/${audit.related_alert_id}` : undefined,
    })
  }

  for (const note of input.notes) {
    entries.push({
      id: `note-${note.id}`,
      timestamp: note.created_at,
      category: 'Notes',
      title: 'Note added',
      description: note.body,
      actor: note.author_id,
    })
  }

  for (const event of input.focusedAlertTimeline ?? []) {
    entries.push({
      id: `investigation-${event.event_id}`,
      timestamp: event.event_timestamp,
      category: 'Investigation',
      title: event.event_type,
      description: summarizeTimelineEntry(event),
      actor: null,
      navigateTo: `/events/${event.event_id}`,
    })
  }

  for (const audit of input.focusedAlertCopilotAudits ?? []) {
    entries.push({
      id: `copilot-${audit.id}`,
      timestamp: audit.created_at,
      category: 'Copilot',
      title: COPILOT_AUDIT_TITLE_BY_REQUEST_TYPE[audit.request_type],
      description: `${audit.outcome}${audit.model_name ? ` · ${audit.provider_name} · ${audit.model_name}` : ` · ${audit.provider_name}`}`,
      actor: null,
    })
  }

  // Newest-first; ties (identical timestamp, e.g. server_default=func.now()
  // resolving to the same instant within one transaction) break
  // deterministically on the entry's own stable id string -- never left
  // to incidental array/object ordering.
  return entries.sort((a, b) => {
    const diff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    return diff !== 0 ? diff : a.id.localeCompare(b.id)
  })
}
