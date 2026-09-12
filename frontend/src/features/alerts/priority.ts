import { formatRelativeTime } from '@/lib/format'
import type { AlertRead, AlertStatus, DetectionSeverity } from '@/types/api'

/** Step 12G: a deterministic, explainable triage ordering built
 * exclusively from real AlertRead fields already returned by
 * GET /alerts -- severity, status, first_seen. This is NOT a machine
 * learning risk score, NOT a probability, and NOT threat intelligence:
 * it is a fixed, documented, human-auditable sort over enum values
 * AMNIX already tracks. No number is ever surfaced to the analyst --
 * only the human-readable factors that produced the ordering (see
 * explainAlertPriority below).
 *
 * Two real signals were investigated and deliberately NOT used, because
 * no backend data actually supports them without introducing an N+1
 * request per alert row:
 *   - "has this alert already been investigated" -- InvestigationContext
 *     is computed on demand and never persisted (see
 *     backend/app/services/investigation_service.py); there is no
 *     stored "was this alert's investigation ever opened" flag on
 *     AlertRead to sort or filter by.
 *   - "has Copilot already been asked about this alert" -- CopilotAudit
 *     rows exist per-alert, but GET /alerts does not embed any
 *     per-alert audit summary, and fetching Copilot audits for every
 *     row on a list page would be exactly the N+1 pattern this step
 *     explicitly forbids.
 * Both are reportable gaps, not implemented here -- see the Step 12G
 * completion report's Known Limitations section.
 */

/** Lower rank = more urgent. DetectionSeverity's own declaration order
 * (low, medium, high, critical) is ascending impact -- this table is
 * the reverse, since triage wants the highest-impact severity first.
 */
const SEVERITY_PRIORITY_RANK: Record<DetectionSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

/** Lower rank = more urgent. Reasoning, per status (see the real 5-value
 * AlertStatus lifecycle in backend/app/services/alert_lifecycle.py):
 *   - escalated ranks above new: the lifecycle's own docstring
 *     describes escalation as flagging an alert for "immediate"
 *     attention -- a stronger urgency signal than an untouched NEW
 *     alert.
 *   - new ranks above acknowledged: an alert no analyst has looked at
 *     yet needs a first pass before one that has at least been seen.
 *   - acknowledged ranks above investigating: an alert already being
 *     actively worked by an analyst is, from a triage-queue point of
 *     view, less in need of being picked up than one that's seen but
 *     not yet started.
 *   - resolved ranks lowest: a terminal, closed state.
 */
const STATUS_PRIORITY_RANK: Record<AlertStatus, number> = {
  escalated: 0,
  new: 1,
  acknowledged: 2,
  investigating: 3,
  resolved: 4,
}

const STATUS_PRIORITY_LABEL: Record<AlertStatus, string> = {
  escalated: 'Escalated',
  new: 'Needs triage',
  acknowledged: 'Acknowledged',
  investigating: 'Investigating',
  resolved: 'Resolved',
}

/** Deterministic comparator: severity, then status, then recency
 * (newer first_seen first). Every tiebreaker is a strict, documented
 * rule -- never randomized, never dependent on anything not already on
 * AlertRead.
 */
export function compareAlertPriority(a: AlertRead, b: AlertRead): number {
  const severityDelta = SEVERITY_PRIORITY_RANK[a.severity] - SEVERITY_PRIORITY_RANK[b.severity]
  if (severityDelta !== 0) return severityDelta

  const statusDelta = STATUS_PRIORITY_RANK[a.status] - STATUS_PRIORITY_RANK[b.status]
  if (statusDelta !== 0) return statusDelta

  return new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime()
}

/** Human-readable explanation of why an alert ranks where it does --
 * e.g. "Critical severity · Escalated · 2h ago". Built entirely from
 * the same three real fields the comparator uses; never a hidden score.
 */
export function explainAlertPriority(alert: AlertRead): string {
  const severityLabel = alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1)
  return `${severityLabel} severity · ${STATUS_PRIORITY_LABEL[alert.status]} · ${formatRelativeTime(alert.first_seen)}`
}
