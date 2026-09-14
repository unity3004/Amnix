import { FilePlus, Pencil, AlignLeft, ArrowRightLeft, Flag, UserCog, Link2, Unlink, Lock, LockOpen, type LucideIcon } from 'lucide-react'
import type { CaseAuditAction } from '@/types/api'

/** Shared label/icon presentation for the ten real CaseAuditAction
 * values -- used by both CaseAuditPanel (Case Detail) and the Step 12W
 * Incident Console's own audit/timeline views, so the two surfaces can
 * never drift into inconsistent wording or icon choices for the same
 * real backend action.
 */
export const CASE_AUDIT_ACTION_LABEL: Record<string, string> = {
  CASE_CREATED: 'Case created',
  CASE_TITLE_CHANGED: 'Title changed',
  CASE_DESCRIPTION_CHANGED: 'Description changed',
  CASE_STATUS_CHANGED: 'Status changed',
  CASE_PRIORITY_CHANGED: 'Priority changed',
  CASE_OWNER_CHANGED: 'Owner changed',
  CASE_ALERT_LINKED: 'Alert linked',
  CASE_ALERT_UNLINKED: 'Alert unlinked',
  CASE_CLOSED: 'Case closed',
  CASE_REOPENED: 'Case reopened',
}

/** Each real audit action gets its own icon SHAPE (not just a color) so
 * state-changing events (closed/reopened/status/owner) stay
 * distinguishable for a colorblind analyst or in a printed/greyscale
 * view -- exactly the ten actions CaseAuditAction actually defines
 * server-side, nothing invented. */
export const CASE_AUDIT_ACTION_ICON: Record<string, LucideIcon> = {
  CASE_CREATED: FilePlus,
  CASE_TITLE_CHANGED: Pencil,
  CASE_DESCRIPTION_CHANGED: AlignLeft,
  CASE_STATUS_CHANGED: ArrowRightLeft,
  CASE_PRIORITY_CHANGED: Flag,
  CASE_OWNER_CHANGED: UserCog,
  CASE_ALERT_LINKED: Link2,
  CASE_ALERT_UNLINKED: Unlink,
  CASE_CLOSED: Lock,
  CASE_REOPENED: LockOpen,
}

/** The three broader categories the Incident Console's timeline filter
 * chips group these ten actions into (Status/Owner/Alerts) -- everything
 * else (title/description/priority changes, case creation) stays
 * generically "Audit". Pure classification, no new data.
 */
export function categoryForAuditAction(action: CaseAuditAction): 'Status' | 'Owner' | 'Alerts' | 'Audit' {
  if (action === 'CASE_STATUS_CHANGED' || action === 'CASE_CLOSED' || action === 'CASE_REOPENED') return 'Status'
  if (action === 'CASE_OWNER_CHANGED') return 'Owner'
  if (action === 'CASE_ALERT_LINKED' || action === 'CASE_ALERT_UNLINKED') return 'Alerts'
  return 'Audit'
}
