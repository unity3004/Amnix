import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, LayoutGrid, Pencil } from 'lucide-react'
import { WorkflowBreadcrumb } from '@/components/layout/WorkflowBreadcrumb'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { useAuth } from '@/features/auth/useAuth'
import { useCaseDetail } from '@/features/cases/useCaseDetail'
import { useCaseAlerts } from '@/features/cases/useCaseAlerts'
import { CaseEditPanel } from '@/features/cases/components/CaseEditPanel'
import { CaseStatusPanel } from '@/features/cases/components/CaseStatusPanel'
import { CaseOwnerPanel } from '@/features/cases/components/CaseOwnerPanel'
import { CaseAlertsPanel } from '@/features/cases/components/CaseAlertsPanel'
import { CaseNotesPanel } from '@/features/cases/components/CaseNotesPanel'
import { CaseAuditPanel } from '@/features/cases/components/CaseAuditPanel'
import { CaseWorkflowGuidance } from '@/features/cases/components/CaseWorkflowGuidance'
import type { CaseRead, CaseStatus } from '@/types/api'

const STATUS_TONE: Record<CaseStatus, 'accent' | 'neutral' | 'success' | 'warning'> = {
  OPEN: 'accent',
  INVESTIGATING: 'warning',
  RESOLVED: 'success',
  CLOSED: 'neutral',
}

/** Honest owner display -- "You" is a real comparison against the
 * authenticated user's own id, never a fabricated display name (there
 * is no GET /admin/users endpoint anywhere in AMNIX to resolve a UUID
 * to one). A different owner is shown as its real UUID, not hidden or
 * relabeled "Someone else".
 */
function describeOwner(caseItem: CaseRead, currentUserId: string | undefined): string {
  if (caseItem.owner_id === null) return 'Unassigned'
  if (caseItem.owner_id === currentUserId) return 'You'
  return caseItem.owner_id
}

/** AMNIX SOC Case Detail (Step 12S) -- the real, single-case view backed
 * by GET /cases/{id} plus its linked alerts/notes/audit sub-resources.
 * Every field is REAL BACKEND DATA; `severity` is the value CaseService
 * already derived server-side (max severity among linked alerts, or
 * none), never recomputed client-side.
 */
export function CaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const { data: caseItem, isPending, isError, refetch } = useCaseDetail(caseId)
  // Shares its query cache/network request with CaseAlertsPanel's own
  // identical useCaseAlerts(caseId) call below (same queryKey -> React
  // Query dedupes them into one GET /cases/{id}/alerts, not two) -- this
  // is only here so the summary strip can show a REAL linked-alert
  // count instead of inventing one.
  const { data: alertsData } = useCaseAlerts(caseId)
  const [isEditing, setIsEditing] = useState(false)

  return (
    <div className="mx-auto max-w-[1000px] px-6 py-6">
      <button
        type="button"
        onClick={() => navigate('/cases')}
        className="mb-4 flex items-center gap-1.5 text-xs text-fg-subtle transition-colors duration-fast hover:text-fg"
      >
        <ArrowLeft className="size-3.5" strokeWidth={2} aria-hidden="true" />
        Back to Cases
      </button>

      {isPending && (
        <Card className="p-6">
          <Skeleton className="h-6 w-64" />
          <Skeleton className="mt-3 h-4 w-40" />
          <Skeleton className="mt-6 h-24 w-full" />
        </Card>
      )}

      {isError && !isPending && (
        <Card>
          <ErrorState title="Unable to retrieve this case" onRetry={() => refetch()} />
        </Card>
      )}

      {caseItem && (
        <>
          <WorkflowBreadcrumb steps={[{ label: 'SOC Cases', to: '/cases' }, { label: 'Case' }]} />

          <Card className="p-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="font-mono text-xs text-fg-subtle">Case #{caseItem.case_number}</p>
                <h1 className="mt-1 text-lg font-semibold text-fg">{caseItem.title}</h1>
              </div>
              <div className="flex items-center gap-2">
                <Link to={`/cases/${caseItem.id}/console`}>
                  <Button type="button" variant="secondary" size="sm">
                    <LayoutGrid className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                    Incident Console
                  </Button>
                </Link>
                <Badge tone={STATUS_TONE[caseItem.status]}>{caseItem.status}</Badge>
                <Badge tone={caseItem.priority}>{caseItem.priority} priority</Badge>
                {caseItem.severity && <Badge tone={caseItem.severity} dot>{caseItem.severity}</Badge>}
              </div>
            </div>

            {isEditing ? (
              <CaseEditPanel caseItem={caseItem} onDone={() => setIsEditing(false)} />
            ) : (
              <>
                <p className="mt-4 whitespace-pre-wrap text-sm text-fg-muted">{caseItem.description}</p>

                {/* ---- Case Summary (Step 12T): the operational
                 * at-a-glance answer to "who owns this, and how many
                 * alerts is it grounded in" -- owner is a direct
                 * comparison against the authenticated user's own real
                 * id (see describeOwner), never a fabricated display
                 * name; the alert count is `alertsData.items.length`
                 * from the exact same GET /cases/{id}/alerts response
                 * CaseAlertsPanel below renders, never a separate
                 * invented total. */}
                <dl className="mt-6 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-3">
                  <div>
                    <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Owner</dt>
                    <dd className="mt-0.5 truncate font-mono text-sm text-fg" title={caseItem.owner_id ?? undefined}>
                      {describeOwner(caseItem, user?.id)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Linked Alerts</dt>
                    <dd className="mt-0.5 text-sm text-fg">{alertsData ? alertsData.items.length : '—'}</dd>
                  </div>
                  <div>
                    <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Created</dt>
                    <dd className="mt-0.5 text-sm text-fg">{new Date(caseItem.created_at).toLocaleString()}</dd>
                  </div>
                  <div>
                    <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Updated</dt>
                    <dd className="mt-0.5 text-sm text-fg">{new Date(caseItem.updated_at).toLocaleString()}</dd>
                  </div>
                  <div className="min-w-0">
                    <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Case ID</dt>
                    <dd className="mt-0.5 break-all font-mono text-xs text-fg-muted">{caseItem.id}</dd>
                  </div>
                </dl>

                <div className="mt-4">
                  <Button type="button" variant="ghost" size="sm" onClick={() => setIsEditing(true)}>
                    <Pencil className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                    Edit Case
                  </Button>
                </div>
              </>
            )}
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CaseWorkflowGuidance />
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CaseStatusPanel caseItem={caseItem} />
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CaseOwnerPanel caseItem={caseItem} />
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CaseAlertsPanel caseId={caseItem.id} caseNumber={caseItem.case_number} />
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CaseNotesPanel caseId={caseItem.id} />
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CaseAuditPanel caseId={caseItem.id} />
          </Card>
        </>
      )}
    </div>
  )
}
