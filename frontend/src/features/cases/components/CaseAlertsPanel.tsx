import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, FileSearch } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { Skeleton } from '@/components/ui/Skeleton'
import { ApiError } from '@/services/httpClient'
import { linkCaseAlert, unlinkCaseAlert } from '@/services/casesService'
import { useCaseAlerts } from '../useCaseAlerts'
import { buildCaseContextQuery } from '../caseNavigationContext'
import { getRuleDefinition } from '@/features/rules/ruleRegistry'
import type { AlertRead } from '@/types/api'

const STATUS_TONE: Record<AlertRead['status'], 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

/** GET/POST/DELETE /cases/{id}/alerts (Step 12R/12S) -- the real alerts
 * linked to this case, reusing AlertRead's own real fields unmodified
 * (no duplicate/derived representation). Linking accepts a real alert
 * ID typed by the analyst -- there is no bulk/search-based alert picker
 * here on purpose: an analyst normally arrives at "link this alert" FROM
 * the alert's own detail page (see LinkAlertToCasePanel), so this
 * form exists only to cover the reverse direction without fabricating a
 * search index that doesn't exist server-side.
 *
 * Step 12U: every navigation link out of this panel (alert title,
 * Investigate shortcut, the trailing arrow) carries a case-context
 * query string (see caseNavigationContext.ts) so Alert Detail/
 * Investigation can show "opened from Case #N" -- a pure client-side
 * breadcrumb, never a backend request, never a claim that the alert is
 * (still) linked to this case beyond "this is where you came from".
 */
export function CaseAlertsPanel({ caseId, caseNumber }: { caseId: string; caseNumber: number }) {
  const queryClient = useQueryClient()
  const caseContextQuery = buildCaseContextQuery({ caseId, caseNumber })
  const { data, isPending, isError } = useCaseAlerts(caseId)
  const [alertId, setAlertId] = useState('')
  const [linkError, setLinkError] = useState<string | null>(null)

  const linkMutation = useMutation({
    mutationFn: (id: string) => linkCaseAlert(caseId, id),
    onSuccess: (_alert, linkedAlertId) => {
      queryClient.invalidateQueries({ queryKey: ['case-alerts', caseId] })
      // Linking/unlinking changes this case's DERIVED severity (see
      // CaseService.derive_severity) -- both the still-mounted detail
      // view and the cases list's own badge for this row must reflect
      // it, not just the sub-resource that literally changed.
      queryClient.invalidateQueries({ queryKey: ['case-detail', caseId] })
      queryClient.invalidateQueries({ queryKey: ['case-audit', caseId] })
      queryClient.invalidateQueries({ queryKey: ['cases-list'] })
      // Step 12V: the linked alert's own authoritative "Linked Cases"
      // query (GET /alerts/{id}/cases) now includes this case -- a
      // precise, single-key invalidation, never a global cache flush.
      queryClient.invalidateQueries({ queryKey: ['alert-cases', linkedAlertId] })
      setAlertId('')
      setLinkError(null)
    },
    onError: (error) => {
      setLinkError(error instanceof ApiError ? error.message : 'This alert could not be linked.')
    },
  })

  const unlinkMutation = useMutation({
    mutationFn: (id: string) => unlinkCaseAlert(caseId, id),
    onSuccess: (_void, unlinkedAlertId) => {
      queryClient.invalidateQueries({ queryKey: ['case-alerts', caseId] })
      queryClient.invalidateQueries({ queryKey: ['case-detail', caseId] })
      queryClient.invalidateQueries({ queryKey: ['case-audit', caseId] })
      queryClient.invalidateQueries({ queryKey: ['cases-list'] })
      queryClient.invalidateQueries({ queryKey: ['alert-cases', unlinkedAlertId] })
    },
  })

  const alerts = data?.items ?? []

  return (
    <>
      <CardHeader title="Linked Alerts" subtitle="Real alerts grouped under this case." />

      <div className="flex items-end gap-2 px-5 pb-4">
        <div className="flex-1">
          <label htmlFor="case-link-alert-id" className="text-[11px] uppercase tracking-wide text-fg-subtle">
            Link Alert by ID
          </label>
          <input
            id="case-link-alert-id"
            type="text"
            placeholder="Alert UUID"
            value={alertId}
            onChange={(e) => setAlertId(e.target.value)}
            className="mt-1 w-full rounded-md border border-border bg-surface px-3 py-1.5 font-mono text-xs text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
          />
        </div>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          disabled={linkMutation.isPending || !alertId.trim()}
          onClick={() => linkMutation.mutate(alertId.trim())}
        >
          {linkMutation.isPending ? 'Linking…' : 'Link'}
        </Button>
      </div>
      {linkError && <p className="px-5 pb-3 text-xs text-danger">{linkError}</p>}

      {isPending ? (
        <div>
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="px-5 py-3">
              <Skeleton className="h-4 w-full" />
            </div>
          ))}
        </div>
      ) : isError ? (
        <p className="px-5 pb-5 text-xs text-fg-subtle">Linked alerts could not be loaded.</p>
      ) : alerts.length === 0 ? (
        <EmptyState title="No alerts are linked to this case yet." />
      ) : (
        <ul className="divide-y divide-border-faint">
          {alerts.map((alert) => {
            const rule = getRuleDefinition(alert.rule_id)
            const hasEvidence = Object.keys(alert.evidence).length > 0
            const eventCount = alert.source_event_ids.length
            return (
              <li key={alert.id} className="flex flex-col gap-2 px-5 py-3 sm:flex-row sm:items-center sm:justify-between">
                <Link to={`/alerts/${alert.id}${caseContextQuery}`} className="min-w-0 flex-1">
                  <p className="truncate text-sm text-fg hover:text-accent-strong">{alert.title}</p>
                  <p className="mt-0.5 flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={alert.severity} />
                    <Badge tone={STATUS_TONE[alert.status]}>{alert.status}</Badge>
                    <span
                      className="font-mono text-[11px] text-fg-subtle"
                      title="Detection rule -- unrecognized rule_id shown as-is, never a fabricated name"
                    >
                      {rule ? rule.name : alert.rule_id}
                    </span>
                  </p>
                  <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-fg-subtle">
                    <span title={new Date(alert.first_seen).toLocaleString()}>
                      First seen {new Date(alert.first_seen).toLocaleDateString()}
                    </span>
                    <span title={new Date(alert.last_seen).toLocaleString()}>
                      Last seen {new Date(alert.last_seen).toLocaleDateString()}
                    </span>
                    <span>
                      {eventCount} event{eventCount === 1 ? '' : 's'}
                    </span>
                    <span>{hasEvidence ? 'Evidence available' : 'No structured evidence'}</span>
                  </p>
                </Link>
                <div className="flex shrink-0 items-center gap-2">
                  <Link
                    to={`/alerts/${alert.id}/investigation${caseContextQuery}`}
                    className="flex items-center gap-1 rounded-md border border-border-strong px-2 py-1 text-xs font-medium text-fg-muted transition-colors duration-fast hover:border-accent/40 hover:bg-surface-hover hover:text-accent-strong"
                    title="Open the Investigation Workspace for this alert -- fetches investigation data only when you click through, never automatically"
                  >
                    <FileSearch className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                    Investigate
                  </Link>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={unlinkMutation.isPending}
                    onClick={() => unlinkMutation.mutate(alert.id)}
                  >
                    Unlink
                  </Button>
                  <Link to={`/alerts/${alert.id}${caseContextQuery}`} className="text-fg-subtle hover:text-accent-strong">
                    <ArrowRight className="size-3.5" strokeWidth={2} aria-hidden="true" />
                  </Link>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </>
  )
}
