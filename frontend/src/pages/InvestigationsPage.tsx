import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { SearchCode, Bot } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card, CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { Button } from '@/components/ui/Button'
import { SeverityBadge } from '@/components/ui/Badge'
import { getAlertInvestigation } from '@/services/alertsService'

/** When `?alert=<id>` is present, this page becomes a real,
 * alert-scoped investigation view (GET /alerts/{id}/investigation --
 * REAL BACKEND DATA, one request for the one alert being viewed, never
 * a per-list-row fetch). With no `alert` param it keeps its original
 * Step 12A placeholder, since a general "browse all investigations"
 * view has no backing list endpoint (there is no investigation list
 * endpoint, and the brief explicitly says not to create one).
 */
export function InvestigationsPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const alertId = searchParams.get('alert')

  const { data, isPending, isError, refetch } = useQuery({
    queryKey: ['investigation', alertId],
    queryFn: () => getAlertInvestigation(alertId as string),
    enabled: Boolean(alertId),
  })

  if (!alertId) {
    return (
      <div className="mx-auto max-w-[1400px] px-6 py-6">
        <PageHeader title="Investigations" description="Deterministic, alert-scoped investigation context" />
        <Card>
          <EmptyState
            icon={SearchCode}
            title="No investigation selected"
            description="Open an alert and choose “View Investigation” to see its timeline, related entities, and summary here."
          />
        </Card>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-[1000px] px-6 py-6">
      <PageHeader title="Investigation" description={`Alert-scoped context for ${alertId}`} />

      {isPending && (
        <Card className="p-6">
          <Skeleton className="h-5 w-72" />
          <Skeleton className="mt-6 h-32 w-full" />
        </Card>
      )}

      {isError && !isPending && (
        <Card>
          <ErrorState title="Unable to retrieve this investigation" onRetry={() => refetch()} />
        </Card>
      )}

      {data && (
        <>
          <Card className="p-6">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={data.alert.severity} />
              <h2 className="text-base font-semibold text-fg">{data.alert.title}</h2>
            </div>
            <p className="mt-3 text-sm text-fg-muted">{data.summary.text}</p>
            <dl className="mt-4 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-4">
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Events</dt>
                <dd className="mt-0.5 text-sm text-fg">{data.summary.event_count}</dd>
              </div>
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Unique Hosts</dt>
                <dd className="mt-0.5 text-sm text-fg">{data.summary.unique_host_count}</dd>
              </div>
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Unique Users</dt>
                <dd className="mt-0.5 text-sm text-fg">{data.summary.unique_user_count}</dd>
              </div>
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Generated</dt>
                <dd className="mt-0.5 text-sm text-fg">{new Date(data.generated_at).toLocaleTimeString()}</dd>
              </div>
            </dl>
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Timeline" subtitle={`${data.timeline.length} related event(s)`} />
            {data.timeline.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No related events.</p>
            ) : (
              <ul className="divide-y divide-border-faint">
                {data.timeline.map((entry) => (
                  <li key={entry.event_id} className="px-5 py-2.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-medium text-fg">{entry.event_type}</span>
                      <span className="text-[11px] text-fg-subtle">{new Date(entry.event_timestamp).toLocaleString()}</span>
                    </div>
                    <p className="mt-0.5 text-[11px] text-fg-subtle">
                      {entry.hostname ?? entry.source}
                      {entry.username && <span> · {entry.username}</span>}
                      {entry.source_ip && <span className="font-mono"> · {entry.source_ip}</span>}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Button variant="primary" className="mt-4 w-full justify-center" onClick={() => navigate(`/copilot?alert=${data.alert.id}`)}>
            <Bot className="size-4" strokeWidth={1.75} aria-hidden="true" />
            Open with Copilot
          </Button>
        </>
      )}
    </div>
  )
}
