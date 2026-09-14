import { CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { Skeleton } from '@/components/ui/Skeleton'
import { formatRelativeTime } from '@/lib/format'
import { useCaseAudit } from '../useCaseAudit'
import { CASE_AUDIT_ACTION_ICON as ACTION_ICON, CASE_AUDIT_ACTION_LABEL as ACTION_LABEL } from '../caseAuditPresentation'

/** GET /cases/{id}/audit (Step 12R/12S) -- who did what, and when, over
 * this case's lifetime. Rendered exactly as returned (newest-first, the
 * backend's own order) -- previous_value/new_value are shown verbatim,
 * never reinterpreted or reformatted into a fabricated narrative.
 */
export function CaseAuditPanel({ caseId }: { caseId: string }) {
  const { data, isPending, isError } = useCaseAudit(caseId)
  const entries = data?.items ?? []

  return (
    <>
      <CardHeader title="Audit History" subtitle="Who did what, and when, across the life of this case." />

      {isPending ? (
        <div className="px-5 pb-5">
          <Skeleton className="h-16 w-full" />
        </div>
      ) : isError ? (
        <p className="px-5 pb-5 text-xs text-fg-subtle">Audit history could not be loaded.</p>
      ) : entries.length === 0 ? (
        <EmptyState title="No audit entries exist for this case yet." />
      ) : (
        <ul className="divide-y divide-border-faint">
          {entries.map((entry) => {
            const Icon = ACTION_ICON[entry.action]
            return (
              <li key={entry.id} className="flex gap-3 px-5 py-3">
                <div className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border border-border-strong bg-surface-elevated">
                  {Icon ? (
                    <Icon className="size-3.5 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
                  ) : (
                    <span className="size-1.5 rounded-full bg-fg-subtle" aria-hidden="true" />
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-medium text-fg">{ACTION_LABEL[entry.action] ?? entry.action}</p>
                    <span className="shrink-0 text-[11px] text-fg-subtle" title={new Date(entry.created_at).toLocaleString()}>
                      {formatRelativeTime(entry.created_at)}
                    </span>
                  </div>
                  {(entry.previous_value || entry.new_value) && (
                    <p className="mt-1 text-xs text-fg-subtle">
                      {entry.previous_value && <span>from "{entry.previous_value}" </span>}
                      {entry.new_value && <span>to "{entry.new_value}"</span>}
                    </p>
                  )}
                  <p className="mt-1 font-mono text-[11px] text-fg-subtle" title={entry.actor_user_id}>
                    by {entry.actor_user_id}
                  </p>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </>
  )
}
