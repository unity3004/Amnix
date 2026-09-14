import { Card, CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { Skeleton } from '@/components/ui/Skeleton'
import { formatRelativeTime } from '@/lib/format'
import { CASE_AUDIT_ACTION_ICON, CASE_AUDIT_ACTION_LABEL } from '@/features/cases/caseAuditPresentation'
import { groupAuditsByDay } from '../logic'
import type { CaseAuditResponse } from '@/types/api'

/** GET /cases/{id}/audit, already fetched by useIncidentConsole -- this
 * panel only adds Today/Yesterday/Older day grouping (derived from each
 * row's own real created_at) on top of the same icon/label presentation
 * CaseAuditPanel already uses (see caseAuditPresentation.ts), so the two
 * surfaces can never show the same real action differently.
 */
export function IncidentAuditPanel({ audits, isPending }: { audits: CaseAuditResponse[]; isPending: boolean }) {
  const groups = groupAuditsByDay(audits)

  return (
    <Card id="console-audit" className="scroll-mt-20 overflow-hidden">
      <CardHeader title="Audit Trail" subtitle="Who did what, and when, across the life of this case." />
      {isPending ? (
        <div className="px-5 pb-5">
          <Skeleton className="h-16 w-full" />
        </div>
      ) : groups.length === 0 ? (
        <EmptyState title="No audit entries exist for this case yet." />
      ) : (
        <div className="flex flex-col">
          {groups.map((group) => (
            <div key={group.label}>
              <p className="border-b border-t border-border-faint bg-bg-inset px-5 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">
                {group.label}
              </p>
              <ul className="divide-y divide-border-faint">
                {group.items.map((entry) => {
                  const Icon = CASE_AUDIT_ACTION_ICON[entry.action]
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
                          <p className="text-sm font-medium text-fg">{CASE_AUDIT_ACTION_LABEL[entry.action] ?? entry.action}</p>
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
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
