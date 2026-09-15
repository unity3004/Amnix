import { Link } from 'react-router-dom'
import { Bot } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { Skeleton } from '@/components/ui/Skeleton'
import { buildCaseContextQuery } from '@/features/cases/caseNavigationContext'
import { COPILOT_AUDIT_TITLE_BY_REQUEST_TYPE } from '../logic'
import type { CaseRead, CopilotAuditResponse } from '@/types/api'

/** Deliberately shows only what GET /alerts/{id}/copilot/audits actually
 * persists -- outcome/provider/model/timestamp of the focused alert's
 * most recent Copilot call. It does NOT show "last verdict" or "last
 * confidence": CopilotAuditResponse (see types/api.ts) has no
 * verdict/confidence/summary field at all -- the backend deliberately
 * only persists safe call metadata, never the assessment content itself
 * (see app/services/copilot_audit_service.py). Showing a verdict here
 * would mean either re-calling Copilot just to render a summary
 * (an automatic Copilot execution, explicitly forbidden) or inventing
 * one -- both wrong. This panel never embeds the conversation itself;
 * "Open Copilot Investigation" is the one real action.
 */
export function CopilotSummaryPanel({
  caseItem,
  focusedAlertId,
  focusedAlertTitle,
  audits,
  isPending,
}: {
  caseItem: CaseRead
  focusedAlertId: string | undefined
  focusedAlertTitle: string | null
  audits: CopilotAuditResponse[] | undefined
  isPending: boolean
}) {
  const latest = audits && audits.length > 0 ? audits[0] : null
  const caseContextQuery = focusedAlertId ? buildCaseContextQuery({ caseId: caseItem.id, caseNumber: caseItem.case_number }) : ''

  return (
    <Card id="console-copilot" className="scroll-mt-20 overflow-hidden">
      <CardHeader title="Copilot Activity" subtitle={focusedAlertTitle ? `Focused on: ${focusedAlertTitle}` : 'No alert focused yet'} />

      <div className="px-5 pb-5">
        {!focusedAlertId ? (
          <EmptyState icon={Bot} title="Select an alert to view its Copilot activity." />
        ) : isPending ? (
          <Skeleton className="h-16 w-full" />
        ) : !latest ? (
          <EmptyState icon={Bot} title="Copilot has not been asked about this alert yet." />
        ) : (
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Last Request</dt>
              <dd className="mt-0.5 text-fg">{COPILOT_AUDIT_TITLE_BY_REQUEST_TYPE[latest.request_type]}</dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Outcome</dt>
              <dd className="mt-0.5">
                <Badge tone={latest.outcome === 'success' ? 'success' : 'danger'}>{latest.outcome}</Badge>
              </dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Provider</dt>
              <dd className="mt-0.5 text-fg">
                {latest.provider_name}
                {latest.model_name ? ` · ${latest.model_name}` : ''}
              </dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Asked</dt>
              <dd className="mt-0.5 text-fg" title={new Date(latest.created_at).toLocaleString()}>
                {new Date(latest.created_at).toLocaleString()}
              </dd>
            </div>
          </dl>
        )}

        {focusedAlertId && (
          <Link to={`/alerts/${focusedAlertId}/investigation${caseContextQuery}`} className="mt-4 inline-block">
            <Button type="button" variant="secondary" size="sm">
              <Bot className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
              Open Copilot Investigation
            </Button>
          </Link>
        )}
      </div>
    </Card>
  )
}
