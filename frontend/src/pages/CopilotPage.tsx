import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Bot, Send } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { Button } from '@/components/ui/Button'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { getAlert, askCopilot } from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import type { CopilotAssessment } from '@/types/api'

const VERDICT_TONE: Record<CopilotAssessment['verdict'], 'danger' | 'warning' | 'success' | 'neutral'> = {
  likely_malicious: 'danger',
  suspicious: 'warning',
  likely_benign: 'success',
  inconclusive: 'neutral',
}

/** When `?alert=<id>` is present: a real, minimal ask-Copilot
 * interaction for that exact alert, using the existing
 * POST /alerts/{id}/copilot capability (built in Step 10, never
 * wired to any UI until now) -- REAL BACKEND DATA once asked, never a
 * fabricated response. No follow-up/history UI, no new backend
 * capability -- a single question, a single structured assessment.
 */
export function CopilotPage() {
  const [searchParams] = useSearchParams()
  const alertId = searchParams.get('alert')
  const [question, setQuestion] = useState('')

  const alertQuery = useQuery({
    queryKey: ['alert-detail', alertId],
    queryFn: () => getAlert(alertId as string),
    enabled: Boolean(alertId),
  })

  const askMutation = useMutation({
    mutationFn: (q: string) => askCopilot(alertId as string, q),
  })

  if (!alertId) {
    return (
      <div className="mx-auto max-w-[1400px] px-6 py-6">
        <PageHeader title="AI Copilot" description="AI-assisted reasoning over an alert's investigation context" />
        <Card>
          <EmptyState
            icon={Bot}
            title="No alert selected"
            description="Select an alert and choose “Open with Copilot” to begin AI-assisted investigation."
          />
        </Card>
      </div>
    )
  }

  const assessment = askMutation.data?.assessment

  return (
    <div className="mx-auto max-w-[900px] px-6 py-6">
      <PageHeader title="AI Copilot" description="AI-assisted reasoning, scoped to one alert" />

      <Card className="p-5">
        {alertQuery.isPending && <Skeleton className="h-5 w-64" />}
        {alertQuery.data && (
          <div className="mb-4 flex items-center gap-2 border-b border-border pb-4">
            <SeverityBadge severity={alertQuery.data.severity} />
            <span className="text-sm font-medium text-fg">{alertQuery.data.title}</span>
          </div>
        )}

        <label htmlFor="copilot-question" className="mb-1.5 block text-xs font-medium text-fg-muted">
          Ask Copilot about this alert
        </label>
        <textarea
          id="copilot-question"
          rows={3}
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="What happened here? Is this likely malicious?"
          className="w-full resize-none rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
        />
        <div className="mt-2 flex justify-end">
          <Button
            variant="primary"
            size="sm"
            disabled={!question.trim() || askMutation.isPending}
            onClick={() => askMutation.mutate(question)}
          >
            <Send className="size-3.5" strokeWidth={2} aria-hidden="true" />
            {askMutation.isPending ? 'Analyzing…' : 'Ask'}
          </Button>
        </div>

        {askMutation.isError && (
          <div className="mt-4">
            <ErrorState
              title="Copilot is unavailable"
              message={askMutation.error instanceof ApiError ? askMutation.error.message : 'Unable to reach the AMNIX backend.'}
              onRetry={() => askMutation.mutate(question)}
            />
          </div>
        )}

        {assessment && (
          <div className="mt-5 border-t border-border pt-4">
            <div className="flex items-center gap-2">
              <Badge tone={VERDICT_TONE[assessment.verdict]}>{assessment.verdict.replace('_', ' ')}</Badge>
              <span className="text-xs text-fg-subtle">confidence: {assessment.confidence}</span>
            </div>
            <p className="mt-2 text-sm text-fg">{assessment.summary}</p>

            {assessment.key_findings.length > 0 && (
              <ul className="mt-3 flex flex-col gap-1.5">
                {assessment.key_findings.map((finding, i) => (
                  <li key={i} className="text-xs text-fg-muted">
                    <span className="mr-1.5 font-mono uppercase text-fg-subtle">[{finding.type}]</span>
                    {finding.statement}
                  </li>
                ))}
              </ul>
            )}

            {assessment.recommended_next_steps.length > 0 && (
              <div className="mt-3">
                <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Recommended next steps</p>
                <ul className="mt-1 list-inside list-disc text-xs text-fg-muted">
                  {assessment.recommended_next_steps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
