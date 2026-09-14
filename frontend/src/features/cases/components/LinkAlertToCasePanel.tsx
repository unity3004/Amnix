import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FolderKanban } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ApiError } from '@/services/httpClient'
import { listCases, linkCaseAlert } from '@/services/casesService'

const selectClass =
  'h-9 flex-1 rounded-md border border-border bg-surface px-2 text-sm text-fg transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none'

/** POST /cases/{id}/alerts (Step 12S) -- links this real alert into an
 * existing, real, persisted Case. The dropdown is populated from the
 * same bounded GET /cases the Cases page itself uses (newest 50,
 * open-ended list -- there is no search endpoint to query against, so
 * this deliberately does not fabricate one); creating a brand-new case
 * for this alert is a separate, explicit action via the /cases page.
 */
export function LinkAlertToCasePanel({ alertId }: { alertId: string }) {
  const queryClient = useQueryClient()
  const casesQuery = useQuery({
    queryKey: ['cases-list-for-link'],
    queryFn: () => listCases({ limit: 50 }),
  })
  const [selectedCaseId, setSelectedCaseId] = useState('')
  const [result, setResult] = useState<{ tone: 'success' | 'error'; text: string; caseId?: string } | null>(null)

  const mutation = useMutation({
    mutationFn: (caseId: string) => linkCaseAlert(caseId, alertId),
    onSuccess: (_alert, caseId) => {
      // Same invalidation set CaseAlertsPanel's own link action performs
      // for the identical mutation -- this panel just reaches it from
      // the Alert Detail page instead of the Case Detail page. The
      // target case's derived severity, audit trail, and its row on the
      // cases list are all affected by this link, not only its alert set.
      queryClient.invalidateQueries({ queryKey: ['case-alerts', caseId] })
      queryClient.invalidateQueries({ queryKey: ['case-detail', caseId] })
      queryClient.invalidateQueries({ queryKey: ['case-audit', caseId] })
      queryClient.invalidateQueries({ queryKey: ['cases-list'] })
      // Step 12V: this alert's own authoritative "Linked Cases" query
      // (GET /alerts/{id}/cases, rendered by LinkedCasesPanel right
      // above this one) now includes the case just linked.
      queryClient.invalidateQueries({ queryKey: ['alert-cases', alertId] })
      setResult({ tone: 'success', text: 'This alert was linked to the case.', caseId })
    },
    onError: (error) => {
      setResult({
        tone: 'error',
        text: error instanceof ApiError ? error.message : 'This alert could not be linked to that case.',
      })
    },
  })

  const cases = casesQuery.data?.items ?? []

  return (
    <div className="flex items-start gap-3">
      <div className="flex size-9 shrink-0 items-center justify-center rounded-full border border-border-strong bg-surface-elevated">
        <FolderKanban className="size-4 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-fg">Case Management</p>
        <p className="mt-1.5 text-sm text-fg-muted">Link this alert into an existing SOC case.</p>

        {casesQuery.isPending ? (
          <p className="mt-2 text-xs text-fg-subtle">Loading cases…</p>
        ) : casesQuery.isError ? (
          <p className="mt-2 text-xs text-fg-subtle">Cases could not be loaded.</p>
        ) : cases.length === 0 ? (
          <p className="mt-2 text-xs text-fg-subtle">
            No cases exist yet.{' '}
            <Link to="/cases" className="text-accent-strong hover:text-accent">
              Create one on the SOC Cases page
            </Link>
            .
          </p>
        ) : (
          <div className="mt-2 flex items-center gap-2">
            <label className="sr-only" htmlFor="link-alert-case-select">
              Select a case
            </label>
            <select
              id="link-alert-case-select"
              className={selectClass}
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
            >
              <option value="">Select a case…</option>
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  #{c.case_number} — {c.title} ({c.status})
                </option>
              ))}
            </select>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={!selectedCaseId || mutation.isPending}
              onClick={() => mutation.mutate(selectedCaseId)}
            >
              {mutation.isPending ? 'Linking…' : 'Link to Case'}
            </Button>
          </div>
        )}

        <div aria-live="polite" className="mt-2 min-h-[1rem] text-xs">
          {result && (
            <span className={result.tone === 'success' ? 'text-success' : 'text-danger'}>
              {result.text}{' '}
              {result.tone === 'success' && result.caseId && (
                <Link to={`/cases/${result.caseId}`} className="font-medium underline">
                  View case
                </Link>
              )}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
