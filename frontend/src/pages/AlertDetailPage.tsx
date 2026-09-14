import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft, ArrowRight, FileSearch, Bot } from 'lucide-react'
import { WorkflowBreadcrumb, type BreadcrumbStep } from '@/components/layout/WorkflowBreadcrumb'
import { Card, CardHeader } from '@/components/ui/Card'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { Button } from '@/components/ui/Button'
import { useAlertDetail } from '@/features/alerts/useAlertDetail'
import { EvidenceDetailList } from '@/features/alerts/components/EvidenceDetailList'
import { TriageReadiness } from '@/features/alerts/components/TriageReadiness'
import { AnalystDecisionPanel } from '@/features/alerts/components/AnalystDecisionPanel'
import { LinkAlertToCasePanel } from '@/features/cases/components/LinkAlertToCasePanel'
import { LinkedCasesPanel } from '@/features/cases/components/LinkedCasesPanel'
import { buildCaseContextQuery, readCaseContext } from '@/features/cases/caseNavigationContext'
import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import { explainAlertPriority } from '@/features/alerts/priority'
import { getRuleDefinition } from '@/features/rules/ruleRegistry'

const STATUS_TONE: Record<string, 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

/** Step 12K/12L: the SOC analyst triage workflow for a single alert --
 * built entirely from the one GET /alerts/{id} response this page
 * already fetches (zero additional requests):
 *
 *   Triage header (identity/severity/status/priority)
 *     -> Triage Readiness (is the data needed for triage available?)
 *     -> Rule that fired
 *     -> Condition detected (rule logic + this alert's own evidence)
 *     -> Supporting events
 *     -> MITRE technique(s)
 *     -> Investigate / Copilot (explicit analyst navigation only)
 *     -> Analyst Decision (the real PATCH /alerts/{id}/status action)
 *
 * "Detection Rule Logic" (the rule's static, application-controlled
 * description/logic from ruleRegistry.ts) and "Observed Detection
 * Evidence" (this alert's real AlertRead.evidence) are kept in clearly
 * separate, separately-labeled blocks -- the former describes what the
 * rule generally does, the latter describes what was actually recorded
 * for THIS alert. Neither is presented as the frontend having
 * independently evaluated or verified anything, and no step here
 * fabricates a risk score, confidence percentage, or automated verdict.
 */
export function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { data: alert, isPending, isError, refetch } = useAlertDetail(alertId)
  const rule = alert ? getRuleDefinition(alert.rule_id) : null
  const mitreTechniques = alert ? getMitreTechniquesForRule(alert.rule_id) : []
  // Step 12U: a pure client-side breadcrumb, present only when the
  // analyst actually navigated here from a Case (see
  // caseNavigationContext.ts's own docstring for why this is a query
  // param, never a backend field or persisted relationship). Says "you
  // opened this from Case #N", never "this alert belongs to Case #N" --
  // the backend has no reverse Alert -> Case lookup to make that claim
  // (see Step 12U discovery report).
  const caseContext = readCaseContext(searchParams)
  const investigationHref = alert
    ? `/alerts/${alert.id}/investigation${caseContext ? buildCaseContextQuery(caseContext) : ''}`
    : ''
  // Step 12Z §12: a real workflow-position trail -- a "Case" level only
  // when Step 12U's own navigation context says that's genuinely where
  // the analyst came from, never fabricated for an alert with no such
  // context. Deliberately generic ("Case", not "Case #N"): the specific
  // number already has one clear, unambiguous home -- the "Back to Case
  // #N" button above -- and must never be echoed a second time next to
  // the AUTHORITATIVE Linked Cases panel below, where a stray "Case #N"
  // could be misread as confirmed membership instead of "where you came
  // from" (see that panel's own docstring, and the Step 12U test proving
  // the two must never be conflated).
  const breadcrumbSteps: BreadcrumbStep[] = alert
    ? caseContext
      ? [
          { label: 'SOC Cases', to: '/cases' },
          { label: 'Case', to: `/cases/${caseContext.caseId}` },
          { label: 'Alert' },
        ]
      : [{ label: 'Alerts', to: '/alerts' }, { label: 'Alert' }]
    : []

  return (
    <div className="mx-auto max-w-[1000px] px-6 py-6">
      <button
        type="button"
        onClick={() => navigate(caseContext ? `/cases/${caseContext.caseId}` : '/alerts')}
        className="mb-4 flex items-center gap-1.5 text-xs text-fg-subtle transition-colors duration-fast hover:text-fg"
      >
        <ArrowLeft className="size-3.5" strokeWidth={2} aria-hidden="true" />
        {caseContext ? `Back to Case #${caseContext.caseNumber}` : 'Back to Alerts'}
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
          <ErrorState title="Unable to retrieve this alert" onRetry={() => refetch()} />
        </Card>
      )}

      {alert && (
        <>
          <WorkflowBreadcrumb steps={breadcrumbSteps} />

          {/* REAL BACKEND DATA -- every field below is GET /alerts/{id} verbatim. */}
          <Card className="p-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <SeverityBadge severity={alert.severity} />
                <h1 className="mt-2 text-lg font-semibold text-fg">{alert.title}</h1>
                <p className="mt-1 text-xs text-fg-subtle">{explainAlertPriority(alert)}</p>
              </div>
              <Badge tone={STATUS_TONE[alert.status]}>{alert.status}</Badge>
            </div>

            <dl className="mt-6 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-3 lg:grid-cols-5">
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Confidence</dt>
                <dd className="mt-0.5 text-sm capitalize text-fg">{alert.confidence}</dd>
              </div>
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">First Seen</dt>
                <dd className="mt-0.5 text-sm text-fg">{new Date(alert.first_seen).toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Last Seen</dt>
                <dd className="mt-0.5 text-sm text-fg">{new Date(alert.last_seen).toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Events</dt>
                <dd className="mt-0.5 text-sm text-fg">{alert.source_event_ids.length}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Alert ID</dt>
                <dd className="mt-0.5 break-all font-mono text-xs text-fg-muted">{alert.id}</dd>
              </div>
            </dl>

            <p className="mt-4 text-sm text-fg-muted">{alert.description}</p>
          </Card>

          {/* ---- Triage Readiness: is the data needed for triage
           * available? (Step 12L) -- never a risk/threat assessment. ---- */}
          <Card className="mt-4 overflow-hidden">
            <TriageReadiness alert={alert} rule={rule} mitreTechniques={mitreTechniques} />
          </Card>

          {/* ---- Step 1: Rule that fired ---- */}
          <Card className="mt-4 p-6">
            <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Detection Rule</p>
            <p className="mt-1.5 flex flex-wrap items-center gap-2">
              {rule ? (
                <Link to={`/rules/${alert.rule_id}`} className="text-sm font-medium text-accent-strong transition-colors duration-fast hover:text-accent">
                  {rule.name}
                </Link>
              ) : (
                <span className="text-sm font-medium text-fg" title="Unrecognized rule_id -- shown as-is, never a fabricated name">
                  {alert.rule_id}
                </span>
              )}
              <span className="font-mono text-[11px] text-fg-subtle">{alert.rule_id}</span>
            </p>
          </Card>

          {/* ---- Step 2: Condition detected ---- */}
          <Card className="mt-4 p-6">
            <p className="text-sm font-semibold text-fg">Why This Alert Fired</p>

            <div className="mt-4">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">
                Detection Rule Logic <span className="normal-case text-fg-subtle/70">(application-controlled rule context, not proof of independent verification)</span>
              </p>
              {rule ? (
                <p className="mt-1.5 text-sm text-fg-muted">{rule.detectionLogic}</p>
              ) : (
                <p className="mt-1.5 text-xs text-fg-subtle">No rule context is available for "{alert.rule_id}" in the current registry.</p>
              )}
            </div>

            <div className="mt-4 border-t border-border pt-4">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">
                Observed Detection Evidence <span className="normal-case text-fg-subtle/70">(real data captured for this alert)</span>
              </p>
              <div className="mt-1.5">
                <EvidenceDetailList evidence={alert.evidence} />
              </div>
            </div>
          </Card>

          {/* ---- Step 3: Supporting events ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Supporting Events" subtitle={`${alert.source_event_ids.length} source event(s) cited as evidence`} />
            {alert.source_event_ids.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No source events recorded for this alert.</p>
            ) : (
              <ul className="divide-y divide-border-faint">
                {alert.source_event_ids.map((eventId) => (
                  <li key={eventId}>
                    <Link
                      to={`/events/${eventId}`}
                      className="flex items-center justify-between px-5 py-2.5 font-mono text-xs text-fg-muted transition-colors duration-fast hover:bg-surface-hover hover:text-accent-strong"
                    >
                      {eventId}
                      <ArrowRight className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* ---- Step 4: MITRE technique(s) ---- */}
          <Card className="mt-4 p-6">
            <CardHeader title="MITRE ATT&CK Technique(s)" subtitle="Candidates based on the detection rule -- not independently verified" />
            {mitreTechniques.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No MITRE ATT&CK mapping exists for rule "{alert.rule_id}".</p>
            ) : (
              <ul className="flex flex-col gap-2 px-5 pb-5">
                {mitreTechniques.map((technique) => (
                  <li key={technique.techniqueId} className="flex items-center justify-between rounded-md border border-border-faint bg-bg-inset px-3 py-2">
                    <div>
                      <p className="font-mono text-xs font-semibold text-accent-strong">{technique.techniqueId}</p>
                      <p className="mt-0.5 text-sm text-fg">{technique.name}</p>
                    </div>
                    <Badge tone="neutral">{technique.tactic}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* ---- Step 5: Investigation evidence (CTA into the existing
           * Investigation Workspace -- not duplicated here). ---- */}
          <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Button variant="primary" className="justify-center" onClick={() => navigate(investigationHref)}>
              <FileSearch className="size-4" strokeWidth={1.75} aria-hidden="true" />
              Investigate Alert
            </Button>
            <Button variant="secondary" className="justify-center" onClick={() => navigate(`/copilot?alert=${alert.id}`)}>
              <Bot className="size-4" strokeWidth={1.75} aria-hidden="true" />
              Open with Copilot
            </Button>
          </div>

          {/* ---- Analyst Decision: the real status-changing action
           * (Step 12L) -- distinct from every read-only section above. ---- */}
          <Card className="mt-4 overflow-hidden">
            <AnalystDecisionPanel alert={alert} />
          </Card>

          {/* ---- Linked Cases (Step 12V): the AUTHORITATIVE Alert ->
           * Case relationship, GET /alerts/{id}/cases -- distinct from
           * the Step 12U "Back to Case #N" navigation breadcrumb that
           * may also be showing above (see LinkedCasesPanel's own
           * docstring for why the two are never conflated). ---- */}
          <Card className="mt-4 overflow-hidden">
            <LinkedCasesPanel alertId={alert.id} />
          </Card>

          {/* ---- Case Management (Step 12S): a real action -- POST
           * /cases/{id}/alerts against the real, persisted Case domain
           * built in Step 12R. See LinkAlertToCasePanel's own docstring. ---- */}
          <Card className="mt-4 p-6">
            <LinkAlertToCasePanel alertId={alert.id} />
          </Card>
        </>
      )}
    </div>
  )
}
