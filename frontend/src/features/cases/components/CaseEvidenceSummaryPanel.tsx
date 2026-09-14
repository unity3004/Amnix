import { CardHeader } from '@/components/ui/Card'
import { deriveCaseEvidenceSummary } from '../caseEvidence'
import type { AlertRead } from '@/types/api'

/** Step 13A §10 -- an honest evidence summary derived entirely from
 * this case's already-loaded linked alerts (the same GET
 * /cases/{id}/alerts response CaseAlertsPanel renders below -- no
 * second fetch). Plain counts only, deliberately never labeled "Total
 * Evidence"/"Complete Evidence"/"Confirmed Evidence" and never shown as
 * a percentage: these are bounded counts over the CURRENT linked-alert
 * set, not a claim about the underlying incident's completeness.
 *
 * Deliberately does NOT repeat `summary.linkedAlerts` as its own field
 * here -- the case header above already states that exact count; this
 * panel only adds the genuinely new breakdown.
 */
export function CaseEvidenceSummaryPanel({ alerts }: { alerts: AlertRead[] }) {
  const summary = deriveCaseEvidenceSummary(alerts)

  const items: { label: string; value: number }[] = [
    { label: 'Alerts with Structured Evidence', value: summary.alertsWithStructuredEvidence },
    { label: 'Alerts with Supporting Events', value: summary.alertsWithSupportingEvents },
    { label: 'Security Events Reachable', value: summary.securityEventsReachable },
  ]

  return (
    <>
      <CardHeader
        title="Case Evidence Summary"
        subtitle={`Real counts derived from this case's ${summary.linkedAlerts} currently linked alert${summary.linkedAlerts === 1 ? '' : 's'}.`}
      />
      <dl className="grid grid-cols-2 gap-4 px-5 pb-5 sm:grid-cols-4">
        {items.map((item) => (
          <div key={item.label}>
            <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{item.label}</dt>
            <dd className="mt-0.5 text-lg font-semibold text-fg">{item.value}</dd>
          </div>
        ))}
      </dl>
    </>
  )
}
