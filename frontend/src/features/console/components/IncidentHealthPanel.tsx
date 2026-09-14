import { CardHeader } from '@/components/ui/Card'
import type { IncidentHealth } from '../logic'

/** Operational counts only -- derived from data already on this page,
 * never a score or health percentage (this is deliberately NOT
 * Detection Health / Step 12O, which measures rule/telemetry coverage;
 * this measures THIS case's own activity volume).
 */
export function IncidentHealthPanel({ health }: { health: IncidentHealth }) {
  const rows: Array<[string, number]> = [
    ['Linked Alerts', health.linkedAlerts],
    ['Open Alerts', health.openAlerts],
    ['Investigating Alerts', health.investigatingAlerts],
    ['Resolved Alerts', health.resolvedAlerts],
    ['Escalated Alerts', health.escalatedAlerts],
    ['Notes Added', health.notesAdded],
    ['Copilot Conversations (focused alert)', health.focusedAlertCopilotConversations],
    ['Timeline Events', health.timelineEvents],
  ]

  return (
    <div className="rounded-lg border border-border bg-surface">
      <CardHeader title="Incident Health" subtitle="Derived activity counts -- not a score." />
      <dl className="grid grid-cols-2 gap-3 px-5 pb-5 text-sm">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
            <dd className="mt-0.5 tabular-nums text-fg">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}
