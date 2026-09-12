import { CardHeader } from '@/components/ui/Card'
import type { AlertRead, TimelineEntry } from '@/types/api'

interface TimelinePoint {
  key: string
  label: string
  detail: string
  timestamp: string
}

/** Section H: a visual timeline built exclusively from real timestamps
 * already present on the alert and its related events -- every
 * TimelineEntry.event_timestamp, plus the alert's own first_seen/
 * last_seen/updated_at. No point on this timeline is fabricated or
 * interpolated; if there were no related events, only the alert's own
 * first/last-seen and current-status points would render.
 */
export function InvestigationTimeline({ alert, timeline }: { alert: AlertRead; timeline: TimelineEntry[] }) {
  const points: TimelinePoint[] = [
    ...timeline.map((entry) => ({
      key: entry.event_id,
      label: entry.event_type,
      detail: [entry.hostname, entry.username].filter(Boolean).join(' · ') || entry.source,
      timestamp: entry.event_timestamp,
    })),
    {
      key: 'current-status',
      label: `Status: ${alert.status}`,
      detail: 'Current alert lifecycle state',
      timestamp: alert.updated_at,
    },
  ].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

  return (
    <div>
      <CardHeader title="Investigation Timeline" subtitle="Chronological sequence of real observed activity and alert state" />
      <div className="px-5 pb-5">
        {points.length === 0 ? (
          <p className="text-xs text-fg-subtle">No timestamped evidence is available for this alert.</p>
        ) : (
          <ol className="relative border-l border-border pl-4">
            {points.map((point) => (
              <li key={point.key} className="mb-4 last:mb-0">
                <span
                  className="absolute -left-[4.5px] mt-1.5 size-[7px] rounded-full border-2 border-bg bg-accent"
                  aria-hidden="true"
                />
                <p className="text-[11px] text-fg-subtle">{new Date(point.timestamp).toLocaleString()}</p>
                <p className="mt-0.5 text-sm font-medium text-fg">{point.label}</p>
                {point.detail && <p className="text-xs text-fg-subtle">{point.detail}</p>}
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  )
}
