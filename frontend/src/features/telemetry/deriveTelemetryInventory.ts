import type { SecurityEventRead } from '@/types/api'

/** DERIVED ANALYST VIEW -- computed entirely from the real, bounded
 * GET /events page already fetched by useTelemetryHealth. Every count/
 * timestamp here describes only the events actually present in that
 * one response; it is never a historical total (see the caller for the
 * "observed in current window (bounded page)" wording this feeds).
 */
export interface EventTypeSummary {
  eventType: string
  observedCount: number
  latestSeen: string
  sources: string[]
}

export function deriveEventTypeInventory(events: SecurityEventRead[]): EventTypeSummary[] {
  const byType = new Map<string, { count: number; latest: string; sources: Set<string> }>()
  for (const event of events) {
    const entry = byType.get(event.event_type) ?? { count: 0, latest: event.event_timestamp, sources: new Set<string>() }
    entry.count += 1
    if (event.event_timestamp > entry.latest) entry.latest = event.event_timestamp
    entry.sources.add(event.source)
    byType.set(event.event_type, entry)
  }
  return Array.from(byType.entries())
    .map(([eventType, entry]) => ({
      eventType,
      observedCount: entry.count,
      latestSeen: entry.latest,
      sources: Array.from(entry.sources).sort(),
    }))
    .sort((a, b) => (a.latestSeen < b.latestSeen ? 1 : -1))
}

export interface SourceSummary {
  source: string
  observedCount: number
  latestSeen: string
}

/** SecurityEventRead.source is a required, always-present field (see
 * backend/app/schemas/security_event.py) -- safe to derive a real
 * distribution from, unlike a field that could be null/unreliable.
 */
export function deriveSourceInventory(events: SecurityEventRead[]): SourceSummary[] {
  const bySource = new Map<string, { count: number; latest: string }>()
  for (const event of events) {
    const entry = bySource.get(event.source) ?? { count: 0, latest: event.event_timestamp }
    entry.count += 1
    if (event.event_timestamp > entry.latest) entry.latest = event.event_timestamp
    bySource.set(event.source, entry)
  }
  return Array.from(bySource.entries())
    .map(([source, entry]) => ({ source, observedCount: entry.count, latestSeen: entry.latest }))
    .sort((a, b) => (a.latestSeen < b.latestSeen ? 1 : -1))
}
