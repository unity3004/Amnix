/** Formatting helpers shared across AMNIX components. Kept here rather
 * than duplicated per-component so relative-time/number formatting stays
 * consistent everywhere it appears (metric cards, alert rows, audit rows).
 */

export function formatRelativeTime(iso: string, now: Date = new Date()): string {
  const then = new Date(iso)
  const diffMs = now.getTime() - then.getTime()
  const diffSec = Math.round(diffMs / 1000)

  if (diffSec < 5) return 'just now'
  if (diffSec < 60) return `${diffSec}s ago`
  const diffMin = Math.round(diffSec / 60)
  if (diffMin < 60) return `${diffMin} min ago`
  const diffHour = Math.round(diffMin / 60)
  if (diffHour < 24) return `${diffHour}h ago`
  const diffDay = Math.round(diffHour / 24)
  if (diffDay < 7) return `${diffDay}d ago`
  return then.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

export function formatCount(value: number): string {
  return new Intl.NumberFormat(undefined).format(value)
}

export function formatClockTime(date: Date = new Date()): string {
  return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}
