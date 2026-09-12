import type { AlertRead } from '@/types/api'
import type { ThreatActivityPoint } from '../types'

const BUCKET_COUNT = 24
const BUCKET_MS = 60 * 60 * 1000 // 1 hour

/** Buckets the CURRENTLY RETRIEVED (bounded, up to MAX_LIST_LIMIT)
 * alert page into 24 hourly buckets covering the last 24 hours,
 * counting each alert's `first_seen` by severity. This is real data --
 * every count comes directly from actual Alert rows -- but it is
 * explicitly NOT a historical aggregate query: an alert older than the
 * current bounded page's oldest entry, or outside the last 24 hours,
 * simply does not appear, exactly like every other panel fed by the
 * same bounded GET /alerts response. An empty page produces an
 * all-zero timeline, never a fabricated curve.
 */
export function deriveThreatActivity(alerts: AlertRead[], now: Date = new Date()): ThreatActivityPoint[] {
  const bucketStart = (offsetFromNow: number) =>
    new Date(Math.floor(now.getTime() / BUCKET_MS) * BUCKET_MS - offsetFromNow * BUCKET_MS)

  const buckets: ThreatActivityPoint[] = Array.from({ length: BUCKET_COUNT }, (_, i) => ({
    timestamp: bucketStart(BUCKET_COUNT - 1 - i).toISOString(),
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }))

  const earliestBucketMs = new Date(buckets[0].timestamp).getTime()

  for (const alert of alerts) {
    const firstSeenMs = new Date(alert.first_seen).getTime()
    if (Number.isNaN(firstSeenMs) || firstSeenMs < earliestBucketMs) continue
    const index = Math.floor((firstSeenMs - earliestBucketMs) / BUCKET_MS)
    if (index < 0 || index >= BUCKET_COUNT) continue
    buckets[index][alert.severity] += 1
  }

  return buckets
}
