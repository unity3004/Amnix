/** Step 12K: a generic renderer for AlertRead.evidence -- a real,
 * per-alert dict[str, Any] captured by the DetectionEngine at the
 * moment this specific alert was created (see e.g.
 * backend/app/detections/rules/brute_force.py::_build_detection).
 *
 * Deliberately has NO knowledge of any specific rule's field names
 * (failure_count, threshold, matched_indicators, ...): the backend
 * schema for this field is dict[str, Any], not a fixed shape, so
 * hardcoding per-key labels here would silently break (or worse,
 * mislabel) evidence from any rule not anticipated when this file was
 * written. Every key is humanized generically (underscores -> spaces,
 * capitalized) and every value is formatted for readability only --
 * never reinterpreted, summarized, or turned into a claim ("high risk",
 * "malicious", etc.) the backend itself never made.
 */

function humanizeKey(key: string): string {
  const spaced = key.replace(/_/g, ' ')
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

const ISO_DATETIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/

function formatEvidenceValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'string') {
    // Reformat an ISO-8601 timestamp into a locale-readable string --
    // purely a display transform of the exact same instant, applied
    // uniformly to any string that looks like a timestamp regardless
    // of which key it came from (never key-name-specific).
    if (ISO_DATETIME_PATTERN.test(value)) {
      const parsed = new Date(value)
      if (!Number.isNaN(parsed.getTime())) return parsed.toLocaleString()
    }
    return value
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) {
    return value.length === 0 ? '(empty list)' : value.map((item) => formatEvidenceValue(item)).join(', ')
  }
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

export function EvidenceDetailList({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence)

  if (entries.length === 0) {
    return <p className="text-xs text-fg-subtle">No structured evidence was recorded for this alert.</p>
  }

  return (
    <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      {entries.map(([key, value]) => (
        <div key={key} className="min-w-0">
          <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{humanizeKey(key)}</dt>
          <dd className="mt-0.5 break-words font-mono text-sm text-fg">{formatEvidenceValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}
