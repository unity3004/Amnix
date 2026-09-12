import { CardHeader } from '@/components/ui/Card'
import type { AlertRead, InvestigationContext } from '@/types/api'

function EntityList({ label, values }: { label: string; values: string[] }) {
  if (values.length === 0) return null
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
      <dd className="mt-1 flex flex-wrap gap-1.5">
        {values.map((v) => (
          <span key={v} className="rounded-sm bg-bg-inset px-1.5 py-0.5 font-mono text-[11px] text-fg-muted">
            {v}
          </span>
        ))}
      </dd>
    </div>
  )
}

/** Section D: investigation findings -- the deduplicated entity sets
 * InvestigationEngine extracted from this alert's related events
 * (InvestigationContext.entities), plus investigation metadata
 * (generated_at, and the alert's own alert_metadata if present).
 * REAL BACKEND DATA throughout -- entities are a deterministic set
 * computed from the real timeline, never inferred or guessed by the
 * UI. No findings are invented here beyond what the backend returned.
 */
export function FindingsPanel({ alert, investigation }: { alert: AlertRead; investigation: InvestigationContext }) {
  const { entities } = investigation
  const hasAnyEntities =
    entities.hostnames.length > 0 ||
    entities.usernames.length > 0 ||
    entities.source_ips.length > 0 ||
    entities.destination_ips.length > 0 ||
    entities.process_names.length > 0 ||
    entities.file_hashes.length > 0

  return (
    <div>
      <CardHeader title="Investigation Findings" subtitle="Entities extracted from this alert's related events" />
      <div className="px-5 pb-5">
        {!hasAnyEntities ? (
          <p className="text-xs text-fg-subtle">No affected entities were extracted from this alert's related events.</p>
        ) : (
          <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <EntityList label="Hostnames" values={entities.hostnames} />
            <EntityList label="Usernames" values={entities.usernames} />
            <EntityList label="Source IPs" values={entities.source_ips} />
            <EntityList label="Destination IPs" values={entities.destination_ips} />
            <EntityList label="Process Names" values={entities.process_names} />
            <EntityList label="File Hashes" values={entities.file_hashes} />
          </dl>
        )}

        <div className="mt-4 flex flex-wrap gap-x-6 gap-y-1 border-t border-border pt-3 text-[11px] text-fg-subtle">
          <span>Context generated: {new Date(investigation.generated_at).toLocaleString()}</span>
          {alert.alert_metadata && Object.keys(alert.alert_metadata).length > 0 && (
            <span>Alert metadata: {Object.keys(alert.alert_metadata).length} field(s) recorded</span>
          )}
        </div>
      </div>
    </div>
  )
}
