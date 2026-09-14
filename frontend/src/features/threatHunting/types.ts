/** Exactly the filter set GET /events actually supports (Step 12B +
 * Step 12X's four additions) -- nothing here may be added without a
 * corresponding real backend query parameter. See
 * backend/app/api/events.py::list_events for the authoritative contract.
 */
export interface HuntFilters {
  event_type?: string
  source?: string
  hostname?: string
  username?: string
  source_ip?: string
  destination_ip?: string
  since?: string
  until?: string
}

/** The fields a pivot action can legitimately act on -- each one maps
 * 1:1 onto a real HuntFilters key and a real, exact-match backend
 * filter. There is deliberately no pivot for process_name/file_hash/
 * command_line/etc: those columns exist on SecurityEvent but GET
 * /events has no filter for them (see the Step 12X discovery report) --
 * offering a pivot button for a filter the backend can't apply would be
 * a fake pivot dimension.
 */
export const PIVOT_FIELDS = [
  { key: 'event_type', filterKey: 'event_type', label: 'event type' },
  { key: 'source', filterKey: 'source', label: 'source' },
  { key: 'hostname', filterKey: 'hostname', label: 'host' },
  { key: 'username', filterKey: 'username', label: 'user' },
  { key: 'source_ip', filterKey: 'source_ip', label: 'source IP' },
  { key: 'destination_ip', filterKey: 'destination_ip', label: 'destination IP' },
] as const satisfies ReadonlyArray<{ key: keyof HuntFilters; filterKey: keyof HuntFilters; label: string }>
