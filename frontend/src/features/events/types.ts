/** Exactly the filter set GET /events actually supports (Step 12B). */
export interface EventsFilters {
  event_type?: string
  source?: string
  since?: string
  until?: string
}
