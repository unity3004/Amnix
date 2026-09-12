import type { TimelineEntry } from '@/types/api'

/** Copilot's evidence citations (EvidenceItem.event_ref,
 * KeyFinding/MitreAnalysisEntry/RecommendedInvestigationAction/
 * CopilotFollowUpResponse.supporting_event_refs) are NOT real database
 * event ids. They are synthetic, request-scoped labels ("evt-1",
 * "evt-2", ...) that the backend's AIContextBuilder assigns purely from
 * each event's POSITION in InvestigationContext.timeline -- see
 * backend/app/ai/context_builder.py::_map_timeline_entry:
 *
 *   event_ref=f"evt-{index}" for index, entry in enumerate(investigation.timeline, start=1)
 *
 * Since the Investigation Workspace already fetches that exact same
 * ordered `investigation.timeline` (GET /alerts/{id}/investigation),
 * this mapping is fully computable client-side from data already in
 * memory -- no additional backend request, no backend change, and no
 * N+1 per-reference event lookup. If a ref can't be resolved (e.g. the
 * investigation fetch failed or the timeline changed since Copilot was
 * asked), the caller renders it as a plain, non-clickable label rather
 * than guessing at a URL.
 */
export function buildEventRefMap(timeline: TimelineEntry[]): Map<string, string> {
  const map = new Map<string, string>()
  timeline.forEach((entry, index) => {
    map.set(`evt-${index + 1}`, entry.event_id)
  })
  return map
}
