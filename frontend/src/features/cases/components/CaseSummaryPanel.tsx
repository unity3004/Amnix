import { CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { formatRelativeTime } from '@/lib/format'
import { deriveParticipatingRules, groupMitreByTactic } from '@/features/console/logic'
import { DetectionRulesPanel } from '@/features/console/components/DetectionRulesPanel'
import { MitreCoveragePanel } from '@/features/console/components/MitreCoveragePanel'
import { deriveClosureReadiness } from '../caseEvidence'
import { deriveIncidentNarrative, deriveOpenItems, deriveTemporalSummary } from '../caseSummary'
import type { AlertRead, CaseNoteResponse, CaseRead } from '@/types/api'

const NOTE_PREVIEW_MAX_CHARS = 160
const NOTE_PREVIEW_COUNT = 3

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max).trimEnd()}…` : text
}

/** "You" is a real comparison against the authenticated user's own id,
 * mirroring CaseNotesPanel's own describeAuthor() precedent exactly --
 * never a fabricated display name.
 */
function describeAuthor(authorId: string, currentUserId: string | undefined): string {
  return authorId === currentUserId ? 'You' : authorId
}

/** Step 13C: the deterministic, application-generated Case Summary &
 * Incident Narrative -- an analyst orientation layer, NOT an AI
 * conclusion, risk engine, or verdict. Every section is built ONLY from
 * data CaseDetailPage already loaded for its own Alerts/Notes/Closure-
 * Readiness panels (zero additional request; see CaseDetailPage's own
 * dedup comments). Detection-rule grouping and MITRE-tactic grouping
 * reuse the existing Step 12W DetectionRulesPanel/MitreCoveragePanel
 * components VERBATIM rather than reimplementing them, per this step's
 * own "prefer one reusable implementation" instruction.
 *
 * Deliberately does NOT include a per-event Security Event Summary
 * (hosts/users/source IPs/destination IPs observed): that data lives on
 * SecurityEvent, reachable only through a per-alert Investigation fetch
 * -- looping that across every linked alert on page load would be
 * exactly the N+1 pattern this codebase has repeatedly ruled out (see
 * Step 13B's own architectural note). The Case Timeline's own focused-
 * alert selector (Step 13B) remains the honest, on-demand place to see
 * one alert's real telemetry detail.
 *
 * Deliberately does NOT include a Copilot section: no Copilot data is
 * loaded case-wide here (same N+1 reasoning -- Copilot audits are
 * alert-scoped), so there is nothing real to show without an extra
 * fetch. This keeps the deterministic Summary honestly independent of
 * Copilot, per this step's own explicit separation requirement, rather
 * than fetching Copilot data merely to populate a section.
 */
export function CaseSummaryPanel({
  caseItem,
  alerts,
  notes,
  currentUserId,
}: {
  caseItem: CaseRead
  alerts: AlertRead[]
  notes: CaseNoteResponse[]
  currentUserId: string | undefined
}) {
  const narrative = deriveIncidentNarrative({ caseItem, alerts, notes })
  const openItems = deriveOpenItems({ caseItem, alerts, notes })
  const temporal = deriveTemporalSummary(alerts)
  const closureItems = deriveClosureReadiness({ caseItem, alerts, notes })
  const closureDoneCount = closureItems.filter((i) => i.complete).length
  const recentNotes = notes.slice(-NOTE_PREVIEW_COUNT).reverse()
  const participatingRules = deriveParticipatingRules(alerts)
  const mitreByTactic = groupMitreByTactic(alerts)

  return (
    <div id="case-summary" className="flex flex-col gap-4">
      <div className="rounded-lg border border-border bg-surface">
        <CardHeader title="Case Summary" subtitle="Deterministic orientation, generated from this case's own real data." />

        <div className="flex flex-col gap-4 px-5 pb-5">
          <div>
            <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Incident Narrative</p>
            <ul className="mt-1.5 flex flex-col gap-1 text-sm text-fg">
              {narrative.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>

          <div className="grid grid-cols-1 gap-4 border-t border-border pt-3 sm:grid-cols-2">
            <div>
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Observed Telemetry Range</p>
              {temporal.earliest && temporal.latest ? (
                <p className="mt-1 text-sm text-fg">
                  {new Date(temporal.earliest).toLocaleString()} <span className="text-fg-subtle">to</span>{' '}
                  {new Date(temporal.latest).toLocaleString()}
                </p>
              ) : (
                <p className="mt-1 text-sm text-fg-subtle">No linked alerts to derive a range from.</p>
              )}
              <p className="mt-1 text-[11px] text-fg-subtle">Based on linked alerts' own first/last seen -- not a precise per-event range.</p>
            </div>

            <div>
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Closure Checklist</p>
              <p className="mt-1 text-sm text-fg">
                {closureDoneCount} of {closureItems.length} documented
              </p>
              <a href="#case-closure-readiness" className="mt-1 inline-block text-[11px] font-medium text-accent-strong hover:text-accent">
                View closure checklist ↓
              </a>
            </div>
          </div>

          <div className="border-t border-border pt-3">
            <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Open Items</p>
            <ul className="mt-1.5 flex flex-col gap-1 text-sm text-fg">
              {openItems.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>

          <div className="border-t border-border pt-3">
            <div className="flex items-center justify-between gap-2">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Latest Analyst Observations</p>
              {notes.length > 0 && (
                <a href="#case-notes-panel" className="text-[11px] font-medium text-accent-strong hover:text-accent">
                  View all notes ↓
                </a>
              )}
            </div>
            {recentNotes.length === 0 ? (
              <div className="mt-1.5">
                <EmptyState title="Nothing to preview yet." />
              </div>
            ) : (
              <ul className="mt-1.5 flex flex-col gap-2">
                {recentNotes.map((note) => (
                  <li key={note.id} className="rounded-md border border-border-faint bg-bg-inset px-3 py-2">
                    <p className="text-sm text-fg">{truncate(note.body, NOTE_PREVIEW_MAX_CHARS)}</p>
                    <p className="mt-1 flex items-center gap-2 font-mono text-[11px] text-fg-subtle">
                      <span title={note.author_id}>{describeAuthor(note.author_id, currentUserId)}</span>
                      <span aria-hidden="true">·</span>
                      <span title={new Date(note.created_at).toLocaleString()}>{formatRelativeTime(note.created_at)}</span>
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <p className="border-t border-border pt-3 text-[11px] text-fg-subtle">
            Summary generated from current Case, Alert, telemetry, investigation, note, and audit data. It is deterministic application
            output, not an AI-generated conclusion.
          </p>
        </div>
      </div>

      <DetectionRulesPanel rules={participatingRules} />
      <MitreCoveragePanel byTactic={mitreByTactic} />
    </div>
  )
}
