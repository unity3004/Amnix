/** Generic, alert-agnostic question prompts (brief Phase 4). These are
 * static UI copy only -- no alert-specific fact, evidence, or telemetry
 * is ever embedded in a starter string, and clicking one only fills the
 * question textarea; it never auto-submits and never bypasses the
 * normal ask()/follow-up() request path. Copilot itself, not this
 * list, is what grounds any answer in this alert's real evidence.
 */
const QUESTION_STARTERS = [
  'What evidence supports this alert?',
  'What happened first?',
  'Which events are most suspicious?',
  'What MITRE techniques are relevant?',
  'What should I investigate next?',
  'Why might this be benign?',
]

export function QuestionStarters({ onSelect, disabled }: { onSelect: (question: string) => void; disabled: boolean }) {
  return (
    <div className="flex flex-wrap gap-1.5" role="group" aria-label="Suggested investigation questions">
      {QUESTION_STARTERS.map((starter) => (
        <button
          key={starter}
          type="button"
          disabled={disabled}
          onClick={() => onSelect(starter)}
          className="rounded-full border border-border-strong bg-surface-elevated px-2.5 py-1 text-[11px] text-fg-muted transition-colors duration-fast hover:border-accent/40 hover:text-fg disabled:cursor-not-allowed disabled:opacity-50"
        >
          {starter}
        </button>
      ))}
    </div>
  )
}
