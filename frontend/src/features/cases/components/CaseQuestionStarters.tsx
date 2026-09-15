/** Deterministic, case-agnostic question prompts (Step 13E Phase 13).
 * Static UI copy only -- no case-specific fact, evidence, or telemetry is
 * ever embedded in a starter string, and clicking one only fills the
 * question textarea; it never auto-submits and never bypasses the normal
 * generate()/ask() request path. Mirrors
 * features/investigation/components/QuestionStarters.tsx's own pattern
 * exactly, generalized to Case scope.
 */
const CASE_QUESTION_STARTERS = [
  'What evidence most strongly supports this case?',
  'What telemetry gaps should I investigate?',
  'Which alert deserves attention first?',
  'How are the linked alerts related?',
  'Which MITRE techniques are supported by the evidence?',
  'What should I verify before closing this case?',
]

export function CaseQuestionStarters({ onSelect, disabled }: { onSelect: (question: string) => void; disabled: boolean }) {
  return (
    <div className="flex flex-wrap gap-1.5" role="group" aria-label="Suggested case investigation questions">
      {CASE_QUESTION_STARTERS.map((starter) => (
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
