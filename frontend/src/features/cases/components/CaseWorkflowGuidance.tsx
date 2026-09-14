import { CardHeader } from '@/components/ui/Card'

const STEPS = [
  { label: 'Review Alert', detail: 'Open a linked alert to see its severity, status, and rule.' },
  { label: 'Review Evidence', detail: "Read the alert's own recorded evidence and supporting events." },
  { label: 'Review Investigation', detail: 'Open the Investigation Workspace for timeline and extracted entities.' },
  { label: 'Review MITRE Context', detail: 'Check the rule-derived ATT&CK techniques for the linked alert.' },
  { label: 'Record a Case Note', detail: 'Capture what you found for the next analyst who opens this case.' },
  { label: 'Update Case Status', detail: 'Move the case forward once your review supports it.' },
]

/** Step 12U (Phase 12): static, explanatory guidance only -- NOT a
 * tracked checklist. There is no backend field recording which of these
 * steps an analyst has actually performed for a given case, so this
 * deliberately renders as plain numbered guidance text, never a
 * checkbox/checkmark that would imply a completion state AMNIX doesn't
 * track. If per-step completion tracking is ever wanted, it needs a
 * real backend field and audit trail first -- not a frontend-only flag.
 */
export function CaseWorkflowGuidance() {
  return (
    <>
      <CardHeader title="Investigation Workflow" subtitle="Suggested order of review -- not a tracked checklist." />
      <ol className="flex flex-col gap-2 px-5 pb-5">
        {STEPS.map((step, i) => (
          <li key={step.label} className="flex items-start gap-3">
            <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border border-border-strong bg-surface-elevated text-[11px] font-medium text-fg-subtle">
              {i + 1}
            </span>
            <div className="min-w-0">
              <p className="text-sm text-fg">{step.label}</p>
              <p className="text-[11px] text-fg-subtle">{step.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </>
  )
}
