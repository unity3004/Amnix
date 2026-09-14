import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/Button'
import { updateCase } from '@/services/casesService'
import { CASE_PRIORITY_VALUES } from '../types'
import type { CasePriority, CaseRead } from '@/types/api'

const inputClass =
  'w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none'

/** PATCH /cases/{id} (Step 12R/12S) -- title/description/priority only.
 * Only fields that actually changed are submitted as non-null; the
 * backend itself only records an audit row per field whose value
 * actually changed (see CaseService.update_case's own docstring).
 */
export function CaseEditPanel({ caseItem, onDone }: { caseItem: CaseRead; onDone: () => void }) {
  const queryClient = useQueryClient()
  const [title, setTitle] = useState(caseItem.title)
  const [description, setDescription] = useState(caseItem.description)
  const [priority, setPriority] = useState<CasePriority>(caseItem.priority)
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () =>
      updateCase(caseItem.id, {
        title: title.trim() !== caseItem.title ? title.trim() : null,
        description: description.trim() !== caseItem.description ? description.trim() : null,
        priority: priority !== caseItem.priority ? priority : null,
      }),
    onSuccess: (updated) => {
      queryClient.setQueryData(['case-detail', caseItem.id], updated)
      queryClient.invalidateQueries({ queryKey: ['cases-list'] })
      queryClient.invalidateQueries({ queryKey: ['case-audit', caseItem.id] })
      onDone()
    },
    onError: () => {
      setError('This case could not be updated.')
    },
  })

  return (
    <div className="mt-4 flex flex-col gap-3 border-t border-border pt-4">
      <div>
        <label htmlFor="edit-case-title" className="text-[11px] uppercase tracking-wide text-fg-subtle">
          Title
        </label>
        <input id="edit-case-title" type="text" className={inputClass} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={500} />
      </div>
      <div>
        <label htmlFor="edit-case-description" className="text-[11px] uppercase tracking-wide text-fg-subtle">
          Description
        </label>
        <textarea
          id="edit-case-description"
          rows={3}
          className={inputClass}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      <div className="w-40">
        <label htmlFor="edit-case-priority" className="text-[11px] uppercase tracking-wide text-fg-subtle">
          Priority
        </label>
        <select id="edit-case-priority" className={inputClass} value={priority} onChange={(e) => setPriority(e.target.value as CasePriority)}>
          {CASE_PRIORITY_VALUES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="text-xs text-danger">{error}</p>}

      <div className="flex items-center gap-2">
        <Button
          type="button"
          variant="primary"
          size="sm"
          disabled={mutation.isPending || !title.trim() || !description.trim()}
          onClick={() => mutation.mutate()}
        >
          {mutation.isPending ? 'Saving…' : 'Save Changes'}
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </div>
  )
}
