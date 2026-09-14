import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/Button'
import { createCase } from '@/services/casesService'
import { CASE_PRIORITY_VALUES } from '../types'
import type { CasePriority } from '@/types/api'

const inputClass =
  'w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-fg placeholder:text-fg-subtle transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none'

/** POST /cases (Step 12R/12S) -- creates a real, persisted Case row.
 * `created_by`/`status` are never sent from here -- the backend
 * server-resolves the actor and always starts a new case as OPEN.
 */
export function CaseCreateForm({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [priority, setPriority] = useState<CasePriority>('medium')
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () => createCase({ title: title.trim(), description: description.trim(), priority }),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ['cases-list'] })
      navigate(`/cases/${created.id}`)
    },
    onError: () => {
      setError('This case could not be created.')
    },
  })

  function handleSubmit() {
    setError(null)
    if (!title.trim() || !description.trim()) {
      setError('Title and description are required.')
      return
    }
    mutation.mutate()
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        handleSubmit()
      }}
      className="flex flex-col gap-3 border-b border-border px-5 py-4"
    >
      <div>
        <label htmlFor="new-case-title" className="text-[11px] uppercase tracking-wide text-fg-subtle">
          Title
        </label>
        <input
          id="new-case-title"
          type="text"
          className={inputClass}
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          maxLength={500}
        />
      </div>
      <div>
        <label htmlFor="new-case-description" className="text-[11px] uppercase tracking-wide text-fg-subtle">
          Description
        </label>
        <textarea
          id="new-case-description"
          className={inputClass}
          rows={3}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      <div className="w-40">
        <label htmlFor="new-case-priority" className="text-[11px] uppercase tracking-wide text-fg-subtle">
          Priority
        </label>
        <select
          id="new-case-priority"
          className={inputClass}
          value={priority}
          onChange={(e) => setPriority(e.target.value as CasePriority)}
        >
          {CASE_PRIORITY_VALUES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </div>

      <div aria-live="polite" className="min-h-[1rem] text-xs text-danger">
        {error}
      </div>

      <div className="flex items-center gap-2">
        <Button type="submit" variant="primary" size="sm" disabled={mutation.isPending}>
          {mutation.isPending ? 'Creating…' : 'Create Case'}
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
