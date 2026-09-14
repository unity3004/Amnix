import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { Skeleton } from '@/components/ui/Skeleton'
import { formatRelativeTime } from '@/lib/format'
import { createCaseNote } from '@/services/casesService'
import { useAuth } from '@/features/auth/useAuth'
import { useCaseNotes } from '../useCaseNotes'

const ADD_NOTE_ERROR = 'This note could not be added.'

/** "You" is a real comparison against the authenticated user's own id --
 * never a fabricated display name (there is no GET /admin/users
 * endpoint anywhere in AMNIX to resolve a UUID to one). Mirrors
 * CaseDetailPage's own describeOwner() precedent exactly.
 */
function describeAuthor(authorId: string, currentUserId: string | undefined): string {
  return authorId === currentUserId ? 'You' : authorId
}

/** GET/POST /cases/{id}/notes (Step 12R/12S). Notes are analyst
 * free-text annotations, never audited as a CaseAudit row (the note's
 * own author_id/created_at is already its own authorship record -- see
 * app/models/case_note.py). Rendered oldest-first, matching the
 * backend's own "journal" ordering.
 *
 * Step 13A §7: each note now also shows its real author (author_id, via
 * CaseNoteResponse -- always server-resolved from the authenticated
 * caller at creation, never client-suppliable; see CaseNoteCreate's own
 * schema, which has no author field at all). There is no backend
 * max-length on note bodies (CaseNoteCreate.body: min_length=1 only,
 * confirmed by direct schema inspection) -- so §8's "respect backend
 * maximum length" has nothing to enforce here beyond the existing
 * blank-rejection, and none is invented.
 */
export function CaseNotesPanel({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const { data, isPending, isError } = useCaseNotes(caseId)
  const [body, setBody] = useState('')
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: (text: string) => createCaseNote(caseId, text),
    onMutate: () => setError(null),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case-notes', caseId] })
      setBody('')
    },
    onError: () => {
      // Deliberately generic, matching CaseCreateForm/CaseEditPanel's own
      // precedent -- every realistic failure here (network error, the
      // case having vanished mid-session) has nothing more specific and
      // safe to tell the analyst than "try again".
      setError(ADD_NOTE_ERROR)
    },
  })

  const notes = data?.items ?? []

  return (
    <>
      <CardHeader title="Analyst Notes" subtitle="Free-text annotations attached to this case." />

      {isPending ? (
        <div className="px-5 pb-4">
          <Skeleton className="h-10 w-full" />
        </div>
      ) : isError ? (
        <p className="px-5 pb-4 text-xs text-fg-subtle">Notes could not be loaded.</p>
      ) : notes.length === 0 ? (
        <div className="px-5 pb-4">
          <EmptyState title="No notes have been added to this case yet." />
        </div>
      ) : (
        <ul className="flex flex-col gap-3 px-5 pb-4">
          {notes.map((note) => (
            <li key={note.id} className="rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
              <p className="whitespace-pre-wrap text-sm text-fg">{note.body}</p>
              <p className="mt-1.5 flex flex-wrap items-center gap-x-2 font-mono text-[11px] text-fg-subtle">
                <span title={note.author_id}>{describeAuthor(note.author_id, user?.id)}</span>
                <span aria-hidden="true">·</span>
                <span title={new Date(note.created_at).toLocaleString()}>{formatRelativeTime(note.created_at)}</span>
              </p>
            </li>
          ))}
        </ul>
      )}

      <div className="flex flex-col gap-2 border-t border-border px-5 py-4">
        <label htmlFor="case-new-note" className="text-[11px] uppercase tracking-wide text-fg-subtle">
          Add a Note
        </label>
        <textarea
          id="case-new-note"
          rows={2}
          value={body}
          onChange={(e) => setBody(e.target.value)}
          className="w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
        />
        <div>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={mutation.isPending || !body.trim()}
            onClick={() => mutation.mutate(body.trim())}
          >
            {mutation.isPending ? 'Adding…' : 'Add Note'}
          </Button>
        </div>

        <div aria-live="polite" className="min-h-[1rem] text-xs text-danger">
          {error}
        </div>
      </div>
    </>
  )
}
