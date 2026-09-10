import { AlertTriangle } from 'lucide-react'
import { Button } from './Button'

/** Reusable, safe error presentation (brief §22). Only ever receives a
 * plain string message — services/httpClient.ts already guarantees the
 * message passed here is the backend's own safe, generic error detail
 * (or a generic network-failure string), never a stack trace, SQL, or
 * provider exception text.
 */
export function ErrorState({
  title = 'Unable to load security data',
  message = 'Something went wrong while retrieving this information.',
  onRetry,
}: {
  title?: string
  message?: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center" role="alert">
      <div className="flex size-11 items-center justify-center rounded-full border border-danger/30 bg-danger-dim">
        <AlertTriangle className="size-5 text-danger" strokeWidth={1.5} aria-hidden="true" />
      </div>
      <div>
        <p className="text-sm font-medium text-fg">{title}</p>
        <p className="mt-1 max-w-xs text-xs text-fg-subtle">{message}</p>
      </div>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  )
}
