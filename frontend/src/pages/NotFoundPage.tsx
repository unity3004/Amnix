import { Link } from 'react-router-dom'
import { Compass } from 'lucide-react'
import { EmptyState } from '@/components/ui/EmptyState'

export function NotFoundPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg">
      <EmptyState
        icon={Compass}
        title="Page not found"
        description="The screen you're looking for doesn't exist or has moved."
        action={
          <Link
            to="/dashboard"
            className="inline-flex h-8 items-center justify-center rounded-md border border-transparent bg-accent px-3 text-sm font-medium text-fg-inverse transition-colors duration-fast hover:bg-accent-strong"
          >
            Back to Dashboard
          </Link>
        }
      />
    </div>
  )
}
