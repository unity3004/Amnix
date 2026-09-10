import { cn } from '@/lib/cn'

/** Shimmer skeleton — the one loading primitive every list/card/chart
 * loading state composes from, so motion/timing stays consistent
 * app-wide (brief §21: avoid scattering ad-hoc "Loading..." text).
 */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'animate-pulse rounded-md bg-surface-elevated',
        className,
      )}
      aria-hidden="true"
    />
  )
}

export function SkeletonCard() {
  return (
    <div className="rounded-lg border border-border bg-surface p-5">
      <Skeleton className="h-3 w-24" />
      <Skeleton className="mt-4 h-7 w-16" />
      <Skeleton className="mt-3 h-3 w-32" />
    </div>
  )
}

export function SkeletonRow() {
  return (
    <div className="flex items-center gap-4 px-5 py-3.5">
      <Skeleton className="h-4 w-16 shrink-0" />
      <Skeleton className="h-4 flex-1" />
      <Skeleton className="h-4 w-20 shrink-0" />
      <Skeleton className="h-4 w-14 shrink-0" />
    </div>
  )
}
