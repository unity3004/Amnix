import { useEffect, useState } from 'react'
import { cn } from '@/lib/cn'

export const CONSOLE_SECTIONS = [
  { id: 'console-overview', label: 'Overview' },
  { id: 'console-timeline', label: 'Timeline' },
  { id: 'console-evidence', label: 'Evidence' },
  { id: 'console-alerts', label: 'Alerts' },
  { id: 'console-mitre', label: 'MITRE' },
  { id: 'console-copilot', label: 'Copilot' },
  { id: 'console-notes', label: 'Notes' },
  { id: 'console-audit', label: 'Audit Trail' },
] as const

/** In-page navigation only -- no new routes. Highlights the section
 * currently in view via IntersectionObserver (root: null == the actual
 * browser viewport, which correctly accounts for AppShell's own
 * scrollable <main>, not a fabricated "active" state). Clicking a link
 * scrolls smoothly unless the analyst's OS-level reduced-motion
 * preference is set, matching every other motion-aware surface in
 * AMNIX.
 */
export function IncidentNavRail() {
  const [activeId, setActiveId] = useState<string>(CONSOLE_SECTIONS[0].id)

  useEffect(() => {
    const elements = CONSOLE_SECTIONS.map((s) => document.getElementById(s.id)).filter((el): el is HTMLElement => el !== null)
    if (elements.length === 0) return

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)
        if (visible.length > 0) setActiveId(visible[0].target.id)
      },
      { rootMargin: '-96px 0px -70% 0px', threshold: 0 },
    )
    for (const el of elements) observer.observe(el)
    return () => observer.disconnect()
  }, [])

  const prefersReducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

  return (
    <nav aria-label="Incident console sections" className="sticky top-20 flex flex-col gap-1">
      {CONSOLE_SECTIONS.map((section) => (
        <a
          key={section.id}
          href={`#${section.id}`}
          aria-current={activeId === section.id ? 'true' : undefined}
          onClick={(e) => {
            e.preventDefault()
            document.getElementById(section.id)?.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth', block: 'start' })
          }}
          className={cn(
            'rounded-md px-3 py-1.5 text-xs font-medium transition-colors duration-fast',
            activeId === section.id
              ? 'bg-accent-dim text-accent-strong'
              : 'text-fg-subtle hover:bg-surface-hover hover:text-fg',
          )}
        >
          {section.label}
        </a>
      ))}
    </nav>
  )
}
