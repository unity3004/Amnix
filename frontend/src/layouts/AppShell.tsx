import { useEffect, useState } from 'react'
import { Outlet } from 'react-router-dom'
import { Sidebar } from '@/components/layout/Sidebar'
import { Topbar } from '@/components/layout/Topbar'
import { CommandPalette } from '@/components/layout/CommandPalette'

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const isCombo = (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k'
      if (isCombo) {
        event.preventDefault()
        setPaletteOpen((open) => !open)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Responsive: auto-collapse the sidebar to icon-only below the `lg`
  // breakpoint (1024px) so tablet/mobile widths reclaim ~170px of
  // content space instead of the full 240px sidebar -- the manual
  // collapse toggle still works on top of this; crossing the
  // breakpoint again just re-applies the sensible default for that
  // width, the same behavior most responsive shells use.
  useEffect(() => {
    const query = window.matchMedia('(max-width: 1023px)')
    function apply(e: MediaQueryList | MediaQueryListEvent) {
      setCollapsed(e.matches)
    }
    apply(query)
    query.addEventListener('change', apply)
    return () => query.removeEventListener('change', apply)
  }, [])

  return (
    <div className="flex h-screen w-full overflow-hidden bg-bg">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onOpenCommandPalette={() => setPaletteOpen(true)} />
        <main className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  )
}
