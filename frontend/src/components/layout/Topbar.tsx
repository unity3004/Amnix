import { Bell, Search, LogOut } from 'lucide-react'
import { useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { useAuth } from '@/features/auth/useAuth'

const isMac = typeof navigator !== 'undefined' && /Mac/.test(navigator.platform)

export function Topbar({ onOpenCommandPalette }: { onOpenCommandPalette: () => void }) {
  const { user, logout } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-border bg-bg px-5">
      <button
        type="button"
        onClick={onOpenCommandPalette}
        className="flex h-9 w-full max-w-sm items-center gap-2 rounded-md border border-border bg-surface px-3 text-sm text-fg-subtle transition-colors duration-fast hover:border-border-strong hover:text-fg-muted"
      >
        <Search className="size-4 shrink-0" strokeWidth={1.75} aria-hidden="true" />
        <span className="flex-1 text-left">Search or jump to…</span>
        <kbd className="rounded-sm border border-border-strong bg-surface-elevated px-1.5 py-0.5 text-[10px] font-medium text-fg-subtle">
          {isMac ? '⌘K' : 'Ctrl K'}
        </kbd>
      </button>

      <div className="flex items-center gap-1.5">
        <button
          type="button"
          className="relative flex size-9 items-center justify-center rounded-md text-fg-muted transition-colors duration-fast hover:bg-surface-hover hover:text-fg"
          aria-label="Notifications"
        >
          <Bell className="size-[18px]" strokeWidth={1.75} aria-hidden="true" />
          <span className="absolute right-2 top-2 size-1.5 rounded-full bg-accent" aria-hidden="true" />
        </button>

        <div className="relative">
          <button
            type="button"
            onClick={() => setMenuOpen((open) => !open)}
            className="flex items-center gap-2 rounded-md px-2 py-1.5 transition-colors duration-fast hover:bg-surface-hover"
            aria-haspopup="menu"
            aria-expanded={menuOpen}
          >
            <div className="flex size-7 items-center justify-center rounded-full bg-secondary-dim text-xs font-semibold text-secondary">
              {user?.email.slice(0, 1).toUpperCase() ?? '?'}
            </div>
          </button>

          <AnimatePresence>
            {menuOpen && (
              <motion.div
                role="menu"
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.15, ease: [0.16, 1, 0.3, 1] }}
                className="absolute right-0 top-11 z-20 w-52 rounded-md border border-border bg-surface-elevated p-1 shadow-elevated"
              >
                <div className="border-b border-border px-2.5 py-2">
                  <p className="truncate text-xs font-medium text-fg">{user?.email}</p>
                  <p className="text-[11px] capitalize text-fg-subtle">{user?.role}</p>
                </div>
                <button
                  type="button"
                  role="menuitem"
                  onClick={logout}
                  className="mt-1 flex w-full items-center gap-2 rounded-sm px-2.5 py-1.5 text-left text-sm text-fg-muted transition-colors duration-fast hover:bg-surface-hover hover:text-danger"
                >
                  <LogOut className="size-4" strokeWidth={1.75} aria-hidden="true" />
                  Log out
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </header>
  )
}
