import { NavLink } from 'react-router-dom'
import { motion } from 'motion/react'
import { Settings, ChevronsLeft, ChevronsRight } from 'lucide-react'
import { Logo } from './Logo'
import { primaryNav } from '@/app/navigation'
import { cn } from '@/lib/cn'
import { useAuth } from '@/features/auth/useAuth'

export function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const { user } = useAuth()

  return (
    <aside
      className={cn(
        'flex h-full shrink-0 flex-col border-r border-border bg-bg-inset transition-[width] duration-base ease-out-premium',
        collapsed ? 'w-[68px]' : 'w-60',
      )}
      aria-label="Primary navigation"
    >
      <div className="flex h-14 items-center gap-2.5 border-b border-border px-4">
        <Logo className="size-6 shrink-0" />
        {!collapsed && (
          <span className="text-sm font-semibold tracking-[0.14em] text-fg">AMNIX</span>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto px-2.5 py-4">
        <ul className="flex flex-col gap-0.5">
          {primaryNav.map((item) => (
            <li key={item.path}>
              <NavLink
                to={item.path}
                className={({ isActive }) =>
                  cn(
                    'group relative flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium transition-colors duration-fast ease-out-premium',
                    isActive ? 'text-fg' : 'text-fg-muted hover:bg-surface-hover hover:text-fg',
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <motion.span
                        layoutId="sidebar-active-indicator"
                        className="absolute inset-0 rounded-md bg-surface-elevated ring-1 ring-inset ring-border-strong"
                        transition={{ type: 'spring', stiffness: 500, damping: 40 }}
                      />
                    )}
                    {isActive && (
                      <motion.span
                        layoutId="sidebar-active-rail"
                        className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-accent"
                        transition={{ type: 'spring', stiffness: 500, damping: 40 }}
                      />
                    )}
                    <item.icon
                      className={cn('relative z-10 size-[18px] shrink-0', isActive && 'text-accent')}
                      strokeWidth={1.75}
                      aria-hidden="true"
                    />
                    {!collapsed && <span className="relative z-10 truncate">{item.label}</span>}
                  </>
                )}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      <div className="border-t border-border px-2.5 py-3">
        <NavLink
          to="/settings"
          className={({ isActive }) =>
            cn(
              'flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium text-fg-muted transition-colors duration-fast hover:bg-surface-hover hover:text-fg',
              isActive && 'text-fg',
            )
          }
        >
          <Settings className="size-[18px] shrink-0" strokeWidth={1.75} aria-hidden="true" />
          {!collapsed && <span>Settings</span>}
        </NavLink>

        {!collapsed && user && (
          <div className="mt-3 flex items-center gap-2.5 rounded-md px-2.5 py-2">
            <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-secondary-dim text-xs font-semibold text-secondary">
              {user.email.slice(0, 1).toUpperCase()}
            </div>
            <div className="min-w-0">
              <p className="truncate text-xs font-medium text-fg">{user.email}</p>
              <p className="text-[11px] capitalize text-fg-subtle">{user.role}</p>
            </div>
          </div>
        )}

        <button
          type="button"
          onClick={onToggle}
          className="mt-2 flex w-full items-center justify-center gap-2 rounded-md py-1.5 text-fg-subtle transition-colors duration-fast hover:bg-surface-hover hover:text-fg"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronsRight className="size-4" /> : <ChevronsLeft className="size-4" />}
        </button>
      </div>
    </aside>
  )
}
