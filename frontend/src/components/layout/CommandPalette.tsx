import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'motion/react'
import { CornerDownLeft } from 'lucide-react'
import { primaryNav } from '@/app/navigation'

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)

  const commands = useMemo(
    () =>
      primaryNav
        .map((item) => ({ label: `Go to ${item.label}`, path: item.path, icon: item.icon }))
        .filter((cmd) => cmd.label.toLowerCase().includes(query.toLowerCase())),
    [query],
  )

  useEffect(() => {
    if (!open) {
      setQuery('')
      setActiveIndex(0)
    }
  }, [open])

  useEffect(() => {
    setActiveIndex(0)
  }, [query])

  function runCommand(path: string) {
    navigate(path)
    onClose()
  }

  function handleKeyDown(event: React.KeyboardEvent) {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActiveIndex((i) => Math.min(i + 1, commands.length - 1))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActiveIndex((i) => Math.max(i - 1, 0))
    } else if (event.key === 'Enter' && commands[activeIndex]) {
      event.preventDefault()
      runCommand(commands[activeIndex].path)
    } else if (event.key === 'Escape') {
      onClose()
    }
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[15vh]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          onClick={onClose}
          role="presentation"
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label="Command palette"
            initial={{ opacity: 0, scale: 0.97, y: -8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: -8 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-lg overflow-hidden rounded-lg border border-border-strong bg-surface-elevated shadow-elevated"
          >
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a command or search…"
              aria-label="Command search"
              className="w-full border-b border-border bg-transparent px-4 py-3.5 text-sm text-fg placeholder:text-fg-subtle focus:outline-none"
            />
            <ul className="max-h-72 overflow-y-auto p-1.5" role="listbox">
              {commands.length === 0 && (
                <li className="px-3 py-6 text-center text-sm text-fg-subtle">No matching commands</li>
              )}
              {commands.map((cmd, index) => (
                <li key={cmd.path}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={index === activeIndex}
                    onMouseEnter={() => setActiveIndex(index)}
                    onClick={() => runCommand(cmd.path)}
                    className={`flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left text-sm transition-colors duration-fast ${
                      index === activeIndex ? 'bg-surface-hover text-fg' : 'text-fg-muted'
                    }`}
                  >
                    <cmd.icon className="size-4 shrink-0 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
                    <span className="flex-1">{cmd.label}</span>
                    {index === activeIndex && (
                      <CornerDownLeft className="size-3.5 text-fg-subtle" aria-hidden="true" />
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
