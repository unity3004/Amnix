import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { motion } from 'motion/react'
import { Lock, Mail, ShieldCheck } from 'lucide-react'
import { Logo } from '@/components/layout/Logo'
import { Button } from '@/components/ui/Button'
import { useAuth } from '@/features/auth/useAuth'
import { ApiError } from '@/services/httpClient'

export function LoginPage() {
  const { login, isAuthenticating } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    try {
      await login(email, password)
      const redirectTo = (location.state as { from?: Location })?.from?.pathname ?? '/dashboard'
      navigate(redirectTo, { replace: true })
    } catch (err) {
      // ApiError.message is always the backend's own safe, generic
      // detail (see AMNIX's Step 11O contract review) -- never a stack
      // trace or credential-bearing text. Never log the password here.
      setError(err instanceof ApiError ? err.message : 'Unable to sign in.')
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-bg-inset px-4">
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(60% 50% at 50% 0%, color-mix(in srgb, var(--color-accent) 8%, transparent), transparent)',
        }}
        aria-hidden="true"
      />

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
        className="relative w-full max-w-sm"
      >
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <Logo className="size-10" />
          <div>
            <h1 className="text-lg font-semibold tracking-[0.08em] text-fg">AMNIX</h1>
            <p className="mt-1 text-sm text-fg-subtle">Security Operations Copilot</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-lg border border-border bg-surface p-6 shadow-panel"
          noValidate
        >
          <div className="mb-5 flex items-center gap-2 text-xs text-fg-subtle">
            <ShieldCheck className="size-3.5 text-accent" strokeWidth={1.75} aria-hidden="true" />
            Sign in with your analyst credentials
          </div>

          <label htmlFor="email" className="mb-1.5 block text-xs font-medium text-fg-muted">
            Email
          </label>
          <div className="relative mb-4">
            <Mail className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="h-10 w-full rounded-md border border-border bg-bg-inset pl-9 pr-3 text-sm text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
              placeholder="you@organization.com"
            />
          </div>

          <label htmlFor="password" className="mb-1.5 block text-xs font-medium text-fg-muted">
            Password
          </label>
          <div className="relative mb-5">
            <Lock className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="h-10 w-full rounded-md border border-border bg-bg-inset pl-9 pr-3 text-sm text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
              placeholder="••••••••••••"
            />
          </div>

          {error && (
            <p role="alert" className="mb-4 rounded-md border border-danger/30 bg-danger-dim px-3 py-2 text-xs text-danger">
              {error}
            </p>
          )}

          <Button type="submit" variant="primary" className="w-full" disabled={isAuthenticating}>
            {isAuthenticating ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>

        <p className="mt-6 text-center text-xs text-fg-subtle">
          Access is limited to registered SOC analysts and administrators.
        </p>
      </motion.div>
    </div>
  )
}
