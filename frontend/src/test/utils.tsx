import type { ReactElement, ReactNode } from 'react'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthContext, AuthProvider } from '@/features/auth/AuthContext'
import type { UserRead } from '@/types/api'

/** `authUser`, when provided, bypasses the real login flow and injects
 * an already-authenticated AuthContext value directly -- needed for
 * components (e.g. CaseOwnerPanel) that read useAuth().user to decide
 * what to render, since AuthProvider itself only ever populates `user`
 * as the result of an actual login() call (see AuthContext.test.tsx).
 * Omitting it preserves every existing test's real, unauthenticated-user
 * default behavior unchanged.
 */
export function renderWithProviders(
  ui: ReactElement,
  { route = '/', authUser }: { route?: string; authUser?: UserRead } = {},
) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })

  function Wrapper({ children }: { children: ReactNode }) {
    const authTree = authUser ? (
      <AuthContext
        value={{
          user: authUser,
          isAuthenticated: true,
          isAuthenticating: false,
          login: async () => {},
          logout: () => {},
        }}
      >
        {children}
      </AuthContext>
    ) : (
      <AuthProvider>{children}</AuthProvider>
    )
    return (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[route]}>{authTree}</MemoryRouter>
      </QueryClientProvider>
    )
  }

  return render(ui, { wrapper: Wrapper })
}
