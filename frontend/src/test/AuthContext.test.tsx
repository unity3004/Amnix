import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useAuth } from '@/features/auth/useAuth'
import * as authService from '@/services/authService'
import { setTokens } from '@/services/tokenStore'
import { renderWithProviders } from './utils'

function RoleProbe() {
  const { user, login } = useAuth()
  return (
    <>
      <button onClick={() => login('root@example.com', 'x')}>trigger</button>
      <div data-testid="role-probe">{user?.role ?? 'none'}</div>
    </>
  )
}

describe('AuthContext role foundation (item 13: role-aware navigation foundation)', () => {
  it('exposes the authenticated user\'s real role (admin), the data foundation future role-aware nav will read', async () => {
    setTokens(null)
    vi.spyOn(authService, 'login').mockResolvedValue({
      access_token: 'a',
      refresh_token: 'b',
      token_type: 'Bearer',
      expires_in: 900,
      user: {
        id: 'u1',
        email: 'root@example.com',
        role: 'admin',
        is_active: true,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    })

    renderWithProviders(<RoleProbe />)
    expect(screen.getByTestId('role-probe')).toHaveTextContent('none')

    await userEvent.setup().click(screen.getByText('trigger'))
    expect(await screen.findByTestId('role-probe')).toHaveTextContent('admin')
  })

  it('exposes "analyst" for a plain analyst account, distinct from admin', async () => {
    setTokens(null)
    vi.spyOn(authService, 'login').mockResolvedValue({
      access_token: 'a',
      refresh_token: 'b',
      token_type: 'Bearer',
      expires_in: 900,
      user: {
        id: 'u2',
        email: 'analyst@example.com',
        role: 'analyst',
        is_active: true,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    })

    renderWithProviders(<RoleProbe />)
    await userEvent.setup().click(screen.getByText('trigger'))
    expect(await screen.findByTestId('role-probe')).toHaveTextContent('analyst')
  })
})
