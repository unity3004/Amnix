import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from '@/App'
import { setTokens } from '@/services/tokenStore'
import * as authService from '@/services/authService'
import { ApiError } from '@/services/httpClient'

function goTo(path: string) {
  window.history.pushState({}, '', path)
}

describe('login flow', () => {
  beforeEach(() => {
    setTokens(null)
    goTo('/login')
    vi.restoreAllMocks()
  })

  it('logs in successfully and reaches the dashboard (item 4: login state)', async () => {
    vi.spyOn(authService, 'login').mockResolvedValue({
      access_token: 'access-123',
      refresh_token: 'refresh-123',
      token_type: 'Bearer',
      expires_in: 900,
      user: {
        id: 'user-1',
        email: 'analyst@example.com',
        role: 'analyst',
        is_active: true,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    })

    render(<App />)
    const user = userEvent.setup()

    await user.type(screen.getByLabelText(/^email$/i), 'analyst@example.com')
    await user.type(screen.getByLabelText(/^password$/i), 'correct horse battery staple')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByText(/security operations overview/i)).toBeInTheDocument()
    expect(authService.login).toHaveBeenCalledWith({
      email: 'analyst@example.com',
      password: 'correct horse battery staple',
    })
  })

  it('shows the backend-provided safe error message on failure (item 15: API error handling)', async () => {
    vi.spyOn(authService, 'login').mockRejectedValue(new ApiError(401, { detail: 'Invalid email or password.' }, 'Invalid email or password.'))

    render(<App />)
    const user = userEvent.setup()

    await user.type(screen.getByLabelText(/^email$/i), 'analyst@example.com')
    await user.type(screen.getByLabelText(/^password$/i), 'wrong-password')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Invalid email or password.')
    // Never render raw fetch/network internals or the submitted password.
    expect(alert.textContent).not.toMatch(/wrong-password/)
    expect(document.body.textContent).not.toMatch(/TypeError|stack|traceback/i)
  })

  it('never crashes the UI on an unreachable backend, and shows a generic message', async () => {
    vi.spyOn(authService, 'login').mockRejectedValue(new ApiError(0, null, 'Unable to reach the AMNIX backend.'))

    render(<App />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/^email$/i), 'analyst@example.com')
    await user.type(screen.getByLabelText(/^password$/i), 'whatever12345')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByText(/unable to reach the amnix backend/i)).toBeInTheDocument()
  })

  it('logout clears the session and protected routes redirect to login again (item 16)', async () => {
    setTokens({ accessToken: 'a', refreshToken: 'b' })
    goTo('/dashboard')
    render(<App />)

    expect(await screen.findByText(/security operations overview/i)).toBeInTheDocument()

    const user = userEvent.setup()
    // Open the user menu (avatar button in the topbar) then log out.
    const menuButtons = screen.getAllByRole('button', { expanded: false })
    const avatarButton = menuButtons.find((btn) => btn.getAttribute('aria-haspopup') === 'menu')
    expect(avatarButton).toBeTruthy()
    await user.click(avatarButton!)
    await user.click(await screen.findByRole('menuitem', { name: /log out/i }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
    })
  })
})
