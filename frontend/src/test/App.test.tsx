import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App } from '@/App'
import { setTokens } from '@/services/tokenStore'

function goTo(path: string) {
  window.history.pushState({}, '', path)
}

describe('App', () => {
  beforeEach(() => {
    setTokens(null)
    goTo('/')
  })

  it('renders without crashing', () => {
    render(<App />)
    expect(document.body).toBeTruthy()
  })

  it('redirects an unauthenticated user away from a protected route to /login', async () => {
    goTo('/dashboard')
    render(<App />)
    expect(await screen.findByRole('heading', { name: /amnix/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/^email$/i)).toBeInTheDocument()
  })

  it('renders the login page at /login', async () => {
    goTo('/login')
    render(<App />)
    expect(await screen.findByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('renders a not-found page for an unknown route', async () => {
    goTo('/this-route-does-not-exist')
    render(<App />)
    expect(await screen.findByText(/page not found/i)).toBeInTheDocument()
  })

  it('redirects an already-authenticated user away from /login to the dashboard', async () => {
    setTokens({ accessToken: 'fake-access', refreshToken: 'fake-refresh' })
    goTo('/login')
    render(<App />)
    // Dashboard renders its static "Security Operations" heading
    // regardless of data state -- proves routing reached the
    // dashboard, independent of whether GET /alerts/GET /events
    // succeed in this network-less test environment.
    expect(await screen.findByRole('heading', { name: /^security operations$/i })).toBeInTheDocument()
  })
})
