import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { EventsPage } from '@/pages/EventsPage'
import { renderWithProviders } from './utils'
import * as eventsService from '@/services/eventsService'
import { ApiError } from '@/services/httpClient'
import type { SecurityEventRead, SecurityEventListResponse } from '@/types/api'

function makeEvent(overrides: Partial<SecurityEventRead> = {}): SecurityEventRead {
  const now = new Date().toISOString()
  return {
    id: `event-${Math.random().toString(36).slice(2)}`,
    event_timestamp: now,
    event_type: 'process_creation',
    source: 'sysmon',
    hostname: 'WIN-CLIENT-04',
    username: 'jdoe',
    source_ip: '10.0.0.9',
    raw_data: {},
    created_at: now,
    ...overrides,
  }
}
function resp(items: SecurityEventRead[]): SecurityEventListResponse {
  return { items, limit: 25, offset: 0 }
}

afterEach(() => vi.restoreAllMocks())

describe('EventsPage', () => {
  it('renders REAL event data in a table', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ event_type: 'network_connection', hostname: 'endpoint-12' })]))
    renderWithProviders(<EventsPage />, { route: '/events' })

    expect(await screen.findByText('network_connection')).toBeInTheDocument()
    expect(screen.getByText('endpoint-12')).toBeInTheDocument()
  })

  it('shows loading skeleton, then a distinct empty state per filter presence', async () => {
    vi.spyOn(eventsService, 'listEvents').mockReturnValue(new Promise(() => {}))
    const { container } = renderWithProviders(<EventsPage />, { route: '/events' })
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('shows "No security events" with no filters and "No events found" with filters', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderWithProviders(<EventsPage />, { route: '/events' })
    expect(await screen.findByText('No security events')).toBeInTheDocument()

    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderWithProviders(<EventsPage />, { route: '/events?source=sysmon' })
    expect(await screen.findByText('No events found')).toBeInTheDocument()
  })

  it('shows a safe error state on failure, with retry', async () => {
    const mock = vi.spyOn(eventsService, 'listEvents').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderWithProviders(<EventsPage />, { route: '/events' })
    expect(await screen.findByText(/unable to retrieve telemetry/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)

    mock.mockResolvedValue(resp([]))
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByText('No security events')).toBeInTheDocument())
  })

  it('applies event_type/source filters as real backend query parameters', async () => {
    const mock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderWithProviders(<EventsPage />, { route: '/events' })
    await screen.findByText('No security events')

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Event type'), 'authentication_failure')
    await user.type(screen.getByLabelText('Source'), 'sysmon')
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ event_type: 'authentication_failure', source: 'sysmon' })
    })
  })

  it('paginates using limit/offset, never claiming a total', async () => {
    const fullPage = Array.from({ length: 25 }, () => makeEvent())
    const mock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp(fullPage))
    renderWithProviders(<EventsPage />, { route: '/events' })
    await screen.findByText('Page 1')
    expect(screen.queryByText(/total/i)).not.toBeInTheDocument()

    await userEvent.setup().click(screen.getByRole('button', { name: /^next$/i }))
    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ offset: 25 })
    })
  })

  it('manual refresh re-fetches', async () => {
    const mock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderWithProviders(<EventsPage />, { route: '/events' })
    await screen.findByText('No security events')
    expect(mock).toHaveBeenCalledTimes(1)

    await userEvent.setup().click(screen.getByRole('button', { name: /refresh dashboard data/i }))
    await waitFor(() => expect(mock).toHaveBeenCalledTimes(2))
  })

  it('handles a 401 from GET /events gracefully without crashing', async () => {
    vi.spyOn(eventsService, 'listEvents').mockRejectedValue(new ApiError(401, { detail: 'Could not validate credentials.' }, 'Could not validate credentials.'))
    renderWithProviders(<EventsPage />, { route: '/events' })
    expect(await screen.findByText(/unable to retrieve telemetry/i)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /^events$/i })).toBeInTheDocument()
  })
})
