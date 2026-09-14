import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { EventDetailPage } from '@/pages/EventDetailPage'
import { renderWithProviders } from './utils'
import * as eventsService from '@/services/eventsService'
import { ApiError } from '@/services/httpClient'
import type { AlertListResponse, AlertRead, SecurityEventRead } from '@/types/api'

afterEach(() => vi.restoreAllMocks())

function makeEvent(overrides: Partial<SecurityEventRead> = {}): SecurityEventRead {
  const now = new Date().toISOString()
  return {
    id: 'event-detail-1',
    event_timestamp: now,
    event_type: 'authentication_failure',
    source: 'auth-log',
    raw_data: {},
    created_at: now,
    ...overrides,
  }
}

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: `alert-${Math.random().toString(36).slice(2)}`,
    rule_id: 'brute_force_authentication',
    title: 'Brute force authentication detected',
    description: 'd',
    severity: 'high',
    confidence: 'high',
    status: 'new',
    first_seen: now,
    last_seen: now,
    created_at: now,
    updated_at: now,
    evidence: {},
    alert_metadata: null,
    source_event_ids: ['event-detail-1'],
    ...overrides,
  }
}

function alertResp(items: AlertRead[]): AlertListResponse {
  return { items, limit: 50, offset: 0 }
}

function renderEventDetail(route = '/events/event-detail-1') {
  return renderWithProviders(
    <Routes>
      <Route path="/events/:eventId" element={<EventDetailPage />} />
      <Route path="/alerts/:alertId" element={<div>ALERT DETAIL MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('Step 12Y: authoritative Linked Alerts (GET /events/{id}/alerts)', () => {
  it('shows a loading state before the linked-alerts request resolves', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    vi.spyOn(eventsService, 'getEventAlerts').mockReturnValue(new Promise(() => {}))
    const { container } = renderEventDetail()

    await screen.findByText('authentication_failure')
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('shows an honest empty state -- never "No threats detected"', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderEventDetail()

    expect(await screen.findByText('No alerts are linked to this event.')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/no threats detected/i)
  })

  it('shows a safe error state with retry, never a raw exception', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    const mock = vi.spyOn(eventsService, 'getEventAlerts').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderEventDetail()

    expect(await screen.findByText(/linked alerts could not be loaded/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)

    mock.mockResolvedValue(alertResp([]))
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByText('No alerts are linked to this event.')).toBeInTheDocument())
  })

  it('renders one real linked alert with its real fields', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([makeAlert({ title: 'Real brute-force alert' })]))
    renderEventDetail()

    expect(await screen.findByText('Real brute-force alert')).toBeInTheDocument()
    expect(screen.getByText('Linked Alerts (1)')).toBeInTheDocument()
    expect(screen.getByText('brute_force_authentication')).toBeInTheDocument()
    expect(screen.getByText('high confidence')).toBeInTheDocument()
  })

  it('renders multiple linked alerts -- never assumes exactly one', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(
      alertResp([makeAlert({ title: 'Alert A' }), makeAlert({ title: 'Alert B' })]),
    )
    renderEventDetail()

    expect(await screen.findByText('Linked Alerts (2)')).toBeInTheDocument()
    expect(screen.getByText('Alert A')).toBeInTheDocument()
    expect(screen.getByText('Alert B')).toBeInTheDocument()
  })

  it('navigates to the real, existing Alert Detail route when a linked alert is opened', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([makeAlert({ id: 'alert-999' })]))
    renderEventDetail()

    const link = await screen.findByRole('link', { name: /brute force authentication detected/i })
    expect(link).toHaveAttribute('href', '/alerts/alert-999')
    await userEvent.setup().click(link)
    expect(await screen.findByText('ALERT DETAIL MARKER')).toBeInTheDocument()
  })

  it('fetches linked alerts exactly once, scoped to the real event ID -- no polling, no extra requests', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    const spy = vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderEventDetail()

    await screen.findByText('No alerts are linked to this event.')
    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy).toHaveBeenCalledWith('event-detail-1')
  })

  it('never fabricates a relationship or a threat score alongside the linked alerts', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([makeAlert()]))
    renderEventDetail()

    await screen.findByText('Linked Alerts (1)')
    expect(document.body.textContent).not.toMatch(/threat score|risk score|compromise probability|attacker likelihood/i)
  })
})
