import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { ThreatHuntingPage } from '@/pages/ThreatHuntingPage'
import { renderWithProviders } from './utils'
import * as eventsService from '@/services/eventsService'
import { ApiError } from '@/services/httpClient'
import type { AlertListResponse, AlertRead, SecurityEventListResponse, SecurityEventRead } from '@/types/api'

afterEach(() => vi.restoreAllMocks())

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
    source_event_ids: [],
    ...overrides,
  }
}
function alertResp(items: AlertRead[]): AlertListResponse {
  return { items, limit: 50, offset: 0 }
}

function makeEvent(overrides: Partial<SecurityEventRead> = {}): SecurityEventRead {
  const now = new Date().toISOString()
  return {
    id: `event-${Math.random().toString(36).slice(2)}`,
    event_timestamp: now,
    event_type: 'authentication_failure',
    source: 'auth-log',
    hostname: 'workstation-07',
    username: 'jdoe',
    source_ip: '10.0.0.5',
    destination_ip: '10.0.0.1',
    raw_data: {},
    created_at: now,
    ...overrides,
  }
}
function resp(items: SecurityEventRead[]): SecurityEventListResponse {
  return { items, limit: 50, offset: 0 }
}

function renderHunting(route = '/threat-hunting') {
  return renderWithProviders(
    <Routes>
      <Route path="/threat-hunting" element={<ThreatHuntingPage />} />
      <Route path="/events/:eventId" element={<div>EVENT DETAIL MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('ThreatHuntingPage: rendering', () => {
  it('renders the hunting header and structured filter controls', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderHunting()

    expect(await screen.findByRole('heading', { name: 'Threat Hunting' })).toBeInTheDocument()
    expect(screen.getByLabelText('Event type')).toBeInTheDocument()
    expect(screen.getByLabelText('Source')).toBeInTheDocument()
    expect(screen.getByLabelText('Host')).toBeInTheDocument()
    expect(screen.getByLabelText('User')).toBeInTheDocument()
    expect(screen.getByLabelText('Source IP')).toBeInTheDocument()
    expect(screen.getByLabelText('Destination IP')).toBeInTheDocument()
    expect(screen.getByLabelText('Time window')).toBeInTheDocument()
  })

  it('renders REAL event data in the results table', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(
      resp([makeEvent({ event_type: 'powershell_execution', hostname: 'WIN-7A3B', username: 'asmith' })]),
    )
    renderHunting()

    expect(await screen.findByText('powershell_execution')).toBeInTheDocument()
    expect(screen.getByText('WIN-7A3B')).toBeInTheDocument()
    expect(screen.getByText('asmith')).toBeInTheDocument()
  })

  it('never renders a fabricated threat score, confidence, or total', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent()]))
    renderHunting()

    await screen.findByText('authentication_failure')
    expect(document.body.textContent).not.toMatch(/threat score|risk score|confidence:\s*\d+%|attacker likelihood|compromise probability/i)
    expect(document.body.textContent).not.toMatch(/total events:\s*\d/i)
  })
})

describe('ThreatHuntingPage: loading / empty / error states', () => {
  it('shows a loading skeleton before the hunt resolves', () => {
    vi.spyOn(eventsService, 'listEvents').mockReturnValue(new Promise(() => {}))
    const { container } = renderHunting()
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('distinguishes an unfiltered empty window from a filtered empty result', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderHunting()
    expect(await screen.findByText('No events in this time window.')).toBeInTheDocument()

    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderHunting('/threat-hunting?hostname=WIN-9999')
    expect(await screen.findByText('No events match this hunt.')).toBeInTheDocument()
  })

  it('shows a safe error state with retry, never a raw exception', async () => {
    const mock = vi.spyOn(eventsService, 'listEvents').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderHunting()
    expect(await screen.findByText(/unable to run this hunt/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)

    mock.mockResolvedValue(resp([]))
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByText('No events in this time window.')).toBeInTheDocument())
  })
})

describe('ThreatHuntingPage: filter construction', () => {
  it('applies structured filters as real GET /events query parameters', async () => {
    const mock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderHunting()
    await screen.findByText('No events in this time window.')

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Host'), 'WIN-7A3B')
    await user.type(screen.getByLabelText('User'), 'jdoe')
    await user.type(screen.getByLabelText('Source IP'), '10.0.0.5')
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ hostname: 'WIN-7A3B', username: 'jdoe', source_ip: '10.0.0.5' })
    })
  })

  it('changing the time window sets a real since bound, never a fabricated total window', async () => {
    const mock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderHunting()
    await screen.findByText('No events in this time window.')

    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Time window'), String(7 * 24 * 60))
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall?.since).toBeDefined()
      const sinceMs = new Date(lastCall!.since as string).getTime()
      const expectedMs = Date.now() - 7 * 24 * 60 * 60 * 1000
      expect(Math.abs(sinceMs - expectedMs)).toBeLessThan(60_000)
    })
  })

  it('"All time" omits the since bound entirely', async () => {
    const mock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderHunting()
    await screen.findByText('No events in this time window.')

    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Time window'), 'all')
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall?.since).toBeUndefined()
    })
  })

  it('paginates using limit/offset, never claiming a total', async () => {
    const fullPage = Array.from({ length: 50 }, () => makeEvent())
    const mock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp(fullPage))
    renderHunting()
    await screen.findByText('Page 1')

    await userEvent.setup().click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ offset: 50 })
    })
  })
})

describe('ThreatHuntingPage: Event Inspector (zero additional fetch)', () => {
  it('selecting a row shows real evidence without any per-event API call', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(
      resp([makeEvent({ id: 'event-focus', process_name: 'powershell.exe', file_hash: 'a'.repeat(64) })]),
    )
    const getEventSpy = vi.spyOn(eventsService, 'getEvent')
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderHunting()

    await screen.findByText('No event selected.')
    await userEvent.setup().click(await screen.findByText('authentication_failure'))

    expect(await screen.findByText('powershell.exe')).toBeInTheDocument()
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument()
    expect(getEventSpy).not.toHaveBeenCalled()
  })

  it('"Open Full Event Detail" links to the real, existing event permalink route', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ id: 'event-999' })]))
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderHunting()

    await userEvent.setup().click(await screen.findByText('authentication_failure'))
    const link = await screen.findByRole('link', { name: /open full event detail/i })
    expect(link).toHaveAttribute('href', '/events/event-999')
    await userEvent.setup().click(link)
    expect(await screen.findByText('EVENT DETAIL MARKER')).toBeInTheDocument()
  })
})

describe('ThreatHuntingPage: pivot behavior', () => {
  it('pivoting on a real event field constructs a real GET /events request, preserving the active window and other filters', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(
      resp([makeEvent({ id: 'event-pivot', hostname: 'WIN-7A3B', event_type: 'powershell_execution' })]),
    )
    const mock = vi.spyOn(eventsService, 'listEvents')
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderHunting('/threat-hunting?event_type=powershell_execution&window=60')

    const user = userEvent.setup()
    await user.click(await screen.findByText('powershell_execution'))
    await user.click(screen.getByRole('button', { name: /same host/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ hostname: 'WIN-7A3B', event_type: 'powershell_execution' })
      expect(lastCall?.since).toBeDefined()
    })
  })

  it('never shows a pivot button for a field the backend cannot filter on', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ process_name: 'powershell.exe' })]))
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderHunting()

    await userEvent.setup().click(await screen.findByText('authentication_failure'))
    expect(screen.queryByRole('button', { name: /same process/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /same file hash/i })).not.toBeInTheDocument()
  })

  it('only shows a pivot button for a field that is actually present on the selected event', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ destination_ip: null })]))
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderHunting()

    await userEvent.setup().click(await screen.findByText('authentication_failure'))
    expect(screen.getByRole('button', { name: /same host/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /same destination ip/i })).not.toBeInTheDocument()
  })
})

describe('ThreatHuntingPage: no N+1', () => {
  it('renders many events from a single request, never one request per row', async () => {
    const events = Array.from({ length: 10 }, (_, i) => makeEvent({ id: `evt-${i}` }))
    const mock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp(events))
    renderHunting()

    await screen.findByText('Page 1')
    await waitFor(() => expect(mock).toHaveBeenCalledTimes(1))
  })
})

describe('Step 12Y: Threat Hunting Linked Alerts integration (GET /events/{id}/alerts)', () => {
  it('never fetches linked alerts for any row while nothing is selected', async () => {
    const events = Array.from({ length: 10 }, (_, i) => makeEvent({ id: `evt-${i}` }))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp(events))
    const alertsSpy = vi.spyOn(eventsService, 'getEventAlerts')
    renderHunting()

    await screen.findByText('Page 1')
    expect(alertsSpy).not.toHaveBeenCalled()
  })

  it('fetches linked alerts exactly once, for the real selected event, when the inspector is explicitly opened', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ id: 'event-focus' })]))
    const alertsSpy = vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderHunting()

    await userEvent.setup().click(await screen.findByText('authentication_failure'))

    await waitFor(() => expect(alertsSpy).toHaveBeenCalledTimes(1))
    expect(alertsSpy).toHaveBeenCalledWith('event-focus')
  })

  it('shows an honest empty state when the selected event has no linked alerts', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ id: 'event-empty' })]))
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderHunting()

    await userEvent.setup().click(await screen.findByText('authentication_failure'))
    expect(await screen.findByText('No alerts are linked to this event.')).toBeInTheDocument()
  })

  it('renders real linked alerts once selected, and re-fetches for a newly selected event', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(
      resp([makeEvent({ id: 'event-a', event_type: 'authentication_failure' }), makeEvent({ id: 'event-b', event_type: 'powershell_execution' })]),
    )
    const alertsSpy = vi.spyOn(eventsService, 'getEventAlerts').mockImplementation((eventId) =>
      Promise.resolve(alertResp(eventId === 'event-a' ? [makeAlert({ title: 'Alert for A' })] : [])),
    )
    renderHunting()

    const user = userEvent.setup()
    await user.click(await screen.findByText('authentication_failure'))
    expect(await screen.findByText('Alert for A')).toBeInTheDocument()

    await user.click(screen.getByText('powershell_execution'))
    await screen.findByText('No alerts are linked to this event.')

    expect(alertsSpy).toHaveBeenNthCalledWith(1, 'event-a')
    expect(alertsSpy).toHaveBeenNthCalledWith(2, 'event-b')
  })
})

describe('Step 12Z: Current Hunt context (selected event + real linked-alert count)', () => {
  it('shows no selected-event context, and no linked-alert count, until an event is actually selected', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent()]))
    renderHunting()

    await screen.findByText('Page 1')
    expect(screen.queryByText(/Selected:/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Linked alerts:/)).not.toBeInTheDocument()
  })

  it('names the real selected event and its real linked-alert count once selected -- deduped to the one shared request', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ id: 'event-ctx', event_type: 'powershell_execution' })]))
    const alertsSpy = vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([makeAlert(), makeAlert()]))
    renderHunting()

    await userEvent.setup().click(await screen.findByText('powershell_execution'))

    await waitFor(() => expect(screen.getByText(/Linked alerts: 2/)).toBeInTheDocument())
    expect(screen.getAllByText('powershell_execution').length).toBeGreaterThan(0)
    // Three components (HuntContextBar, EventInspectorPanel, LinkedAlertsPanel)
    // all read this same event's linked alerts -- still exactly one request.
    expect(alertsSpy).toHaveBeenCalledTimes(1)
  })

  it('never implies the current hunt has been saved', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([]))
    renderHunting()

    expect(await screen.findByText(/\(not saved\)/)).toBeInTheDocument()
  })
})

describe('Step 12Z: honest empty-alert exploratory guidance', () => {
  it('offers to continue hunting -- never a fake "Create Alert"/"Promote to Incident" action -- when the selected event has no linked alerts', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ id: 'event-empty' })]))
    vi.spyOn(eventsService, 'getEventAlerts').mockResolvedValue(alertResp([]))
    renderHunting()

    await userEvent.setup().click(await screen.findByText('authentication_failure'))

    expect(await screen.findByText(/continue hunting using the pivots above/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/no threat|no compromise|no detection/i)
    expect(screen.queryByRole('button', { name: /create alert/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /promote to incident/i })).not.toBeInTheDocument()
  })

  it('does not show the "continue hunting" guidance while a linked-alert lookup is still pending', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(resp([makeEvent({ id: 'event-pending' })]))
    vi.spyOn(eventsService, 'getEventAlerts').mockReturnValue(new Promise(() => {}))
    renderHunting()

    await userEvent.setup().click(await screen.findByText('authentication_failure'))
    expect(screen.queryByText(/continue hunting using the pivots above/i)).not.toBeInTheDocument()
  })
})
