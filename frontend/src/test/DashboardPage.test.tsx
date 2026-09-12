import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { DashboardPage } from '@/pages/DashboardPage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
import * as eventsService from '@/services/eventsService'
import * as healthService from '@/services/healthService'
import { ApiError } from '@/services/httpClient'
import type { AlertRead, AlertListResponse, SecurityEventListResponse, SecurityEventRead } from '@/types/api'

const originalMatchMedia = window.matchMedia
beforeEach(() => {
  window.matchMedia = (query: string) =>
    ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList
})
afterEach(() => {
  window.matchMedia = originalMatchMedia
  vi.restoreAllMocks()
})

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: `alert-${Math.random().toString(36).slice(2)}`,
    rule_id: 'brute_force_authentication',
    title: 'Brute Force Authentication',
    description: 'd',
    severity: 'critical',
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

function makeEvent(overrides: Partial<SecurityEventRead> = {}): SecurityEventRead {
  const now = new Date().toISOString()
  return {
    id: `event-${Math.random().toString(36).slice(2)}`,
    event_timestamp: now,
    event_type: 'authentication_failure',
    source: 'test-source',
    hostname: 'workstation-01',
    username: 'jdoe',
    source_ip: '10.0.0.5',
    raw_data: {},
    created_at: now,
    ...overrides,
  }
}

function alertsResponse(items: AlertRead[]): AlertListResponse {
  return { items, limit: 50, offset: 0 }
}
function eventsResponse(items: SecurityEventRead[]): SecurityEventListResponse {
  return { items, limit: 50, offset: 0 }
}

function mockHealthy() {
  vi.spyOn(healthService, 'getHealth').mockResolvedValue({ status: 'healthy', service: 'amnix' })
}

describe('DashboardPage (Step 12C: real data)', () => {
  it('renders the static header regardless of data state (item: loading state)', () => {
    vi.spyOn(alertsService, 'listAlerts').mockReturnValue(new Promise(() => {}))
    vi.spyOn(eventsService, 'listEvents').mockReturnValue(new Promise(() => {}))
    mockHealthy()
    renderWithProviders(<DashboardPage />)
    expect(screen.getByRole('heading', { name: /^security operations$/i })).toBeInTheDocument()
  })

  it('shows skeleton loading state before data resolves', () => {
    vi.spyOn(alertsService, 'listAlerts').mockReturnValue(new Promise(() => {}))
    vi.spyOn(eventsService, 'listEvents').mockReturnValue(new Promise(() => {}))
    mockHealthy()
    const { container } = renderWithProviders(<DashboardPage />)
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('renders REAL alert data in Active Threats and the instrumentation strip (not demo data)', async () => {
    const alerts = [
      makeAlert({ id: 'a1', title: 'Brute Force Authentication', severity: 'critical' }),
      makeAlert({ id: 'a2', title: 'Suspicious PowerShell Execution', rule_id: 'suspicious_powershell_execution', severity: 'high' }),
    ]
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResponse(alerts))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)

    expect(await screen.findByText('Brute Force Authentication')).toBeInTheDocument()
    expect(screen.getByText('Suspicious PowerShell Execution')).toBeInTheDocument()
    // The instrumentation strip's "Active Alerts" count must equal the
    // exact number of items the mocked API returned (2) -- proving it
    // is not a hardcoded demo number like the old "128". ("2" may
    // legitimately appear more than once elsewhere on the page, e.g.
    // in the MITRE detection count, so scope to the strip itself.)
    const activeAlertsLabel = screen.getByText('Active Alerts (recent)')
    const activeAlertsValue = activeAlertsLabel.nextElementSibling
    expect(activeAlertsValue).toHaveTextContent('2')
  })

  it('renders REAL event data in the Live Event Stream', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResponse([]))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(
      eventsResponse([makeEvent({ id: 'e1', event_type: 'process_creation', hostname: 'WIN-CLIENT-04' })]),
    )
    mockHealthy()

    renderWithProviders(<DashboardPage />)

    expect(await screen.findByText('process_creation')).toBeInTheDocument()
    expect(screen.getByText(/WIN-CLIENT-04/)).toBeInTheDocument()
  })

  it('renders a polished empty state for alerts and events when both are empty', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResponse([]))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)

    expect(await screen.findByText(/no active threats/i)).toBeInTheDocument()
    expect(await screen.findByText(/waiting for telemetry/i)).toBeInTheDocument()
  })

  it('renders an independent error state per panel without destroying the rest of the dashboard (error isolation)', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'Unable to reach the AMNIX backend.'))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([makeEvent({ event_type: 'network_connection' })]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)

    expect(await screen.findByText(/unable to retrieve alerts/i)).toBeInTheDocument()
    // Events must still render successfully -- one resource failing must
    // never destroy the other (brief §19).
    expect(await screen.findByText('network_connection')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback/i)
  })

  it('shows a degraded state (not a crash) when a subsequent refresh fails after an initial success', async () => {
    const alertsMock = vi
      .spyOn(alertsService, 'listAlerts')
      .mockResolvedValueOnce(alertsResponse([makeAlert({ id: 'a1' })]))
      .mockRejectedValueOnce(new ApiError(500, null, 'boom'))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)
    expect(await screen.findByText('LIVE')).toBeInTheDocument()
    expect(await screen.findByText('Brute Force Authentication')).toBeInTheDocument()

    await userEvent.setup().click(screen.getByRole('button', { name: /refresh dashboard data/i }))

    await waitFor(() => {
      expect(screen.getByText('DEGRADED')).toBeInTheDocument()
    })
    // Previous data must remain visible -- degraded means stale-but-usable.
    expect(screen.getByText('Brute Force Authentication')).toBeInTheDocument()
    expect(alertsMock).toHaveBeenCalledTimes(2)
  })

  it('manual refresh re-fetches both resources exactly once each', async () => {
    const alertsMock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResponse([]))
    const eventsMock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)
    await screen.findByText(/no active threats/i)
    expect(alertsMock).toHaveBeenCalledTimes(1)
    expect(eventsMock).toHaveBeenCalledTimes(1)

    await userEvent.setup().click(screen.getByRole('button', { name: /refresh dashboard data/i }))

    await waitFor(() => {
      expect(alertsMock).toHaveBeenCalledTimes(2)
      expect(eventsMock).toHaveBeenCalledTimes(2)
    })
    // Called with the same bounded page size every time -- one events
    // request, one alerts request per cycle, never per-panel.
    expect(alertsMock).toHaveBeenCalledWith({ limit: 50 })
    expect(eventsMock).toHaveBeenCalledWith({ limit: 50 })
  })

  it('shows a real "last updated" timestamp after a successful load', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResponse([]))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)
    expect(await screen.findByText(/last updated:/i)).toBeInTheDocument()
    expect(await screen.findByText(/just now|sec ago/i)).toBeInTheDocument()
  })

  it('maps alert severity to the correct visible label (severity mapping)', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResponse([makeAlert({ severity: 'critical' })]))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)
    expect(await screen.findAllByText('critical')).not.toHaveLength(0)
  })

  it('aggregates MITRE technique counts from real alert rule_ids', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResponse([
        makeAlert({ id: 'a1', rule_id: 'brute_force_authentication' }),
        makeAlert({ id: 'a2', rule_id: 'brute_force_authentication' }),
        makeAlert({ id: 'a3', rule_id: 'suspicious_powershell_execution' }),
      ]),
    )
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)
    expect(await screen.findByText('T1110')).toBeInTheDocument()
    expect(screen.getByText('T1059.001')).toBeInTheDocument()
    // brute_force_authentication appeared twice -> "2 detections".
    expect(screen.getByText('2 detections')).toBeInTheDocument()
  })

  it('derives a CRITICAL threat pulse from a recent critical alert', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResponse([makeAlert({ severity: 'critical', first_seen: new Date().toISOString() })]),
    )
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)
    expect(await screen.findByText('Critical')).toBeInTheDocument()
  })

  it('derives a QUIET threat pulse when there is no recent alert activity', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResponse([]))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)
    expect(await screen.findByText('Quiet')).toBeInTheDocument()
  })

  it('handles a 401 from GET /alerts gracefully without crashing the page', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(
      new ApiError(401, { detail: 'Could not validate credentials.' }, 'Could not validate credentials.'),
    )
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(<DashboardPage />)
    expect(await screen.findByText(/unable to retrieve alerts/i)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /^security operations$/i })).toBeInTheDocument()
  })

  it('clicking an active threat row navigates to the alert workflow', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResponse([makeAlert({ id: 'nav-target-alert' })]))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResponse([]))
    mockHealthy()

    renderWithProviders(
      <Routes>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/alerts/:alertId" element={<div>ALERT DETAIL PAGE MARKER</div>} />
      </Routes>,
      { route: '/dashboard' },
    )

    const row = await screen.findByText('Brute Force Authentication')
    await userEvent.setup().click(row)

    // Step 12D: the dashboard now navigates straight to the alert
    // detail route (/alerts/{id}), not a query-param-based /alerts?focus=.
    expect(await screen.findByText('ALERT DETAIL PAGE MARKER')).toBeInTheDocument()
  })
})
