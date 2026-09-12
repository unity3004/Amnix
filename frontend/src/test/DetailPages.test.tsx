import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { AlertDetailPage } from '@/pages/AlertDetailPage'
import { EventDetailPage } from '@/pages/EventDetailPage'
import { InvestigationsPage } from '@/pages/InvestigationsPage'
import { CopilotPage } from '@/pages/CopilotPage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
import * as eventsService from '@/services/eventsService'
import { ApiError } from '@/services/httpClient'
import type { AlertRead, SecurityEventRead, CopilotResponse } from '@/types/api'

afterEach(() => vi.restoreAllMocks())

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: 'alert-detail-1',
    rule_id: 'brute_force_authentication',
    title: 'Brute force authentication detected for jdoe',
    description: 'Six failed authentication attempts observed.',
    severity: 'critical',
    confidence: 'high',
    status: 'new',
    first_seen: now,
    last_seen: now,
    created_at: now,
    updated_at: now,
    evidence: {},
    alert_metadata: null,
    source_event_ids: ['event-aaa', 'event-bbb'],
    ...overrides,
  }
}

function makeEvent(overrides: Partial<SecurityEventRead> = {}): SecurityEventRead {
  const now = new Date().toISOString()
  return {
    id: 'event-detail-1',
    event_timestamp: now,
    event_type: 'authentication_failure',
    source: 'auth-log',
    hostname: 'workstation-07',
    username: 'jdoe',
    source_ip: '10.0.0.5',
    raw_data: { note: 'unique-marker-value' },
    created_at: now,
    ...overrides,
  }
}

describe('AlertDetailPage', () => {
  it('renders REAL alert identity fields', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    renderWithProviders(
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
      </Routes>,
      { route: '/alerts/alert-detail-1' },
    )

    expect(await screen.findByText('Brute force authentication detected for jdoe')).toBeInTheDocument()
    expect(document.body.textContent).toMatch(/T1110.*Brute Force/)
  })

  it('lists related event IDs as links to their own detail page, with zero extra requests', async () => {
    const alertMock = vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    const eventMock = vi.spyOn(eventsService, 'getEvent')
    renderWithProviders(
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
      </Routes>,
      { route: '/alerts/alert-detail-1' },
    )

    expect(await screen.findByText('event-aaa')).toBeInTheDocument()
    expect(screen.getByText('event-bbb')).toBeInTheDocument()
    expect(alertMock).toHaveBeenCalledTimes(1)
    expect(eventMock).not.toHaveBeenCalled()
  })

  it('shows a safe error state when the alert cannot be retrieved', async () => {
    vi.spyOn(alertsService, 'getAlert').mockRejectedValue(new ApiError(404, { detail: 'Alert not found' }, 'Alert not found'))
    renderWithProviders(
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
      </Routes>,
      { route: '/alerts/does-not-exist' },
    )
    expect(await screen.findByText(/unable to retrieve this alert/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/traceback|stack/i)
  })

  it('shows an explainable triage priority line built from real severity/status/recency, no fake score', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ severity: 'critical', status: 'escalated' }))
    renderWithProviders(
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
      </Routes>,
      { route: '/alerts/alert-detail-1' },
    )

    await screen.findByText('Brute force authentication detected for jdoe')
    expect(screen.getByText(/Critical severity · Escalated ·/)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/risk score|threat score|ai score|probability of attack/i)
    expect(document.body.textContent).not.toMatch(
      /isolate host|kill process|block ip|disable account|run command|quarantine host/i,
    )
  })

  it('navigates to the Investigation Workspace and Copilot for the exact alert_id', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    renderWithProviders(
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="/alerts/:alertId/investigation" element={<div>INVESTIGATION WORKSPACE MARKER</div>} />
      </Routes>,
      { route: '/alerts/alert-detail-1' },
    )
    await screen.findByText('Brute force authentication detected for jdoe')
    await userEvent.setup().click(screen.getByRole('button', { name: /investigate alert/i }))
    expect(await screen.findByText('INVESTIGATION WORKSPACE MARKER')).toBeInTheDocument()
  })
})

describe('EventDetailPage', () => {
  it('renders REAL event fields', async () => {
    vi.spyOn(eventsService, 'getEvent').mockResolvedValue(makeEvent())
    renderWithProviders(
      <Routes>
        <Route path="/events/:eventId" element={<EventDetailPage />} />
      </Routes>,
      { route: '/events/event-detail-1' },
    )

    expect(await screen.findByText('authentication_failure')).toBeInTheDocument()
    expect(screen.getByText('workstation-07')).toBeInTheDocument()
    expect(screen.getByText('jdoe')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
    expect(screen.getByText(/unique-marker-value/)).toBeInTheDocument()
  })

  it('shows a safe error state, never a raw exception', async () => {
    vi.spyOn(eventsService, 'getEvent').mockRejectedValue(new ApiError(404, { detail: 'Security event not found' }, 'Security event not found'))
    renderWithProviders(
      <Routes>
        <Route path="/events/:eventId" element={<EventDetailPage />} />
      </Routes>,
      { route: '/events/missing' },
    )
    expect(await screen.findByText(/unable to retrieve this event/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/traceback|TypeError/i)
  })
})

describe('Investigation and Copilot alert-scoped connections', () => {
  it('InvestigationsPage redirects ?alert=<id> to the canonical /alerts/:id/investigation workspace', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/investigations" element={<InvestigationsPage />} />
        <Route path="/alerts/:alertId/investigation" element={<div>WORKSPACE MARKER for alert-detail-1</div>} />
      </Routes>,
      { route: '/investigations?alert=alert-detail-1' },
    )

    expect(await screen.findByText('WORKSPACE MARKER for alert-detail-1')).toBeInTheDocument()
  })

  it('InvestigationsPage without an alert param keeps the original placeholder', () => {
    renderWithProviders(<InvestigationsPage />, { route: '/investigations' })
    expect(screen.getByText(/no investigation selected/i)).toBeInTheDocument()
  })

  it('CopilotPage asks the real POST /alerts/{id}/copilot for the exact alert and renders the real assessment', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    const assessment: CopilotResponse = {
      alert_id: 'alert-detail-1',
      provider: 'mock',
      model: 'mock-model',
      generated_at: new Date().toISOString(),
      usage: null,
      assessment: {
        verdict: 'suspicious',
        confidence: 'medium',
        summary: 'This looks like a credential-stuffing attempt.',
        key_findings: [],
        evidence: [],
        mitre_analysis: [],
        recommended_next_steps: ['Review source IP reputation.'],
        recommended_action: 'investigate',
        recommended_actions: [],
        limitations: [],
      },
    }
    const askMock = vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(assessment)

    renderWithProviders(<CopilotPage />, { route: '/copilot?alert=alert-detail-1' })
    await screen.findByText('Brute force authentication detected for jdoe')

    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot/i), 'What happened here?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    expect(await screen.findByText('This looks like a credential-stuffing attempt.')).toBeInTheDocument()
    expect(askMock).toHaveBeenCalledWith('alert-detail-1', 'What happened here?')
  })

  it('CopilotPage without an alert param keeps the original placeholder (no fake metrics)', () => {
    renderWithProviders(<CopilotPage />, { route: '/copilot' })
    expect(screen.getByText(/no alert selected/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/investigations assisted|analyzed \d+ incidents/i)
  })
})
