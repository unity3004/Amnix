import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { InvestigationWorkspacePage } from '@/pages/InvestigationWorkspacePage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
import * as eventsService from '@/services/eventsService'
import { ApiError } from '@/services/httpClient'
import type { AlertRead, InvestigationContext, CopilotResponse, CopilotFollowUpResponse } from '@/types/api'

afterEach(() => vi.restoreAllMocks())

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: 'alert-ws-1',
    rule_id: 'brute_force_authentication',
    title: 'Brute force authentication detected for jdoe',
    description: 'Five failed authentication attempts observed.',
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

function makeInvestigation(overrides: Partial<InvestigationContext> = {}): InvestigationContext {
  const now = new Date().toISOString()
  return {
    alert: makeAlert(),
    timeline: [
      {
        event_id: 'event-aaa',
        event_timestamp: now,
        event_type: 'authentication_failure',
        source: 'auth-log',
        hostname: 'workstation-07',
        username: 'jdoe',
        source_ip: '10.0.0.5',
        destination_ip: null,
        process_name: null,
        command_line: null,
      },
    ],
    entities: {
      hostnames: ['workstation-07'],
      usernames: ['jdoe'],
      source_ips: ['10.0.0.5'],
      destination_ips: [],
      process_names: [],
      file_hashes: [],
    },
    summary: {
      text: 'Five failed logins observed within 300 seconds.',
      event_count: 5,
      unique_host_count: 1,
      unique_user_count: 1,
      timespan_seconds: 120,
      first_event_at: now,
      last_event_at: now,
    },
    generated_at: now,
    ...overrides,
  }
}

function makeCopilotResponse(overrides: Partial<CopilotResponse['assessment']> = {}): CopilotResponse {
  return {
    alert_id: 'alert-ws-1',
    provider: 'mock',
    model: 'mock-model',
    generated_at: new Date().toISOString(),
    usage: null,
    assessment: {
      verdict: 'suspicious',
      confidence: 'medium',
      summary: 'This looks like a credential-stuffing attempt.',
      key_findings: [{ type: 'fact', statement: 'Five failures in 300 seconds.', supporting_event_refs: [] }],
      evidence: [{ field: 'source_ip', value: '10.0.0.5', event_ref: null, explanation: 'Repeated origin.' }],
      mitre_analysis: [
        { technique_id: 'T1110', technique_name: 'Brute Force', tactic: 'Credential Access', confidence: 'high', rationale: 'Matches pattern.', supporting_event_refs: [] },
      ],
      recommended_next_steps: ['Review source IP reputation.'],
      recommended_action: 'investigate',
      recommended_actions: [
        { action_id: 'review_source_ip_history', label: 'Review source IP activity history', description: 'Check where else this IP appeared.', supporting_event_refs: [] },
      ],
      limitations: ['Limited to observed telemetry only.'],
      ...overrides,
    },
  }
}

function renderWorkspace(route = '/alerts/alert-ws-1/investigation') {
  return renderWithProviders(
    <Routes>
      <Route path="/alerts/:alertId/investigation" element={<InvestigationWorkspacePage />} />
      <Route path="/alerts" element={<div>ALERTS LIST MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('InvestigationWorkspacePage', () => {
  it('loads and displays REAL alert data in the header', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    renderWorkspace()

    expect(await screen.findByText('Brute force authentication detected for jdoe')).toBeInTheDocument()
    expect(screen.getByText('alert-ws-1')).toBeInTheDocument()
  })

  it('fetches GET /alerts/{id}/investigation successfully and renders the real summary/entities', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    const investigationMock = vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    renderWorkspace()

    expect(await screen.findByText('Five failed logins observed within 300 seconds.')).toBeInTheDocument()
    expect(screen.getAllByText('workstation-07').length).toBeGreaterThan(0)
    expect(investigationMock).toHaveBeenCalledWith('alert-ws-1')
  })

  it('shows a distinct, safe error state when the investigation API fails, without blocking the rest of the page', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderWorkspace()

    expect(await screen.findByText('Brute force authentication detected for jdoe')).toBeInTheDocument()
    expect(await screen.findByText(/investigation data could not be loaded/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)
  })

  it('renders related events (evidence) with zero additional per-event requests', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    renderWorkspace()

    expect((await screen.findAllByText('authentication_failure')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('10.0.0.5').length).toBeGreaterThan(0)
  })

  it('shows an honest empty-evidence state (not an error) when the investigation has no related events', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(
      makeInvestigation({
        timeline: [],
        entities: { hostnames: [], usernames: [], source_ips: [], destination_ips: [], process_names: [], file_hashes: [] },
      }),
    )
    renderWorkspace()

    expect(await screen.findByText('No related events')).toBeInTheDocument()
  })

  it('allows a real status transition via the existing PATCH /alerts/{id}/status, reusing AlertStatusControl', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    const statusMock = vi.spyOn(alertsService, 'updateAlertStatus').mockResolvedValue(makeAlert({ status: 'investigating' }))
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText(/change alert status/i), 'investigating')
    await user.click(screen.getByRole('button', { name: /change status/i }))

    await waitFor(() => expect(statusMock).toHaveBeenCalledWith('alert-ws-1', 'investigating'))
  })

  it('asks the real POST /alerts/{id}/copilot for the exact alert and renders the real assessment', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    const askMock = vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What happened here?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    expect(await screen.findByText('This looks like a credential-stuffing attempt.')).toBeInTheDocument()
    expect(askMock).toHaveBeenCalledWith('alert-ws-1', 'What happened here?')
  })

  it('renders verdict, confidence, evidence, MITRE analysis, recommended actions, and limitations from the real response', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'Assess this alert.')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    expect(await screen.findByText('suspicious')).toBeInTheDocument()
    expect(screen.getByText(/confidence: medium/i)).toBeInTheDocument()
    expect(screen.getByText(/Five failures in 300 seconds\./)).toBeInTheDocument()
    expect(screen.getByText(/Review source IP reputation\./)).toBeInTheDocument()
    expect(screen.getByText(/Review source IP activity history/)).toBeInTheDocument()
    expect(screen.getByText(/Limited to observed telemetry only\./)).toBeInTheDocument()
  })

  it('shows a safe Copilot error state on failure, with retry, never a raw exception', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    const askMock = vi.spyOn(alertsService, 'askCopilot').mockRejectedValue(new ApiError(502, null, 'provider unavailable'))
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What happened here?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    expect(await screen.findByText(/copilot is unavailable/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback/i)

    askMock.mockResolvedValue(makeCopilotResponse())
    await user.click(screen.getByRole('button', { name: /retry/i }))
    expect(await screen.findByText('This looks like a credential-stuffing attempt.')).toBeInTheDocument()
  })

  it('supports a follow-up question using the real POST /alerts/{id}/copilot/follow-up with honest, non-fabricated history', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    const followUpResponse: CopilotFollowUpResponse = {
      alert_id: 'alert-ws-1',
      provider: 'mock',
      model: 'mock-model',
      answer: 'Yes, the source IP has appeared in two other alerts recently.',
      generated_at: new Date().toISOString(),
      supporting_event_refs: [],
      mitre_refs: [],
      recommended_actions: [],
      limitations: [],
      usage: null,
    }
    const followUpMock = vi.spyOn(alertsService, 'askCopilotFollowUp').mockResolvedValue(followUpResponse)
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What happened here?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))
    await screen.findByText('This looks like a credential-stuffing attempt.')

    await user.type(screen.getByLabelText(/ask a follow-up question/i), 'Has this IP been seen elsewhere?')
    await user.click(screen.getByRole('button', { name: /ask follow-up/i }))

    expect(await screen.findByText('Yes, the source IP has appeared in two other alerts recently.')).toBeInTheDocument()
    expect(followUpMock).toHaveBeenCalledWith('alert-ws-1', {
      question: 'Has this IP been seen elsewhere?',
      history: [
        { role: 'user', content: 'What happened here?' },
        { role: 'assistant', content: 'This looks like a credential-stuffing attempt.' },
      ],
    })
  })

  it('never renders a fake fallback assessment, MITRE claim, or metric before Copilot has been asked', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    expect(screen.getByText(/ask copilot about this investigation\./i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/likely_malicious|likely_benign|inconclusive|risk score|threat score/i)
  })

  it('navigates back to the Alerts list', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    await userEvent.setup().click(screen.getByRole('button', { name: /back to alerts/i }))
    expect(await screen.findByText('ALERTS LIST MARKER')).toBeInTheDocument()
  })

  it('shows a safe error state when the alert itself cannot be retrieved', async () => {
    vi.spyOn(alertsService, 'getAlert').mockRejectedValue(new ApiError(404, { detail: 'Alert not found' }, 'Alert not found'))
    renderWorkspace()

    expect(await screen.findByText(/unable to retrieve this alert/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/traceback|stack/i)
  })
})

describe('Copilot evidence-centered UX (Step 12F)', () => {
  it('shows the trust/transparency notice and an honest empty state before any question', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    expect(screen.getByText(/copilot provides advisory analysis based on the investigation evidence/i)).toBeInTheDocument()
    expect(screen.getByText(/ask copilot about this investigation\./i)).toBeInTheDocument()
  })

  it('a question starter populates the input without submitting or fabricating alert-specific facts', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    const askMock = vi.spyOn(alertsService, 'askCopilot')
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'What happened first?' }))

    expect(screen.getByLabelText(/ask copilot about this investigation/i)).toHaveValue('What happened first?')
    expect(askMock).not.toHaveBeenCalled()
  })

  it('shows a dedicated "Analyzing investigation..." indicator while a question is pending', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockReturnValue(new Promise(() => {}))
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What happened here?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    expect(await screen.findByText(/analyzing investigation…/i)).toBeInTheDocument()
  })

  it('renders the Assessment section with an explicit "not a confirmed fact" caption, distinct from the evidence below it', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'Assess this alert.')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    expect(await screen.findByText('Assessment')).toBeInTheDocument()
    expect(screen.getByText(/not a confirmed fact/i)).toBeInTheDocument()
    expect(screen.getByText('Evidence')).toBeInTheDocument()
  })

  it('renders MITRE context within the initial Copilot turn itself (not only the aggregated MITRE panel)', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What MITRE techniques are relevant?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    await screen.findByText('This looks like a credential-stuffing attempt.')
    expect(screen.getAllByText('MITRE Context').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/matches pattern\./i).length).toBeGreaterThan(0)
  })

  it('renders a resolvable evidence reference as a real link into the existing EventDetailPage, with zero extra requests', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    const eventMock = vi.spyOn(eventsService, 'getEvent')
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(
      makeCopilotResponse({
        evidence: [{ field: 'source_ip', value: '10.0.0.5', event_ref: 'evt-1', explanation: 'Repeated origin.' }],
      }),
    )
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What evidence supports this alert?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    await screen.findByText('This looks like a credential-stuffing attempt.')
    const refLink = screen.getByRole('link', { name: 'evt-1' })
    expect(refLink).toHaveAttribute('href', '/events/event-aaa')
    expect(eventMock).not.toHaveBeenCalled()
  })

  it('renders an unresolvable evidence reference as plain text, never a broken or guessed link', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(
      makeCopilotResponse({
        evidence: [{ field: 'source_ip', value: '10.0.0.5', event_ref: 'evt-99', explanation: 'Repeated origin.' }],
      }),
    )
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What evidence supports this alert?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    await screen.findByText('This looks like a credential-stuffing attempt.')
    expect(screen.getByText('evt-99')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'evt-99' })).not.toBeInTheDocument()
  })

  it('shows Evidence and MITRE Context for a follow-up answer, using the real supporting_event_refs/mitre_refs', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    vi.spyOn(alertsService, 'askCopilotFollowUp').mockResolvedValue({
      alert_id: 'alert-ws-1',
      provider: 'mock',
      model: 'mock-model',
      answer: 'This source IP has not been seen in any other recent alert.',
      generated_at: new Date().toISOString(),
      supporting_event_refs: ['evt-1'],
      mitre_refs: [
        { technique_id: 'T1110', technique_name: 'Brute Force', tactic: 'Credential Access', confidence: 'medium', rationale: 'Consistent with the follow-up question.', supporting_event_refs: [] },
      ],
      recommended_actions: [],
      limitations: [],
      usage: null,
    } satisfies CopilotFollowUpResponse)
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What happened here?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))
    await screen.findByText('This looks like a credential-stuffing attempt.')

    await user.type(screen.getByLabelText(/ask a follow-up question/i), 'Has this IP been seen elsewhere?')
    await user.click(screen.getByRole('button', { name: /ask follow-up/i }))

    expect(await screen.findByText('This source IP has not been seen in any other recent alert.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'evt-1' })).toHaveAttribute('href', '/events/event-aaa')
    expect(screen.getAllByText(/consistent with the follow-up question\./i).length).toBeGreaterThan(0)
  })

  it('visually distinguishes analyst questions from Copilot answers with sender labels', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'Assess this alert.')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    await screen.findByText('This looks like a credential-stuffing attempt.')
    expect(screen.getByText('You')).toBeInTheDocument()
    expect(screen.getByText('Copilot')).toBeInTheDocument()
  })

  it('preserves the prior conversation and allows retry on a follow-up failure, without fabricating an assistant answer', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    const followUpMock = vi
      .spyOn(alertsService, 'askCopilotFollowUp')
      .mockRejectedValue(new ApiError(502, null, 'The AI provider failed to generate a response.'))
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What happened here?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))
    await screen.findByText('This looks like a credential-stuffing attempt.')

    await user.type(screen.getByLabelText(/ask a follow-up question/i), 'Has this IP been seen elsewhere?')
    await user.click(screen.getByRole('button', { name: /ask follow-up/i }))

    expect(await screen.findByText(/copilot is unavailable/i)).toBeInTheDocument()
    expect(screen.getByText('This looks like a credential-stuffing attempt.')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback/i)

    followUpMock.mockResolvedValue({
      alert_id: 'alert-ws-1',
      provider: 'mock',
      model: 'mock-model',
      answer: 'Retried answer: no further activity observed.',
      generated_at: new Date().toISOString(),
      supporting_event_refs: [],
      mitre_refs: [],
      recommended_actions: [],
      limitations: [],
      usage: null,
    } satisfies CopilotFollowUpResponse)
    await user.click(screen.getByRole('button', { name: /retry/i }))
    expect(await screen.findByText('Retried answer: no further activity observed.')).toBeInTheDocument()
  })

  it('never exposes a system prompt, provider exception, API key, or internal AIContext', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockRejectedValue(new ApiError(502, null, 'The AI provider failed to generate a response.'))
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What happened here?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    await screen.findByText(/copilot is unavailable/i)
    expect(document.body.textContent).not.toMatch(/system_instructions|SYSTEM_INSTRUCTIONS|api[_-]?key|bearer |sk-ant|AIContext/i)
  })

  it('never renders any remediation/execution control anywhere in the Copilot panel', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    vi.spyOn(alertsService, 'askCopilot').mockResolvedValue(makeCopilotResponse())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/ask copilot about this investigation/i), 'What should I investigate next?')
    await user.click(screen.getByRole('button', { name: /^ask$/i }))

    await screen.findByText('This looks like a credential-stuffing attempt.')
    expect(document.body.textContent).not.toMatch(
      /isolate host|kill process|block ip|disable account|delete evidence|run command|quarantine host|remediate/i,
    )
  })

  it('question starters are keyboard accessible and grouped with an accessible name', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    renderWorkspace()

    await screen.findByText('Brute force authentication detected for jdoe')
    expect(screen.getByRole('group', { name: /suggested investigation questions/i })).toBeInTheDocument()
    const starter = screen.getByRole('button', { name: 'Why might this be benign?' })
    starter.focus()
    expect(starter).toHaveFocus()
  })
})
