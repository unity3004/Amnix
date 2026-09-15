import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CaseCopilotPanel } from '@/features/cases/components/CaseCopilotPanel'
import { renderWithProviders } from './utils'
import * as casesService from '@/services/casesService'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import type { AlertRead, CaseCopilotResponse, CaseInvestigationBrief, InvestigationContext } from '@/types/api'

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: `alert-${Math.random().toString(36).slice(2)}`,
    rule_id: 'brute_force_authentication',
    title: 'Linked alert',
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

function makeBrief(overrides: Partial<CaseInvestigationBrief> = {}): CaseInvestigationBrief {
  return {
    summary: 'A structured investigation summary.',
    key_findings: [],
    supporting_evidence: [],
    mitre_analysis: [],
    timeline_summary: 'No telemetry timeline was focused for this brief.',
    uncertainties: ['No analyst notes have been recorded.'],
    recommended_next_steps: ['Review each linked alert.'],
    ...overrides,
  }
}

function makeResponse(overrides: Partial<CaseCopilotResponse> = {}): CaseCopilotResponse {
  return {
    case_id: 'case-1',
    provider: 'mock',
    model: 'amnix-mock-v1',
    brief: makeBrief(),
    generated_at: new Date().toISOString(),
    usage: null,
    ...overrides,
  }
}

function makeInvestigation(overrides: Partial<InvestigationContext> = {}): InvestigationContext {
  const now = new Date().toISOString()
  return {
    alert: makeAlert(),
    timeline: [],
    entities: { hostnames: [], usernames: [], source_ips: [], destination_ips: [], process_names: [], file_hashes: [] },
    summary: {
      text: '',
      event_count: 0,
      unique_host_count: 0,
      unique_user_count: 0,
      timespan_seconds: null,
      first_event_at: null,
      last_event_at: null,
    },
    generated_at: now,
    ...overrides,
  }
}

afterEach(() => vi.restoreAllMocks())

describe('Step 13D: Case AI Investigation Brief panel', () => {
  it('starts in a READY state and never calls the AI layer on mount', async () => {
    const spy = vi.spyOn(casesService, 'askCaseCopilot')
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    expect(await screen.findByText('No brief generated yet.')).toBeInTheDocument()
    expect(spy).not.toHaveBeenCalled()
  })

  it('Generate button stays disabled until a question is entered', async () => {
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    const button = screen.getByRole('button', { name: /Generate Investigation Brief/i })
    expect(button).toBeDisabled()

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'What happened?')
    expect(button).toBeEnabled()
  })

  it('clicking Generate calls POST /cases/{id}/copilot exactly once with the real case id and question, no focused alert by default', async () => {
    const spy = vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(makeResponse())
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'What happened?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    expect(spy).toHaveBeenCalledWith('case-1', { question: 'What happened?', focused_alert_id: null })
  })

  it('shows a GENERATING state while the request is in flight, with no fabricated content shown', async () => {
    let resolvePromise!: (value: CaseCopilotResponse) => void
    vi.spyOn(casesService, 'askCaseCopilot').mockReturnValue(
      new Promise((resolve) => {
        resolvePromise = resolve
      }),
    )
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'What happened?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    expect(await screen.findByRole('status')).toHaveTextContent('Generating investigation brief…')
    expect(screen.queryByText('Generated Brief')).not.toBeInTheDocument()

    resolvePromise(makeResponse())
    await waitFor(() => expect(screen.getByText('Generated Brief')).toBeInTheDocument())
  })

  it('renders the real structured brief on SUCCESS, with a mandatory advisory-only trust notice', async () => {
    vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(
      makeResponse({ brief: makeBrief({ summary: 'Real generated summary text.' }) }),
    )
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'What happened?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    expect(await screen.findByText('Real generated summary text.')).toBeInTheDocument()
    expect(screen.getByText(/AI-generated, advisory only/i)).toBeInTheDocument()
    expect(screen.getByText(/AMNIX does not act on this automatically/i)).toBeInTheDocument()
  })

  it('never renders a verdict/confidence/risk-score field -- CaseInvestigationBrief has none', async () => {
    vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(makeResponse())
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    await screen.findByText('Generated Brief')
    expect(screen.queryByText(/verdict/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/risk score/i)).not.toBeInTheDocument()
  })

  it('labels recommended next steps as analyst guidance only, with no automatic actions', async () => {
    vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(
      makeResponse({ brief: makeBrief({ recommended_next_steps: ['Interview the affected user.'] }) }),
    )
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    expect(await screen.findByText('Interview the affected user.')).toBeInTheDocument()
    expect(screen.getByText(/Analyst guidance only -- no actions are executed automatically/i)).toBeInTheDocument()
  })

  it('resolves a key finding\'s supporting_alert_refs to a real Alert Detail link using this case\'s own linked alerts', async () => {
    const alert = makeAlert({ id: 'real-alert-id-123' })
    vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(
      makeResponse({
        brief: makeBrief({
          key_findings: [
            { type: 'fact', statement: 'Observed brute-force activity.', supporting_alert_refs: ['alert-1'], supporting_event_refs: [] },
          ],
        }),
      }),
    )
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[alert]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    const link = await screen.findByRole('link', { name: 'alert-1' })
    expect(link).toHaveAttribute('href', '/alerts/real-alert-id-123')
  })

  it('renders an unresolvable alert_ref as plain, non-clickable text rather than guessing a URL', async () => {
    vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(
      makeResponse({
        brief: makeBrief({
          key_findings: [
            { type: 'fact', statement: 'A finding.', supporting_alert_refs: ['alert-99'], supporting_event_refs: [] },
          ],
        }),
      }),
    )
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    await screen.findByText('A finding.')
    expect(screen.queryByRole('link', { name: 'alert-99' })).not.toBeInTheDocument()
    expect(screen.getByText('alert-99')).toBeInTheDocument()
  })

  it('does not fetch any alert investigation when no alert is focused', async () => {
    const investigationSpy = vi.spyOn(alertsService, 'getAlertInvestigation')
    vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(makeResponse())
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[makeAlert()]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))
    await screen.findByText('Generated Brief')

    expect(investigationSpy).not.toHaveBeenCalled()
  })

  it('fetches the focused alert\'s investigation only after it is explicitly selected, and resolves event_ref citations to real Event Detail links', async () => {
    const alert = makeAlert({ id: 'focused-alert-1', title: 'Brute force auth' })
    const investigationSpy = vi
      .spyOn(alertsService, 'getAlertInvestigation')
      .mockResolvedValue(makeInvestigation({ timeline: [{ event_id: 'real-event-42', event_timestamp: new Date().toISOString(), event_type: 'authentication_failure', source: 'test', hostname: null, username: null, source_ip: null, destination_ip: null, process_name: null, command_line: null }] }))
    vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(
      makeResponse({
        brief: makeBrief({
          supporting_evidence: [
            { field: 'hostname', value: 'WKS-01', alert_ref: null, event_ref: 'evt-1', explanation: 'Observed on the focused alert timeline.' },
          ],
        }),
      }),
    )
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[alert]} />)

    expect(investigationSpy).not.toHaveBeenCalled()

    await userEvent.selectOptions(screen.getByLabelText('Focus on alert (optional)'), 'focused-alert-1')
    await waitFor(() => expect(investigationSpy).toHaveBeenCalledWith('focused-alert-1'))

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Tell me about this alert.')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    const link = await screen.findByRole('link', { name: 'evt-1' })
    expect(link).toHaveAttribute('href', '/events/real-event-42')
  })

  it('sends the real focused_alert_id when an alert is selected', async () => {
    const alert = makeAlert({ id: 'focused-alert-1' })
    vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    const spy = vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(makeResponse())
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[alert]} />)

    await userEvent.selectOptions(screen.getByLabelText('Focus on alert (optional)'), 'focused-alert-1')
    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Tell me about this alert.')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith('case-1', { question: 'Tell me about this alert.', focused_alert_id: 'focused-alert-1' }),
    )
  })

  it('shows a FAILURE state with a safe error message, never fabricated content, on a backend failure', async () => {
    vi.spyOn(casesService, 'askCaseCopilot').mockRejectedValue(
      new ApiError(502, null, 'Investigation Brief could not be generated.'),
    )
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))

    expect(await screen.findByText('Investigation Brief could not be generated.')).toBeInTheDocument()
    expect(screen.queryByText('Generated Brief')).not.toBeInTheDocument()
  })

  it('retry after a failure re-issues exactly one more request', async () => {
    const spy = vi
      .spyOn(casesService, 'askCaseCopilot')
      .mockRejectedValueOnce(new ApiError(502, null, 'Unavailable.'))
      .mockResolvedValueOnce(makeResponse())
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))
    await screen.findByText('Unavailable.')

    await userEvent.click(screen.getByRole('button', { name: /Retry/i }))

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2))
    await screen.findByText('Generated Brief')
  })

  it('never issues more than one AI request per Generate click', async () => {
    const spy = vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(makeResponse())
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))
    await screen.findByText('Generated Brief')

    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('Clear resets the panel back to a READY state', async () => {
    vi.spyOn(casesService, 'askCaseCopilot').mockResolvedValue(makeResponse())
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)

    await userEvent.type(screen.getByLabelText('Ask about this case'), 'Why?')
    await userEvent.click(screen.getByRole('button', { name: /Generate Investigation Brief/i }))
    await screen.findByText('Generated Brief')

    await userEvent.click(screen.getByRole('button', { name: /Clear/i }))

    expect(await screen.findByText('No brief generated yet.')).toBeInTheDocument()
  })

  it('does not render a focused-alert selector when the case has no linked alerts', () => {
    renderWithProviders(<CaseCopilotPanel caseId="case-1" alerts={[]} />)
    expect(screen.queryByLabelText('Focus on alert (optional)')).not.toBeInTheDocument()
  })
})
