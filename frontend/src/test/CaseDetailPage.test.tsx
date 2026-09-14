import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { CaseDetailPage } from '@/pages/CaseDetailPage'
import { renderWithProviders } from './utils'
import * as casesService from '@/services/casesService'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import type { AlertListResponse, AlertRead, CaseAuditListResponse, CaseNoteListResponse, CaseRead } from '@/types/api'

const ANALYST = {
  id: 'analyst-1',
  email: 'analyst@example.com',
  role: 'analyst' as const,
  is_active: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

function makeCase(overrides: Partial<CaseRead> = {}): CaseRead {
  const now = new Date().toISOString()
  return {
    id: 'case-1',
    case_number: 42,
    title: 'Suspicious lateral movement',
    description: 'Grouping alerts related to lateral movement on host web-03.',
    status: 'OPEN',
    priority: 'high',
    severity: 'high',
    created_at: now,
    updated_at: now,
    created_by: 'user-1',
    owner_id: null,
    closed_at: null,
    closure_reason: null,
    ...overrides,
  }
}

function emptyAlerts(): AlertListResponse {
  return { items: [], limit: 0, offset: 0 }
}
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
function emptyNotes(): CaseNoteListResponse {
  return { items: [], limit: 50, offset: 0 }
}
function emptyAudit(): CaseAuditListResponse {
  return { items: [], limit: 200, offset: 0 }
}

function mockCaseFixtures(caseItem: CaseRead) {
  vi.spyOn(casesService, 'getCase').mockResolvedValue(caseItem)
  vi.spyOn(casesService, 'listCaseAlerts').mockResolvedValue(emptyAlerts())
  vi.spyOn(casesService, 'listCaseNotes').mockResolvedValue(emptyNotes())
  vi.spyOn(casesService, 'listCaseAudit').mockResolvedValue(emptyAudit())
}

function renderCaseDetail(route = '/cases/case-1', authUser = ANALYST) {
  return renderWithProviders(
    <Routes>
      <Route path="/cases/:caseId" element={<CaseDetailPage />} />
      <Route path="/cases" element={<div>SOC CASES MARKER</div>} />
    </Routes>,
    { route, authUser },
  )
}

afterEach(() => vi.restoreAllMocks())

describe('Step 12S: SOC Case Detail (real backend data)', () => {
  it('renders REAL case header data', async () => {
    mockCaseFixtures(makeCase())
    renderCaseDetail()

    expect(await screen.findByText('Suspicious lateral movement')).toBeInTheDocument()
    expect(screen.getByText('Case #42')).toBeInTheDocument()
    expect(screen.getAllByText('OPEN').length).toBeGreaterThan(0)
    expect(screen.getByText('high priority')).toBeInTheDocument()
    expect(screen.getByText(/Grouping alerts related to lateral movement/)).toBeInTheDocument()
  })

  it('Case Summary shows a real owner and a real linked-alert count -- never a fabricated total', async () => {
    const caseItem = makeCase({ owner_id: null })
    vi.spyOn(casesService, 'getCase').mockResolvedValue(caseItem)
    vi.spyOn(casesService, 'listCaseAlerts').mockResolvedValue({
      items: [makeAlert({ id: 'alert-1' }), makeAlert({ id: 'alert-2' })],
      limit: 2,
      offset: 0,
    })
    vi.spyOn(casesService, 'listCaseNotes').mockResolvedValue(emptyNotes())
    vi.spyOn(casesService, 'listCaseAudit').mockResolvedValue(emptyAudit())
    renderCaseDetail()

    await screen.findByText('Suspicious lateral movement')
    const linkedAlertsLabels = screen.getAllByText('Linked Alerts')
    expect(linkedAlertsLabels.length).toBeGreaterThan(0)
    // The summary `dt` (as opposed to CaseAlertsPanel's own CardHeader,
    // which shares the same label text) is the one immediately followed
    // by a real derived count.
    const summaryLabel = linkedAlertsLabels.find((el) => el.tagName === 'DT')
    expect(summaryLabel?.nextElementSibling).toHaveTextContent('2')
    expect(screen.getAllByText('Unassigned').length).toBeGreaterThan(0)
  })

  it('shows only the backend-supported next status actions for the current status', async () => {
    mockCaseFixtures(makeCase({ status: 'OPEN' }))
    renderCaseDetail()

    await screen.findByText('Case Status')
    expect(screen.getByRole('button', { name: 'Start Investigating' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Resolve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Close Case' })).not.toBeInTheDocument()
  })

  it('transitions status via PATCH /cases/{id}/status and reflects the new status', async () => {
    const caseItem = makeCase({ status: 'OPEN' })
    mockCaseFixtures(caseItem)
    const statusMock = vi.spyOn(casesService, 'updateCaseStatus').mockResolvedValue({ ...caseItem, status: 'INVESTIGATING' })
    renderCaseDetail()

    await screen.findByText('Case Status')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Start Investigating' }))

    await waitFor(() => expect(statusMock).toHaveBeenCalledWith('case-1', { status: 'INVESTIGATING', closure_reason: null }))
    expect(await screen.findByText('Case status updated.')).toBeInTheDocument()
  })

  it('requires a non-blank closure reason before closing a case', async () => {
    mockCaseFixtures(makeCase({ status: 'RESOLVED' }))
    const statusMock = vi.spyOn(casesService, 'updateCaseStatus').mockResolvedValue(makeCase({ status: 'CLOSED' }))
    renderCaseDetail()

    await screen.findByText('Case Status')
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Close Case' }))

    const confirmButton = await screen.findByRole('button', { name: 'Confirm Close' })
    expect(confirmButton).toBeDisabled()

    await user.type(screen.getByLabelText(/Closure Reason/), 'Confirmed false positive.')
    expect(confirmButton).toBeEnabled()
    await user.click(confirmButton)

    await waitFor(() =>
      expect(statusMock).toHaveBeenCalledWith('case-1', { status: 'CLOSED', closure_reason: 'Confirmed false positive.' }),
    )
  })

  it('labels RESOLVED->INVESTIGATING as "Return to Investigating", distinct from reopening a closed case', async () => {
    mockCaseFixtures(makeCase({ status: 'RESOLVED' }))
    renderCaseDetail()
    await screen.findByText('Case Status')
    expect(screen.getByRole('button', { name: 'Return to Investigating' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reopen Case' })).not.toBeInTheDocument()
  })

  it('labels CLOSED->INVESTIGATING as "Reopen Case" -- the backend\'s own distinct CASE_REOPENED audit action, not a generic status change', async () => {
    mockCaseFixtures(makeCase({ status: 'CLOSED', closure_reason: 'Confirmed benign.' }))
    renderCaseDetail()
    await screen.findByText('Case Status')
    expect(screen.getByRole('button', { name: 'Reopen Case' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Return to Investigating' })).not.toBeInTheDocument()
  })

  it('surfaces the backend\'s specific message on a 409 concurrent transition, not a generic error', async () => {
    mockCaseFixtures(makeCase({ status: 'OPEN' }))
    vi.spyOn(casesService, 'updateCaseStatus').mockRejectedValue(
      new ApiError(409, { detail: "Cannot transition case status from 'RESOLVED' to 'INVESTIGATING'" }, "Cannot transition case status from 'RESOLVED' to 'INVESTIGATING'"),
    )
    renderCaseDetail()

    await screen.findByText('Case Status')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Start Investigating' }))

    expect(await screen.findByText("Cannot transition case status from 'RESOLVED' to 'INVESTIGATING'")).toBeInTheDocument()
    expect(screen.queryByText('Case status could not be updated.')).not.toBeInTheDocument()
  })

  it('offers "Assign to Me" for an unowned case, then "Release Ownership" once owned by the current analyst', async () => {
    const unowned = makeCase({ owner_id: null })
    mockCaseFixtures(unowned)
    const ownerMock = vi.spyOn(casesService, 'updateCaseOwner').mockResolvedValue({ ...unowned, owner_id: ANALYST.id })
    renderCaseDetail()

    await screen.findByText('Case Owner')
    expect(screen.getAllByText('Unassigned').length).toBeGreaterThan(0)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Assign to Me' }))

    await waitFor(() => expect(ownerMock).toHaveBeenCalledWith('case-1', { owner_id: ANALYST.id }))
    await waitFor(() => expect(screen.getAllByText('You').length).toBeGreaterThan(0))
    expect(screen.getByRole('button', { name: 'Release Ownership' })).toBeInTheDocument()
  })

  it('does not offer any ownership action for a case owned by a different analyst', async () => {
    mockCaseFixtures(makeCase({ owner_id: 'someone-else' }))
    renderCaseDetail()

    await screen.findByText('Case Owner')
    expect(screen.getByText('This case is owned by another analyst.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Assign to Me' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Release Ownership' })).not.toBeInTheDocument()
  })

  it('shows linked alerts and links a new alert by real ID via POST /cases/{id}/alerts', async () => {
    const caseItem = makeCase()
    mockCaseFixtures(caseItem)
    const alert = makeAlert({ id: 'alert-1', title: 'Brute force detected' })
    const linkMock = vi.spyOn(casesService, 'linkCaseAlert').mockResolvedValue(alert)
    renderCaseDetail()

    await screen.findByText('No alerts are linked to this case yet.')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Link Alert by ID'), 'alert-1')
    await user.click(screen.getByRole('button', { name: 'Link' }))

    await waitFor(() => expect(linkMock).toHaveBeenCalledWith('case-1', 'alert-1'))
  })

  it('shows the real rule, first/last seen, event count, and evidence availability for each linked alert', async () => {
    const caseItem = makeCase()
    vi.spyOn(casesService, 'getCase').mockResolvedValue(caseItem)
    vi.spyOn(casesService, 'listCaseAlerts').mockResolvedValue({
      items: [
        makeAlert({
          id: 'alert-1',
          title: 'Brute force detected',
          rule_id: 'brute_force_authentication',
          evidence: { failure_count: 7 },
          source_event_ids: ['evt-1', 'evt-2'],
        }),
      ],
      limit: 1,
      offset: 0,
    })
    vi.spyOn(casesService, 'listCaseNotes').mockResolvedValue(emptyNotes())
    vi.spyOn(casesService, 'listCaseAudit').mockResolvedValue(emptyAudit())
    renderCaseDetail()

    expect(await screen.findByText('Brute force detected')).toBeInTheDocument()
    expect(screen.getByText('2 events')).toBeInTheDocument()
    expect(screen.getByText('Evidence available')).toBeInTheDocument()
    expect(screen.getByText(/First seen/)).toBeInTheDocument()
    expect(screen.getByText(/Last seen/)).toBeInTheDocument()
  })

  it('Step 12U: carries case context on every linked-alert link and provides a direct Investigate shortcut, without any automatic Investigation/Copilot fetch', async () => {
    const caseItem = makeCase({ id: 'case-1', case_number: 42 })
    vi.spyOn(casesService, 'getCase').mockResolvedValue(caseItem)
    vi.spyOn(casesService, 'listCaseAlerts').mockResolvedValue({
      items: [makeAlert({ id: 'alert-1', title: 'Brute force detected' })],
      limit: 1,
      offset: 0,
    })
    vi.spyOn(casesService, 'listCaseNotes').mockResolvedValue(emptyNotes())
    vi.spyOn(casesService, 'listCaseAudit').mockResolvedValue(emptyAudit())
    const investigationSpy = vi.spyOn(alertsService, 'getAlertInvestigation')
    const copilotSpy = vi.spyOn(alertsService, 'askCopilot')
    const alertCasesSpy = vi.spyOn(alertsService, 'getAlertCases')
    renderCaseDetail()

    await screen.findByText('Brute force detected')
    const alertLink = screen.getByRole('link', { name: /Brute force detected/ })
    expect(alertLink).toHaveAttribute('href', '/alerts/alert-1?case=case-1&caseNumber=42')

    const investigateLink = screen.getByRole('link', { name: /investigate/i })
    expect(investigateLink).toHaveAttribute('href', '/alerts/alert-1/investigation?case=case-1&caseNumber=42')

    expect(investigationSpy).not.toHaveBeenCalled()
    expect(copilotSpy).not.toHaveBeenCalled()
    // Step 12V: Case Detail's own linked-alerts panel must not fetch
    // each alert's reverse Case relationship either -- that query is
    // Alert-Detail-scoped only (see LinkedCasesPanel).
    expect(alertCasesSpy).not.toHaveBeenCalled()
  })

  it('Step 12U: shows the static Investigation Workflow guidance -- never a fake completion checkmark', async () => {
    mockCaseFixtures(makeCase())
    renderCaseDetail()

    expect(await screen.findByText('Investigation Workflow')).toBeInTheDocument()
    expect(screen.getByText('Suggested order of review -- not a tracked checklist.')).toBeInTheDocument()
    expect(screen.getByText('Review Alert')).toBeInTheDocument()
    expect(screen.getByText('Update Case Status')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/✓|investigation completed|step \d of \d complete/i)
  })

  it('adds a note via POST /cases/{id}/notes', async () => {
    mockCaseFixtures(makeCase())
    const noteMock = vi.spyOn(casesService, 'createCaseNote').mockResolvedValue({
      id: 'note-1',
      case_id: 'case-1',
      author_id: ANALYST.id,
      body: 'Escalated to on-call.',
      created_at: new Date().toISOString(),
    })
    renderCaseDetail()

    await screen.findByText('No notes have been added to this case yet.')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Add a Note'), 'Escalated to on-call.')
    await user.click(screen.getByRole('button', { name: /add note/i }))

    await waitFor(() => expect(noteMock).toHaveBeenCalledWith('case-1', 'Escalated to on-call.'))
  })

  it('shows a visible error (never a silent failure) when a note fails to save', async () => {
    mockCaseFixtures(makeCase())
    vi.spyOn(casesService, 'createCaseNote').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderCaseDetail()

    await screen.findByText('No notes have been added to this case yet.')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Add a Note'), 'This will fail.')
    await user.click(screen.getByRole('button', { name: /add note/i }))

    expect(await screen.findByText('This note could not be added.')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)
  })

  it('edits the case via PATCH /cases/{id}, sending only fields that actually changed', async () => {
    const caseItem = makeCase()
    mockCaseFixtures(caseItem)
    const updateMock = vi.spyOn(casesService, 'updateCase').mockResolvedValue({ ...caseItem, title: 'Updated title' })
    renderCaseDetail()

    await screen.findByText('Suspicious lateral movement')
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /edit case/i }))

    const titleInput = screen.getByLabelText('Title')
    await user.clear(titleInput)
    await user.type(titleInput, 'Updated title')
    await user.click(screen.getByRole('button', { name: /save changes/i }))

    await waitFor(() =>
      expect(updateMock).toHaveBeenCalledWith('case-1', { title: 'Updated title', description: null, priority: null }),
    )
  })

  it('renders real audit entries with distinct icons per action, never a generic CASE_UPDATED', async () => {
    const caseItem = makeCase()
    vi.spyOn(casesService, 'getCase').mockResolvedValue(caseItem)
    vi.spyOn(casesService, 'listCaseAlerts').mockResolvedValue(emptyAlerts())
    vi.spyOn(casesService, 'listCaseNotes').mockResolvedValue(emptyNotes())
    vi.spyOn(casesService, 'listCaseAudit').mockResolvedValue({
      items: [
        {
          id: 'audit-2',
          case_id: 'case-1',
          actor_user_id: ANALYST.id,
          action: 'CASE_CLOSED',
          related_alert_id: null,
          previous_value: 'RESOLVED',
          new_value: 'Confirmed false positive.',
          created_at: new Date().toISOString(),
        },
        {
          id: 'audit-1',
          case_id: 'case-1',
          actor_user_id: ANALYST.id,
          action: 'CASE_CREATED',
          related_alert_id: null,
          previous_value: null,
          new_value: "case_number=42, title='Suspicious lateral movement', priority='high'",
          created_at: new Date().toISOString(),
        },
      ],
      limit: 200,
      offset: 0,
    })
    const { container } = renderCaseDetail()

    expect(await screen.findByText('Case created')).toBeInTheDocument()
    expect(screen.getByText('Case closed')).toBeInTheDocument()
    expect(screen.queryByText('CASE_UPDATED')).not.toBeInTheDocument()
    // Distinguishable by icon SHAPE, not only by label text.
    expect(container.querySelector('.lucide-file-plus')).toBeTruthy()
    expect(container.querySelector('.lucide-lock')).toBeTruthy()
    expect(screen.getAllByText(new RegExp(ANALYST.id)).length).toBeGreaterThan(0)
  })

  it('no security-sensitive data (tokens, credentials, secrets) is present', async () => {
    mockCaseFixtures(makeCase())
    renderCaseDetail()
    await screen.findByText('Suspicious lateral movement')
    expect(document.body.textContent).not.toMatch(/bearer |access_token|refresh_token|password|api[_-]?key/i)
  })
})
