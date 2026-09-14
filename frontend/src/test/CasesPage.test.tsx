import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { CasesPage } from '@/pages/CasesPage'
import { renderWithProviders } from './utils'
import * as casesService from '@/services/casesService'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import type { CaseListResponse, CaseRead } from '@/types/api'

function makeCase(overrides: Partial<CaseRead> = {}): CaseRead {
  const now = new Date().toISOString()
  return {
    id: `case-${Math.random().toString(36).slice(2)}`,
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
function resp(items: CaseRead[]): CaseListResponse {
  return { items, limit: 25, offset: 0 }
}

function renderCases(route = '/cases') {
  return renderWithProviders(
    <Routes>
      <Route path="/cases" element={<CasesPage />} />
      <Route path="/cases/:caseId" element={<div>CASE DETAIL MARKER</div>} />
    </Routes>,
    { route },
  )
}

afterEach(() => vi.restoreAllMocks())

describe('Step 12S: SOC Case Management (real backend data)', () => {
  it('renders REAL case data from GET /cases', async () => {
    vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([makeCase()]))
    renderCases()

    expect(await screen.findByText('Suspicious lateral movement')).toBeInTheDocument()
    const row = screen.getByRole('button', { name: /Suspicious lateral movement/i })
    expect(row).toHaveTextContent('OPEN')
    expect(row).toHaveTextContent('high priority')
    expect(row).toHaveTextContent('#42')
  })

  it('Step 12V: never requests GET /alerts/{id}/cases for any row on the list -- zero reverse relationship requests', async () => {
    vi.spyOn(casesService, 'listCases').mockResolvedValue(
      resp([makeCase({ id: 'c1', title: 'Case one' }), makeCase({ id: 'c2', title: 'Case two' })]),
    )
    const alertCasesSpy = vi.spyOn(alertsService, 'getAlertCases')
    renderCases()

    await screen.findByText('Case one')
    await screen.findByText('Case two')
    expect(alertCasesSpy).not.toHaveBeenCalled()
  })

  it('shows the loading skeleton before data resolves', () => {
    vi.spyOn(casesService, 'listCases').mockReturnValue(new Promise(() => {}))
    const { container } = renderCases()
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('shows a distinct empty state for a genuinely empty environment vs. an active filter', async () => {
    vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([]))
    renderCases()
    expect(await screen.findByText('No cases have been created yet.')).toBeInTheDocument()

    vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([]))
    renderCases('/cases?status=CLOSED')
    expect(await screen.findByText('No cases match the selected filters.')).toBeInTheDocument()
  })

  it('shows a safe error state on failure, with retry', async () => {
    const mock = vi.spyOn(casesService, 'listCases').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderCases()
    expect(await screen.findByText(/cases could not be loaded/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)

    mock.mockResolvedValue(resp([]))
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByText('No cases have been created yet.')).toBeInTheDocument())
  })

  it('applies status/priority filters as real backend query parameters', async () => {
    const mock = vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([]))
    renderCases()
    await screen.findByText('No cases have been created yet.')

    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Status'), 'INVESTIGATING')
    await user.selectOptions(screen.getByLabelText('Priority'), 'critical')
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ status: 'INVESTIGATING', priority: 'critical' })
    })
  })

  it('applies the owner_id filter -- a real GET /cases query parameter, not an invented search feature', async () => {
    const mock = vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([]))
    renderCases()
    await screen.findByText('No cases have been created yet.')

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Owner ID'), 'owner-uuid-123')
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ owner_id: 'owner-uuid-123' })
    })
  })

  it('paginates using limit/offset, never claiming a total', async () => {
    const fullPage = Array.from({ length: 25 }, () => makeCase({ id: `c-${Math.random()}` }))
    const mock = vi.spyOn(casesService, 'listCases').mockResolvedValue(resp(fullPage))
    renderCases()
    await screen.findByText('Page 1')

    expect(document.body.textContent).not.toMatch(/total cases:\s*\d+|page \d+ of \d+/i)
    await userEvent.setup().click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ offset: 25 })
    })
  })

  it('clicking a case row navigates to its real detail page', async () => {
    vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([makeCase({ id: 'case-xyz' })]))
    renderCases()

    const row = await screen.findByRole('button', { name: /Suspicious lateral movement/i })
    await userEvent.setup().click(row)
    expect(await screen.findByText('CASE DETAIL MARKER')).toBeInTheDocument()
  })

  it('creates a real case via POST /cases and navigates to it -- never fabricates a case number client-side', async () => {
    vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([]))
    const createMock = vi.spyOn(casesService, 'createCase').mockResolvedValue(makeCase({ id: 'new-case-1', case_number: 7 }))
    renderCases()
    await screen.findByText('No cases have been created yet.')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /new case/i }))
    await user.type(screen.getByLabelText('Title'), 'New investigation')
    await user.type(screen.getByLabelText('Description'), 'Details about the new investigation.')
    await user.click(screen.getByRole('button', { name: /^create case$/i }))

    await waitFor(() =>
      expect(createMock).toHaveBeenCalledWith({
        title: 'New investigation',
        description: 'Details about the new investigation.',
        priority: 'medium',
      }),
    )
    expect(await screen.findByText('CASE DETAIL MARKER')).toBeInTheDocument()
  })

  it('never renders demo/fabricated data (values match exactly what the mock returned)', async () => {
    vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([makeCase({ title: 'Unique Case Marker 99' })]))
    renderCases()
    expect(await screen.findByText('Unique Case Marker 99')).toBeInTheDocument()
    expect(screen.queryByText(/CASE-1234/)).not.toBeInTheDocument()
  })

  it('no security-sensitive data (tokens, credentials, secrets) is present', async () => {
    vi.spyOn(casesService, 'listCases').mockResolvedValue(resp([makeCase()]))
    renderCases()
    await screen.findByText('Suspicious lateral movement')
    expect(document.body.textContent).not.toMatch(/bearer |access_token|refresh_token|password|api[_-]?key/i)
  })
})
