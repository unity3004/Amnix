import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { RuleExplorerPage } from '@/pages/RuleExplorerPage'
import { RuleDetailPage } from '@/pages/RuleDetailPage'
import { AlertDetailPage } from '@/pages/AlertDetailPage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import { DETECTION_RULES } from '@/features/rules/ruleRegistry'
import type { AlertRead, AlertListResponse } from '@/types/api'

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
    source_event_ids: ['evt-1'],
    ...overrides,
  }
}
function resp(items: AlertRead[]): AlertListResponse {
  return { items, limit: 10, offset: 0 }
}

function renderExplorer() {
  return renderWithProviders(
    <Routes>
      <Route path="/rules" element={<RuleExplorerPage />} />
      <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
    </Routes>,
    { route: '/rules' },
  )
}

describe('RuleExplorerPage', () => {
  it('renders the real, static rule inventory -- every registered rule, with its real rule ID, name, and severity', () => {
    renderExplorer()

    for (const rule of DETECTION_RULES) {
      expect(screen.getByText(rule.name)).toBeInTheDocument()
      expect(screen.getByText(rule.ruleId)).toBeInTheDocument()
    }
    expect(screen.getAllByText(/^high$/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/^medium$/i).length).toBeGreaterThan(0)
  })

  it('labels every rule "Active · Application-controlled" -- no enable/disable toggle exists', () => {
    renderExplorer()

    expect(screen.getAllByText('Active · Application-controlled').length).toBe(DETECTION_RULES.length)
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })

  it('shows the MITRE technique mapping associated with each rule', () => {
    renderExplorer()
    expect(screen.getByText('T1110')).toBeInTheDocument()
  })

  it('filters rules by real search text (rule ID, name, or description) -- entirely client-side', async () => {
    renderExplorer()
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/search rules/i), 'encoded')

    expect(screen.getByText('Encoded PowerShell Command')).toBeInTheDocument()
    expect(screen.queryByText('Brute Force Authentication')).not.toBeInTheDocument()
  })

  it('filters rules by severity', async () => {
    renderExplorer()
    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Severity'), 'medium')

    expect(screen.getByText('Suspicious PowerShell Execution')).toBeInTheDocument()
    expect(screen.queryByText('Brute Force Authentication')).not.toBeInTheDocument()
  })

  it('shows an honest empty state when no rule matches the filter -- never fabricates a rule', async () => {
    renderExplorer()
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/search rules/i), 'does-not-exist-rule')

    expect(screen.getByText('No rules match')).toBeInTheDocument()
  })

  it('navigates to Rule Detail for the exact rule ID', async () => {
    renderExplorer()
    await userEvent.setup().click(screen.getByRole('link', { name: /Brute Force Authentication/i }))
    expect(await screen.findByText('brute_force_authentication')).toBeInTheDocument()
    expect(screen.getByText(/detects repeated authentication failures/i)).toBeInTheDocument()
  })
})

describe('RuleDetailPage', () => {
  it('shows real rule fields: name, rule ID, description, severity, confidence, event type(s), MITRE', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderWithProviders(
      <Routes>
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      </Routes>,
      { route: '/rules/encoded_powershell_command' },
    )

    expect(await screen.findByText('Encoded PowerShell Command')).toBeInTheDocument()
    expect(screen.getByText('encoded_powershell_command')).toBeInTheDocument()
    expect(screen.getByText('process_creation')).toBeInTheDocument()
    expect(screen.getByText('T1059.001')).toBeInTheDocument()
    expect(screen.getByText('T1027.010')).toBeInTheDocument()
  })

  it('shows an honest "Rule not found" state for an unknown rule ID -- never invents a rule', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      </Routes>,
      { route: '/rules/does_not_exist_rule' },
    )

    expect(await screen.findByText('Rule not found')).toBeInTheDocument()
    expect(screen.getByText(/does not match any detection rule/i)).toBeInTheDocument()
  })

  it('shows the real alerts generated by this rule via GET /alerts?rule_id=..., with zero investigation/Copilot/event requests', async () => {
    const listMock = vi
      .spyOn(alertsService, 'listAlerts')
      .mockResolvedValue(resp([makeAlert({ title: 'Real rule-linked alert', rule_id: 'brute_force_authentication' })]))
    renderWithProviders(
      <Routes>
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      </Routes>,
      { route: '/rules/brute_force_authentication' },
    )

    expect(await screen.findByText('Real rule-linked alert')).toBeInTheDocument()
    expect(listMock).toHaveBeenCalledWith(expect.objectContaining({ rule_id: 'brute_force_authentication' }))
    expect(listMock).toHaveBeenCalledTimes(1)
  })

  it('shows an honest empty-alerts message when this rule has generated no alerts in the current view', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderWithProviders(
      <Routes>
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      </Routes>,
      { route: '/rules/brute_force_authentication' },
    )

    expect(await screen.findByText('No alerts generated by this rule in the current view.')).toBeInTheDocument()
  })

  it('shows a safe error state if the rule-scoped alert fetch fails, with retry', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderWithProviders(
      <Routes>
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      </Routes>,
      { route: '/rules/brute_force_authentication' },
    )

    expect(await screen.findByText(/unable to retrieve alerts for this rule/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)

    mock.mockResolvedValue(resp([]))
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByText('No alerts generated by this rule in the current view.')).toBeInTheDocument())
  })

  it('never displays a fabricated historical alert total -- only the real page of returned items', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert({ title: 'Count-free alert' })]))
    renderWithProviders(
      <Routes>
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      </Routes>,
      { route: '/rules/brute_force_authentication' },
    )

    await screen.findByText('Count-free alert')
    expect(screen.queryByText(/^total/i)).not.toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/total alerts:\s*\d+/i)
  })

  it('never renders a rule editor or any execution control on the rule detail page', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderWithProviders(
      <Routes>
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      </Routes>,
      { route: '/rules/brute_force_authentication' },
    )

    await screen.findByText('Brute Force Authentication')
    expect(screen.queryByRole('textbox', { name: /yaml|sigma|query|regex/i })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/isolate host|kill process|block ip|run command|execute playbook/i)
  })
})

describe('Alert -> Rule navigation', () => {
  it('makes a resolvable rule_id a real link to Rule Detail from Alert Detail', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ rule_id: 'brute_force_authentication' }))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderWithProviders(
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      </Routes>,
      { route: '/alerts/alert-1' },
    )

    const ruleLink = await screen.findByRole('link', { name: 'Brute Force Authentication' })
    expect(ruleLink).toHaveAttribute('href', '/rules/brute_force_authentication')
    expect(screen.getByText('brute_force_authentication')).toBeInTheDocument()

    await userEvent.setup().click(ruleLink)
    expect(await screen.findByText('brute_force_authentication')).toBeInTheDocument()
    expect(screen.getAllByText('Brute Force Authentication').length).toBeGreaterThan(0)
  })

  it('shows an unresolvable rule_id as plain text, never a fabricated rule link', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ rule_id: 'future_unmapped_rule' }))
    renderWithProviders(
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
      </Routes>,
      { route: '/alerts/alert-1' },
    )

    const matches = await screen.findAllByText('future_unmapped_rule')
    expect(matches.length).toBeGreaterThan(0)
    expect(screen.queryByRole('link', { name: 'future_unmapped_rule' })).not.toBeInTheDocument()
  })
})
