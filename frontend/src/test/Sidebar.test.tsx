import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Sidebar } from '@/components/layout/Sidebar'
import { renderWithProviders } from './utils'

describe('Sidebar', () => {
  it('renders every primary navigation item (item 5: sidebar navigation)', () => {
    renderWithProviders(<Sidebar collapsed={false} onToggle={() => {}} />)

    for (const label of ['Dashboard', 'Alerts', 'Events', 'Investigations', 'AI Copilot', 'Audit Logs']) {
      expect(screen.getByRole('link', { name: new RegExp(label, 'i') })).toBeInTheDocument()
    }
  })

  it('links point at the correct routes', () => {
    renderWithProviders(<Sidebar collapsed={false} onToggle={() => {}} />)
    expect(screen.getByRole('link', { name: /alerts/i })).toHaveAttribute('href', '/alerts')
    expect(screen.getByRole('link', { name: /ai copilot/i })).toHaveAttribute('href', '/copilot')
  })

  it('collapses to icon-only width when toggled', async () => {
    let collapsed = false
    const { rerender } = renderWithProviders(
      <Sidebar collapsed={collapsed} onToggle={() => (collapsed = !collapsed)} />,
    )
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /collapse sidebar/i }))
    expect(collapsed).toBe(true)

    rerender(<Sidebar collapsed={true} onToggle={() => {}} />)
    expect(screen.queryByText('Dashboard')).not.toBeInTheDocument()
  })
})
