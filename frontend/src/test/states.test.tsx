import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'

describe('EmptyState (item 10)', () => {
  it('renders title and description', () => {
    render(<EmptyState title="No investigations yet" description="Nothing to show." />)
    expect(screen.getByText('No investigations yet')).toBeInTheDocument()
    expect(screen.getByText('Nothing to show.')).toBeInTheDocument()
  })
})

describe('ErrorState (item 11)', () => {
  it('renders a safe default message and calls onRetry', async () => {
    const onRetry = vi.fn()
    render(<ErrorState onRetry={onRetry} />)

    expect(screen.getByRole('alert')).toHaveTextContent(/unable to load security data/i)
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it('never renders without an explicit, safe message even when none is passed', () => {
    render(<ErrorState />)
    expect(screen.getByRole('alert').textContent).not.toMatch(/sql|traceback|stack/i)
  })
})
