import { describe, expect, it, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MetricCard } from '@/features/dashboard/components/MetricCard'
import { ShieldAlert } from 'lucide-react'

const originalMatchMedia = window.matchMedia

describe('reduced motion (item 14)', () => {
  afterEach(() => {
    window.matchMedia = originalMatchMedia
  })

  it('jumps straight to the final metric value when prefers-reduced-motion is set, instead of animating', async () => {
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

    render(<MetricCard label="Total Alerts" value={128} icon={ShieldAlert} />)

    // With reduced motion honored, the value is set synchronously on
    // mount rather than ramping up over animation frames.
    await waitFor(() => {
      expect(screen.getByText('128')).toBeInTheDocument()
    })
  })
})
