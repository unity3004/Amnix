import { describe, expect, it, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ThreatPulsePanel } from '@/features/dashboard/components/ThreatPulsePanel'
import { LiveIndicator } from '@/components/live/LiveIndicator'

const originalMatchMedia = window.matchMedia

function mockReducedMotion(matches: boolean) {
  window.matchMedia = (query: string) =>
    ({
      matches: query.includes('prefers-reduced-motion') ? matches : false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList
}

describe('reduced motion (item 14)', () => {
  afterEach(() => {
    window.matchMedia = originalMatchMedia
  })

  it('ThreatPulsePanel still renders its state label under prefers-reduced-motion', () => {
    mockReducedMotion(true)
    render(<ThreatPulsePanel state="critical" />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText('Threat Pulse')).toBeInTheDocument()
  })

  it('ThreatPulsePanel renders the same content regardless of motion preference', () => {
    mockReducedMotion(false)
    const { unmount } = render(<ThreatPulsePanel state="active" />)
    expect(screen.getByText('Active')).toBeInTheDocument()
    unmount()

    mockReducedMotion(true)
    render(<ThreatPulsePanel state="active" />)
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('LiveIndicator renders correctly under prefers-reduced-motion', () => {
    mockReducedMotion(true)
    render(<LiveIndicator state="live" lastSuccessfulRefreshAt={new Date()} />)
    expect(screen.getByText('LIVE')).toBeInTheDocument()
  })
})
