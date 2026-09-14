import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
})

// jsdom does not implement matchMedia -- MetricCard's count-up animation
// and the reduced-motion base styles both query it.
if (!window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })
}

// jsdom does not implement ResizeObserver -- recharts' ResponsiveContainer needs it.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
;(globalThis as any).ResizeObserver = (globalThis as any).ResizeObserver ?? ResizeObserverStub

// jsdom does not implement IntersectionObserver -- the Step 12W Incident
// Console's scroll-spy nav rail (IncidentNavRail) needs it.
class IntersectionObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords(): IntersectionObserverEntry[] {
    return []
  }
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
;(globalThis as any).IntersectionObserver = (globalThis as any).IntersectionObserver ?? IntersectionObserverStub
