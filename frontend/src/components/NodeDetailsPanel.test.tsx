// @vitest-environment jsdom
import { cleanup, render, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NodeDetailsPanel } from './NodeDetailsPanel'


afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})


describe('NodeDetailsPanel request lifecycle', () => {
  it('aborts the previous request when the selected IP changes', async () => {
    const signals: AbortSignal[] = []
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.signal) signals.push(init.signal)
      return new Promise<Response>(() => undefined)
    })
    vi.stubGlobal('fetch', fetchMock)

    const view = render(
      <NodeDetailsPanel ip="192.168.1.10" onClose={() => undefined} onScanVuln={() => undefined} />,
    )
    await waitFor(() => expect(signals).toHaveLength(1))

    view.rerender(
      <NodeDetailsPanel ip="192.168.1.20" onClose={() => undefined} onScanVuln={() => undefined} />,
    )
    await waitFor(() => expect(signals).toHaveLength(2))

    expect(signals[0].aborted).toBe(true)
    view.unmount()
    expect(signals[1].aborted).toBe(true)
  })
})
