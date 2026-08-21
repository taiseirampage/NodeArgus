// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NodeDetailsPanel } from './NodeDetailsPanel'


afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})


describe('NodeDetailsPanel request lifecycle', () => {
  it('aborts the previous request when the selected IP changes', async () => {
    const ipNode = (id: string) => ({
      id,
      node_type: 'ip' as const,
      source: null,
      resolved_ips: [],
      country: null,
      city: null,
      os: null,
      ports_count: 0,
    })
    const signals: AbortSignal[] = []
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.signal) signals.push(init.signal)
      return new Promise<Response>(() => undefined)
    })
    vi.stubGlobal('fetch', fetchMock)

    const view = render(
      <NodeDetailsPanel node={ipNode('192.168.1.10')} onClose={() => undefined} />,
    )
    await waitFor(() => expect(signals).toHaveLength(1))

    view.rerender(
      <NodeDetailsPanel node={ipNode('192.168.1.20')} onClose={() => undefined} />,
    )
    await waitFor(() => expect(signals).toHaveLength(2))

    expect(signals[0].aborted).toBe(true)
    view.unmount()
    expect(signals[1].aborted).toBe(true)
  })

  it('polls vulnerability status and stops after a terminal result', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn()
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        ip: '192.168.1.10',
        country: null,
        city: null,
        os: null,
        provider: null,
        ports: [],
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ task_id: 'vuln-task-1', status: 'queued' }), { status: 202 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ task_id: 'vuln-task-1', status: 'processing' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        task_id: 'vuln-task-1',
        status: 'success',
        vulnerabilities: [],
        message: null,
      }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    render(<NodeDetailsPanel
      node={{
        id: '192.168.1.10',
        node_type: 'ip',
        source: null,
        resolved_ips: [],
        country: null,
        city: null,
        os: null,
        ports_count: 0,
      }}
      onClose={() => undefined}
    />)
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    fireEvent.click(screen.getByRole('button', { name: /запустить поиск уязвимостей/i }))
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(screen.getByText('Сканирование...')).toBeTruthy()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(screen.getByText('Уязвимостей не обнаружено')).toBeTruthy()
    expect(fetchMock).toHaveBeenCalledTimes(4)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000)
    })
    expect(fetchMock).toHaveBeenCalledTimes(4)
    vi.useRealTimers()
  })
})


describe('NodeDetailsPanel ASN and sources', () => {
  it('shows ASN information for a domain node', () => {
    render(
      <NodeDetailsPanel
        node={{
          id: 'example.com',
          node_type: 'domain',
          source: null,
          resolved_ips: [],
          country: null,
          city: null,
          os: null,
          ports_count: 0,
          asn_number: '13335',
          asn_cidr: '104.20.16.0/20',
          asn_org: 'CLOUDFLARENET',
        }}
        onClose={() => undefined}
      />,
    )

    expect(screen.getByText('AS13335')).toBeTruthy()
    expect(screen.getByText('CLOUDFLARENET')).toBeTruthy()
    expect(screen.getByText('104.20.16.0/20')).toBeTruthy()
  })

  it('shows the full comma-separated source list for a subdomain', () => {
    render(
      <NodeDetailsPanel
        node={{
          id: 'www.example.com',
          node_type: 'subdomain',
          source: 'crtsh,subfinder,amass',
          resolved_ips: ['104.20.23.154'],
          country: null,
          city: null,
          os: null,
          ports_count: 0,
        }}
        onClose={() => undefined}
      />,
    )

    expect(screen.getByText('crtsh · subfinder · amass')).toBeTruthy()
  })
})
