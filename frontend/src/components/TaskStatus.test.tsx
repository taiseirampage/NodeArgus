// @vitest-environment jsdom
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TaskStatus } from './TaskStatus'


afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})


function statusResponse(id: string, status: string, result: Record<string, unknown> | null = null): Response {
  return new Response(JSON.stringify({
    task_id: id,
    status,
    result,
    error: null,
    progress: null,
  }), { status: 200 })
}


describe('TaskStatus multi-target polling', () => {
  it('polls every task and reports success only when all complete', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn()
    fetchMock
      .mockResolvedValueOnce(statusResponse('t1', 'pending'))
      .mockResolvedValueOnce(statusResponse('t2', 'processing'))
      .mockResolvedValueOnce(statusResponse('t1', 'success', { total_subdomains: 3 }))
      .mockResolvedValueOnce(statusResponse('t2', 'success', { total_subdomains: 1 }))
    vi.stubGlobal('fetch', fetchMock)

    const onSuccess = vi.fn()
    render(<TaskStatus taskIds={['t1', 't2']} targets={['a.com', 'b.com']} onSuccess={onSuccess} />)

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(screen.getByText('a.com')).toBeTruthy()
    expect(screen.getByText('b.com')).toBeTruthy()
    expect(screen.getAllByText('В процессе...').length).toBeGreaterThan(0)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })

    expect(onSuccess).toHaveBeenCalledWith(['a.com', 'b.com'])
    expect(screen.getByText(/Завершено задач: 2/)).toBeTruthy()
    expect(screen.queryByText('В процессе...')).toBeFalsy()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000)
    })
    expect(fetchMock).toHaveBeenCalledTimes(4)
    vi.useRealTimers()
  })

  it('does not report success when any task failed', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn()
    fetchMock
      .mockResolvedValueOnce(statusResponse('t1', 'pending'))
      .mockResolvedValueOnce(statusResponse('t2', 'pending'))
      .mockResolvedValueOnce(statusResponse('t1', 'success', { total_subdomains: 2 }))
      .mockResolvedValueOnce(statusResponse('t2', 'failed', null))
    vi.stubGlobal('fetch', fetchMock)

    const onSuccess = vi.fn()
    render(<TaskStatus taskIds={['t1', 't2']} targets={['a.com', 'b.com']} onSuccess={onSuccess} />)

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })

    expect(onSuccess).not.toHaveBeenCalled()
    expect(screen.queryByText(/Операция завершена/)).toBeFalsy()
    expect(screen.getByText(/Ошибка/)).toBeTruthy()
    vi.useRealTimers()
  })

  it('renders the waiting state when no tasks are tracked', async () => {
    render(<TaskStatus taskIds={[]} targets={[]} onSuccess={() => undefined} />)
    await waitFor(() => expect(screen.getByText('Ожидание задачи')).toBeTruthy())
  })
})