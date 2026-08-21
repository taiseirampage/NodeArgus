import { useEffect, useState } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const POLL_INTERVAL_MS = 3000

interface TaskResult {
  ports_found?: number
  subdomains?: number
  subdomains_found?: number
  total_subdomains?: number
  unique_ips?: number
  tools_used?: string[]
  ips_to_scan?: number
  message?: string
  [key: string]: unknown
}

interface ScanStatusResponse {
  task_id: string
  status: string
  result: TaskResult | null
  error: string | null
  progress: Record<string, unknown> | null
}

interface TaskStatusProps {
  taskId: string | null
  targetIp: string | null
  onSuccess: (targetIp: string) => void
}

export function TaskStatus({ taskId, targetIp, onSuccess }: TaskStatusProps) {
  const [status, setStatus] = useState<ScanStatusResponse | null>(null)
  const [requestError, setRequestError] = useState<string | null>(null)

  useEffect(() => {
    if (!taskId) {
      setStatus(null)
      setRequestError(null)
      return
    }

    let isMounted = true
    let intervalId: number | undefined

    const stopPolling = (): void => {
      if (intervalId !== undefined) {
        window.clearInterval(intervalId)
      }
    }

    const pollStatus = async (): Promise<void> => {
      try {
        const response = await fetch(`${API_BASE_URL}/scan/${encodeURIComponent(taskId)}/status`)
        if (!response.ok) {
          throw new Error(`Ошибка статуса: HTTP ${response.status}`)
        }
        const nextStatus = (await response.json()) as ScanStatusResponse
        if (!isMounted) return
        setStatus(nextStatus)
        setRequestError(null)
        if (nextStatus.status === 'success' || nextStatus.status === 'failed') {
          stopPolling()
        }
        if (nextStatus.status === 'success' && targetIp) {
          onSuccess(targetIp)
        }
      } catch (error) {
        if (!isMounted) return
        setRequestError(error instanceof Error ? error.message : 'Не удалось получить статус задачи.')
      }
    }

    intervalId = window.setInterval(() => void pollStatus(), POLL_INTERVAL_MS)
    void pollStatus()

    return () => {
      isMounted = false
      stopPolling()
    }
  }, [onSuccess, targetIp, taskId])

  if (!taskId) {
    return (
      <aside className="panel-glow flex min-h-[20rem] flex-col justify-between rounded-3xl border border-dashed border-white/10 bg-slate-950/45 p-6 sm:p-8">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-600">02 / Live telemetry</p>
          <div className="mt-8 h-12 w-12 rounded-2xl border border-white/10 bg-white/[0.03] p-3 text-slate-600">
            <span className="block h-full w-full rounded-full border border-current" />
          </div>
          <h2 className="mt-6 font-display text-2xl font-medium text-slate-400">Ожидание задачи</h2>
          <p className="mt-3 max-w-sm text-sm leading-6 text-slate-600">Здесь появится поток состояния после запуска сканирования.</p>
        </div>
        <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-700">Polling interval // 3 sec</div>
      </aside>
    )
  }

  const isFinished = status?.status === 'success' || status?.status === 'failed'
  const statusLabel = status?.status === 'success'
    ? 'Операция завершена'
    : status?.status === 'failed'
      ? 'Операция остановлена'
      : status?.status === 'processing'
        ? 'Сканирование в процессе...'
        : 'Ожидание...'

  return (
    <aside className="panel-glow min-h-[20rem] rounded-3xl border border-white/10 bg-slate-950/75 p-6 shadow-2xl shadow-black/20 backdrop-blur-xl sm:p-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">02 / Live telemetry</p>
          <h2 className="mt-2 font-display text-2xl font-medium text-white">Task signal</h2>
        </div>
        <span className={`mt-1 h-3 w-3 rounded-full ${isFinished ? 'bg-emerald-300' : 'animate-pulse bg-amber-300 shadow-[0_0_18px_#fcd34d]'}`} />
      </div>

      <div className="mt-10 rounded-2xl border border-white/10 bg-black/20 p-5">
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-600">Task ID</p>
        <p className="mt-2 break-all font-mono text-xs leading-5 text-cyan-200">{taskId}</p>
      </div>

      {requestError ? (
        <p className="mt-6 rounded-xl border border-rose-300/20 bg-rose-300/5 px-4 py-3 text-sm text-rose-200" role="alert">{requestError}</p>
) : status?.status === 'success' ? (
        status.result?.total_subdomains !== undefined || status.result?.subdomains !== undefined || status.result?.subdomains_found !== undefined ? (
          <div className="mt-6 space-y-2">
            <p className="text-lg text-emerald-200">
              Успешно! Найдено поддоменов: {status.result?.total_subdomains ?? status.result?.subdomains ?? status.result?.subdomains_found ?? 0}
            </p>
            {(status.result?.unique_ips !== undefined || status.result?.tools_used !== undefined) && (
              <div className="rounded-xl border border-gray-700 bg-gray-900/50 p-3 font-mono text-xs leading-5 text-gray-300">
                {status.result?.unique_ips !== undefined && (
                  <p>unique IP: <span className="text-cyan-300">{status.result.unique_ips}</span></p>
                )}
                {Array.isArray(status.result.tools_used) && status.result.tools_used.length > 0 && (
                  <p className="mt-1">
                    tools: {status.result.tools_used.map((tool) => (
                      <span key={tool} className="ml-1 rounded-md bg-violet-400/10 px-2 py-0.5 uppercase text-violet-300">{tool}</span>
                    ))}
                  </p>
                )}
              </div>
            )}
            {status.result?.ips_to_scan !== undefined && (
              <p className="text-sm text-emerald-200">Активных сканов: {status.result.ips_to_scan}</p>
            )}
          </div>
        ) : (
          <p className="mt-6 text-lg text-emerald-200">Успешно! Найдено портов: {status.result?.ports_found ?? 0}</p>
        )
    ) : status?.status === 'failed' ? (
        <p className="mt-6 text-sm leading-6 text-rose-200">Ошибка: {status.error ?? 'Неизвестная ошибка'}</p>
      ) : (
        <div className="mt-6 space-y-3">
          <div className="flex items-center gap-3 text-sm text-amber-100">
            <span className="h-2 w-2 animate-pulse rounded-full bg-amber-300" />
            {statusLabel}
          </div>
          {status?.progress && Object.keys(status.progress).length > 0 && (
            <ul className="space-y-2 rounded-xl border border-gray-700 bg-black/20 p-3">
              {Object.entries(status.progress).map(([tool, state]) => (
                <li key={tool} className="flex items-center justify-between gap-3 text-xs">
                  <span className="font-mono uppercase tracking-wider text-gray-400">{tool}</span>
                  <span className={`flex items-center gap-2 font-mono ${
                    state === 'success'
                      ? 'text-emerald-300'
                      : state === 'failed'
                        ? 'text-rose-300'
                        : 'text-amber-200'
                  }`}>
                    {state !== 'success' && state !== 'failed' && (
                      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-300" />
                    )}
                    {String(state)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="mt-10 border-t border-white/10 pt-4 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-600">
        {isFinished ? 'Polling stopped // terminal state' : 'Polling active // every 3 seconds'}
      </div>
    </aside>
  )
}
