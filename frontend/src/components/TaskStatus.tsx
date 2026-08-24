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
  taskIds: string[]
  targets: string[]
  onSuccess: (targets: string[]) => void
}

function resultMetric(result: TaskResult | null | undefined): string | null {
  if (!result) return null
  if (typeof result.total_subdomains === 'number') return `${result.total_subdomains} поддоменов`
  if (typeof result.subdomains_found === 'number') return `${result.subdomains_found} поддоменов`
  if (typeof result.subdomains === 'number') return `${result.subdomains} поддоменов`
  if (typeof result.ports_found === 'number') return `${result.ports_found} портов`
  return null
}

export function TaskStatus({ taskIds, targets, onSuccess }: TaskStatusProps) {
  const [statuses, setStatuses] = useState<Record<string, ScanStatusResponse>>({})
  const [requestError, setRequestError] = useState<string | null>(null)

  useEffect(() => {
    if (taskIds.length === 0) {
      setStatuses({})
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

    const pollAll = async (): Promise<void> => {
      try {
        const settled = await Promise.allSettled(
          taskIds.map(
            async (id): Promise<{ id: string; status: ScanStatusResponse }> => {
              const response = await fetch(
                `${API_BASE_URL}/scan/${encodeURIComponent(id)}/status`,
              )
              if (!response.ok) {
                throw new Error(`Ошибка статуса: HTTP ${response.status}`)
              }
              return { id, status: (await response.json()) as ScanStatusResponse }
            },
          ),
        )
        if (!isMounted) return

        const nextMap: Record<string, ScanStatusResponse> = {}
        let hadFailure = false
        for (const outcome of settled) {
          if (outcome.status === 'fulfilled') {
            nextMap[outcome.value.id] = outcome.value.status
          } else {
            hadFailure = true
          }
        }
        setStatuses(nextMap)
        setRequestError(hadFailure ? 'Не удалось получить статус всех задач.' : null)

        const allDone = taskIds.every((id) => {
          const current = nextMap[id]
          return current?.status === 'success' || current?.status === 'failed'
        })
        if (allDone) {
          stopPolling()
          const anyFailed = taskIds.some((id) => nextMap[id]?.status === 'failed')
          if (!anyFailed) {
            onSuccess(targets)
          }
        }
      } catch (error) {
        if (!isMounted) return
        setRequestError(error instanceof Error ? error.message : 'Не удалось получить статус задач.')
      }
    }

    intervalId = window.setInterval(() => void pollAll(), POLL_INTERVAL_MS)
    void pollAll()

    return () => {
      isMounted = false
      stopPolling()
    }
  }, [onSuccess, targets, taskIds])

  if (taskIds.length === 0) {
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

  const terminal = (id: string): boolean => {
    const current = statuses[id]
    return current?.status === 'success' || current?.status === 'failed'
  }
  const anyFailed = taskIds.some((id) => statuses[id]?.status === 'failed')
  const allDone = taskIds.every(terminal)
  const allSuccess = allDone && !anyFailed
  const doneCount = taskIds.filter(terminal).length

  let statusLabel = 'Ожидание...'
  let signalClass = 'animate-pulse bg-amber-300 shadow-[0_0_18px_#fcd34d]'
  if (allSuccess) {
    statusLabel = 'Операция завершена'
    signalClass = 'bg-emerald-300'
  } else if (allDone && anyFailed) {
    statusLabel = 'Операция остановлена с ошибками'
    signalClass = 'bg-rose-400'
  } else if (anyFailed) {
    statusLabel = 'Частично завершено (есть ошибки)'
    signalClass = 'animate-pulse bg-rose-400 shadow-[0_0_18px_#fb7185]'
  } else if (doneCount > 0) {
    statusLabel = 'Сканирование в процессе...'
  }

  const firstError = taskIds
    .map((id) => statuses[id]?.error)
    .find((error): error is string => Boolean(error))

  const firstProgress = taskIds
    .map((id) => statuses[id])
    .find((current) => current?.progress && Object.keys(current.progress).length > 0)
    ?.progress

  return (
    <aside className="panel-glow min-h-[20rem] rounded-3xl border border-white/10 bg-slate-950/75 p-6 shadow-2xl shadow-black/20 backdrop-blur-xl sm:p-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">02 / Live telemetry</p>
          <h2 className="mt-2 font-display text-2xl font-medium text-white">Task signal</h2>
        </div>
        <span className={`mt-1 h-3 w-3 rounded-full ${signalClass}`} />
      </div>

      <div className="mt-10 rounded-2xl border border-white/10 bg-black/20 p-5">
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-600">
          Task IDs // {taskIds.length}
        </p>
        <p className="mt-2 break-all font-mono text-xs leading-5 text-cyan-200">
          {taskIds.join(', ')}
        </p>
      </div>

      {requestError ? (
        <p className="mt-6 rounded-xl border border-rose-300/20 bg-rose-300/5 px-4 py-3 text-sm text-rose-200" role="alert">{requestError}</p>
      ) : allSuccess ? (
        <div className="mt-6 space-y-2">
          <p className="text-lg text-emerald-200">Успешно! Завершено задач: {doneCount}</p>
          <ul className="space-y-1.5">
            {targets.map((target, index) => {
              const id = taskIds[index]
              const metric = resultMetric(id ? statuses[id]?.result : null)
              return (
                <li key={id ?? target} className="flex items-center justify-between gap-3 text-xs">
                  <span className="font-mono text-gray-300">{target}</span>
                  {metric && <span className="text-emerald-300">{metric}</span>}
                </li>
              )
            })}
          </ul>
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          <div className="flex items-center gap-3 text-sm text-amber-100">
            <span className={`h-2 w-2 rounded-full ${allDone ? 'bg-rose-400' : 'animate-pulse bg-amber-300'}`} />
            {statusLabel}
          </div>

          {firstError && (
            <p className="text-sm leading-6 text-rose-200" role="alert">Ошибка: {firstError}</p>
          )}

          <ul className="space-y-2 rounded-xl border border-gray-700 bg-black/20 p-3">
            {targets.map((target, index) => {
              const id = taskIds[index]
              const current = id ? statuses[id] : undefined
              const done = current?.status === 'success'
              const failed = current?.status === 'failed'
              const metric = resultMetric(current?.result)
              const label = failed ? 'Ошибка' : done ? 'Завершено' : 'В процессе...'
              return (
                <li key={id ?? `${target}-${index}`} className="flex items-center justify-between gap-3 text-xs">
                  <span className="font-mono tracking-wider text-gray-300">{target}</span>
                  <span className="flex items-center gap-2 font-mono">
                    {!done && !failed && (
                      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-300" />
                    )}
                    <span className={failed ? 'text-rose-300' : done ? 'text-emerald-300' : 'text-amber-200'}>
                      {label}
                    </span>
                    {metric && <span className="text-slate-400">· {metric}</span>}
                  </span>
                </li>
              )
            })}
          </ul>

          {firstProgress && (
            <ul className="space-y-2 rounded-xl border border-gray-700 bg-black/20 p-3">
              {Object.entries(firstProgress).map(([tool, state]) => (
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
        {allDone ? 'Polling stopped // terminal state' : 'Polling active // every 3 seconds'}
      </div>
    </aside>
  )
}