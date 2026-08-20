import { useEffect, useState } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

interface PortDetails {
  port_number: number
  protocol: string
  service: string
  banner: string | null
}

interface IpDetails {
  ip: string
  country: string | null
  city: string | null
  os: string | null
  provider: string | null
  ports: PortDetails[]
}

interface NodeDetailsPanelProps {
  ip: string | null
  onClose: () => void
  onScanVuln: (ip: string) => void | Promise<void>
}

export function NodeDetailsPanel({ ip, onClose, onScanVuln }: NodeDetailsPanelProps) {
  const [details, setDetails] = useState<IpDetails | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [vulnerabilityRequested, setVulnerabilityRequested] = useState(false)

  useEffect(() => {
    if (!ip) return

    const selectedIp = ip
    const controller = new AbortController()
    setDetails(null)
    setLoading(true)
    setError(null)
    setVulnerabilityRequested(false)

    async function loadDetails(): Promise<void> {
      try {
        const response = await fetch(`${API_BASE_URL}/ip/${encodeURIComponent(selectedIp)}`, {
          signal: controller.signal,
        })
        if (!response.ok) {
          throw new Error(`Не удалось загрузить детали: HTTP ${response.status}`)
        }
        const payload = (await response.json()) as IpDetails
        console.info('[NodeDetailsPanel] IP details received', {
          ip: payload.ip,
          portsCount: payload.ports?.length ?? 0,
          ports: payload.ports,
        })
        setDetails(payload)
      } catch (requestError) {
        if (requestError instanceof DOMException && requestError.name === 'AbortError') return
        setError(requestError instanceof Error ? requestError.message : 'Ошибка загрузки деталей.')
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    void loadDetails()
    return () => controller.abort()
  }, [ip])

  if (!ip) return null

  return (
    <aside className="fixed right-0 top-0 z-50 h-full w-full overflow-y-auto border-l border-gray-700 bg-gray-800 shadow-2xl transition-transform sm:w-96">
      <div className="sticky top-0 z-10 flex items-start justify-between border-b border-gray-700 bg-gray-800/95 p-5 backdrop-blur">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-300">Node details</p>
          <h2 className="mt-2 break-all font-mono text-lg font-semibold text-white">{ip}</h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Закрыть панель"
          className="rounded-lg px-2 py-1 text-2xl leading-none text-gray-400 transition hover:bg-gray-700 hover:text-white"
        >
          ×
        </button>
      </div>

      <div className="space-y-6 p-5">
        {loading && <p className="font-mono text-sm text-cyan-300">Загрузка деталей...</p>}
        {error && (
          <p className="rounded-lg border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200" role="alert">
            {error}
          </p>
        )}

        {details && (
          <>
            <section>
              <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">Geo data</p>
              <dl className="space-y-3 rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm">
                <div className="flex justify-between gap-4"><dt className="text-gray-500">Страна</dt><dd className="text-right text-gray-200">{details.country ?? '—'}</dd></div>
                <div className="flex justify-between gap-4"><dt className="text-gray-500">Город</dt><dd className="text-right text-gray-200">{details.city ?? '—'}</dd></div>
                <div className="flex justify-between gap-4"><dt className="text-gray-500">Провайдер</dt><dd className="max-w-[11rem] text-right text-gray-200">{details.provider ?? '—'}</dd></div>
              </dl>
            </section>

            {details.os && (
              <section>
                <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">Operating system</p>
                <p className="rounded-xl border border-gray-700 bg-gray-900/50 p-4 font-mono text-sm text-emerald-300">{details.os}</p>
              </section>
            )}

            <section>
              <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">Open ports</p>
              {details.ports.length === 0 ? (
                <p className="rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm leading-6 text-gray-400">
                  Открытых портов не найдено или сканирование не проводилось
                </p>
              ) : (
                <div className="overflow-hidden rounded-xl border border-gray-700">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-gray-900 font-mono uppercase tracking-wider text-gray-500">
                      <tr><th className="px-3 py-3">Порт</th><th className="px-3 py-3">Протокол</th><th className="px-3 py-3">Сервис</th></tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700/80">
                      {details.ports.map((port) => (
                        <tr key={`${port.protocol}-${port.port_number}`} className="bg-gray-800/60">
                          <td className="px-3 py-3 font-mono text-cyan-300">{port.port_number}</td>
                          <td className="px-3 py-3 text-gray-400">{port.protocol}</td>
                          <td className="px-3 py-3 text-gray-200">
                            <div>{port.service}</div>
                            {port.banner && <div className="mt-1 break-all font-mono text-[10px] text-gray-500">{port.banner}</div>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <button
              type="button"
              disabled={vulnerabilityRequested}
              onClick={async () => {
                setVulnerabilityRequested(true)
                try {
                  await onScanVuln(ip)
                } finally {
                  setVulnerabilityRequested(false)
                }
              }}
              className="w-full rounded-xl bg-orange-500 px-4 py-3 text-sm font-semibold text-gray-950 transition hover:bg-orange-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {vulnerabilityRequested ? 'Задача отправлена...' : '🛡️ Запустить поиск уязвимостей'}
            </button>
          </>
        )}
      </div>
    </aside>
  )
}
