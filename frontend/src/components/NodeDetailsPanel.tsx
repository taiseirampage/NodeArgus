import { useEffect, useRef, useState, type ReactElement } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const VULN_POLL_INTERVAL_MS = 3000

interface PortDetails {
  port_number: number
  protocol: string
  service: string
  banner: string | null
  state: string
}

interface IpDetails {
  ip: string
  country: string | null
  city: string | null
  os: string | null
  provider: string | null
  scripts_info: Record<string, string>
  has_anonymous_access: boolean
  traceroute: TracerouteHop[]
  ports: PortDetails[]
  web_techs: WebTechDetails[]
}

interface TracerouteHop {
  ttl: number
  ip: string | null
  hostname: string | null
  rtt: string | null
}

interface WebTechDetails {
  id: number
  url: string
  status_code: number | null
  title: string | null
  technologies: string[]
  web_server: string | null
  discovered_at: string
  endpoints: WebEndpointDetails[]
}

interface WebEndpointDetails {
  id: number
  path: string
  method: string
  source: string | null
  discovered_at: string
}

export interface Vulnerability {
  id: number
  cve_id: string | null
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string
  matched_at: string
  found_at: string
}

export interface SelectedNode {
  id: string
  node_type: 'ip' | 'domain' | 'subdomain' | 'asn'
  source: string | null
  resolved_ips: string[]
  country: string | null
  city: string | null
  os: string | null
  ports_count: number
  asn_number?: string | null
  asn_cidr?: string | null
  asn_org?: string | null
}

interface VulnerabilityScanResponse {
  task_id: string | null
  status: 'queued' | 'processing' | 'success' | 'failed' | 'cached' | 'cancelled'
  vulnerabilities: Vulnerability[] | null
  message: string | null
}

interface VulnerabilityQueueResponse {
  task_id: string
  status: 'queued'
}

interface NodeDetailsPanelProps {
  node: SelectedNode | null
  onClose: () => void
}

const severityStyles: Record<Vulnerability['severity'], string> = {
  critical: 'bg-red-900 text-red-200',
  high: 'bg-orange-900 text-orange-200',
  medium: 'bg-yellow-900 text-yellow-200',
  low: 'bg-blue-900 text-blue-200',
  info: 'bg-gray-700 text-gray-300',
}

const severityLabels: Record<Vulnerability['severity'], string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
}

const WEB_SCAN_TAG_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'wordpress', label: 'WordPress' },
  { value: 'php', label: 'PHP' },
  { value: 'nginx', label: 'Nginx' },
  { value: 'apache', label: 'Apache' },
  { value: 'laravel', label: 'Laravel' },
  { value: 'django', label: 'Django' },
  { value: 'misconfig', label: 'Misconfig' },
  { value: 'exposure', label: 'Exposure' },
  { value: 'cve', label: 'CVE' },
  { value: 'default-login', label: 'Default login' },
  { value: 'tech', label: 'Tech' },
]

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

function waitForNextPoll(signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let timeoutId: number | undefined
    const onAbort = (): void => {
      if (timeoutId !== undefined) window.clearTimeout(timeoutId)
      reject(new DOMException('Polling aborted', 'AbortError'))
    }
    timeoutId = window.setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, VULN_POLL_INTERVAL_MS)
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

function scriptLabel(scriptId: string): string {
  return scriptId.replace(/[:_/-]+/g, ' ')
}

function isUnknownOs(os: string | null): boolean {
  return !os || /unknown|filtered|не определ/i.test(os)
}

function portStateClass(state: string): string {
  if (state === 'open') return 'text-emerald-300'
  if (state === 'closed') return 'text-rose-300'
  if (state === 'filtered') return 'text-amber-300'
  return 'text-gray-400'
}

const techPalette = [
  'bg-cyan-400/10 text-cyan-300 border-cyan-400/30',
  'bg-emerald-400/10 text-emerald-300 border-emerald-400/30',
  'bg-violet-400/10 text-violet-300 border-violet-400/30',
  'bg-amber-400/10 text-amber-300 border-amber-400/30',
  'bg-rose-400/10 text-rose-300 border-rose-400/30',
  'bg-sky-400/10 text-sky-300 border-sky-400/30',
]

function techBadgeClass(tech: string): string {
  let hash = 0
  for (const char of tech) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  return techPalette[hash % techPalette.length]
}

function statusCodeClass(code: number | null): string {
  if (code === null) return 'text-gray-400'
  if (code >= 200 && code < 300) return 'text-emerald-300'
  if (code >= 300 && code < 400) return 'text-cyan-300'
  if (code >= 400 && code < 500) return 'text-amber-300'
  return 'text-rose-300'
}

function methodBadgeClass(method: string): string {
  const upper = method.toUpperCase()
  if (upper === 'GET') return 'bg-cyan-400/10 text-cyan-300'
  if (upper === 'POST') return 'bg-amber-400/10 text-amber-300'
  return 'bg-gray-500/20 text-gray-300'
}

async function copyToClipboard(
  text: string,
  setCopied: (value: string) => void,
  setClear: (updater: (current: string | null) => string | null) => void,
): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
    setCopied(text)
    window.setTimeout(() => {
      setClear((current: string | null) => (current === text ? null : current))
    }, 1500)
  } catch {
    /* Clipboard unavailable (e.g. non-HTTPS); the URL remains visible. */
  }
}

export function NodeDetailsPanel({ node, onClose }: NodeDetailsPanelProps): ReactElement | null {
  const [details, setDetails] = useState<IpDetails | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isScanningVuln, setIsScanningVuln] = useState(false)
  const [vulnTaskId, setVulnTaskId] = useState<string | null>(null)
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[] | null>(null)
  const [vulnError, setVulnError] = useState<string | null>(null)
  const [vulnMessage, setVulnMessage] = useState<string | null>(null)
  const [isCancellingVuln, setIsCancellingVuln] = useState(false)
  const [scriptsExpanded, setScriptsExpanded] = useState(false)
  const [webReconExpanded, setWebReconExpanded] = useState(true)
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null)
  const [useStealthMode, setUseStealthMode] = useState<boolean>(false)
  const [useWafBypassMode, setUseWafBypassMode] = useState<boolean>(false)
  const [webScanTags, setWebScanTags] = useState<string[]>([])
  const [exportOpen, setExportOpen] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const vulnControllerRef = useRef<AbortController | null>(null)

  const isIpNode = node?.node_type === 'ip'

  useEffect(() => {
    vulnControllerRef.current?.abort()
    vulnControllerRef.current = null
    setIsScanningVuln(false)
    setVulnTaskId(null)
    setVulnerabilities(null)
    setVulnError(null)
    setVulnMessage(null)
    setIsCancellingVuln(false)
    setWebScanTags([])
    setExportOpen(false)
    setExportError(null)
    setScriptsExpanded(false)
    setWebReconExpanded(true)
    setCopiedUrl(null)

    if (!node) {
      setDetails(null)
      setLoading(false)
      setError(null)
      return
    }

    if (node.node_type !== 'ip') {
      setDetails(null)
      setLoading(false)
      setError(null)
      return
    }

    const selectedIp = node.id
    const controller = new AbortController()
    setDetails(null)
    setLoading(true)
    setError(null)

    async function loadDetails(): Promise<void> {
      try {
        const response = await fetch(`${API_BASE_URL}/ip/${encodeURIComponent(selectedIp)}`, {
          signal: controller.signal,
        })
        if (!response.ok) {
          throw new Error(`Не удалось загрузить детали: HTTP ${response.status}`)
        }
        const payload = (await response.json()) as IpDetails
        setDetails({
          ...payload,
          scripts_info: payload.scripts_info ?? {},
          has_anonymous_access: payload.has_anonymous_access ?? false,
          traceroute: payload.traceroute ?? [],
          web_techs: payload.web_techs ?? [],
        })
      } catch (requestError: unknown) {
        if (isAbortError(requestError)) return
        setError(requestError instanceof Error ? requestError.message : 'Ошибка загрузки деталей.')
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    void loadDetails()
    return () => {
      controller.abort()
      vulnControllerRef.current?.abort()
    }
  }, [node])

  async function startVulnerabilityScan(): Promise<void> {
    if (!node || !isIpNode || isScanningVuln) return

    const selectedIp = node.id
    const controller = new AbortController()
    vulnControllerRef.current?.abort()
    vulnControllerRef.current = controller
    setIsScanningVuln(true)
    setVulnTaskId(null)
    setVulnerabilities(null)
    setVulnError(null)
    setVulnMessage(null)

    try {
      const query = new URLSearchParams()
      if (useStealthMode) query.set('use_stealth_mode', 'true')
      if (useWafBypassMode) query.set('waf_bypass_mode', 'true')
      const queryString = query.toString()
      const queueUrl = `${API_BASE_URL}/vuln/${encodeURIComponent(selectedIp)}${queryString ? `?${queryString}` : ''}`
      const queueResponse = await fetch(queueUrl, {
        method: 'POST',
        signal: controller.signal,
      })
      if (!queueResponse.ok) {
        throw new Error(`Не удалось запустить поиск уязвимостей: HTTP ${queueResponse.status}`)
      }
      const queued = (await queueResponse.json()) as VulnerabilityQueueResponse
      setVulnTaskId(queued.task_id)
      await pollVulnerabilityTask(selectedIp, queued.task_id, controller)
    } catch (requestError: unknown) {
      if (isAbortError(requestError)) return
      if (!controller.signal.aborted) {
        setVulnError(requestError instanceof Error ? requestError.message : 'Ошибка поиска уязвимостей.')
        setIsScanningVuln(false)
      }
    } finally {
      if (vulnControllerRef.current === controller && controller.signal.aborted) {
        vulnControllerRef.current = null
      }
    }
  }

  async function startWebHostVulnerabilityScan(): Promise<void> {
    if (!node || !isIpNode || isScanningVuln) return
    if (!details || !details.web_techs || details.web_techs.length === 0) return

    const selectedIp = node.id
    const controller = new AbortController()
    vulnControllerRef.current?.abort()
    vulnControllerRef.current = controller
    setIsScanningVuln(true)
    setVulnTaskId(null)
    setVulnerabilities(null)
    setVulnError(null)
    setVulnMessage(null)

    try {
      const query = new URLSearchParams()
      if (useStealthMode) query.set('use_stealth_mode', 'true')
      if (useWafBypassMode) query.set('waf_bypass_mode', 'true')
      webScanTags.forEach((tag) => query.append('tags', tag))
      const queryString = query.toString()
      const queueUrl = `${API_BASE_URL}/vuln/${encodeURIComponent(selectedIp)}/web${queryString ? `?${queryString}` : ''}`
      const queueResponse = await fetch(queueUrl, {
        method: 'POST',
        signal: controller.signal,
      })
      if (!queueResponse.ok) {
        const body = (await queueResponse.json().catch(() => null)) as { detail?: string } | null
        throw new Error(body?.detail ?? `Не удалось запустить сканирование веб-хостов: HTTP ${queueResponse.status}`)
      }
      const queued = (await queueResponse.json()) as VulnerabilityQueueResponse
      setVulnTaskId(queued.task_id)
      await pollVulnerabilityTask(selectedIp, queued.task_id, controller)
    } catch (requestError: unknown) {
      if (isAbortError(requestError)) return
      if (!controller.signal.aborted) {
        setVulnError(requestError instanceof Error ? requestError.message : 'Ошибка сканирования веб-хостов.')
        setIsScanningVuln(false)
      }
    } finally {
      if (vulnControllerRef.current === controller && controller.signal.aborted) {
        vulnControllerRef.current = null
      }
    }
  }

  async function pollVulnerabilityTask(
    selectedIp: string,
    taskId: string,
    controller: AbortController,
  ): Promise<void> {
    while (!controller.signal.aborted) {
      const response = await fetch(
        `${API_BASE_URL}/vuln/${encodeURIComponent(selectedIp)}/${encodeURIComponent(taskId)}`,
        { signal: controller.signal },
      )
      if (!response.ok) {
        throw new Error(`Не удалось получить статус поиска: HTTP ${response.status}`)
      }
      const result = (await response.json()) as VulnerabilityScanResponse
      if (result.status === 'success' || result.status === 'cached') {
        setVulnerabilities(result.vulnerabilities ?? [])
        setVulnMessage(
          result.status === 'cached'
            ? 'Показаны результаты последнего сканирования (менее 24 часов)'
            : result.message,
        )
        setIsScanningVuln(false)
        return
      }
      if (result.status === 'failed') {
        throw new Error(result.message ?? 'Поиск уязвимостей завершился с ошибкой.')
      }
      if (result.status === 'cancelled') {
        setVulnMessage(result.message ?? 'Сканирование отменено.')
        setIsScanningVuln(false)
        return
      }
      await waitForNextPoll(controller.signal)
    }
  }

  async function downloadExport(kind: 'full' | 'ports' | 'vulns' | 'endpoints'): Promise<void> {
    if (!node) return
    const target = node.id.trim()
    if (!target) return

    const ext = kind === 'full' ? 'json' : 'csv'
    const filename = `nodeargus_${target.replace(/[^\w.-]/g, '_')}_${kind}.${ext}`
    setExportError(null)
    setExportOpen(false)
    try {
      const response = await fetch(`${API_BASE_URL}/export/${encodeURIComponent(target)}/${kind}`)
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { detail?: string } | null
        throw new Error(body?.detail ?? `Ошибка экспорта: HTTP ${response.status}`)
      }
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (requestError: unknown) {
      setExportError(requestError instanceof Error ? requestError.message : 'Не удалось скачать файл.')
    }
  }

  async function cancelVulnerabilityScan(): Promise<void> {
    if (!node || !isIpNode || !vulnTaskId || isCancellingVuln) return

    const selectedIp = node.id
    const selectedTaskId = vulnTaskId
    vulnControllerRef.current?.abort()
    setIsCancellingVuln(true)
    setVulnError(null)
    try {
      const response = await fetch(
        `${API_BASE_URL}/vuln/${encodeURIComponent(selectedIp)}/${encodeURIComponent(selectedTaskId)}/cancel`,
        { method: 'POST' },
      )
      if (!response.ok) {
        throw new Error(`Не удалось отменить сканирование: HTTP ${response.status}`)
      }
      setIsScanningVuln(false)
      setVulnMessage('Сканирование отменено.')
    } catch (requestError: unknown) {
      setVulnError(requestError instanceof Error ? requestError.message : 'Не удалось отменить сканирование.')
      setIsScanningVuln(false)
    } finally {
      setIsCancellingVuln(false)
    }
  }

  if (!node) return null

  const nodeLabel = node.node_type === 'domain'
    ? 'Домен'
    : node.node_type === 'subdomain'
      ? 'Поддомен'
      : 'IP-адрес'
  const nodeAccent = node.node_type === 'ip' ? 'text-cyan-300' : 'text-violet-300'

  return (
    <aside className="fixed right-0 top-0 z-50 h-full w-full overflow-y-auto border-l border-gray-700 bg-gray-800 shadow-2xl transition-transform sm:w-96">
      <div className="sticky top-0 z-10 flex items-start justify-between border-b border-gray-700 bg-gray-800/95 p-5 backdrop-blur">
        <div>
          <p className={`font-mono text-[10px] uppercase tracking-[0.2em] ${nodeAccent}`}>{nodeLabel}</p>
          <h2 className="mt-2 break-all font-mono text-lg font-semibold text-white">{node.id}</h2>
        </div>
        <div className="flex items-start gap-2">
          {(node.node_type === 'ip' || node.node_type === 'domain') && (
            <div className="relative">
              <button
                type="button"
                onClick={() => setExportOpen((open) => !open)}
                aria-haspopup="menu"
                aria-expanded={exportOpen}
                aria-label="Экспорт результатов"
                className="rounded-lg border border-gray-600 px-2 py-1 text-lg leading-none text-gray-300 transition hover:border-cyan-400/60 hover:text-white"
              >
                ⬇️
              </button>
              {exportOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setExportOpen(false)} aria-hidden="true" />
                  <div
                    role="menu"
                    className="absolute right-0 top-full z-50 mt-2 w-52 overflow-hidden rounded-xl border border-gray-600 bg-gray-900 text-left shadow-xl"
                  >
                    <p className="border-b border-gray-700 px-3 py-2 font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">Экспорт</p>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => void downloadExport('full')}
                      className="flex w-full items-center gap-2 px-3 py-2.5 text-sm text-gray-200 transition hover:bg-gray-800"
                    >
                      <span aria-hidden="true">📄</span> Полный отчет (JSON)
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => void downloadExport('ports')}
                      className="flex w-full items-center gap-2 px-3 py-2.5 text-sm text-gray-200 transition hover:bg-gray-800"
                    >
                      <span aria-hidden="true">📊</span> Порты (CSV)
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => void downloadExport('vulns')}
                      className="flex w-full items-center gap-2 px-3 py-2.5 text-sm text-gray-200 transition hover:bg-gray-800"
                    >
                      <span aria-hidden="true">🛡️</span> Уязвимости (CSV)
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => void downloadExport('endpoints')}
                      className="flex w-full items-center gap-2 px-3 py-2.5 text-sm text-gray-200 transition hover:bg-gray-800"
                    >
                      <span aria-hidden="true">🌐</span> Эндпоинты (CSV)
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
          <button
            type="button"
            onClick={onClose}
            aria-label="Закрыть панель"
            className="rounded-lg px-2 py-1 text-2xl leading-none text-gray-400 transition hover:bg-gray-700 hover:text-white"
          >
            ×
          </button>
        </div>
      </div>

      <div className="space-y-6 p-5">
        {loading && <p className="font-mono text-sm text-cyan-300">Загрузка деталей...</p>}
        {error && (
          <p className="rounded-lg border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200" role="alert">
            {error}
          </p>
        )}

        {exportError && (
          <p className="rounded-lg border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200" role="alert">
            {exportError}
          </p>
        )}

        {!isIpNode && node && (
          <section>
            <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">Разведка</p>
            {node.node_type === 'subdomain' && (
              <div className="space-y-3 rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm">
                <div className="flex items-start justify-between gap-4">
                  <span className="text-gray-500">🔍 Источник</span>
                  <span className="text-right font-mono text-violet-300">
                    {(node.source ?? 'неизвестен').split(',').filter(Boolean).join(' · ')}
                  </span>
                </div>
                <div className="flex items-start justify-between gap-4">
                  <span className="text-gray-500">Порты</span>
                  <span className="text-right font-mono text-cyan-300">{node.ports_count}</span>
                </div>
              </div>
            )}
            {node.node_type === 'domain' && (
              <div className="space-y-3 rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm">
                {node.asn_number ? (
                  <>
                    <div className="flex items-start justify-between gap-4">
                      <span className="text-gray-500">ASN</span>
                      <span className="text-right font-mono text-emerald-300">AS{node.asn_number}</span>
                    </div>
                    {node.asn_org && (
                      <div className="flex items-start justify-between gap-4">
                        <span className="text-gray-500">Организация</span>
                        <span className="max-w-[12rem] text-right font-mono text-emerald-200">{node.asn_org}</span>
                      </div>
                    )}
                    {node.asn_cidr && (
                      <div className="flex items-start justify-between gap-4">
                        <span className="text-gray-500">CIDR</span>
                        <span className="max-w-[12rem] break-all text-right font-mono text-emerald-200">{node.asn_cidr}</span>
                      </div>
                    )}
                  </>
                ) : (
                  <p className="leading-6 text-gray-400">
                    Корневой домен. Кликните на поддомены в графе, чтобы увидеть источник discovery и резолвленные IP.
                    ASN-информация появится после объединённой разведки с Amass.
                  </p>
                )}
              </div>
            )}
            <p className="mb-3 mt-4 font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">Резолвленные IP</p>
            {node.resolved_ips.length === 0 ? (
              <p className="rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm text-gray-400">
                IP-адреса не резолвлены
              </p>
            ) : (
              <ul className="space-y-2">
                {node.resolved_ips.map((resolvedIp) => (
                  <li
                    key={resolvedIp}
                    className="flex items-center justify-between gap-4 rounded-xl border border-gray-700 bg-gray-900/50 p-3 font-mono text-sm text-cyan-300"
                  >
                    <span>{resolvedIp}</span>
                    <span className="rounded-md bg-cyan-400/10 px-2 py-0.5 font-mono text-[10px] uppercase text-cyan-300">
                      DNS A
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {isIpNode && details && (
          <>
            <section>
              <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">Geo data</p>
              <dl className="space-y-3 rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm">
                <div className="flex justify-between gap-4"><dt className="text-gray-500">Страна</dt><dd className="text-right text-gray-200">{details.country ?? '—'}</dd></div>
                <div className="flex justify-between gap-4"><dt className="text-gray-500">Город</dt><dd className="text-right text-gray-200">{details.city ?? '—'}</dd></div>
                <div className="flex justify-between gap-4"><dt className="text-gray-500">Провайдер</dt><dd className="max-w-[11rem] text-right text-gray-200">{details.provider ?? '—'}</dd></div>
              </dl>
            </section>

            <section>
              <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">ОС и сеть</p>
              <div className="space-y-3 rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm">
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500">ОС</span>
                  {isUnknownOs(details.os) ? (
                    <span className="text-right text-gray-400">🖥️ ОС: Не определена (возможно, включена фильтрация фаерволом)</span>
                  ) : (
                    <span className="text-right font-mono text-emerald-300">🖥️ {details.os}</span>
                  )}
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500">Hops</span>
                  <span className="font-mono text-cyan-300">{details.traceroute.length}</span>
                </div>
              </div>
              {details.traceroute.length > 0 && (
                <ol className="mt-3 space-y-1 rounded-xl border border-gray-700/70 bg-gray-950/40 p-3 font-mono text-[11px] text-gray-400">
                  {details.traceroute.map((hop) => (
                    <li key={`${hop.ttl}-${hop.ip ?? hop.hostname ?? 'timeout'}`}>
                      {hop.ttl}. {hop.ip ?? hop.hostname ?? '*'}{hop.hostname && hop.ip ? ` (${hop.hostname})` : ''}
                      {hop.rtt ? ` · ${hop.rtt} ms` : ''}
                    </li>
                  ))}
                </ol>
              )}
              {details.traceroute.length <= 1 && (
                <p className="mt-3 rounded-lg border border-gray-700/70 bg-gray-950/40 p-3 text-xs leading-5 text-gray-400">
                  🌐 Сеть: Локальный сегмент ({details.traceroute.length} хопов) или скрытая топология.
                </p>
              )}
            </section>

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
                      <tr><th className="px-3 py-3">Порт</th><th className="px-3 py-3">Статус</th><th className="px-3 py-3">Протокол</th><th className="px-3 py-3">Сервис</th></tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700/80">
                      {details.ports.map((port) => (
                        <tr key={`${port.protocol}-${port.port_number}`} className="bg-gray-800/60">
                          <td className="px-3 py-3 font-mono text-cyan-300">{port.port_number}</td>
                          <td
                            className={`px-3 py-3 font-mono text-[10px] font-semibold uppercase ${portStateClass(port.state)}`}
                            title={port.state === 'filtered' ? 'Порт фильтруется фаерволом (нет ответа)' : undefined}
                          >
                            {port.state}
                          </td>
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

            <section>
              <button
                type="button"
                className="flex w-full items-center justify-between border-b border-gray-700 pb-3 text-left"
                onClick={() => setWebReconExpanded((expanded) => !expanded)}
                aria-expanded={webReconExpanded}
              >
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">Web & Endpoints</span>
                <span className="text-gray-500">{webReconExpanded ? '⌃' : '⌄'}</span>
              </button>
              {webReconExpanded && (
                <div className="space-y-4 pt-4">
                  {details.web_techs.length === 0 ? (
                    <p className="rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm leading-6 text-gray-400">
                      Веб-ресурсы не обнаружены (httpx пробинг не проводился или не вернул живых хостов)
                    </p>
                  ) : (
                    details.web_techs.map((tech) => (
                      <article key={tech.id} className="overflow-hidden rounded-xl border border-gray-700 bg-gray-900/60">
                        <div className="space-y-2 p-3">
                          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                            <button
                              type="button"
                              onClick={() => void copyToClipboard(tech.url, setCopiedUrl, setCopiedUrl)}
                              title="Скопировать URL"
                              className={`max-w-full truncate break-all font-mono text-xs text-cyan-300 transition hover:text-cyan-200 ${copiedUrl === tech.url ? 'text-emerald-300' : ''}`}
                            >
                              {copiedUrl === tech.url ? '✓ Скопировано' : tech.url}
                            </button>
                            <span className={`font-mono text-[10px] font-semibold ${statusCodeClass(tech.status_code)}`}>
                              {tech.status_code ?? '—'}
                            </span>
                          </div>
                          {tech.title && (
                            <p className="text-sm font-medium leading-5 text-gray-200">{tech.title}</p>
                          )}
                          {(tech.web_server || tech.technologies.length > 0) && (
                            <div className="flex flex-wrap gap-1.5">
                              {tech.web_server && (
                                <span className="rounded-md border border-gray-600 bg-gray-700/50 px-2 py-0.5 font-mono text-[10px] text-gray-300">
                                  {tech.web_server}
                                </span>
                              )}
                              {tech.technologies.map((name) => (
                                <span
                                  key={name}
                                  className={`rounded-md border px-2 py-0.5 font-mono text-[10px] ${techBadgeClass(name)}`}
                                >
                                  {name}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        {tech.endpoints.length > 0 && (
                          <div className="border-t border-gray-700/70">
                            <table className="w-full text-left text-xs">
                              <thead className="bg-gray-900 font-mono uppercase tracking-wider text-gray-500">
                                <tr>
                                  <th className="px-3 py-2">Метод</th>
                                  <th className="px-3 py-2">Endpoint</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-700/80">
                                {tech.endpoints.map((endpoint) => (
                                  <tr key={endpoint.id} className="bg-gray-800/40">
                                    <td className="px-3 py-2 align-top">
                                      <span className={`rounded-md px-1.5 py-0.5 font-mono text-[10px] font-semibold ${methodBadgeClass(endpoint.method)}`}>
                                        {endpoint.method}
                                      </span>
                                    </td>
                                    <td className="px-3 py-2">
                                      <button
                                        type="button"
                                        onClick={() => void copyToClipboard(endpoint.path, setCopiedUrl, setCopiedUrl)}
                                        title="Скопировать endpoint"
                                        className={`block max-w-full break-all text-left font-mono text-gray-300 transition hover:text-cyan-200 ${copiedUrl === endpoint.path ? 'text-emerald-300' : ''}`}
                                      >
                                        {endpoint.path}
                                      </button>
                                      {endpoint.source && (
                                        <span className="mt-0.5 block break-all font-mono text-[10px] text-gray-500">
                                          src: {endpoint.source}
                                        </span>
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </article>
                    ))
                  )}
                </div>
              )}
            </section>

            {Object.entries(details.scripts_info).some(([, output]) => output.trim().length > 0) && (
              <section>
                <button
                  type="button"
                  className="flex w-full items-center justify-between border-b border-gray-700 pb-3 text-left"
                  onClick={() => setScriptsExpanded((expanded) => !expanded)}
                  aria-expanded={scriptsExpanded}
                >
                  <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">NSE Scripts Info</span>
                  <span className="text-gray-500">⌄</span>
                </button>
                <div hidden={!scriptsExpanded} className="space-y-3 pt-3">
                  {Object.entries(details.scripts_info)
                    .filter(([, output]) => output.trim().length > 0)
                    .map(([scriptId, output]) => (
                      <article key={scriptId} className="rounded-lg border border-gray-700 bg-gray-950/50 p-3">
                        <h3 className="font-mono text-xs font-semibold capitalize text-cyan-300">{scriptLabel(scriptId)}</h3>
                        <pre className="mt-2 whitespace-pre-wrap break-words text-xs leading-5 text-gray-300">{output}</pre>
                      </article>
                    ))}
                </div>
              </section>
            )}

            <section className="space-y-4">
              <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-gray-700 bg-gray-900/50 p-3 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={useStealthMode}
                  disabled={isScanningVuln || isCancellingVuln || useWafBypassMode}
                  onChange={(event) => {
                    const checked = event.target.checked
                    setUseStealthMode(checked)
                    if (checked) setUseWafBypassMode(false)
                  }}
                  className="mt-0.5 h-4 w-4 accent-cyan-400"
                />
                <span>
                  <span className="font-medium text-gray-200">🕵️ Stealth Mode</span>
                  <span className="mt-1 block text-xs leading-5 text-gray-500">Медленнее, но обходит базовые WAF</span>
                </span>
              </label>
              {useStealthMode && (
                <p className="rounded-lg border border-amber-300/20 bg-amber-300/10 p-3 text-xs leading-5 text-amber-100" role="note">
                  Stealth mode может увеличить время сканирования до 10-15 минут.
                </p>
              )}

              <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-orange-700/60 bg-orange-900/20 p-3 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={useWafBypassMode}
                  disabled={isScanningVuln || isCancellingVuln || useStealthMode}
                  onChange={(event) => {
                    const checked = event.target.checked
                    setUseWafBypassMode(checked)
                    if (checked) setUseStealthMode(false)
                  }}
                  className="mt-0.5 h-4 w-4 accent-orange-400"
                />
                <span>
                  <span className="font-medium text-gray-200">⚡ WAF Bypass Mode</span>
                  <span className="mt-1 block text-xs leading-5 text-gray-500">
                    Агрессивный обход WAF (Cloudflare, ModSecurity, AWS WAF)
                  </span>
                </span>
              </label>
              {useWafBypassMode && (
                <p className="rounded-lg border border-amber-300/20 bg-amber-300/10 p-3 text-xs leading-5 text-amber-100" role="note">
                  WAF Bypass генерирует значительно больше трафика и может вызвать
                  блокировку IP со стороны WAF, срабатывание IDS/IPS, нагрузку на
                  целевой сервер и ложные срабатывания защиты (rate limiting, CAPTCHA).
                  Требуется ALLOW_WAF_BYPASS=true в .env.
                </p>
              )}
              <button
                type="button"
                disabled={isScanningVuln}
                onClick={() => void startVulnerabilityScan()}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-orange-500 px-4 py-3 text-sm font-semibold text-gray-950 transition hover:bg-orange-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isScanningVuln && <span className="h-4 w-4 animate-spin rounded-full border-2 border-gray-950/30 border-t-gray-950" aria-hidden="true" />}
                {isScanningVuln ? 'Сканирование...' : '🛡️ Запустить поиск уязвимостей'}
              </button>

              <button
                type="button"
                disabled={isScanningVuln || details.web_techs.length === 0}
                onClick={() => void startWebHostVulnerabilityScan()}
                title={details.web_techs.length === 0 ? 'Сначала запустите web recon, чтобы обнаружить веб-хосты' : 'Nuclei по хостам из WebTech (виртуальные хосты)'}
                className="flex w-full items-center justify-center gap-2 rounded-xl border border-orange-500/60 px-4 py-3 text-sm font-semibold text-orange-200 transition hover:bg-orange-500/10 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isScanningVuln ? 'Сканирование...' : `🕸️ Сканировать веб-хосты (${details.web_techs.length})`}
              </button>

              <div className="space-y-2 rounded-xl border border-gray-700 bg-gray-900/40 p-3">
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-gray-500">
                  Теги веб-хостов (пусто = все шаблоны)
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {WEB_SCAN_TAG_OPTIONS.map((option) => {
                    const active = webScanTags.includes(option.value)
                    return (
                      <button
                        key={option.value}
                        type="button"
                        disabled={isScanningVuln}
                        onClick={() => {
                          setWebScanTags((current) =>
                            active
                              ? current.filter((tag) => tag !== option.value)
                              : [...current, option.value],
                          )
                        }}
                        aria-pressed={active}
                        className={`rounded-md border px-2 py-1 font-mono text-[10px] transition disabled:cursor-not-allowed disabled:opacity-50 ${
                          active
                            ? 'border-orange-400/60 bg-orange-400/10 text-orange-200'
                            : 'border-gray-600 bg-gray-800/50 text-gray-400 hover:border-gray-500'
                        }`}
                      >
                        {option.label}
                      </button>
                    )
                  })}
                </div>
              </div>

              {isScanningVuln && (
                <>
                  <p className="text-xs leading-5 text-gray-400" role="status">
                    Сканирование может занять 2-5 минут
                  </p>
                  <button
                    type="button"
                    disabled={isCancellingVuln}
                    onClick={() => void cancelVulnerabilityScan()}
                    className="w-full rounded-xl border border-rose-300/30 px-4 py-2.5 text-sm font-semibold text-rose-200 transition hover:border-rose-300/60 hover:bg-rose-300/10 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {isCancellingVuln ? 'Отмена...' : 'Отменить сканирование'}
                  </button>
                </>
              )}

              {vulnTaskId && isScanningVuln && (
                <p className="break-all font-mono text-[10px] text-gray-500">Task: {vulnTaskId}</p>
              )}
              {vulnMessage && <p className="rounded-lg border border-cyan-400/20 bg-cyan-400/10 p-3 text-sm text-cyan-200" role="status">{vulnMessage}</p>}
              {vulnError && <p className="rounded-lg border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200" role="alert">{vulnError}</p>}

              {vulnerabilities !== null && (
                <div className="space-y-3 transition-all duration-500" aria-live="polite">
                  {vulnerabilities.length === 0 ? (
                    <p className="rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm text-gray-400">Уязвимостей не обнаружено</p>
                  ) : (
                    vulnerabilities.map((vulnerability) => (
                      <article key={vulnerability.id} className="rounded-xl border border-gray-700 bg-gray-900/60 p-4 transition-all duration-500">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className={`rounded-md px-2 py-1 font-mono text-[10px] font-semibold ${severityStyles[vulnerability.severity]}`}>
                            {severityLabels[vulnerability.severity]}
                          </span>
                          <time className="font-mono text-[10px] text-gray-500" dateTime={vulnerability.found_at}>
                            {new Date(vulnerability.found_at).toLocaleString()}
                          </time>
                        </div>
                        <h3 className="mt-3 font-semibold leading-5 text-white">{vulnerability.name}</h3>
                        {vulnerability.cve_id && (
                          <a
                            className="mt-1 inline-block font-mono text-xs text-cyan-300 underline decoration-cyan-300/40 underline-offset-2 transition hover:text-cyan-200"
                            href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(vulnerability.cve_id)}`}
                            target="_blank"
                            rel="noreferrer"
                          >
                            {vulnerability.cve_id}
                          </a>
                        )}
                        <p className="mt-3 break-all font-mono text-xs text-gray-400">{vulnerability.matched_at}</p>
                        <p className="mt-3 text-sm leading-6 text-gray-300">{vulnerability.description || 'Описание отсутствует.'}</p>
                      </article>
                    ))
                  )}
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </aside>
  )
}
