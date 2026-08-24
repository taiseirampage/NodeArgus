import { useState, type FormEvent, type ReactElement } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export type ViewMode = 'map' | 'topology'

type ScanType = 'active' | 'recon' | 'full'
type ReconTool = 'subfinder' | 'amass'
type AmassMode = 'passive' | 'active'

interface ScanResponse {
  task_id: string
  status: string
  scan_type: ScanType
  recon_tools?: ReconTool[]
}

interface FloatingPanelProps {
  view: ViewMode
  onViewChange: (view: ViewMode) => void
  assetCount: number
  onScanSubmitted: (taskId: string, targetIp: string) => void
  onSearch: (ip: string) => void
}

const SCAN_TYPE_OPTIONS: Array<{ value: ScanType; label: string }> = [
  { value: 'active', label: 'Active' },
  { value: 'recon', label: 'Recon' },
  { value: 'full', label: 'Full' },
]

export function FloatingPanel({
  view,
  onViewChange,
  assetCount,
  onScanSubmitted,
  onSearch,
}: FloatingPanelProps): ReactElement {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<ScanType>('active')
  const [reconTools, setReconTools] = useState<ReconTool[]>(['subfinder'])
  const [amassMode, setAmassMode] = useState<AmassMode>('passive')
  const [searchInput, setSearchInput] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searchError, setSearchError] = useState<string | null>(null)

  const isDomainScan = scanType === 'recon' || scanType === 'full'
  const amassSelected = reconTools.includes('amass')

  function toggleTool(tool: ReconTool): void {
    setReconTools((current) => {
      if (current.includes(tool)) {
        const next = current.filter((item) => item !== tool)
        return next.length > 0 ? next : current
      }
      return [...current, tool]
    })
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    const normalizedTarget = target.trim()
    if (!normalizedTarget) {
      setError('Укажите IP-адрес, CIDR-подсеть или домен.')
      return
    }
    setIsSubmitting(true)
    setError(null)
    try {
      const payload: Record<string, unknown> = {
        target: normalizedTarget,
        scan_type: scanType,
      }
      if (isDomainScan) {
        payload.recon_tools = reconTools
        if (amassSelected) payload.amass_mode = amassMode
      }
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const body = (await response.json()) as ScanResponse | { detail?: string }
      if (!response.ok || !('task_id' in body)) {
        throw new Error('detail' in body ? body.detail : 'Не удалось поставить задачу в очередь.')
      }
      onScanSubmitted(body.task_id, normalizedTarget)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Бэкенд недоступен.')
    } finally {
      setIsSubmitting(false)
    }
  }

  function handleSearchSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault()
    const ip = searchInput.trim()
    if (!ip) {
      setSearchError('Введите IP-адрес для поиска на карте.')
      return
    }
    setSearchError(null)
    onSearch(ip)
  }

  return (
    <div className="absolute left-4 top-4 z-[1000] w-[320px] rounded-2xl border border-white/10 bg-gray-900/80 p-4 shadow-2xl shadow-black/40 backdrop-blur-md">
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-cyan-300">NodeArgus</p>
        <div className="flex rounded-lg border border-white/10 p-0.5">
          <button
            type="button"
            onClick={() => onViewChange('map')}
            className={`rounded-md px-2 py-1 font-mono text-[10px] transition ${
              view === 'map'
                ? 'bg-cyan-400/15 text-cyan-200'
                : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            🗺️ Карта
          </button>
          <button
            type="button"
            onClick={() => onViewChange('topology')}
            className={`rounded-md px-2 py-1 font-mono text-[10px] transition ${
              view === 'topology'
                ? 'bg-cyan-400/15 text-cyan-200'
                : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            🕸️ Топология
          </button>
        </div>
      </div>

      <form onSubmit={(event) => void handleSubmit(event)} className="space-y-3">
        <div>
          <label
            htmlFor="panel-target"
            className="mb-1.5 block font-mono text-[9px] uppercase tracking-[0.2em] text-slate-500"
          >
            Цель
          </label>
          <div className="flex items-center rounded-lg border border-white/10 bg-black/30 px-3 transition focus-within:border-cyan-400/50">
            <span className="mr-2 font-mono text-xs text-cyan-300/70">&gt;_</span>
            <input
              id="panel-target"
              type="text"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="IP / CIDR / домен"
              autoComplete="off"
              spellCheck={false}
              disabled={isSubmitting}
              className="w-full bg-transparent py-2.5 font-mono text-xs text-white outline-none placeholder:text-slate-700"
            />
          </div>
        </div>

        <div>
          <span className="mb-1.5 block font-mono text-[9px] uppercase tracking-[0.2em] text-slate-500">
            Режим
          </span>
          <div className="grid grid-cols-3 gap-1" role="radiogroup" aria-label="Режим сканирования">
            {SCAN_TYPE_OPTIONS.map((option) => (
              <button
                key={option.value}
                type="button"
                role="radio"
                aria-checked={scanType === option.value}
                onClick={() => setScanType(option.value)}
                disabled={isSubmitting}
                className={`rounded-lg border px-2 py-1.5 font-mono text-[10px] transition ${
                  scanType === option.value
                    ? 'border-cyan-400/50 bg-cyan-400/10 text-cyan-200'
                    : 'border-white/10 bg-black/20 text-slate-500 hover:border-white/20 hover:text-slate-300'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        {isDomainScan && (
          <div className="space-y-2.5 rounded-lg border border-white/10 bg-black/20 p-2.5">
            <span className="block font-mono text-[9px] uppercase tracking-[0.2em] text-slate-500">
              Разведка
            </span>
            <div className="flex gap-2">
              {(['subfinder', 'amass'] as const).map((tool) => {
                const active = reconTools.includes(tool)
                return (
                  <label key={tool} className="flex cursor-pointer items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={active}
                      disabled={isSubmitting}
                      onChange={() => toggleTool(tool)}
                      className="h-3.5 w-3.5 accent-violet-400"
                    />
                    <span className={`font-mono text-[10px] ${active ? 'text-violet-200' : 'text-slate-500'}`}>
                      {tool === 'subfinder' ? 'Subfinder' : 'Amass'}
                    </span>
                  </label>
                )
              })}
            </div>
            {amassSelected && (
              <div className="flex items-center gap-2">
                <span className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-600">Amass</span>
                <select
                  value={amassMode}
                  disabled={isSubmitting}
                  onChange={(event) => setAmassMode(event.target.value as AmassMode)}
                  className="flex-1 rounded-md border border-white/10 bg-gray-900 px-2 py-1 font-mono text-[10px] text-slate-300 outline-none focus:border-cyan-400/50"
                >
                  <option value="passive">passive</option>
                  <option value="active">active</option>
                </select>
              </div>
            )}
          </div>
        )}

        <button
          type="submit"
          disabled={isSubmitting}
          className="flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 py-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <span className={isSubmitting ? 'animate-spin' : ''}>✦</span>
          {isSubmitting ? 'Отправка...' : 'Сканировать'}
        </button>
        {error && (
          <p className="rounded-lg border border-rose-300/20 bg-rose-300/5 px-3 py-2 text-[11px] leading-4 text-rose-200" role="alert">
            {error}
          </p>
        )}
      </form>

      <form onSubmit={handleSearchSubmit} className="mt-3 border-t border-white/10 pt-3">
        <span className="mb-1.5 block font-mono text-[9px] uppercase tracking-[0.2em] text-slate-500">
          Поиск по карте
        </span>
        <div className="flex gap-1.5">
          <input
            type="text"
            value={searchInput}
            onChange={(event) => setSearchInput(event.target.value)}
            placeholder="IP-адрес"
            autoComplete="off"
            spellCheck={false}
            className="min-w-0 flex-1 rounded-lg border border-white/10 bg-black/30 px-3 py-2 font-mono text-[11px] text-white outline-none placeholder:text-slate-700 focus:border-cyan-400/50"
          />
          <button
            type="submit"
            className="shrink-0 rounded-lg border border-cyan-400/40 px-3 py-2 font-mono text-[10px] text-cyan-200 transition hover:bg-cyan-400/10"
          >
            Найти
          </button>
        </div>
        {searchError && (
          <p className="mt-1.5 text-[10px] leading-4 text-rose-300" role="alert">
            {searchError}
          </p>
        )}
      </form>

      <div className="mt-3 flex items-center justify-between border-t border-white/10 pt-3">
        <span className="font-mono text-[9px] uppercase tracking-[0.18em] text-slate-600">
          Активов на карте
        </span>
        <span className="font-mono text-xs text-cyan-300">{assetCount}</span>
      </div>
    </div>
  )
}