import { useState } from 'react'
import type { FormEvent } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

type ScanType = 'active' | 'recon' | 'full'
type ReconTool = 'subfinder' | 'amass'
type AmassMode = 'passive' | 'active'

interface ScanRequest {
  target: string
  scan_type: ScanType
  recon_tools?: ReconTool[]
  amass_mode?: AmassMode
}

interface ScanResponse {
  task_id: string
  status: string
  scan_type: ScanType
  recon_tools?: ReconTool[]
}

interface ScanFormProps {
  onTaskCreated: (taskId: string, targetIp: string) => void
}

const SCAN_TYPE_OPTIONS: Array<{ value: ScanType; label: string; hint: string }> = [
  { value: 'active', label: 'Active', hint: 'Nmap + Masscan по IP/CIDR' },
  { value: 'recon', label: 'Recon', hint: 'Поддомены по домену (пассивно)' },
  { value: 'full', label: 'Full', hint: 'Recon → активное сканирование IP' },
]

const TOOL_OPTIONS: Array<{ value: ReconTool; label: string; hint: string }> = [
  { value: 'subfinder', label: 'Subfinder', hint: 'Быстрый пассивный OSINT' },
  { value: 'amass', label: 'Amass', hint: 'Глубокий OSINT + ASN' },
]

const AMASS_MODE_OPTIONS: Array<{ value: AmassMode; label: string; hint: string }> = [
  { value: 'passive', label: 'Passive', hint: 'Пассивные источники' },
  { value: 'active', label: 'Active', hint: '+ DNS-брутфорс (шумно, 10-30 мин)' },
]

export function ScanForm({ onTaskCreated }: ScanFormProps) {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<ScanType>('active')
  const [reconTools, setReconTools] = useState<ReconTool[]>(['subfinder'])
  const [amassMode, setAmassMode] = useState<AmassMode>('passive')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const selectedOption = SCAN_TYPE_OPTIONS.find((option) => option.value === scanType)
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
      const payload: ScanRequest = {
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
      onTaskCreated(body.task_id, normalizedTarget)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Бэкенд недоступен.')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <form className="space-y-5" onSubmit={handleSubmit}>
      <div>
        <label className="mb-3 block font-mono text-xs uppercase tracking-[0.16em] text-slate-400" htmlFor="target">
          Target
        </label>
        <div className="group flex items-center rounded-2xl border border-white/10 bg-black/20 px-4 transition focus-within:border-cyan-300/60 focus-within:ring-4 focus-within:ring-cyan-300/10">
          <span className="mr-3 font-mono text-sm text-cyan-300/70">&gt;_</span>
          <input
            id="target"
            name="target"
            type="text"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={scanType === 'active' ? '192.168.1.0/24' : 'example.com'}
            autoComplete="off"
            spellCheck={false}
            className="w-full bg-transparent py-4 font-mono text-sm text-white outline-none placeholder:text-slate-700"
            disabled={isSubmitting}
          />
        </div>
        {scanType === 'active' ? (
          <p className="mt-3 text-sm text-slate-500">Поддерживаются одиночный IPv4/IPv6, CIDR и списки адресов.</p>
        ) : (
          <p className="mt-3 text-sm text-slate-500">Введите корневой домен для пассивной разведки поддоменов.</p>
        )}
      </div>

      <div>
        <label className="mb-2 block font-mono text-xs uppercase tracking-[0.16em] text-slate-400" htmlFor="scan_type">
          Режим сканирования
        </label>
        <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Режим сканирования">
          {SCAN_TYPE_OPTIONS.map((option) => (
            <button
              key={option.value}
              type="button"
              role="radio"
              aria-checked={scanType === option.value}
              onClick={() => setScanType(option.value)}
              disabled={isSubmitting}
              className={`rounded-xl border px-3 py-3 text-left transition ${
                scanType === option.value
                  ? 'border-cyan-300/60 bg-cyan-300/10'
                  : 'border-white/10 bg-black/20 hover:border-white/25'
              }`}
            >
              <span className={`block font-mono text-xs font-semibold ${scanType === option.value ? 'text-cyan-300' : 'text-slate-300'}`}>
                {option.label}
              </span>
              <span className="mt-1 block text-[11px] leading-4 text-slate-500">{option.hint}</span>
            </button>
          ))}
        </div>
      </div>

      {isDomainScan && (
        <div className="space-y-4 rounded-2xl border border-white/10 bg-black/20 p-4">
          <div>
            <p className="mb-2 block font-mono text-xs uppercase tracking-[0.16em] text-slate-400">
              Инструменты разведки
            </p>
            <div className="grid grid-cols-2 gap-2">
              {TOOL_OPTIONS.map((tool) => {
                const isActive = reconTools.includes(tool.value)
                return (
                  <label
                    key={tool.value}
                    className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition ${
                      isActive
                        ? 'border-violet-300/50 bg-violet-300/10'
                        : 'border-white/10 bg-black/30 hover:border-white/25'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={isActive}
                      disabled={isSubmitting}
                      onChange={() => toggleTool(tool.value)}
                      className="mt-0.5 h-4 w-4 accent-violet-400"
                    />
                    <span>
                      <span className={`block font-mono text-xs font-semibold ${isActive ? 'text-violet-200' : 'text-slate-300'}`}>
                        {tool.label}
                      </span>
                      <span className="mt-1 block text-[11px] leading-4 text-slate-500">{tool.hint}</span>
                    </span>
                  </label>
                )
              })}
            </div>
          </div>

          {amassSelected && (
            <div>
              <p className="mb-2 block font-mono text-xs uppercase tracking-[0.16em] text-slate-400">
                Режим Amass
              </p>
              <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label="Режим Amass">
                {AMASS_MODE_OPTIONS.map((option) => (
                  <button
                    key={option.value}
                    type="button"
                    role="radio"
                    aria-checked={amassMode === option.value}
                    onClick={() => setAmassMode(option.value)}
                    disabled={isSubmitting}
                    className={`rounded-xl border px-3 py-3 text-left transition ${
                      amassMode === option.value
                        ? 'border-orange-300/60 bg-orange-300/10'
                        : 'border-white/10 bg-black/30 hover:border-white/25'
                    }`}
                  >
                    <span className={`block font-mono text-xs font-semibold ${amassMode === option.value ? 'text-orange-200' : 'text-slate-300'}`}>
                      {option.label}
                    </span>
                    <span className="mt-1 block text-[11px] leading-4 text-slate-500">{option.hint}</span>
                  </button>
                ))}
              </div>
              {amassMode === 'active' && (
                <p className="mt-3 rounded-lg border border-amber-300/20 bg-amber-300/10 p-3 text-xs leading-5 text-amber-100" role="note">
                  Active Amass генерирует заметный DNS-шум и может занимать 10-30 минут. Требует ALLOW_ACTIVE_RECON=true.
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-300/20 bg-rose-300/5 px-4 py-3 text-sm text-rose-200" role="alert">
          {error}
        </div>
      )}

      <button
        type="submit"
        disabled={isSubmitting}
        className="flex w-full items-center justify-center gap-3 rounded-2xl bg-cyan-300 px-5 py-4 font-display text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
      >
        <span className={isSubmitting ? 'animate-spin' : ''}>✦</span>
        {isSubmitting ? 'Отправка...' : selectedOption?.hint ?? 'Сканировать цель'}
      </button>
    </form>
  )
}