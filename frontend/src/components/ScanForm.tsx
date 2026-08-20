import { useState } from 'react'
import type { FormEvent } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

interface ScanResponse {
  task_id: string
  status: string
}

interface ScanFormProps {
  onTaskCreated: (taskId: string, targetIp: string) => void
}

export function ScanForm({ onTaskCreated }: ScanFormProps) {
  const [target, setTarget] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    const normalizedTarget = target.trim()
    if (!normalizedTarget) {
      setError('Укажите IP-адрес или CIDR-подсеть.')
      return
    }

    setIsSubmitting(true)
    setError(null)
    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: normalizedTarget }),
      })
      const payload = (await response.json()) as ScanResponse | { detail?: string }
      if (!response.ok || !('task_id' in payload)) {
        throw new Error('detail' in payload ? payload.detail : 'Не удалось поставить задачу в очередь.')
      }
      onTaskCreated(payload.task_id, normalizedTarget)
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
          IP / CIDR target
        </label>
        <div className="group flex items-center rounded-2xl border border-white/10 bg-black/20 px-4 transition focus-within:border-cyan-300/60 focus-within:ring-4 focus-within:ring-cyan-300/10">
          <span className="mr-3 font-mono text-sm text-cyan-300/70">&gt;_</span>
          <input
            id="target"
            name="target"
            type="text"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="192.168.1.0/24"
            autoComplete="off"
            spellCheck={false}
            className="w-full bg-transparent py-4 font-mono text-sm text-white outline-none placeholder:text-slate-700"
            disabled={isSubmitting}
          />
        </div>
        <p className="mt-3 text-sm text-slate-500">Поддерживаются одиночный IPv4/IPv6, CIDR и списки адресов.</p>
      </div>

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
        {isSubmitting ? 'Отправка...' : 'Сканировать цель'}
      </button>
    </form>
  )
}
