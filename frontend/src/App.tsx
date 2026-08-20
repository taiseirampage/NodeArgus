import { useCallback, useState } from 'react'
import { ScanForm } from './components/ScanForm'
import { NetworkGraph } from './components/NetworkGraph'
import { NodeDetailsPanel } from './components/NodeDetailsPanel'
import { TaskStatus } from './components/TaskStatus'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

function App() {
  const [scanTask, setScanTask] = useState<{ id: string; targetIp: string } | null>(null)
  const [currentGraphIp, setCurrentGraphIp] = useState<string | null>(null)
  const [selectedIp, setSelectedIp] = useState<string | null>(null)
  const handleGraphReady = useCallback((targetIp: string): void => {
    setCurrentGraphIp(targetIp)
  }, [])
  const handleNodeClick = useCallback((ip: string): void => {
    setSelectedIp(ip)
  }, [])
  const handleScanVuln = useCallback(async (ip: string): Promise<void> => {
    const message = `Задача на сканирование уязвимостей для ${ip} отправлена`
    try {
      const response = await fetch(`${API_BASE_URL}/vuln/${encodeURIComponent(ip)}`, {
        method: 'POST',
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      window.alert(message)
    } catch (error) {
      console.info(`${message} (заглушка)`, error)
      window.alert(`${message} (заглушка)`)
    }
  }, [])

  return (
    <main className="relative min-h-screen overflow-hidden px-5 py-6 text-slate-100 sm:px-8 sm:py-10">
      <div className="pointer-events-none absolute inset-0 bg-grid opacity-40" />
      <div className="pointer-events-none absolute -left-24 top-[-10rem] h-96 w-96 rounded-full bg-cyan-400/10 blur-3xl" />
      <div className="pointer-events-none absolute -right-32 bottom-[-12rem] h-[30rem] w-[30rem] rounded-full bg-emerald-400/10 blur-3xl" />

      <div className="relative mx-auto max-w-6xl">
        <header className="mb-12 flex items-start justify-between gap-6">
          <div>
            <div className="mb-4 flex items-center gap-3 font-mono text-xs uppercase tracking-[0.28em] text-cyan-300">
              <span className="h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_16px_#67e8f9]" />
              NodeArgus / Operations
            </div>
            <h1 className="max-w-3xl font-display text-4xl font-semibold tracking-[-0.05em] text-white sm:text-6xl">
              See what is awake
              <span className="text-cyan-300">.</span>
            </h1>
            <p className="mt-5 max-w-xl text-base leading-7 text-slate-400 sm:text-lg">
              Launch a controlled network scan and watch its signal move through the pipeline in real time.
            </p>
          </div>
          <div className="hidden rounded-full border border-emerald-300/20 bg-emerald-300/5 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.18em] text-emerald-300 sm:block">
            System ready
          </div>
        </header>

        <section className="grid gap-5 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="panel-glow rounded-3xl border border-white/10 bg-slate-950/75 p-6 shadow-2xl shadow-black/20 backdrop-blur-xl sm:p-8">
            <div className="mb-8 flex items-center justify-between">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">01 / New operation</p>
                <h2 className="mt-2 font-display text-2xl font-medium text-white">Target definition</h2>
              </div>
              <span className="rounded-lg border border-white/10 px-2.5 py-1 font-mono text-[10px] text-slate-500">ASYNC</span>
            </div>
            <ScanForm onTaskCreated={(id, targetIp) => setScanTask({ id, targetIp })} />
          </div>

          <TaskStatus
            taskId={scanTask?.id ?? null}
            targetIp={scanTask?.targetIp ?? null}
            onSuccess={handleGraphReady}
          />
        </section>

        {currentGraphIp && (
          <section className="mt-5 rounded-3xl border border-white/10 bg-slate-950/75 p-6 shadow-2xl shadow-black/20 backdrop-blur-xl sm:p-8">
            <div className="mb-5 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">03 / Network topology</p>
                <h2 className="mt-2 font-display text-2xl font-medium text-white">Live neighborhood</h2>
              </div>
              <span className="font-mono text-xs text-cyan-300">center // {currentGraphIp}</span>
            </div>
            <NetworkGraph targetIp={currentGraphIp} onNodeClick={handleNodeClick} />
          </section>
        )}

        <footer className="mt-10 flex flex-col gap-2 border-t border-white/10 pt-5 font-mono text-[10px] uppercase tracking-[0.18em] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
          <span>NodeArgus // Scan control interface</span>
          <span>Local development channel · v0.1.0</span>
        </footer>
      </div>
      <NodeDetailsPanel
        ip={selectedIp}
        onClose={() => setSelectedIp(null)}
        onScanVuln={handleScanVuln}
      />
    </main>
  )
}

export default App
