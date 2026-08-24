import { useCallback, type ReactElement } from 'react'
import { NetworkGraph, type GraphNode } from './NetworkGraph'
import { TaskStatus } from './TaskStatus'

interface TopologyViewProps {
  scanTask: { id: string; targetIp: string } | null
  scannedIps: string[]
  onGraphReady: (targetIp: string) => void
  onNodeClick: (node: GraphNode) => void
  onClearGraph: () => void
}

export function TopologyView({
  scanTask,
  scannedIps,
  onGraphReady,
  onNodeClick,
  onClearGraph,
}: TopologyViewProps): ReactElement {
  const latestScannedIp = scannedIps[scannedIps.length - 1] ?? null
  const handleGraphReady = useCallback(
    (targetIp: string): void => onGraphReady(targetIp),
    [onGraphReady],
  )

  return (
    <div className="pointer-events-auto relative h-full overflow-y-auto px-5 py-6 sm:px-8 sm:py-10">
      <div className="pointer-events-none absolute inset-0 bg-grid opacity-40" />
      <div className="pointer-events-none absolute -left-24 top-[-10rem] h-96 w-96 rounded-full bg-cyan-400/10 blur-3xl" />
      <div className="pointer-events-none absolute -right-32 bottom-[-12rem] h-[30rem] w-[30rem] rounded-full bg-emerald-400/10 blur-3xl" />

      <div className="relative mx-auto max-w-6xl">
        <header className="mb-8 flex items-start justify-between gap-6">
          <div>
            <div className="mb-4 flex items-center gap-3 font-mono text-xs uppercase tracking-[0.28em] text-cyan-300">
              <span className="h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_16px_#67e8f9]" />
              NodeArgus / Topology
            </div>
            <h1 className="max-w-3xl font-display text-3xl font-semibold tracking-[-0.05em] text-white sm:text-5xl">
              Network topology<span className="text-cyan-300">.</span>
            </h1>
            <p className="mt-3 max-w-xl text-base leading-7 text-slate-400">
              D3 force-layout graph of the scanned neighborhood. Launch a scan from the floating
              panel and watch its signal move through the pipeline.
            </p>
          </div>
          <div className="hidden rounded-full border border-emerald-300/20 bg-emerald-300/5 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.18em] text-emerald-300 sm:block">
            System ready
          </div>
        </header>

        <section className="grid gap-5 lg:grid-cols-[1fr_1fr]">
          <div className="panel-glow rounded-3xl border border-white/10 bg-slate-950/75 p-6 shadow-2xl shadow-black/20 backdrop-blur-xl sm:p-8">
            <div className="mb-6">
              <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">01 / Control</p>
              <h2 className="mt-2 font-display text-2xl font-medium text-white">Scan station</h2>
            </div>
            <p className="text-sm leading-6 text-slate-400">
              Цель, режим и рекон-инструменты задаются во плавающей панели слева поверх карты.
              Статус задачи и прогресс по инструментам — справа.
            </p>
            <div className="mt-6 rounded-2xl border border-white/10 bg-black/20 p-4 font-mono text-[10px] leading-5 text-slate-500">
              <p className="uppercase tracking-[0.18em] text-slate-600">Active // Masscan → Nmap → save</p>
              <p className="mt-1 uppercase tracking-[0.18em] text-slate-600">Recon // Subfinder/Amass → resolve → web recon</p>
            </div>
          </div>

          <TaskStatus
            taskId={scanTask?.id ?? null}
            targetIp={scanTask?.targetIp ?? null}
            onSuccess={handleGraphReady}
          />
        </section>

        {scannedIps.length > 0 && (
          <section className="mt-5 rounded-3xl border border-white/10 bg-slate-950/75 p-6 shadow-2xl shadow-black/20 backdrop-blur-xl sm:p-8">
            <div className="mb-5 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500">02 / Network topology</p>
                <h2 className="mt-2 font-display text-2xl font-medium text-white">Live neighborhood</h2>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-xs text-cyan-300">targets // {scannedIps.length}</span>
                <button
                  type="button"
                  onClick={onClearGraph}
                  className="rounded-lg border border-rose-300/20 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-rose-200 transition hover:border-rose-300/50 hover:bg-rose-300/10"
                >
                  Очистить граф
                </button>
              </div>
            </div>
            <NetworkGraph
              allScannedIps={scannedIps}
              latestScannedIp={latestScannedIp}
              onNodeClick={onNodeClick}
            />
          </section>
        )}

        <footer className="mt-10 flex flex-col gap-2 border-t border-white/10 pt-5 font-mono text-[10px] uppercase tracking-[0.18em] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
          <span>NodeArgus // Scan control interface</span>
          <span>Local development channel · v0.1.0</span>
        </footer>
      </div>
    </div>
  )
}