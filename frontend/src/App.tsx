import { useCallback, useEffect, useState, type ReactElement } from 'react'
import { MapView, type MapAsset } from './components/MapView'
import { FloatingPanel, type ViewMode } from './components/FloatingPanel'
import { TopologyView } from './components/TopologyView'
import { TaskStatus } from './components/TaskStatus'
import { NodeDetailsPanel, type SelectedNode } from './components/NodeDetailsPanel'

const SCANNED_IPS_STORAGE_KEY = 'nodeargus.scannedIps'
const VIEW_MODE_STORAGE_KEY = 'nodeargus.viewMode'

function loadScannedIps(): string[] {
  try {
    const stored = window.localStorage.getItem(SCANNED_IPS_STORAGE_KEY)
    if (!stored) return []
    const parsed: unknown = JSON.parse(stored)
    if (!Array.isArray(parsed)) return []
    return Array.from(new Set(parsed.filter((value): value is string => typeof value === 'string' && value.length > 0)))
  } catch {
    return []
  }
}

function loadViewMode(): ViewMode {
  try {
    const stored = window.localStorage.getItem(VIEW_MODE_STORAGE_KEY)
    if (stored === 'map' || stored === 'topology') return stored
  } catch {
    /* localStorage unavailable; fall back to the map. */
  }
  return 'map'
}

function mapAssetToSelectedNode(asset: MapAsset): SelectedNode {
  return {
    id: asset.ip,
    node_type: 'ip',
    source: null,
    resolved_ips: [],
    country: asset.country ?? null,
    city: asset.city ?? null,
    os: null,
    ports_count: asset.ports_count,
  }
}

function App(): ReactElement {
  const [scanTask, setScanTask] = useState<{ id: string; targetIp: string } | null>(null)
  const [scannedIps, setScannedIps] = useState<string[]>(loadScannedIps)
  const [selectedNode, setSelectedNode] = useState<SelectedNode | null>(null)
  const [view, setView] = useState<ViewMode>(loadViewMode)
  const [assetCount, setAssetCount] = useState(0)
  const [focusIp, setFocusIp] = useState<string | null>(null)
  const [mapRefreshKey, setMapRefreshKey] = useState(0)

  const handleGraphReady = useCallback((targetIp: string): void => {
    setScannedIps((currentIps) => [...currentIps.filter((ip) => ip !== targetIp), targetIp])
    setMapRefreshKey((current) => current + 1)
  }, [])

  const handleNodeClick = useCallback((node: { id: string; node_type: SelectedNode['node_type']; source: string | null; resolved_ips: string[]; country: string | null; city: string | null; os: string | null; ports_count: number; asn_number?: string | null; asn_cidr?: string | null; asn_org?: string | null }): void => {
    setSelectedNode({
      id: node.id,
      node_type: node.node_type,
      source: node.source ?? null,
      resolved_ips: node.resolved_ips ?? [],
      country: node.country ?? null,
      city: node.city ?? null,
      os: node.os ?? null,
      ports_count: node.ports_count ?? 0,
      asn_number: node.asn_number ?? null,
      asn_cidr: node.asn_cidr ?? null,
      asn_org: node.asn_org ?? null,
    })
  }, [])

  const clearGraph = useCallback((): void => {
    setScannedIps([])
    setSelectedNode(null)
  }, [])

  const handleViewChange = useCallback((nextView: ViewMode): void => {
    setView(nextView)
    try {
      window.localStorage.setItem(VIEW_MODE_STORAGE_KEY, nextView)
    } catch {
      /* Persisting the view is best-effort. */
    }
  }, [])

  const handleAssetsLoaded = useCallback((count: number): void => {
    setAssetCount(count)
  }, [])

  const handleSelectAsset = useCallback((asset: MapAsset): void => {
    setSelectedNode(mapAssetToSelectedNode(asset))
  }, [])

  const handleSearch = useCallback((ip: string): void => {
    setFocusIp(ip)
  }, [])

  const handleFocusHandled = useCallback((): void => {
    setFocusIp(null)
  }, [])

  useEffect(() => {
    if (scannedIps.length === 0) {
      window.localStorage.removeItem(SCANNED_IPS_STORAGE_KEY)
      return
    }
    window.localStorage.setItem(SCANNED_IPS_STORAGE_KEY, JSON.stringify(scannedIps))
  }, [scannedIps])

  return (
    <main className="relative h-screen w-full overflow-hidden bg-slate-950 text-slate-100">
      {view === 'map' ? (
        <MapView
          onSelectAsset={handleSelectAsset}
          onAssetsLoaded={handleAssetsLoaded}
          focusIp={focusIp}
          onFocusHandled={handleFocusHandled}
          refreshKey={mapRefreshKey}
        />
      ) : (
        <TopologyView
          scanTask={scanTask}
          scannedIps={scannedIps}
          onGraphReady={handleGraphReady}
          onNodeClick={handleNodeClick}
          onClearGraph={clearGraph}
        />
      )}

      <FloatingPanel
        view={view}
        onViewChange={handleViewChange}
        assetCount={assetCount}
        onScanSubmitted={(id, targetIp) => setScanTask({ id, targetIp })}
        onSearch={handleSearch}
      />

      {view === 'map' && scanTask && (
        <div className="absolute right-4 top-16 z-[900] w-80 max-w-[calc(100vw-3rem)]">
          <TaskStatus
            taskId={scanTask.id}
            targetIp={scanTask.targetIp}
            onSuccess={handleGraphReady}
          />
        </div>
      )}

      <NodeDetailsPanel
        node={selectedNode}
        onClose={() => setSelectedNode(null)}
      />
    </main>
  )
}

export default App