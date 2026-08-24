import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react'
import { MapContainer, Marker, Popup, TileLayer, useMap } from 'react-leaflet'
import MarkerClusterGroup from 'react-leaflet-cluster'
import L from 'leaflet'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const REFRESH_INTERVAL_MS = 5 * 60 * 1000

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#60a5fa',
  no_vulns: '#22c55e',
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  no_vulns: 'No vulns',
}

export interface MapAsset {
  ip: string
  latitude: number
  longitude: number
  country: string | null
  country_code: string | null
  city: string | null
  ports_count: number
  max_severity: string | null
}

interface MapViewProps {
  onSelectAsset: (asset: MapAsset) => void
  onAssetsLoaded: (count: number) => void
  focusIp: string | null
  onFocusHandled: () => void
  refreshKey?: number
}

function severityKey(asset: MapAsset): string {
  return asset.max_severity ?? 'no_vulns'
}

function markerIcon(asset: MapAsset): L.DivIcon {
  const color = SEVERITY_COLORS[severityKey(asset)] ?? SEVERITY_COLORS.no_vulns
  return L.divIcon({
    className: '',
    html: `<div style="width:12px;height:12px;border-radius:9999px;border:1px solid rgba(0,0,0,0.55);background:${color};box-shadow:0 0 6px ${color}, 0 1px 3px rgba(0,0,0,0.6);"></div>`,
    iconSize: [12, 12],
    iconAnchor: [6, 6],
    popupAnchor: [0, -10],
  })
}

function clusterIcon(cluster: { childCount: number }): L.DivIcon {
  const size = cluster.childCount < 10 ? 34 : cluster.childCount < 100 ? 44 : 56
  return L.divIcon({
    className: 'marker-cluster-custom',
    html: `<div style="display:flex;align-items:center;justify-content:center;width:${size}px;height:${size}px;border-radius:9999px;background:rgba(15,23,42,0.9);border:1px solid rgba(34,211,238,0.4);color:#67e8f9;font-family:'DM Mono',monospace;font-size:12px;letter-spacing:0;box-shadow:0 0 14px rgba(34,211,238,0.25);">${cluster.childCount}</div>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  })
}

function MapBridge({ onReady }: { onReady: (map: L.Map) => void }): ReactElement | null {
  const map = useMap()
  useEffect(() => {
    onReady(map)
  }, [map, onReady])
  return null
}

function assetLabel(asset: MapAsset): string {
  const parts = [asset.country, asset.city].filter(Boolean)
  return parts.length > 0 ? parts.join(' · ') : 'Location unknown'
}

export function MapView({
  onSelectAsset,
  onAssetsLoaded,
  focusIp,
  onFocusHandled,
  refreshKey = 0,
}: MapViewProps): ReactElement {
  const [assets, setAssets] = useState<MapAsset[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [searchNotice, setSearchNotice] = useState<string | null>(null)
  const mapRef = useRef<L.Map | null>(null)
  const markerRefs = useRef(new Map<string, L.Marker>())
  const openTimerRef = useRef<number | null>(null)

  const handleMapReady = useCallback((map: L.Map): void => {
    mapRef.current = map
  }, [])

  const handleAssetsLoaded = useCallback(
    (count: number): void => {
      onAssetsLoaded(count)
      setLastUpdated(new Date())
    },
    [onAssetsLoaded],
  )

  useEffect(() => {
    const loadAssets = async (_signal: AbortSignal): Promise<void> => {
      try {
        const cacheBuster = refreshKey > 0 ? '?refresh=1' : ''
        const response = await fetch(`${API_BASE_URL}/map/assets${cacheBuster}`, {
          signal: _signal,
        })
        if (!response.ok) {
          throw new Error(`Не удалось загрузить карту: HTTP ${response.status}`)
        }
        const payload = (await response.json()) as { count: number; assets: MapAsset[] }
        if (_signal.aborted) return
        setAssets(payload.assets)
        setError(null)
        handleAssetsLoaded(payload.count)
      } catch (requestError) {
        if (requestError instanceof DOMException && requestError.name === 'AbortError') return
        if (!_signal.aborted) {
          setError(requestError instanceof Error ? requestError.message : 'Не удалось загрузить карту.')
        }
      } finally {
        if (!_signal.aborted) setLoading(false)
      }
    }

    const controller = new AbortController()
    void loadAssets(controller.signal)
    const intervalId = window.setInterval(
      () => void loadAssets(controller.signal),
      REFRESH_INTERVAL_MS,
    )
    return () => {
      controller.abort()
      window.clearInterval(intervalId)
    }
  }, [handleAssetsLoaded, refreshKey])

  useEffect(() => {
    if (!focusIp) {
      setSearchNotice(null)
      return
    }
    const map = mapRef.current
    const marker = markerRefs.current.get(focusIp)
    if (map && marker) {
      if (openTimerRef.current !== null) window.clearTimeout(openTimerRef.current)
      setSearchNotice(null)
      map.flyTo(marker.getLatLng(), Math.max(map.getZoom(), 6), { duration: 0.8 })
      openTimerRef.current = window.setTimeout(() => marker.openPopup(), 850)
      onFocusHandled()
    } else if (map && !loading) {
      setSearchNotice(`Не найдено на карте: ${focusIp}`)
      onFocusHandled()
    }
  }, [focusIp, onFocusHandled, loading])

  return (
    <div className="relative h-full w-full">
      <MapContainer
        center={[20, 0]}
        zoom={2}
        minZoom={2}
        maxZoom={18}
        maxBounds={[[-90, -180], [90, 180]]}
        maxBoundsViscosity={1}
        zoomControl={false}
        attributionControl
        className="z-0 h-full w-full"
      >
        <MapBridge onReady={handleMapReady} />
        <TileLayer
          noWrap
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          detectRetina
        />
        <MarkerClusterGroup
          iconCreateFunction={clusterIcon}
          showCoverageOnHover={false}
          maxClusterRadius={45}
        >
          {assets.map((asset) => (
            <Marker
              key={asset.ip}
              position={[asset.latitude, asset.longitude]}
              icon={markerIcon(asset)}
              ref={(instance) => {
                if (instance) {
                  markerRefs.current.set(asset.ip, instance)
                } else {
                  markerRefs.current.delete(asset.ip)
                }
              }}
            >
              <Popup autoPan={false}>
                <div className="min-w-[190px] max-w-[230px] font-mono">
                  <p className="break-all text-[12px] font-semibold leading-5 text-cyan-300">{asset.ip}</p>
                  <p className="mt-1 text-[11px] leading-4 text-slate-300">{assetLabel(asset)}</p>
                  <p className="mt-1 text-[11px] leading-4 text-slate-400">
                    ports:{' '}
                    <span className="text-emerald-300">{asset.ports_count}</span> · severity:{' '}
                    <span
                      className="font-semibold"
                      style={{ color: SEVERITY_COLORS[severityKey(asset)] }}
                    >
                      {SEVERITY_LABELS[severityKey(asset)]}
                    </span>
                  </p>
                  <button
                    type="button"
                    onClick={() => onSelectAsset(asset)}
                    className="mt-2.5 w-full rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.12em] text-cyan-200 transition hover:border-cyan-400/70 hover:bg-cyan-400/20"
                  >
                    Подробнее
                  </button>
                </div>
              </Popup>
            </Marker>
          ))}
        </MarkerClusterGroup>
      </MapContainer>

      <div className="absolute bottom-6 right-4 z-[500] flex flex-col gap-1.5">
        <button
          type="button"
          aria-label="Приблизить"
          onClick={() => mapRef.current?.zoomIn()}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-gray-700 bg-gray-900/85 text-lg text-slate-200 backdrop-blur transition hover:border-cyan-400/60 hover:text-cyan-300"
        >
          +
        </button>
        <button
          type="button"
          aria-label="Отдалить"
          onClick={() => mapRef.current?.zoomOut()}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-gray-700 bg-gray-900/85 text-lg text-slate-200 backdrop-blur transition hover:border-cyan-400/60 hover:text-cyan-300"
        >
          −
        </button>
      </div>

      <div className="absolute bottom-6 left-4 z-[500] max-w-[220px] rounded-xl border border-gray-700/70 bg-gray-900/80 p-3 font-mono text-[10px] leading-5 text-slate-300 shadow-2xl backdrop-blur">
        <p className="mb-2 uppercase tracking-[0.18em] text-gray-500">Severity legend</p>
        {(Object.keys(SEVERITY_COLORS) as string[]).map((key) => (
          <div key={key} className="flex items-center gap-2">
            <span
              className="h-2.5 w-2.5 shrink-0 rounded-full"
              style={{ background: SEVERITY_COLORS[key] }}
            />
            <span className="capitalize">{SEVERITY_LABELS[key] ?? key}</span>
          </div>
        ))}
      </div>

      {error && (
        <div className="absolute inset-x-0 top-16 z-[500] mx-auto w-max max-w-[90%] rounded-lg border border-rose-400/30 bg-rose-950/90 px-4 py-2 text-center text-xs text-rose-200" role="alert">
          {error}
        </div>
      )}
      {searchNotice && (
        <div className="absolute inset-x-0 bottom-24 z-[500] mx-auto w-max max-w-[90%] rounded-lg border border-amber-400/30 bg-amber-950/90 px-4 py-2 text-center text-xs text-amber-200" role="status">
          {searchNotice}
        </div>
      )}
      {loading && (
        <div className="absolute left-1/2 top-16 z-[500] -translate-x-1/2 rounded-lg border border-white/10 bg-gray-900/85 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-cyan-300 backdrop-blur">
          Загрузка активов...
        </div>
      )}
      {lastUpdated && !loading && (
        <div className="absolute right-4 top-4 z-[500] rounded-lg border border-white/10 bg-gray-900/75 px-3 py-1.5 font-mono text-[9px] uppercase tracking-[0.14em] text-gray-500 backdrop-blur">
          обновлено {lastUpdated.toLocaleTimeString()}
        </div>
      )}
    </div>
  )
}