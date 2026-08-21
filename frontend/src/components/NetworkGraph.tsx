import { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export interface GraphNode extends d3.SimulationNodeDatum {
  id: string
  ip: string
  node_type: 'ip' | 'domain' | 'subdomain' | 'asn'
  source: string | null
  resolved_ips: string[]
  country: string | null
  city: string | null
  os: string | null
  ports_count: number
  is_traceroute_hop: boolean
  traceroute_hop: number | null
  traceroute_rtt: string | null
  asn_number?: string | null
  asn_cidr?: string | null
  asn_org?: string | null
}

export interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  type: 'same_subnet' | 'same_dns' | 'common_port' | 'traceroute_hop' | 'subdomain_of' | 'resolves_to' | 'asn_of' | string
}

interface GraphData {
  center_ip: string
  nodes: GraphNode[]
  links: GraphLink[]
}

interface NetworkGraphProps {
  allScannedIps: string[]
  latestScannedIp: string | null
  onNodeClick: (node: GraphNode) => void
}

type LinkEndpoint = string | number | GraphNode

function endpointNode(endpoint: LinkEndpoint, nodes: GraphNode[]): GraphNode | undefined {
  if (typeof endpoint === 'object') return endpoint
  return nodes.find((node) => node.id === String(endpoint))
}

function endpointId(endpoint: LinkEndpoint): string {
  return typeof endpoint === 'object' ? endpoint.id : String(endpoint)
}

const NODE_COLORS: Record<GraphNode['node_type'], { fill: string; stroke: string }> = {
  ip: { fill: '#34d399', stroke: '#a7f3d0' },
  domain: { fill: '#a78bfa', stroke: '#ddd6fe' },
  subdomain: { fill: '#60a5fa', stroke: '#bfdbfe' },
  asn: { fill: '#9ca3af', stroke: '#e5e7eb' },
}

const SUBDOMAIN_SOURCE_COLORS = {
  both: { fill: '#a855f7', stroke: '#e9d5ff' },
  subfinder: { fill: '#3b82f6', stroke: '#bfdbfe' },
  amass: { fill: '#f97316', stroke: '#fed7aa' },
}

function sourceStyle(source: string | null): { fill: string; stroke: string } {
  const labels = (source ?? '').split(',').map((label) => label.trim())
  const hasSubfinder = labels.includes('subfinder') || labels.some((l) => l !== 'amass' && l.length > 0)
  const hasAmass = labels.includes('amass')
  if (hasSubfinder && hasAmass) return SUBDOMAIN_SOURCE_COLORS.both
  if (hasAmass) return SUBDOMAIN_SOURCE_COLORS.amass
  return SUBDOMAIN_SOURCE_COLORS.subfinder
}

function diamondPath(radius: number): string {
  return `M 0,-${radius} L ${radius},0 L 0,${radius} L -${radius},0 Z`
}

function hexagonPath(radius: number): string {
  const points: string[] = []
  for (let index = 0; index < 6; index += 1) {
    const angle = (Math.PI / 3) * index - Math.PI / 2
    points.push(`${radius * Math.cos(angle)},${radius * Math.sin(angle)}`)
  }
  return `M ${points.join('L ')} Z`
}

function rectPath(width: number, height: number): string {
  return `M ${-width / 2},${-height / 2} L ${width / 2},${-height / 2} L ${width / 2},${height / 2} L ${-width / 2},${height / 2} Z`
}

function nodeShape(node: GraphNode): { d: string | null; radius: number; width?: number; height?: number } {
  if (node.is_traceroute_hop) return { d: null, radius: 5 }
  if (node.node_type === 'domain') return { d: diamondPath(12), radius: 12 }
  if (node.node_type === 'subdomain') return { d: hexagonPath(9), radius: 9 }
  if (node.node_type === 'asn') return { d: rectPath(56, 22), radius: 12, width: 56, height: 22 }
  return { d: null, radius: 7 }
}

function nodeTheme(node: GraphNode): { fill: string; stroke: string } {
  if (node.is_traceroute_hop) return { fill: '#6b7280', stroke: '#d1d5db' }
  if (node.node_type === 'subdomain') return sourceStyle(node.source)
  return NODE_COLORS[node.node_type]
}

function mergeGraphResponses(graphs: GraphData[], targets: string[]): GraphData {
  const nodesById = new Map<string, GraphNode>()
  const linksByKey = new Map<string, GraphLink>()

  for (const graph of graphs) {
    for (const node of graph.nodes) {
      nodesById.set(node.id, {
        ...node,
        is_traceroute_hop: targets.includes(node.id) ? false : node.is_traceroute_hop ?? false,
        traceroute_hop: node.traceroute_hop ?? null,
        traceroute_rtt: node.traceroute_rtt ?? null,
      })
    }
    for (const link of graph.links) {
      const source = endpointId(link.source)
      const target = endpointId(link.target)
      if (source === target || !nodesById.has(source) || !nodesById.has(target)) continue
      const [first, second] = [source, target].sort()
      linksByKey.set(`${link.type}:${first}:${second}`, {
        source: first,
        target: second,
        type: link.type,
      })
    }
  }

  return {
    center_ip: targets[targets.length - 1] ?? '',
    nodes: Array.from(nodesById.values()),
    links: Array.from(linksByKey.values()),
  }
}

export function NetworkGraph({ allScannedIps, latestScannedIp, onNodeClick }: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [data, setData] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    const targets = Array.from(new Set(allScannedIps))
    setLoading(true)
    setError(null)
    if (targets.length === 0) {
      setData(null)
      setLoading(false)
      return () => controller.abort()
    }

    async function loadGraph(): Promise<void> {
      try {
        const responses = await Promise.all(
          targets.map(async (target): Promise<GraphData> => {
            const response = await fetch(`${API_BASE_URL}/graph/${encodeURIComponent(target)}`, {
              signal: controller.signal,
            })
            if (!response.ok) {
              throw new Error(`Не удалось загрузить граф для ${target}: HTTP ${response.status}`)
            }
            return (await response.json()) as GraphData
          }),
        )
        if (!controller.signal.aborted) setData(mergeGraphResponses(responses, targets))
      } catch (requestError) {
        if (requestError instanceof DOMException && requestError.name === 'AbortError') return
        setError(requestError instanceof Error ? requestError.message : 'Не удалось загрузить граф.')
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    void loadGraph()
    return () => controller.abort()
  }, [allScannedIps])

  useEffect(() => {
    if (!data || !svgRef.current) return

    const svgElement = svgRef.current
    const svg = d3.select<SVGSVGElement, unknown>(svgElement)
    svg.selectAll('*').remove()
    const wrapper = svgElement.parentElement
    const width = Math.max(svgElement.clientWidth || wrapper?.clientWidth || 800, 320)
    const height = Math.max(svgElement.clientHeight, 480)
    svg.attr('viewBox', `0 0 ${width} ${height}`).attr('preserveAspectRatio', 'xMidYMid meet')

    const graphGroup = svg.append('g').attr('class', 'graph-content')
    const linkLayer = graphGroup.append('g').attr('stroke-opacity', 0.65)
    const nodeLayer = graphGroup.append('g')
    const labelLayer = graphGroup.append('g')

    const zoomBehavior = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.45, 3])
      .translateExtent([
        [-width, -height],
        [width * 2, height * 2],
      ])
      .on('zoom', (event) => {
        graphGroup.attr('transform', event.transform)
      })
    svg.call(zoomBehavior)

    const links = linkLayer
      .selectAll<SVGLineElement, GraphLink>('line')
      .data(data.links)
      .join('line')
      .attr('stroke', (link) => {
        if (link.type === 'same_subnet') return '#64748b'
        if (link.type === 'resolves_to') return '#818cf8'
        if (link.type === 'subdomain_of') return '#38bdf8'
        if (link.type === 'asn_of') return '#9ca3af'
        return '#22d3ee'
      })
      .attr('stroke-width', (link) => (link.type === 'same_subnet' ? 1 : 1.5))
      .attr('stroke-dasharray', (link) =>
        link.type === 'traceroute_hop' || link.type === 'asn_of' ? '4 4' : null,
      )

    const nodeGroups = nodeLayer
      .selectAll<SVGGElement, GraphNode>('g.node')
      .data(data.nodes)
      .join('g')
      .attr('class', 'node')
      .style('cursor', 'grab')

    nodeGroups
      .filter((node) => nodeShape(node).d === null)
      .selectAll<SVGCircleElement, GraphNode>('circle')
      .data((node) => [node])
      .join('circle')
      .attr('r', (node) => {
        const { radius } = nodeShape(node)
        return node.id === latestScannedIp ? Math.max(radius + 5, 12) : radius
      })

    nodeGroups
      .filter((node) => nodeShape(node).d !== null)
      .selectAll<SVGPathElement, GraphNode>('path')
      .data((node) => [node])
      .join('path')
      .attr('d', (node) => nodeShape(node).d ?? '')

    nodeGroups
      .selectAll<SVGCircleElement | SVGPathElement, GraphNode>('circle, path')
      .attr('fill', (node) => nodeTheme(node).fill)
      .attr('stroke', (node) => (node.id === latestScannedIp ? '#fed7aa' : nodeTheme(node).stroke))
      .attr('stroke-width', (node) => (node.id === latestScannedIp ? 2.5 : 1.5))
      .style('cursor', 'grab')

    nodeGroups
      .append('title')
      .text((node) => {
        if (node.is_traceroute_hop) {
          const rtt = node.traceroute_rtt
            ? node.traceroute_rtt.endsWith('ms') ? node.traceroute_rtt : `${node.traceroute_rtt} ms`
            : 'unknown'
          return `Router Hop #${node.traceroute_hop ?? '?'} (RTT: ${rtt})`
        }
        if (node.node_type === 'asn') {
          return `ASN ${node.asn_number ?? '?'}: ${node.asn_org ?? 'unknown'}\nCIDR: ${node.asn_cidr ?? 'unknown'}`
        }
        if (node.node_type === 'subdomain') {
          return `${node.id} · source: ${node.source ?? 'unknown'}\nresolves to: ${node.resolved_ips.join(', ') || 'none'}`
        }
        if (node.node_type === 'domain') {
          return node.asn_number
            ? `${node.id}\nAS${node.asn_number} · ${node.asn_org ?? ''}`
            : node.id
        }
        return node.id
      })

    nodeGroups.on('click', (_event, node) => {
        onNodeClick(node)
      })

    const labels = labelLayer
      .selectAll<SVGTextElement, GraphNode>('text')
      .data(data.nodes)
      .join('text')
      .text((node) => node.id)
      .attr('fill', '#cbd5e1')
      .attr('font-family', 'DM Mono, monospace')
      .attr('font-size', 10)
      .attr('dx', 12)
      .attr('dy', 4)
      .style('pointer-events', 'none')

    const simulation = d3
      .forceSimulation<GraphNode>(data.nodes)
      .force(
        'link',
        d3
          .forceLink<GraphNode, GraphLink>(data.links)
          .id((node) => node.id)
          .distance(80),
      )
      .force('charge', d3.forceManyBody<GraphNode>().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide<GraphNode>().radius(30).strength(0.9))
      .velocityDecay(0.55)
      .on('tick', () => {
        const boundary = 34
        for (const node of data.nodes) {
          node.x = Math.max(boundary, Math.min(width - boundary, node.x ?? width / 2))
          node.y = Math.max(boundary, Math.min(height - boundary, node.y ?? height / 2))
        }
        links
          .attr('x1', (link) => endpointNode(link.source, data.nodes)?.x ?? 0)
          .attr('y1', (link) => endpointNode(link.source, data.nodes)?.y ?? 0)
          .attr('x2', (link) => endpointNode(link.target, data.nodes)?.x ?? 0)
          .attr('y2', (link) => endpointNode(link.target, data.nodes)?.y ?? 0)
        nodeGroups.attr('transform', (node) => `translate(${node.x ?? 0},${node.y ?? 0})`)
        labels.attr('x', (node) => node.x ?? 0).attr('y', (node) => node.y ?? 0)
      })

    nodeGroups.call(
      d3
        .drag<SVGGElement, GraphNode>()
        .on('start', (event, node) => {
          event.sourceEvent.stopPropagation()
          if (!event.active) simulation.alphaTarget(0.3).restart()
          const point = d3.pointer(event.sourceEvent, svgElement)
          const transform = d3.zoomTransform(svgElement)
          const graphPoint = transform.invert(point)
          node.fx = graphPoint[0]
          node.fy = graphPoint[1]
        })
        .on('drag', (event, node) => {
          const point = d3.pointer(event.sourceEvent, svgElement)
          const transform = d3.zoomTransform(svgElement)
          const graphPoint = transform.invert(point)
          node.fx = Math.max(34, Math.min(width - 34, graphPoint[0]))
          node.fy = Math.max(34, Math.min(height - 34, graphPoint[1]))
        })
        .on('end', (event, node) => {
          if (!event.active) simulation.alphaTarget(0)
          node.fx = null
          node.fy = null
        }),
    )

    return () => {
      simulation.stop()
      svg.on('.zoom', null)
      svg.selectAll('*').remove()
    }
  }, [data, latestScannedIp, onNodeClick])

  return (
    <div className="relative h-[600px] w-full overflow-hidden rounded-lg border border-gray-700 bg-gray-900">
      <svg ref={svgRef} className="h-full w-full" role="img" aria-label={`Network graph for ${allScannedIps.length} scanned targets`} />
      <div className="pointer-events-none absolute left-3 top-3 rounded-lg border border-white/10 bg-gray-950/80 px-3 py-2 font-mono text-[10px] uppercase tracking-[0.14em] text-gray-400">
        Nodes // {data?.nodes.length ?? 0}
      </div>
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-900/80 font-mono text-sm text-cyan-300">
          <span className="mr-3 h-4 w-4 animate-spin rounded-full border-2 border-cyan-300 border-t-transparent" />
          Загрузка графа...
        </div>
      )}
      {error && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-900/90 px-6 text-center text-sm text-rose-300" role="alert">
          {error}
        </div>
      )}
    </div>
  )
}
