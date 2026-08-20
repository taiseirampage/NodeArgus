import { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export interface GraphNode extends d3.SimulationNodeDatum {
  id: string
  ip: string
  country: string | null
  city: string | null
  os: string | null
  ports_count: number
  is_traceroute_hop: boolean
  traceroute_hop: number | null
  traceroute_rtt: string | null
}

export interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  type: 'same_subnet' | 'same_dns' | 'common_port' | 'traceroute_hop' | string
}

interface GraphData {
  center_ip: string
  nodes: GraphNode[]
  links: GraphLink[]
}

interface NetworkGraphProps {
  allScannedIps: string[]
  latestScannedIp: string | null
  onNodeClick: (ip: string) => void
}

type LinkEndpoint = string | number | GraphNode

function endpointNode(endpoint: LinkEndpoint, nodes: GraphNode[]): GraphNode | undefined {
  if (typeof endpoint === 'object') return endpoint
  return nodes.find((node) => node.id === String(endpoint))
}

function endpointId(endpoint: LinkEndpoint): string {
  return typeof endpoint === 'object' ? endpoint.id : String(endpoint)
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
      .attr('stroke', (link) => (link.type === 'same_subnet' ? '#64748b' : '#22d3ee'))
      .attr('stroke-width', (link) => (link.type === 'same_subnet' ? 1 : 2))
      .attr('stroke-dasharray', (link) => (link.type === 'traceroute_hop' ? '4 4' : null))

    const nodes = nodeLayer
      .selectAll<SVGCircleElement, GraphNode>('circle')
      .data(data.nodes)
      .join('circle')
      .attr('r', (node) => (node.is_traceroute_hop ? 5 : node.id === latestScannedIp ? 12 : 7))
      .attr('fill', (node) => (node.is_traceroute_hop ? '#6b7280' : node.id === latestScannedIp ? '#f97316' : '#34d399'))
      .attr('stroke', (node) => (node.is_traceroute_hop ? '#d1d5db' : node.id === latestScannedIp ? '#fed7aa' : '#a7f3d0'))
      .attr('stroke-width', (node) => (node.is_traceroute_hop ? 1 : node.id === latestScannedIp ? 2 : 1))
      .style('cursor', 'grab')

    nodes
      .append('title')
      .text((node) => {
        if (!node.is_traceroute_hop) return node.id
        const rtt = node.traceroute_rtt
          ? node.traceroute_rtt.endsWith('ms') ? node.traceroute_rtt : `${node.traceroute_rtt} ms`
          : 'unknown'
        return `Router Hop #${node.traceroute_hop ?? '?'} (RTT: ${rtt})`
      })

    nodes.on('click', (_event, node) => {
        onNodeClick(node.ip)
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
        nodes.attr('cx', (node) => node.x ?? 0).attr('cy', (node) => node.y ?? 0)
        labels.attr('x', (node) => node.x ?? 0).attr('y', (node) => node.y ?? 0)
      })

    nodes.call(
      d3
        .drag<SVGCircleElement, GraphNode>()
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
