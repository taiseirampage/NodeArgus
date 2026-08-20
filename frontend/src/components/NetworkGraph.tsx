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
}

export interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  type: 'same_subnet' | 'same_dns' | 'common_port' | string
}

interface GraphData {
  center_ip: string
  nodes: GraphNode[]
  links: GraphLink[]
}

interface NetworkGraphProps {
  targetIp: string
  onNodeClick: (ip: string) => void
}

type LinkEndpoint = string | number | GraphNode

function endpointNode(endpoint: LinkEndpoint, nodes: GraphNode[]): GraphNode | undefined {
  if (typeof endpoint === 'object') return endpoint
  return nodes.find((node) => node.id === String(endpoint))
}

export function NetworkGraph({ targetIp, onNodeClick }: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [data, setData] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    setData(null)

    async function loadGraph(): Promise<void> {
      try {
        const response = await fetch(`${API_BASE_URL}/graph/${encodeURIComponent(targetIp)}`, {
          signal: controller.signal,
        })
        if (!response.ok) {
          throw new Error(`Не удалось загрузить граф: HTTP ${response.status}`)
        }
        const graph = (await response.json()) as GraphData
        setData(graph)
      } catch (requestError) {
        if (requestError instanceof DOMException && requestError.name === 'AbortError') return
        setError(requestError instanceof Error ? requestError.message : 'Не удалось загрузить граф.')
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    void loadGraph()
    return () => controller.abort()
  }, [targetIp])

  useEffect(() => {
    if (!data || !svgRef.current) return

    const svg = d3.select<SVGSVGElement, unknown>(svgRef.current)
    svg.selectAll('*').remove()
    const wrapper = svgRef.current.parentElement
    const width = Math.max(wrapper?.clientWidth ?? 800, 320)
    const height = 384
    svg.attr('viewBox', `0 0 ${width} ${height}`).attr('preserveAspectRatio', 'xMidYMid meet')

    const linkLayer = svg.append('g').attr('stroke-opacity', 0.65)
    const nodeLayer = svg.append('g')
    const labelLayer = svg.append('g')

    const links = linkLayer
      .selectAll<SVGLineElement, GraphLink>('line')
      .data(data.links)
      .join('line')
      .attr('stroke', (link) => (link.type === 'same_subnet' ? '#64748b' : '#22d3ee'))
      .attr('stroke-width', (link) => (link.type === 'same_subnet' ? 1 : 2))

    const nodes = nodeLayer
      .selectAll<SVGCircleElement, GraphNode>('circle')
      .data(data.nodes)
      .join('circle')
      .attr('r', (node) => (node.id === targetIp ? 12 : 7))
      .attr('fill', (node) => (node.id === targetIp ? '#f97316' : '#34d399'))
      .attr('stroke', (node) => (node.id === targetIp ? '#fed7aa' : '#a7f3d0'))
      .attr('stroke-width', (node) => (node.id === targetIp ? 2 : 1))
      .style('cursor', 'grab')
      .on('click', (_event, node) => {
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
          .distance(100),
      )
      .force('charge', d3.forceManyBody<GraphNode>().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .on('tick', () => {
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
          if (!event.active) simulation.alphaTarget(0.3).restart()
          node.fx = node.x
          node.fy = node.y
        })
        .on('drag', (event, node) => {
          node.fx = event.x
          node.fy = event.y
        })
        .on('end', (event, node) => {
          if (!event.active) simulation.alphaTarget(0)
          node.fx = null
          node.fy = null
        }),
    )

    return () => {
      simulation.stop()
      svg.selectAll('*').remove()
    }
  }, [data, onNodeClick, targetIp])

  return (
    <div className="relative w-full h-96 overflow-hidden rounded-lg border border-gray-700 bg-gray-900">
      <svg ref={svgRef} className="h-full w-full" role="img" aria-label={`Network graph for ${targetIp}`} />
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
