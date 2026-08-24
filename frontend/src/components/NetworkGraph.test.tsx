import { describe, expect, it } from 'vitest'
import { DEFAULT_LINK_TYPES, filterAndCollapse, mergeGraphResponses } from './NetworkGraph'
import type { GraphLink, GraphNode } from './NetworkGraph'

function node(id: string, overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    id,
    ip: id,
    node_type: 'ip',
    source: null,
    resolved_ips: [],
    country: null,
    city: null,
    os: null,
    ports_count: 0,
    is_traceroute_hop: false,
    traceroute_hop: null,
    traceroute_rtt: null,
    ...overrides,
  }
}

function link(source: string, target: string, type: GraphLink['type']): GraphLink {
  return { source, target, type }
}

function allTypes(): Set<GraphLink['type']> {
  return new Set(DEFAULT_LINK_TYPES)
}

describe('mergeGraphResponses', () => {
  it('deduplicates nodes and links across responses', () => {
    const nodesA = [node('10.0.0.1'), node('10.0.0.2')]
    const nodesB = [node('10.0.0.2'), node('10.0.0.3')]
    const linksA = [link('10.0.0.1', '10.0.0.2', 'same_subnet')]
    const linksB = [link('10.0.0.2', '10.0.0.1', 'same_subnet')]

    const merged = mergeGraphResponses(
      [
        { center_ip: 'a', nodes: nodesA, links: linksA },
        { center_ip: 'b', nodes: nodesB, links: linksB },
      ],
      ['a', 'b'],
    )

    expect(merged.nodes.map((n) => n.id).sort()).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.3'])
    expect(merged.links).toHaveLength(1)
    expect(merged.center_ip).toBe('b')
  })

  it('marks scanned targets as non-traceroute-hop nodes', () => {
    const hop = { ...node('10.0.0.1'), is_traceroute_hop: true }
    const merged = mergeGraphResponses([{ center_ip: 'x', nodes: [hop], links: [] }], ['10.0.0.1'])
    expect(merged.nodes[0].is_traceroute_hop).toBe(false)
  })
})

describe('filterAndCollapse', () => {
  const nodes = [
    node('net:10.0.0.0/24', { node_type: 'network', member_count: 3 }),
    node('10.0.0.1'),
    node('10.0.0.2'),
    node('10.0.0.3'),
    node('8.8.8.8'),
  ]
  const links = [
    link('net:10.0.0.0/24', '10.0.0.1', 'in_subnet'),
    link('net:10.0.0.0/24', '10.0.0.2', 'in_subnet'),
    link('net:10.0.0.0/24', '10.0.0.3', 'in_subnet'),
    link('10.0.0.1', '8.8.8.8', 'same_dns'),
  ]

  it('returns everything when nothing is collapsed and all types active', () => {
    const result = filterAndCollapse(nodes, links, allTypes(), {})
    expect(result.nodes).toHaveLength(5)
    expect(result.links).toHaveLength(4)
    expect(result.hiddenCount).toBe(0)
  })

  it('filters links by active type', () => {
    const types = allTypes()
    types.delete('same_dns')
    const result = filterAndCollapse(nodes, links, types, {})
    expect(result.links).toHaveLength(3)
    expect(result.nodes).toHaveLength(5)
  })

  it('collapses hub members that only have in_subnet edges', () => {
    const result = filterAndCollapse(nodes, links, allTypes(), { 'net:10.0.0.0/24': true })
    expect(result.hiddenCount).toBe(2)
    expect(result.nodes.map((n) => n.id)).toEqual(
      expect.arrayContaining(['net:10.0.0.0/24', '10.0.0.1', '8.8.8.8']),
    )
    expect(result.nodes.map((n) => n.id)).not.toContain('10.0.0.2')
    expect(result.nodes.map((n) => n.id)).not.toContain('10.0.0.3')
    expect(result.links.some((linkItem) => linkItem.type === 'in_subnet')).toBe(false)
    expect(result.links).toContainEqual(expect.objectContaining({ type: 'same_dns' }))
  })

  it('keeps a member connected to a non-subnet edge when its hub collapses', () => {
    const result = filterAndCollapse(nodes, links, allTypes(), { 'net:10.0.0.0/24': true })
    expect(result.nodes.map((n) => n.id)).toContain('10.0.0.1')
    expect(result.links.some((l) => l.type === 'same_dns')).toBe(true)
  })
})
