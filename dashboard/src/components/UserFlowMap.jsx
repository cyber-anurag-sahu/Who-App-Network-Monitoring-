import { useEffect, useRef, useMemo, useState } from 'react'
import * as d3 from 'd3'
import { sankey, sankeyJustify } from 'd3-sankey'

// Sci-Fi Cinematic Palette from image
function getSciFiColor(cat) {
  if (cat.includes('dark') || cat.includes('exploit') || cat.includes('crypto') || cat.includes('scanner')) return '#FF5722'; // Danger Orange
  if (cat.includes('cloud') || cat.includes('vpn') || cat.includes('remote')) return '#00E676'; // Matrix Green
  return '#00E5FF'; // Default Cyan
}

// Subtitles mapping
function getDeviceSubtitle(name) {
  const n = name.toLowerCase()
  if (n.includes('iphone') || n.includes('phone') || n.includes('android')) return '(Primary Handset)'
  if (n.includes('mac') || n.includes('pc') || n.includes('desktop')) return '(Core Workstation)'
  if (n.includes('tv') || n.includes('cast')) return '(Media Hub)'
  if (n.includes('server')) return '(Remote Node)'
  return '(Secure)'
}

// Simple deterministic pseudo-random number generator for stability
function pseudoRandom(seed) {
  const x = Math.sin(seed) * 10000;
  return x - Math.floor(x);
}

function splayLink(d, threadIndex, totalThreads, spreadPixels) {
  const x0 = d.source.x1;
  const x1 = d.target.x0;
  
  // Distribute origin/target Y along the thickness of the link (centered around d.y0/d.y1)
  const width = Math.max(2, d.width);
  const offset = totalThreads > 1 ? (threadIndex / (totalThreads - 1)) : 0.5;
  const y0 = d.y0 - width/2 + width * offset;
  const y1 = d.y1 - width/2 + width * offset;

  const xi = d3.interpolateNumber(x0, x1);
  const x2 = xi(0.5);
  const x3 = xi(0.5);

  // Bowing effect: Middle threads stay straight, outer threads splay widely.
  const normalizedIndex = totalThreads > 1 ? (threadIndex / (totalThreads - 1)) - 0.5 : 0; // -0.5 to 0.5
  const bow = normalizedIndex * spreadPixels;

  return `M${x0},${y0} C${x2},${y0 + bow} ${x3},${y1 + bow} ${x1},${y1}`;
}

export default function UserFlowMap({ devices = [], isIntercepting = false }) {
  const svgRef = useRef(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  const { nodes, links } = useMemo(() => {
    const nodeMap = new Map()
    const linkMap = new Map()
    const getNode = (id, name, group, color) => {
      if (!nodeMap.has(id)) nodeMap.set(id, { id, name, group, color })
      return nodeMap.get(id)
    }
    const addLink = (src, tgt, value, color) => {
      const key = `${src}→${tgt}`
      if (linkMap.has(key)) { linkMap.get(key).value += value }
      else linkMap.set(key, { source: src, target: tgt, value, color })
    }

    devices.forEach(d => {
      const user = d.identity?.user || d.identity?.hostname || d.src_ip || 'UNKNOWN_TARGET'
      const app = d.app?.app_name || 'HTTPS'
      const cat = d.app?.app_category || 'unknown'
      const dst = d.dst_ip || 'EXTERNAL_NODE'
      const userId = `user_${user}`
      const appId = `app_${app}`
      const dstId = `dst_${dst}`

      const dstColor = getSciFiColor(cat)
      const isLaptop = user.toLowerCase().includes('laptop') || user.toLowerCase().includes('mac') || user.toLowerCase().includes('pc')
      const userColor = isLaptop ? '#00E676' : '#00E5FF'

      getNode(userId, user.toUpperCase(), 'user', userColor)
      getNode(appId, `// ${app.toUpperCase()}`, 'app', dstColor)
      getNode(dstId, dst, 'dst', dstColor)

      // Use a fixed value of 10 for all links so the layout geometry is 100% stable 
      // regardless of traffic volume. Only the thread animations will move.
      addLink(userId, appId, 10, userColor)
      addLink(appId, dstId, 10, dstColor)
    })

    return {
      nodes: Array.from(nodeMap.values()),
      links: Array.from(linkMap.values()),
    }
  }, [devices])

  useEffect(() => {
    const el = svgRef.current?.parentElement
    if (!el) return
    const ro = new ResizeObserver(entries => {
      for (let entry of entries) {
        setDimensions({ width: entry.contentRect.width, height: entry.contentRect.height })
      }
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return
    const el = svgRef.current
    const { width: W, height: H } = dimensions
    
    // Generous margins for the complex typography
    const margin = { top: 60, right: 240, bottom: 60, left: 200 }

    const svg = d3.select(el)
      .attr('width', W).attr('height', H)

    if (svg.select('.hud-bg').empty()) {
      const bg = svg.insert('g', ':first-child').attr('class', 'hud-bg')
      
      // Intricate Radar Backdrop
      bg.append('circle').attr('class', 'ring r1').attr('fill', 'none').attr('stroke', 'rgba(0, 229, 255, 0.15)').attr('stroke-width', 1).attr('stroke-dasharray', '2 6')
      bg.append('circle').attr('class', 'ring r2').attr('fill', 'none').attr('stroke', 'rgba(0, 229, 255, 0.05)').attr('stroke-width', 24)
      bg.append('circle').attr('class', 'ring r3').attr('fill', 'none').attr('stroke', 'rgba(0, 229, 255, 0.2)').attr('stroke-width', 1).attr('stroke-dasharray', '1 4')
      bg.append('circle').attr('class', 'ring r4').attr('fill', 'none').attr('stroke', 'rgba(0, 229, 255, 0.1)').attr('stroke-width', 2).attr('stroke-dasharray', '80 30 10 30')
      bg.append('circle').attr('class', 'ring r5').attr('fill', 'none').attr('stroke', 'rgba(0, 229, 255, 0.03)').attr('stroke-width', 60)
      
      // Horizontal & Vertical crosshairs
      bg.append('line').attr('class', 'ch-h').attr('stroke', 'rgba(0, 229, 255, 0.1)').attr('stroke-width', 1)
      bg.append('line').attr('class', 'ch-v').attr('stroke', 'rgba(0, 229, 255, 0.1)').attr('stroke-width', 1)

      svg.append('g').attr('class', 'links-wire-group')
      svg.append('g').attr('class', 'links-group')
      svg.append('g').attr('class', 'nodes-group')
    }

    // Dynamic radar sizing
    const bg = svg.select('.hud-bg').attr('transform', `translate(${W/2}, ${H/2})`)
    const R = Math.min(W, H)
    bg.select('.r1').attr('r', R * 0.42)
    bg.select('.r2').attr('r', R * 0.38)
    bg.select('.r3').attr('r', R * 0.32)
    bg.select('.r4').attr('r', R * 0.25).style('animation', 'hud-spin 40s linear infinite')
    bg.select('.r5').attr('r', R * 0.18)
    bg.select('.ch-h').attr('x1', -R*0.45).attr('x2', R*0.45).attr('y1', 0).attr('y2', 0).attr('stroke-dasharray', '4 8')
    bg.select('.ch-v').attr('x1', 0).attr('x2', 0).attr('y1', -R*0.45).attr('y2', R*0.45).attr('stroke-dasharray', '4 8')

    const nodeIndex = new Map(nodes.map((n, i) => [n.id, i]))
    const resolvedLinks = links
      .filter(l => nodeIndex.has(l.source) && nodeIndex.has(l.target))
      .map(l => ({ ...l, source: nodeIndex.get(l.source), target: nodeIndex.get(l.target) }))

    if (resolvedLinks.length === 0) {
      svg.selectAll('.links-wire-group, .nodes-group, .links-group').selectAll('*').remove()
      return
    }

    // Huge padding to spread nodes vertically
    const dynamicPadding = Math.min(80, Math.max(40, H / (nodes.length || 1) * 0.6))

    const sk = sankey()
      .nodeId(d => d.index)
      .nodeAlign(sankeyJustify)
      .nodeWidth(10)
      .nodePadding(dynamicPadding)
      .extent([[margin.left, margin.top], [W - margin.right, H - margin.bottom]])

    const { nodes: sNodes, links: sLinks } = sk({
      nodes: nodes.map((n, i) => ({ ...n, index: i })),
      links: resolvedLinks,
    })

    // Create the splayed threads
    const sThreads = []
    const SPLAY_PIXELS = Math.max(60, H / 3); // Elegant splay, not too massive

    sLinks.forEach(d => {
      // Create a clean, distinct set of 3 to 6 threads for an elegant fiber-optic look
      const numThreads = Math.min(6, Math.max(3, Math.floor(d.width / 4)))
      
      // Base seed derived from string IDs to ensure stability across re-renders
      let baseSeed = 0;
      const strId = `${d.source.id}->${d.target.id}`;
      for (let j = 0; j < strId.length; j++) baseSeed += strId.charCodeAt(j);

      for(let i = 0; i < numThreads; i++) {
        const seed = baseSeed + i * 10;
        sThreads.push({
          ...d,
          threadId: `th-${d.source.id}-${d.target.id}-${i}`,
          pathData: splayLink(d, i, numThreads, SPLAY_PIXELS),
          speed: 1 + pseudoRandom(seed) * 1.5,
          dash: `${40 + pseudoRandom(seed+1)*40} ${60 + pseudoRandom(seed+2)*80}`, // Longer, more visible dashes
          hasPulse: pseudoRandom(seed+3) > 0.1 // 90% chance to have a pulse so it's very active
        })
      }
    })

    const t = svg.transition().duration(800).ease(d3.easeCubicOut)

    // 1. Thread base wires
    svg.select('.links-wire-group').selectAll('.sankey-thread')
      .data(sThreads, d => d.threadId)
      .join(
        enter => enter.append('path')
          .attr('class', 'sankey-thread')
          .attr('fill', 'none')
          .attr('stroke', d => d.color)
          .attr('stroke-width', 0)
          .attr('stroke-opacity', 0.4) // Increased opacity for better visibility
          .attr('d', d => d.pathData)
          .call(enter => enter.transition(t).attr('stroke-width', 3.0)),
        update => update.call(update => update.transition(t)
          .attr('stroke', d => d.color)
          .attr('stroke-width', 3.0) // Ensure it stays thick on updates
          .attr('d', d => d.pathData)
        ),
        exit => exit.call(exit => exit.transition(t).attr('stroke-width', 0).remove())
      )

    // 2. Thread pulses
    const pulses = sThreads.filter(th => th.hasPulse)
    svg.select('.links-group').selectAll('.sankey-thread-pulse')
      .data(pulses, d => d.threadId)
      .join(
        enter => enter.append('path')
          .attr('class', 'sankey-thread-pulse')
          .attr('fill', 'none')
          .attr('stroke', d => d.color)
          .attr('stroke-width', 0)
          .attr('stroke-dasharray', d => d.dash)
          .attr('stroke-opacity', 1.0) // Max brightness
          .style('animation', d => `hud-flow ${d.speed}s linear infinite`)
          .attr('d', d => d.pathData)
          .call(enter => enter.transition(t).attr('stroke-width', 6.0)),
        update => update.call(update => update.transition(t)
          .attr('stroke', d => d.color)
          .attr('stroke-width', 6.0) // Ensure it stays thick on updates
          .attr('d', d => d.pathData)
        ),
        exit => exit.call(exit => exit.transition(t).attr('stroke-width', 0).remove())
      )

    // 3. Glowing Pillars (Nodes)
    svg.select('.nodes-group').selectAll('.sankey-node')
      .data(sNodes, d => d.id)
      .join(
        enter => {
          const g = enter.append('g').attr('class', 'sankey-node').attr('opacity', 0)
          
          // The main glowing bar
          g.append('rect')
            .attr('class', 'pillar')
            .attr('x', d => d.x0)
            .attr('y', d => d.y0)
            .attr('height', d => Math.max(16, d.y1 - d.y0))
            .attr('width', d => d.x1 - d.x0)
            .attr('fill', d => d.color)
            .attr('opacity', 0.8)
            .style('filter', 'drop-shadow(0 0 12px currentColor)')

          // Left bracket decoration
          g.append('path')
            .attr('class', 'bracket')
            .attr('fill', 'none')
            .attr('stroke', d => d.color)
            .attr('stroke-width', 1)
            .attr('opacity', 0.5)

          // Background data traces extending horizontally
          g.append('line')
            .attr('class', 'trace')
            .attr('stroke', 'rgba(0, 229, 255, 0.15)')
            .attr('stroke-width', 1)

          // Primary Label
          g.append('text')
            .attr('class', 'label-main')
            .attr('fill', '#CFD8DC')
            .attr('font-size', d => d.group === 'app' ? '12px' : '11px')
            .attr('font-weight', '600')
            .attr('letter-spacing', '0.05em')

          // Subtitle / IP / Meta
          g.append('text')
            .attr('class', 'label-sub')
            .attr('fill', '#78909C')
            .attr('font-size', '9px')
            .attr('letter-spacing', '0.05em')

          return g.call(enter => enter.transition(t).attr('opacity', 1))
        },
        update => update, // Handled in the group below
        exit => exit.call(exit => exit.transition(t).attr('opacity', 0).remove())
      )

    // Update Node positions & texts
    svg.select('.nodes-group').selectAll('.sankey-node').each(function(d) {
      const g = d3.select(this)
      const h = Math.max(16, d.y1 - d.y0)
      const w = d.x1 - d.x0

      g.select('.pillar').transition(t)
        .attr('x', d.x0).attr('y', d.y0)
        .attr('height', h).attr('width', w)
        .attr('fill', d.color)

      g.select('.bracket').transition(t)
        .attr('d', `M${d.x0-4},${d.y0} L${d.x0},${d.y0} L${d.x0},${d.y0+h} L${d.x0-4},${d.y0+h}`)
        .attr('stroke', d.color)

      // Background traces
      g.select('.trace').transition(t)
        .attr('x1', d.group === 'user' ? d.x0 - 100 : d.x1)
        .attr('x2', d.group === 'user' ? d.x0 - 10 : d.x1 + 100)
        .attr('y1', d.y0 + h/2).attr('y2', d.y0 + h/2)

      // Typography positioning
      const mainText = g.select('.label-main')
      const subText = g.select('.label-sub')

      if (d.group === 'user') {
        mainText.transition(t).attr('x', d.x0 - 16).attr('y', d.y0 + h/2 - 2).attr('text-anchor', 'end').text(d.name)
        subText.transition(t).attr('x', d.x0 - 16).attr('y', d.y0 + h/2 + 10).attr('text-anchor', 'end').text(getDeviceSubtitle(d.name))
      } else if (d.group === 'dst') {
        mainText.transition(t).attr('x', d.x1 + 16).attr('y', d.y0 + h/2 - 2).attr('text-anchor', 'start').text(d.name)
        const isUnauthorized = d.color === '#FF5722'
        subText.transition(t).attr('x', d.x1 + 16).attr('y', d.y0 + h/2 + 10).attr('text-anchor', 'start').attr('fill', isUnauthorized ? '#FF5722' : '#78909C').text(isUnauthorized ? 'UNAUTHORIZED CONNECTION' : `> ${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`)
      } else { // center (app)
        mainText.transition(t).attr('x', d.x0 + w/2).attr('y', d.y0 - 16).attr('text-anchor', 'middle').text(d.name)
        subText.transition(t).attr('x', d.x0 + w/2).attr('y', d.y0 + h + 14).attr('text-anchor', 'middle').text('DATA ENCRYPTION / PROTOCOL')
      }
    })

  }, [nodes, links, dimensions])

  if (nodes.length === 0) {
    return (
      <div className="empty-state" style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ fontSize: '2.5rem', marginBottom: 12, opacity: 0.7 }}>⚲</div>
        <div style={{ color: '#00E5FF', fontFamily: 'var(--font-mono)', fontSize: '0.9rem', letterSpacing: '0.2em' }}>SYSTEM STANDBY</div>
        <div style={{ marginTop: 8, fontSize: '0.7rem', color: 'rgba(0,229,255,0.5)', fontFamily: 'var(--font-mono)' }}>WAITING FOR TARGET ACQUISITION...</div>
      </div>
    )
  }

  return (
    <div className="hud-container" style={{ width: '100%', height: '100%', position: 'relative', overflow: 'hidden', backgroundColor: '#020617' }}>
      <style>
        {`
          .hud-container {
            background-color: #050B14;
            background-image: 
              linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
              linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
            background-size: 20px 20px;
            box-shadow: inset 0 0 150px rgba(0,0,0,0.95);
          }
          .sankey-thread {
            transition: stroke-width 0.2s;
          }
          .sankey-thread-pulse {
            stroke-linecap: round;
          }
          @keyframes hud-flow {
            from { stroke-dashoffset: 180; }
            to { stroke-dashoffset: 0; }
          }
          @keyframes hud-spin {
            100% { transform: rotate(360deg); }
          }
          .label-main, .label-sub {
            font-family: 'Share Tech Mono', 'Courier New', Courier, monospace;
            text-shadow: 0 2px 4px rgba(0,0,0,0.9), 0 0 10px rgba(0,0,0,0.8);
            pointer-events: none;
          }
          .pillar {
            rx: 2px;
          }
          @keyframes satellitePulse {
            0%, 100% { opacity: 0.2; transform: scale(0.9); }
            50% { opacity: 0.8; transform: scale(1.1); }
          }
        `}
      </style>
      <svg ref={svgRef} style={{ width: '100%', height: '100%', display: 'block' }} />
      
      {/* Decorative Static HUD Overlays from Image */}
      <div style={{ position: 'absolute', top: 20, left: 24, color: '#78909C', fontFamily: 'var(--font-mono)', fontSize: '0.65rem', pointerEvents: 'none', lineHeight: '1.4' }}>
        <span style={{color: '#CFD8DC'}}>[ HUD_ACTIVE ]</span><br/>
        SYS_STATUS: ONLINE<br/>
        TRK_MODE: <span style={{ color: isIntercepting ? '#FF5722' : '#00E5FF', animation: isIntercepting ? 'blink 1.5s infinite' : 'none' }}>{isIntercepting ? 'ACTIVE_INTERCEPT' : 'PASSIVE_MONITOR'}</span>
      </div>

      <div style={{ position: 'absolute', top: 20, right: 24, color: '#78909C', fontFamily: 'var(--font-mono)', fontSize: '0.65rem', textAlign: 'right', pointerEvents: 'none', lineHeight: '1.4' }}>
        NET_SIG: <span style={{color: '#00E676'}}>OK</span><br/>
        ENCRYPTION: BYPASSED<br/>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" style={{marginTop: 8, opacity: 0.4}}>
          <path d="M4 14.899A7 7 0 1 1 15.62 16.5M12 12v.01M8.5 8.5v.01M15.5 8.5v.01M8.5 15.5v.01"/>
        </svg>
      </div>
      
      <div style={{ position: 'absolute', bottom: 30, left: 24, color: '#78909C', fontFamily: 'var(--font-mono)', fontSize: '0.6rem', pointerEvents: 'none', display: 'flex', gap: '16px', alignItems: 'flex-end', lineHeight: '1.4' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
          <div style={{ width: '60px', height: '2px', background: 'rgba(0,229,255,0.6)' }}></div>
          <div style={{ width: '40px', height: '2px', background: 'rgba(0,229,255,0.3)' }}></div>
          <div style={{ width: '80px', height: '2px', background: 'rgba(0,229,255,0.8)' }}></div>
          <div style={{ width: '50px', height: '2px', background: 'rgba(0,229,255,0.2)' }}></div>
        </div>
        <div>
          DATA_STREAM: <span style={{ color: '#00E5FF' }}>ACTIVE</span><br/>
          PACKET_LOSS: <span style={{ color: '#00E676' }}>0.00%</span><br/>
          HOST_ALLOC: 0xPF2B<br/>
          <span style={{ animation: 'blink 1.5s infinite' }}>AWAITING_INPUT...</span>
        </div>
      </div>

      <div style={{ position: 'absolute', bottom: 30, right: 24, color: '#78909C', fontFamily: 'var(--font-mono)', fontSize: '0.65rem', textAlign: 'right', pointerEvents: 'none', lineHeight: '1.4' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, marginBottom: 4 }}>
          <div style={{ width: 12, height: 12, border: '1px solid currentColor', borderRadius: '50%', position: 'relative' }}>
             <div style={{ position: 'absolute', top: '50%', left: '50%', width: 4, height: 4, background: '#00E5FF', transform: 'translate(-50%, -50%)', borderRadius: '50%', animation: 'satellitePulse 2s infinite' }}></div>
          </div>
        </div>
        SEC_LEVEL: ALPHA<br/>
        UPLINK_FREQ: 144.20 MHz
      </div>
    </div>
  )
}
