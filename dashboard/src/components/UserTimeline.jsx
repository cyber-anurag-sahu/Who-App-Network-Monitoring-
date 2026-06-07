import { useMemo } from 'react'
import { format } from 'date-fns'

const CAT_COLORS = {
  messaging: '#8b5cf6', browser: '#3b82f6', dark_web: '#ef4444',
  vpn: '#f97316', torrent: '#eab308', streaming: '#22c55e',
  social_media: '#ec4899', video_conf: '#06b6d4', remote_access: '#f59e0b',
  cloud_storage: '#10b981', crypto_mining: '#ef4444', unknown: '#6b7280',
  email: '#60a5fa', dev_tool: '#a3e635',
}

const WINDOW_MINUTES = 60

export default function UserTimeline({ flows = [] }) {
  const now = Date.now()
  const windowMs = WINDOW_MINUTES * 60 * 1000
  const startTime = now - windowMs

  // Group flows by user, bucket by minute
  const { users, buckets } = useMemo(() => {
    const userMap = new Map()
    const recentFlows = flows.filter(f => {
      const ts = f.ts ? new Date(f.ts).getTime() : 0
      return ts > startTime
    })

    recentFlows.forEach(f => {
      const user = f.identity?.user || f.identity?.hostname || f.src_ip || 'unknown'
      const ts = f.ts ? new Date(f.ts).getTime() : now
      const app = f.app?.app_name || 'unknown'
      const cat = f.app?.app_category || 'unknown'

      if (!userMap.has(user)) userMap.set(user, [])
      userMap.get(user).push({ ts, app, cat })
    })

    // Sort users by number of events desc
    const users = Array.from(userMap.entries())
      .sort((a, b) => b[1].length - a[1].length)
      .slice(0, 12) // max 12 rows

    // Build timeline segments per user
    const buckets = users.map(([user, events]) => {
      const segments = []
      const sorted = events.sort((a, b) => a.ts - b.ts)
      let current = null

      sorted.forEach(ev => {
        const x = ((ev.ts - startTime) / windowMs) * 100
        if (!current || current.app !== ev.app) {
          if (current) segments.push(current)
          current = { app: ev.app, cat: ev.cat, startX: x, endX: x + 1.5, color: CAT_COLORS[ev.cat] || '#6b7280' }
        } else {
          current.endX = Math.min(100, x + 1.5)
        }
      })
      if (current) segments.push(current)

      return { user, segments }
    })

    return { users: users.map(([u]) => u), buckets }
  }, [flows, startTime, now, windowMs])

  // Time axis ticks
  const ticks = useMemo(() => {
    const t = []
    for (let i = 0; i <= 6; i++) {
      const ts = startTime + (i / 6) * windowMs
      t.push({ x: (i / 6) * 100, label: format(new Date(ts), 'HH:mm') })
    }
    return t
  }, [startTime, windowMs])

  if (buckets.length === 0) {
    return (
      <div className="empty-state" style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ fontSize: '2.5rem', marginBottom: 8 }}>⏱️</div>
        <div>No timeline data yet</div>
        <div style={{ marginTop: 4, fontSize: '0.75rem' }}>Last 60 minutes of activity will appear here</div>
      </div>
    )
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <h3 style={{ fontSize: '0.88rem', fontWeight: 600 }}>User Activity Timeline</h3>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Last {WINDOW_MINUTES} minutes</span>
      </div>

      {/* Time axis */}
      <div style={{ display: 'flex', marginLeft: 148, position: 'relative', marginBottom: 6 }}>
        {ticks.map((tick, i) => (
          <div key={i} style={{ position: 'absolute', left: `${tick.x}%`, fontSize: '0.62rem', color: 'var(--text-muted)', transform: 'translateX(-50%)' }}>
            {tick.label}
          </div>
        ))}
      </div>
      <div style={{ height: 8 }} />

      {/* User rows */}
      <div className="timeline-wrap scrollable" style={{ flex: 1 }}>
        {buckets.map(({ user, segments }) => (
          <div key={user} className="timeline-user-row">
            <div className="timeline-user-label" title={user}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{user}</span>
            </div>
            <div className="timeline-track">
              {segments.map((seg, i) => (
                <div
                  key={i}
                  className="timeline-segment"
                  title={`${seg.app} (${seg.cat})`}
                  style={{
                    left: `${seg.startX}%`,
                    width: `${Math.max(1.5, seg.endX - seg.startX)}%`,
                    background: seg.color,
                    opacity: 0.85,
                  }}
                >
                  <span>{seg.app}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
        {Object.entries(CAT_COLORS).slice(0, 8).map(([cat, color]) => (
          <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{cat}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
