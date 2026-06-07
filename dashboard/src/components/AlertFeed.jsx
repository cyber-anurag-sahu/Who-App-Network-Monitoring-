import { useState, useCallback, useMemo } from 'react'
import { formatDistanceToNow } from 'date-fns'

const SEV_ORDER = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }
const SEV_FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low']

export default function AlertFeed({ alerts = [] }) {
  const [sevFilter, setSevFilter] = useState('All')
  const [tagFilter, setTagFilter] = useState('')

  const filtered = useMemo(() => {
    return alerts
      .filter(a => sevFilter === 'All' || a.severity === sevFilter)
      .filter(a => !tagFilter || a.tags?.some(t => t.includes(tagFilter)))
      .sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0))
      .slice(0, 200)
  }, [alerts, sevFilter, tagFilter])

  const counts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    alerts.forEach(a => { if (c[a.severity] !== undefined) c[a.severity]++ })
    return c
  }, [alerts])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Summary row */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        {Object.entries(counts).map(([sev, count]) => (
          <div key={sev} style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '8px 16px', textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.3rem', fontWeight: 700, color: `var(--sev-${sev.toLowerCase()})` }}>{count}</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{sev}</div>
          </div>
        ))}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '8px 16px', textAlign: 'center' }}>
          <div style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)' }}>{alerts.length}</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Total</div>
        </div>
      </div>

      {/* Filters */}
      <div className="filter-bar">
        {SEV_FILTERS.map(f => (
          <button key={f} className={`filter-btn${sevFilter === f ? ' active' : ''}`}
            onClick={() => setSevFilter(f)}>{f}</button>
        ))}
        <input
          style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 99, padding: '4px 14px', fontSize: '0.75rem', color: 'var(--text-primary)', outline: 'none', marginLeft: 'auto' }}
          placeholder="Filter by tag..."
          value={tagFilter}
          onChange={e => setTagFilter(e.target.value)}
        />
      </div>

      {/* Feed */}
      <div className="alert-feed scrollable" style={{ flex: 1 }}>
        {filtered.length === 0 && (
          <div className="empty-state">
            <div style={{ fontSize: '2rem', marginBottom: 8 }}>🛡️</div>
            <div>No alerts match the current filter</div>
            <div style={{ marginTop: 4, fontSize: '0.75rem' }}>Waiting for rule engine events...</div>
          </div>
        )}
        {filtered.map((alert, i) => (
          <AlertItem key={`${alert.rule_name}-${alert.ts}-${i}`} alert={alert} />
        ))}
      </div>
    </div>
  )
}

function AlertItem({ alert }) {
  const sev = alert.severity?.toLowerCase() || 'info'
  const ev = alert.event || {}
  const timeAgo = alert.ts ? formatDistanceToNow(new Date(alert.ts), { addSuffix: true }) : ''

  return (
    <div className={`alert-item ${sev}`}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, paddingTop: 2 }}>
        <span className={`alert-sev ${sev}`}>{alert.severity}</span>
        <SevIcon sev={sev} />
      </div>
      <div className="alert-body">
        <div className="alert-rule">{alert.rule_name}</div>
        <div className="alert-meta">
          {ev.user && <span>👤 {ev.user}</span>}
          {ev.app_name && <span>📦 {ev.app_name}</span>}
          {ev.hostname && ev.hostname !== ev.user && <span>🖥 {ev.hostname}</span>}
          {ev.device_type && <span>📱 {ev.device_type}</span>}
          {ev.src_ip && <span className="mono">{ev.src_ip}</span>}
          {ev.tls_sni && <span className="mono truncate" style={{ maxWidth: 180 }}>🔒 {ev.tls_sni}</span>}
          {ev.byte_count > 0 && <span>📊 {fmtBytes(ev.byte_count)}</span>}
        </div>
        <div className="alert-tags">
          {(alert.tags || []).map(t => <span key={t} className="tag">{t}</span>)}
        </div>
      </div>
      <div className="alert-ts">{timeAgo}</div>
    </div>
  )
}

function SevIcon({ sev }) {
  const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵' }
  return <span style={{ fontSize: '0.9rem' }}>{icons[sev] || '⚪'}</span>
}

function fmtBytes(b) {
  if (b < 1024) return `${b}B`
  if (b < 1048576) return `${(b/1024).toFixed(1)}KB`
  if (b < 1073741824) return `${(b/1048576).toFixed(1)}MB`
  return `${(b/1073741824).toFixed(2)}GB`
}
