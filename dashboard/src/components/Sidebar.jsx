const TABS = [
  { id: 'alerts',   label: '🚨 Alerts',   badge: null },
  { id: 'devices',  label: '📡 Devices',  badge: null },
  { id: 'flowmap',  label: '🌐 Flow Map', badge: null },
  { id: 'timeline', label: '⏱ Timeline',  badge: null },
]

const NAV_LINKS = [
  { label: 'Overview',    icon: '◉', id: 'overview' },
  { label: 'Alerts',      icon: '🚨', id: 'alerts' },
  { label: 'Devices',     icon: '📡', id: 'devices' },
  { label: 'Flow Map',    icon: '🌐', id: 'flowmap' },
  { label: 'Timeline',    icon: '⏱', id: 'timeline' },
]

export default function Sidebar({ activeTab, onTabChange, alertCount, deviceCount }) {
  return (
    <div className="sidebar">
      <div className="sidebar-section" style={{ padding: '8px 16px 12px', borderBottom: '1px solid var(--border)', marginBottom: 8 }}>
        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 10, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' }}>Navigation</div>
        {NAV_LINKS.map(link => (
          <div
            key={link.id}
            className={`sidebar-item${activeTab === link.id ? ' active' : ''}`}
            onClick={() => onTabChange(link.id)}
          >
            <span className="icon">{link.icon}</span>
            <span>{link.label}</span>
            {link.id === 'alerts' && alertCount > 0 && (
              <span className="badge">{alertCount > 99 ? '99+' : alertCount}</span>
            )}
          </div>
        ))}
      </div>

      <div className="sidebar-section" style={{ padding: '0 16px' }}>
        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>System</div>

        <StatRow label="Active Devices" value={deviceCount} color="var(--accent-2)" />
        <StatRow label="Alert Queue" value={alertCount} color={alertCount > 0 ? 'var(--sev-high)' : 'var(--sev-low)'} />

        <div style={{ marginTop: 16, padding: '10px 12px', background: 'var(--bg-elevated)', borderRadius: 8, border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600 }}>SERVICES</div>
          <ServiceRow name="Capture" status="live" />
          <ServiceRow name="Classifier" status="live" />
          <ServiceRow name="WebSocket" status="live" />
          <ServiceRow name="Npcap" status="live" />
        </div>

        <div style={{ marginTop: 12, padding: '10px 12px', background: 'rgba(34,197,94,.06)', borderRadius: 8, border: '1px solid rgba(34,197,94,.2)' }}>
          <div style={{ fontSize: '0.68rem', color: 'var(--sev-low)', fontWeight: 600, marginBottom: 4 }}>📡 Live Capture Active</div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
            Passively monitoring <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>Wi-Fi</code> in real time via Npcap.
          </div>
        </div>
      </div>

      <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, padding: '12px 16px', borderTop: '1px solid var(--border)', background: 'var(--bg-surface)' }}>
        <div style={{ fontSize: '0.62rem', color: 'var(--text-muted)' }}>
          WhoApp v1.0 — Powered by Antigravity
        </div>
        <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: 2 }}>
          <a href="http://localhost:3001" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', textDecoration: 'none' }}>
            Open Grafana →
          </a>
        </div>
      </div>
    </div>
  )
}

function StatRow({ label, value, color }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 0' }}>
      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{label}</span>
      <span style={{ fontSize: '0.78rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color }}>{value}</span>
    </div>
  )
}

function ServiceRow({ name, status }) {
  const colors = { online: 'var(--sev-low)', live: 'var(--sev-low)', offline: 'var(--sev-critical)', demo: 'var(--sev-medium)' }
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '3px 0' }}>
      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{name}</span>
      <span style={{ fontSize: '0.62rem', color: colors[status] || 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
        <span style={{ width: 5, height: 5, borderRadius: '50%', background: colors[status], display: 'inline-block' }} />
        {status}
      </span>
    </div>
  )
}
