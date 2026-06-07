import { useMemo, useState } from 'react'

const CAT_COLORS = {
  messaging: '#8b5cf6', browser: '#3b82f6', dark_web: '#ef4444',
  vpn: '#f97316', torrent: '#eab308', streaming: '#22c55e',
  social_media: '#ec4899', video_conf: '#06b6d4', remote_access: '#f59e0b',
  cloud_storage: '#10b981', crypto_mining: '#ef4444', unknown: '#6b7280',
  email: '#60a5fa', dev_tool: '#a3e635', scanner: '#ef4444',
}

const DEVICE_ICONS = { laptop: '💻', phone: '📱', server: '🖥️', iot: '📡', unknown: '❓' }

export default function DeviceGrid({ devices = [], spoofedIps = [], setSpoofedIps }) {
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState('risk')
  const [selectedDevice, setSelectedDevice] = useState(null)

  const handleInterceptAll = async () => {
    try {
      const res = await fetch('http://localhost:8766/api/spoof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'start_all' })
      })
      const data = await res.json()
      if (data.spoofed) {
        if (setSpoofedIps) setSpoofedIps(data.spoofed)
      }
    } catch (e) {
      console.error('Failed to start all intercepts', e)
    }
  }

  const handleStopAll = async () => {
    try {
      const res = await fetch('http://localhost:8766/api/spoof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'stop_all' })
      })
      const data = await res.json()
      if (data.spoofed) {
        if (setSpoofedIps) setSpoofedIps(data.spoofed)
      }
    } catch (e) {
      console.error('Failed to stop all intercepts', e)
    }
  }

  const dedupedDevices = useMemo(() => {
    const map = new Map()
    devices.forEach(d => {
      const key = d.identity?.ip || d.src_ip || Math.random()
      const existing = map.get(key)
      const risk = d.app?.app_risk_score || 0
      if (!existing || risk > (existing.app?.app_risk_score || 0)) {
        map.set(key, d)
      }
    })
    return Array.from(map.values())
  }, [devices])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return dedupedDevices
      .filter(d => {
        if (!q) return true
        const user = d.identity?.user || ''
        const host = d.identity?.hostname || ''
        const app = d.app?.app_name || ''
        return user.toLowerCase().includes(q) || host.toLowerCase().includes(q) || app.toLowerCase().includes(q)
      })
      .sort((a, b) => {
        if (sortBy === 'risk') return (b.app?.app_risk_score || 0) - (a.app?.app_risk_score || 0)
        if (sortBy === 'user') return (a.identity?.user || '').localeCompare(b.identity?.user || '')
        return 0
      })
  }, [dedupedDevices, search, sortBy])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'center' }}>
        <input
          style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: '7px 14px', fontSize: '0.8rem', color: 'var(--text-primary)', outline: 'none', flex: 1 }}
          placeholder="Search user, host, app..."
          value={search} onChange={e => setSearch(e.target.value)}
        />
        <select
          value={sortBy} onChange={e => setSortBy(e.target.value)}
          style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: '7px 12px', fontSize: '0.8rem', color: 'var(--text-primary)', outline: 'none' }}
        >
          <option value="risk">Sort: Risk</option>
          <option value="user">Sort: User</option>
        </select>
        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {filtered.length} device{filtered.length !== 1 ? 's' : ''}
        </span>
        
        {spoofedIps.length > 0 ? (
          <button 
            onClick={handleStopAll}
            style={{ background: 'transparent', border: '1px solid var(--sev-critical)', color: 'var(--sev-critical)', padding: '6px 12px', borderRadius: 6, fontSize: '0.75rem', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.2s' }}
          >
            🛑 Stop All
          </button>
        ) : (
          <button 
            onClick={handleInterceptAll}
            style={{ background: 'var(--sev-critical)', border: '1px solid var(--sev-critical)', color: '#fff', padding: '6px 12px', borderRadius: 6, fontSize: '0.75rem', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.2s' }}
          >
            🎯 Intercept All
          </button>
        )}
      </div>

      {filtered.length === 0 && (
        <div className="empty-state">
          <div style={{ fontSize: '2.5rem', marginBottom: 8 }}>📡</div>
          <div>No devices discovered yet</div>
          <div style={{ marginTop: 4, fontSize: '0.75rem' }}>Start the simulator or live capture to see devices</div>
        </div>
      )}

      <div className="device-grid scrollable" style={{ flex: 1 }}>
        {filtered.map((d, i) => {
          const ip = d.identity?.ip || d.src_ip
          return (
            <DeviceCard 
              key={i} 
              device={d} 
              apps={d.apps || []} 
              isSpoofed={spoofedIps.includes(ip)}
              onClick={() => setSelectedDevice(d)}
            />
          )
        })}
      </div>

      {selectedDevice && (
        <DeviceModal 
          device={selectedDevice} 
          spoofedIps={spoofedIps}
          setSpoofedIps={setSpoofedIps}
          onClose={() => setSelectedDevice(null)} 
        />
      )}
    </div>
  )
}

function DeviceCard({ device: d, apps = [], isSpoofed, onClick }) {
  const identity = d.identity || {}
  const app = d.app || {}
  const dtype = identity.device_type || 'unknown'
  
  // Calculate maximum risk from all apps if we have apps, else fallback to current flow risk
  const risk = apps.length > 0 
    ? Math.max(...apps.map(a => a.app_risk_score || 0)) 
    : (app.app_risk_score || 0)
    
  const riskColor = risk >= 8 ? 'var(--sev-critical)' : risk >= 6 ? 'var(--sev-high)' : risk >= 4 ? 'var(--sev-medium)' : 'var(--sev-low)'

  return (
    <div className="device-card" style={{ display: 'flex', flexDirection: 'column', cursor: 'pointer', border: isSpoofed ? '1px solid var(--sev-critical)' : undefined }} onClick={onClick}>
      <div className="device-top">
        <div className={`device-avatar ${dtype}`} style={{ position: 'relative' }}>
          {DEVICE_ICONS[dtype] || '❓'}
          {isSpoofed && (
            <div style={{ position: 'absolute', top: -2, right: -2, background: 'var(--sev-critical)', borderRadius: '50%', width: 10, height: 10, border: '2px solid var(--bg-surface)' }} title="Intercepting Traffic" />
          )}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="device-name truncate">{identity.user || identity.hostname || identity.ip}</div>
          <div className="device-ip">{identity.ip}</div>
        </div>
        <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textAlign: 'right' }}>
          <div>{identity.manufacturer?.split(' ')[0] || '?'}</div>
          <div style={{ marginTop: 2, padding: '1px 6px', borderRadius: 4, background: 'var(--bg-elevated)', textTransform: 'capitalize' }}>{dtype}</div>
        </div>
      </div>

      <div className="device-apps" style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 6, flex: 1, alignContent: 'flex-start' }}>
        {apps.length > 0 ? apps.map(a => {
          const color = CAT_COLORS[a.app_category] || '#6b7280'
          return (
            <div key={a.app_name} title={`Category: ${a.app_category} | Risk: ${a.app_risk_score}`} style={{ background: 'var(--bg-elevated)', border: `1px solid ${color}`, borderRadius: 12, padding: '3px 8px', fontSize: '0.68rem', display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: color, boxShadow: `0 0 4px ${color}` }} />
              <span style={{ color: 'var(--text-primary)' }}>{a.app_name}</span>
            </div>
          )
        }) : (
          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 12, padding: '3px 8px', fontSize: '0.68rem', display: 'flex', alignItems: 'center', gap: 6 }}>
             <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#6b7280' }} />
             <span style={{ color: 'var(--text-muted)' }}>{app.app_name || 'Unknown'}</span>
          </div>
        )}
      </div>

      <div style={{ marginTop: 'auto', paddingTop: 16 }}>
        <div className="risk-bar">
          <div className="risk-fill" style={{ width: `${risk * 10}%`, background: riskColor }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Highest Risk</span>
          <span style={{ fontSize: '0.68rem', fontWeight: 600, color: riskColor, fontFamily: 'var(--font-mono)' }}>{risk}/10</span>
        </div>
      </div>
    </div>
  )
}

function DeviceModal({ device, spoofedIps = [], setSpoofedIps, onClose }) {
  const identity = device.identity || {}
  const apps = device.apps || []
  const dtype = identity.device_type || 'unknown'
  const name = identity.user || identity.hostname || identity.ip
  const ip = identity.ip || device.src_ip
  const isSpoofed = spoofedIps.includes(ip)

  const toggleSpoof = async () => {
    const action = isSpoofed ? 'stop' : 'start'
    try {
      const res = await fetch('http://localhost:8766/api/spoof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, action })
      })
      const data = await res.json()
      if (data.spoofed) {
        if (setSpoofedIps) setSpoofedIps(data.spoofed)
      }
    } catch (e) {
      console.error('Failed to toggle spoofing', e)
    }
  }

  const sortedApps = [...apps].sort((a, b) => {
    // Sort by most recently seen
    if (a.lastSeen && b.lastSeen) return new Date(b.lastSeen) - new Date(a.lastSeen)
    return (b.app_risk_score || 0) - (a.app_risk_score || 0)
  })

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
             <div className={`device-avatar ${dtype}`} style={{ width: 48, height: 48, fontSize: 24 }}>
              {DEVICE_ICONS[dtype] || '❓'}
            </div>
            <div>
              <h2 style={{ fontSize: '1.2rem', margin: 0, fontWeight: 700 }}>{name}</h2>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>{ip} • {identity.mac || 'Unknown MAC'}</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <button 
              onClick={toggleSpoof}
              style={{
                background: isSpoofed ? 'transparent' : 'var(--sev-critical)',
                border: `1px solid var(--sev-critical)`,
                color: isSpoofed ? 'var(--sev-critical)' : '#fff',
                padding: '6px 12px', borderRadius: 6, fontSize: '0.75rem', cursor: 'pointer', fontWeight: 600,
                display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.2s'
              }}
            >
              {isSpoofed ? '🛑 Stop Intercepting' : '🎯 Intercept Traffic'}
            </button>
            <button className="modal-close" onClick={onClose}>✕</button>
          </div>
        </div>
        
        <div className="modal-body">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ background: 'var(--bg-elevated)', padding: 16, borderRadius: 12, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700, marginBottom: 8, letterSpacing: '0.05em' }}>Device Identity</div>
              <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr', gap: '8px 4px', fontSize: '0.8rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Type:</span>
                <span style={{ textTransform: 'capitalize', color: 'var(--text-primary)' }}>{dtype}</span>
                <span style={{ color: 'var(--text-muted)' }}>Vendor:</span>
                <span style={{ color: 'var(--text-primary)' }}>{identity.manufacturer || 'Unknown'}</span>
                <span style={{ color: 'var(--text-muted)' }}>Hostname:</span>
                <span style={{ color: 'var(--text-primary)' }}>{identity.hostname || '-'}</span>
              </div>
            </div>

            <div style={{ background: 'var(--bg-elevated)', padding: 16, borderRadius: 12, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700, marginBottom: 8, letterSpacing: '0.05em' }}>Usage Summary</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Total Apps Detected</span>
                  <span style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{apps.length}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                   <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Highest Risk Score</span>
                   <span style={{ fontSize: '1rem', fontWeight: 700, color: apps.length && Math.max(...apps.map(a => a.app_risk_score||0)) >= 8 ? 'var(--sev-critical)' : apps.length && Math.max(...apps.map(a => a.app_risk_score||0)) >= 6 ? 'var(--sev-high)' : 'var(--sev-low)', fontFamily: 'var(--font-mono)' }}>
                     {apps.length ? Math.max(...apps.map(a => a.app_risk_score||0)) : (device.app?.app_risk_score || 0)}/10
                   </span>
                </div>
              </div>
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: 12, borderBottom: '1px solid var(--border)', paddingBottom: 8 }}>Active Applications & Websites</div>
            {sortedApps.length > 0 ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
                {sortedApps.map((a, i) => {
                  const color = CAT_COLORS[a.app_category] || '#6b7280'
                  return (
                    <div key={i} style={{ background: 'var(--bg-elevated)', border: `1px solid ${color}40`, borderRadius: 12, padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
                        <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>{a.app_name}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'capitalize' }}>{a.app_category?.replace('_', ' ')}</span>
                        <span style={{ fontSize: '0.7rem', color: a.app_risk_score >= 8 ? 'var(--sev-critical)' : a.app_risk_score >= 6 ? 'var(--sev-high)' : 'var(--text-muted)' }}>Risk: {a.app_risk_score}/10</span>
                      </div>
                      {a.lastSeen && (
                         <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textAlign: 'right' }}>
                           Seen: {new Date(a.lastSeen).toLocaleTimeString()}
                         </div>
                      )}
                    </div>
                  )
                })}
              </div>
            ) : (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem', background: 'var(--bg-elevated)', borderRadius: 12, border: '1px solid var(--border)' }}>
                 No specific applications detected yet.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
