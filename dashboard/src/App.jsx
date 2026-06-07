import { useState, useCallback, useMemo } from 'react'
import { useWebSocket } from './hooks/useWebSocket'
import Sidebar from './components/Sidebar'
import AlertFeed from './components/AlertFeed'
import DeviceGrid from './components/DeviceGrid'
import UserFlowMap from './components/UserFlowMap'
import UserTimeline from './components/UserTimeline'
import { ErrorBoundary } from './components/ErrorBoundary'

const MAX_ALERTS = 500
const MAX_FLOWS   = 2000

export default function App() {
  const [activeTab, setActiveTab]   = useState('alerts')
  const [alerts, setAlerts]         = useState([])
  const [flows, setFlows]           = useState([])
  const [devices, setDevices]       = useState({}) // ip → last flow
  const [flowCount, setFlowCount]   = useState(0)
  const [spoofedIps, setSpoofedIps] = useState([])

  const handleMessage = useCallback((msg) => {
    const { channel, data } = msg

    if (channel === 'init') {
      // Initial state dump
      if (data.recent_alerts) {
        setAlerts(data.recent_alerts.slice(0, MAX_ALERTS))
      }
      if (data.devices) {
        const devMap = {}
        data.devices.forEach(d => { 
          if (d.src_ip) {
            d.apps = d.app && d.app.app_name ? [{ ...d.app }] : []
            devMap[d.src_ip] = d 
          }
        })
        setDevices(devMap)
      }
      if (data.spoofed_ips) {
        setSpoofedIps(data.spoofed_ips)
      }
    } else if (channel === 'spoof_state') {
      setSpoofedIps(data)
    } else if (channel === 'alerts') {
      setAlerts(prev => [data, ...prev].slice(0, MAX_ALERTS))
    } else if (channel === 'flows:live') {
      const flow = data
      setFlowCount(c => c + 1)
      if (flow.src_ip) {
        setDevices(prev => {
          const prevDev = prev[flow.src_ip] || {}
          const existingApps = prevDev.apps || []
          
          let newApps = [...existingApps]
          if (flow.app && flow.app.app_name) {
            // Don't accumulate "Unknown" if we already have other valid apps
            if (flow.app.app_name === 'Unknown' && newApps.some(a => a.app_name !== 'Unknown')) {
              // do nothing
            } else {
              const idx = newApps.findIndex(a => a.app_name === flow.app.app_name)
              if (idx >= 0) {
                newApps[idx] = { ...flow.app, lastSeen: flow.ts }
              } else {
                newApps.push({ ...flow.app, lastSeen: flow.ts })
              }
            }
          }
          
          // Remove Unknown if we now have valid apps
          if (newApps.length > 1 && newApps.some(a => a.app_name === 'Unknown')) {
             newApps = newApps.filter(a => a.app_name !== 'Unknown')
          }
          
          return { ...prev, [flow.src_ip]: { ...flow, apps: newApps } }
        })
      }
      setFlows(prev => [flow, ...prev].slice(0, MAX_FLOWS))
    }
  }, [])

  const { status, send } = useWebSocket(handleMessage)

  const deviceList = useMemo(() => Object.values(devices), [devices])

  // Top apps across all devices
  const topApps = useMemo(() => {
    const counts = {}
    deviceList.forEach(d => {
      const app = d.app?.app_name || 'Unknown'
      counts[app] = (counts[app] || 0) + 1
    })
    return Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0, 8)
  }, [deviceList])

  // Categories
  const catCounts = useMemo(() => {
    const counts = {}
    deviceList.forEach(d => {
      const cat = d.app?.app_category || 'unknown'
      counts[cat] = (counts[cat] || 0) + 1
    })
    return Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0,6)
  }, [deviceList])

  // Sample for flow map (avoid D3 crash with too many nodes)
  const flowSample = useMemo(() => deviceList.slice(0, 40), [deviceList])

  return (
    <div className="app-layout">
      {/* Header */}
      <header className="app-header">
        <div className="logo">
          <div className="logo-icon">🌐</div>
          <div>
            <span className="logo-text">WhoApp</span>
            <span className="logo-sub"> Network Intelligence</span>
          </div>
        </div>

        <div className="header-stats">
          <div className="stat-chip">
            <span className="dot" />
            <span className="label">Flows:</span>
            <span className="value">{flowCount.toLocaleString()}</span>
          </div>
          <div className="stat-chip">
            <span className="dot" />
            <span className="label">Devices:</span>
            <span className="value">{deviceList.length}</span>
          </div>
          <div className="stat-chip">
            <span className={`dot ${alerts.filter(a => a.severity === 'Critical').length > 0 ? 'red' : ''}`} />
            <span className="label">Alerts:</span>
            <span className="value">{alerts.length}</span>
          </div>
        </div>

        <div className="header-spacer" />
        <span className={`ws-badge ${status}`}>
          {status === 'connected' ? '● Connected' : status === 'offline' ? '○ Wi-Fi Offline' : '○ Reconnecting...'}
        </span>
      </header>

      {/* Sidebar */}
      <aside className="app-sidebar" style={{ position: 'relative' }}>
        <Sidebar
          activeTab={activeTab}
          onTabChange={setActiveTab}
          alertCount={alerts.length}
          deviceCount={deviceList.length}
        />
      </aside>

      {/* Main content */}
      <main className="app-content">
        <div className="tab-content">
          {activeTab === 'overview' && (
            <div style={{ padding: '24px', overflowY: 'auto', height: '100%' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16, marginBottom: 24 }}>
                {[
                  { label: 'Total Flows', value: flowCount.toLocaleString(), color: '#3b82f6', icon: '⚡' },
                  { label: 'Active Devices', value: deviceList.length, color: '#22c55e', icon: '📡' },
                  { label: 'Alerts Fired', value: alerts.length, color: alerts.length > 0 ? '#ef4444' : '#6b7280', icon: '🚨' },
                  { label: 'Critical', value: alerts.filter(a => a.severity === 'Critical').length, color: '#ef4444', icon: '🔴' },
                ].map(stat => (
                  <div key={stat.label} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 12, padding: '20px 16px', textAlign: 'center' }}>
                    <div style={{ fontSize: '1.6rem', marginBottom: 6 }}>{stat.icon}</div>
                    <div style={{ fontSize: '1.8rem', fontWeight: 800, color: stat.color, fontFamily: 'var(--font-mono)' }}>{stat.value}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{stat.label}</div>
                  </div>
                ))}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 12, padding: 16 }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Top Applications</div>
                  {topApps.map(([app, count]) => (
                    <div key={app} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--border)' }}>
                      <span style={{ fontSize: '0.78rem', color: 'var(--text-primary)' }}>{app}</span>
                      <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#3b82f6' }}>{count}</span>
                    </div>
                  ))}
                </div>
                <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 12, padding: 16 }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Traffic Categories</div>
                  {catCounts.map(([cat, count]) => (
                    <div key={cat} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--border)' }}>
                      <span style={{ fontSize: '0.78rem', color: 'var(--text-primary)', textTransform: 'capitalize' }}>{cat.replace('_', ' ')}</span>
                      <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#22c55e' }}>{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
          {activeTab === 'alerts' && <AlertFeed alerts={alerts} />}
          {activeTab === 'devices' && <DeviceGrid devices={deviceList} flows={flows} spoofedIps={spoofedIps} setSpoofedIps={setSpoofedIps} />}
          {activeTab === 'flowmap' && (
            <div style={{ height: 'calc(100vh - 56px)', margin: '-24px', overflow: 'hidden' }}>
              <ErrorBoundary>
                <UserFlowMap devices={flowSample} isIntercepting={spoofedIps.length > 0} />
              </ErrorBoundary>
            </div>
          )}
          {activeTab === 'timeline' && (
            <div style={{ height: 'calc(100vh - 140px)' }}>
              <UserTimeline flows={flows} />
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
