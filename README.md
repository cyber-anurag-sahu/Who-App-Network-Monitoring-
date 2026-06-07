# 🌐 WhoApp — Network Behavioral Fingerprinting

> **Passively monitor every device, user, and application on your network in real time.**  
> Powered by Antigravity's tag-based detection engine.

---

## Architecture

```
[ Network Interface ]
        │  (passive mirror / Scapy sniff)
        ▼
[ Packet Capture ]  ──→  Redis stream: packets:raw
        │
        ▼
[ Flow Extractor ]  ──→  5-tuple + TLS SNI + JA3 + DNS
        │
        ▼
[ Identity Resolver ] ──→  DHCP ACK + mDNS/LLMNR + MAC OUI
        │                   Redis hash: identity:ip:<ip>
        ▼
[ App Classifier ]  ──→  JA3 DB (55 entries) + SNI + DNS + port
        │                   app_name / app_category / risk_score
        ▼
[ Antigravity Engine ] ──→  19 YAML detection rules
        │                    Severity: Info / Low / Medium / High / Critical
        ▼
[ Alert Bus (Redis pub/sub) ]
        │
   ┌────┴──────────────┐
   ▼                   ▼
[InfluxDB 2.7]    [React Dashboard]  [Grafana]
(time-series)     (port 3000)        (port 3001)
```

---

## Quick Start — Demo Mode (No Network Tap Required)

```bash
# 1. Clone / navigate to the project
cd whoapp

# 2. Copy environment file
cp .env.example .env

# 3. Start core services + demo simulator
docker compose --profile demo up -d

# 4. Open dashboard
start http://localhost:3000   # React dashboard
start http://localhost:3001   # Grafana (admin / whoapp1234)
```

The **simulator** (`simulate_traffic.py`) generates realistic synthetic flows for 7 device profiles using 21 app scenarios (weighted random). All detection rules fire automatically — no real network access needed.

---

## Live Capture Mode (Linux / WSL2)

> Requires **root** or `CAP_NET_RAW` + `CAP_NET_ADMIN`. On Windows, run inside WSL2 with a bridged NIC.

```bash
# Set your NIC in .env
CAPTURE_INTERFACE=eth0

# Start everything including live capture
docker compose --profile live up -d
```

---

## Services

| Service | Port | Description |
|---|---|---|
| `redis` | 6379 | Message bus + identity store |
| `influxdb` | 8086 | Time-series metrics storage |
| `capture` | — | Passive packet capture (live mode only) |
| `identity` | — | DHCP + mDNS identity resolver |
| `fingerprint` | — | JA3 + SNI + DNS app classifier |
| `engine` | — | Antigravity rule evaluation + InfluxDB writer |
| `pipeline` | — | Packet → flow → enrich orchestrator |
| `ws-bridge` | 8765 | WebSocket relay to dashboard |
| `dashboard` | 3000 | React frontend |
| `grafana` | 3001 | Grafana dashboards |
| `simulator` | — | Synthetic traffic generator (demo mode) |

---

## Detection Rules (19 total)

| Rule | Severity | Tags |
|---|---|---|
| Unauthorized Messaging on Work Hours | High | policy_violation |
| Dark Web Access Detected | Critical | dark_web_access |
| After-Hours Anomalous Behavior | Medium | insider_threat |
| Unknown Application Fingerprint | Medium | fingerprint_gap |
| Cryptocurrency Mining Detected | Critical | crypto_mining |
| P2P / Torrent Activity | High | bandwidth_abuse |
| VPN Usage Detected | Medium | possible_bypass |
| Unauthorized Remote Desktop | High | lateral_movement |
| Exploit Tool Detected | Critical | active_attack |
| Tor Bridge Connection | Critical | evasion |
| Large Cloud Upload | High | data_exfiltration |
| IoT Device Unexpected Outbound | Medium | iot_anomaly |
| Social Media on Server | Medium | compromise |
| High-Risk App on Laptop | High | policy_violation |
| Scanner Detected | Critical | reconnaissance |
| TikTok on Corporate Device | High | data_privacy |
| Encrypted Messaging Spike | Medium | exfil_risk |
| Weekend High-Risk Application | Medium | weekend_usage |
| After-Hours High-Risk App | Medium | after_hours |

---

## JA3 Fingerprint Database

55 known app fingerprints covering:
- **Browsers**: Chrome, Firefox, Safari, Edge, Brave
- **Messaging**: Slack, Signal, WhatsApp, Telegram, Discord
- **Dark Web**: Tor (3 variants), I2P, Freenet
- **VPN**: Mullvad, NordVPN, ExpressVPN, OpenVPN, WireGuard
- **Video**: Zoom, Teams, Meet, Webex
- **Streaming**: Netflix, Spotify, YouTube, Prime
- **P2P**: BitTorrent, qBittorrent, uTorrent
- **Cloud**: Dropbox, Google Drive, OneDrive, Box
- **Social**: TikTok, Instagram, Twitter/X, LinkedIn
- **Remote**: RDP, VNC, AnyDesk, TeamViewer
- **Exploit**: Metasploit, Nikto, Nmap
- **Mining**: XMRig, EtherMine, CoinHive

---

## Dashboard Panels

### React Dashboard (`http://localhost:3000`)
- **🚨 Alerts** — Live alert stream with severity/tag filters
- **📡 Devices** — Card grid per device with risk bar
- **🌐 Flow Map** — D3 Sankey: User → App → Destination
- **⏱ Timeline** — Per-user 60-minute activity timeline

### Grafana (`http://localhost:3001`)
- Alerts over time (bar chart)
- Top users by risk (table)
- App category distribution (donut)
- Bytes per user per hour (heatmap)
- Policy violations timeline (time-series)
- 4 KPI stat cards

---

## Project Structure

```
whoapp/
├── docker-compose.yml          # All services
├── .env.example                # Config template
├── simulate_traffic.py         # Demo traffic generator
├── Dockerfile.simulator
│
├── capture/                    # Packet capture (Scapy)
│   ├── packet_capture.py
│   ├── flow_extractor.py
│   └── ja3_hasher.py
│
├── identity/                   # Identity resolution
│   ├── dhcp_snooper.py
│   ├── mdns_sniffer.py
│   ├── oui_lookup.py           # 150+ vendor OUI entries
│   └── identity_store.py
│
├── fingerprint/                # App classification
│   ├── app_classifier.py       # 4-level priority chain
│   └── ja3_database.json       # 55 JA3 fingerprints
│
├── engine/                     # Rule engine
│   ├── rule_engine.py          # YAML DSL evaluator
│   ├── alert_emitter.py        # Redis + InfluxDB writer
│   └── rules/
│       └── whoapp_rules.yaml   # 19 detection rules
│
├── pipeline/                   # Orchestrator
│   ├── pipeline.py
│   └── ws_bridge.py            # WebSocket relay
│
├── dashboard/                  # React + Vite frontend
│   └── src/
│       ├── App.jsx
│       ├── components/
│       │   ├── AlertFeed.jsx
│       │   ├── DeviceGrid.jsx
│       │   ├── UserFlowMap.jsx  # D3 Sankey
│       │   ├── UserTimeline.jsx
│       │   └── Sidebar.jsx
│       └── hooks/useWebSocket.js
│
└── grafana/
    └── provisioning/
        ├── datasources/influxdb.yaml
        └── dashboards/whoapp.json    # 9 pre-built panels
```

---

## Adding Custom Rules

Edit `engine/rules/whoapp_rules.yaml`:

```yaml
- name: "My Custom Rule"
  severity: High
  tags: [my_tag]
  conditions:
    all:
      - field: app.name
        op: "=="
        value: MyApp
      - field: identity.device_type
        op: "=="
        value: laptop
```

Supported operators: `==` `!=` `IN` `NOT IN` `>=` `<=` `BETWEEN`  
Supported fields: `app.name` `app.category` `app.risk_score` `identity.user` `identity.device_type` `identity.manufacturer` `network.direction` `time.hour_of_day` `time.is_weekend` `flow.byte_count` `flow.dst_port`

Restart the engine to reload rules:
```bash
docker compose restart engine
```

---

## Useful Commands

```bash
# View live alerts in terminal
docker exec -it whoapp-redis redis-cli SUBSCRIBE alerts

# List all discovered devices
docker exec -it whoapp-redis redis-cli SMEMBERS identity:all_ips

# Inspect a device identity
docker exec -it whoapp-redis redis-cli GET "identity:ip:192.168.1.101"

# View recent alerts stream
docker exec -it whoapp-redis redis-cli XREVRANGE alerts:stream + - COUNT 10

# View InfluxDB data
docker exec -it whoapp-influxdb influx query \
  'from(bucket:"network_flows") |> range(start:-1h) |> filter(fn:(r) => r._measurement == "alert") |> limit(n:10)'

# Run simulator manually (outside Docker)
pip install redis
python simulate_traffic.py
```

---

## Credentials

| Service | URL | Username | Password |
|---|---|---|---|
| Grafana | http://localhost:3001 | admin | whoapp1234 |
| InfluxDB | http://localhost:8086 | admin | whoapp1234 |

---

*WhoApp — Built with Antigravity detection engine*
