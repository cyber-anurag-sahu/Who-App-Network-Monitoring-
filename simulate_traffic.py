"""
WhoApp — Traffic Simulator
Generates realistic synthetic network flow events and publishes them
directly to the flows:enriched Redis stream, bypassing the capture layer.
This lets you demo WhoApp without a real network tap or root privileges.

Usage:
  python simulate_traffic.py
  docker compose --profile demo up simulator
"""
import os
import json
import time
import random
import logging
from datetime import datetime, timezone

import redis

logging.basicConfig(
    level="INFO",
    format="%(asctime)s [SIM] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_URL  = os.getenv("REDIS_URL", "redis://localhost:6379")
SIM_SPEED  = float(os.getenv("SIM_SPEED", "5.0"))
r = redis.from_url(REDIS_URL, decode_responses=True)

# Simulated users with realistic device profiles
USERS = [
    {"user": "alice.chen",   "hostname": "alice-macbook",    "ip": "192.168.1.101", "mac": "3c:07:54:aa:bb:01", "device_type": "laptop",  "manufacturer": "Apple Inc."},
    {"user": "bob.kumar",    "hostname": "bob-laptop",       "ip": "192.168.1.102", "mac": "18:03:73:cc:dd:02", "device_type": "laptop",  "manufacturer": "Dell Inc."},
    {"user": "charlie.obi",  "hostname": "charlie-iphone",   "ip": "192.168.1.103", "mac": "f8:1e:df:ee:ff:03", "device_type": "phone",   "manufacturer": "Apple Inc."},
    {"user": "diana.ross",   "hostname": "diana-workstation","ip": "192.168.1.104", "mac": "54:ee:75:11:22:04", "device_type": "laptop",  "manufacturer": "Lenovo"},
    {"user": "eve.server",   "hostname": "prod-server-01",   "ip": "192.168.1.10",  "mac": "00:0c:29:33:44:05", "device_type": "server",  "manufacturer": "VMware Inc."},
    {"user": "frank.iot",    "hostname": "rpi-sensor-01",    "ip": "192.168.1.201", "mac": "b8:27:eb:55:66:06", "device_type": "iot",     "manufacturer": "Raspberry Pi Foundation"},
    {"user": "guest.phone",  "hostname": "samsung-phone",    "ip": "192.168.1.150", "mac": "2c:44:01:77:88:07", "device_type": "phone",   "manufacturer": "Samsung Electronics"},
]

# App traffic scenarios with weights
SCENARIOS = [
    # Normal traffic (high weight)
    {"app_name": "Chrome 100+",     "app_category": "browser",       "risk": 1, "dst": "8.8.8.8",      "port": 443, "bytes": 50_000,    "weight": 20},
    {"app_name": "Slack",           "app_category": "messaging",     "risk": 2, "dst": "52.1.2.3",     "port": 443, "bytes": 20_000,    "weight": 15},
    {"app_name": "Zoom",            "app_category": "video_conf",    "risk": 2, "dst": "170.114.0.1",  "port": 443, "bytes": 500_000,   "weight": 10},
    {"app_name": "Microsoft Teams", "app_category": "video_conf",    "risk": 2, "dst": "13.107.6.156", "port": 443, "bytes": 300_000,   "weight": 8},
    {"app_name": "Google Drive",    "app_category": "cloud_storage", "risk": 3, "dst": "142.250.0.1",  "port": 443, "bytes": 1_000_000, "weight": 7},
    {"app_name": "YouTube",         "app_category": "streaming",     "risk": 1, "dst": "216.58.0.1",   "port": 443, "bytes": 2_000_000, "weight": 5},
    {"app_name": "Outlook",         "app_category": "email",         "risk": 2, "dst": "40.101.0.1",   "port": 443, "bytes": 80_000,    "weight": 8},
    {"app_name": "GitHub",          "app_category": "dev_tool",      "risk": 2, "dst": "140.82.0.1",   "port": 443, "bytes": 200_000,   "weight": 6},
    # Policy-violating traffic (lower weight but impactful)
    {"app_name": "WhatsApp",        "app_category": "messaging",     "risk": 3, "dst": "157.240.0.1",  "port": 443, "bytes": 30_000,    "weight": 4},
    {"app_name": "Signal",          "app_category": "messaging",     "risk": 3, "dst": "142.250.1.1",  "port": 443, "bytes": 15_000,    "weight": 3},
    {"app_name": "Telegram",        "app_category": "messaging",     "risk": 3, "dst": "149.154.0.1",  "port": 443, "bytes": 25_000,    "weight": 3},
    {"app_name": "TikTok",          "app_category": "social_media",  "risk": 7, "dst": "161.117.0.1",  "port": 443, "bytes": 10_000_000,"weight": 2},
    {"app_name": "Dropbox",         "app_category": "cloud_storage", "risk": 4, "dst": "162.125.0.1",  "port": 443, "bytes": 50_000_000,"weight": 2},
    {"app_name": "qBittorrent",     "app_category": "torrent",       "risk": 8, "dst": "185.21.0.1",   "port": 6881,"bytes": 100_000_000,"weight": 1},
    {"app_name": "NordVPN",         "app_category": "vpn",           "risk": 6, "dst": "192.169.0.1",  "port": 443, "bytes": 5_000_000, "weight": 1},
    {"app_name": "TeamViewer",      "app_category": "remote_access", "risk": 6, "dst": "213.227.0.1",  "port": 443, "bytes": 200_000,   "weight": 1},
    {"app_name": "AnyDesk",         "app_category": "remote_access", "risk": 6, "dst": "195.133.0.1",  "port": 443, "bytes": 200_000,   "weight": 1},
    # High-severity traffic (rare)
    {"app_name": "Tor Browser",     "app_category": "dark_web",      "risk": 10,"dst": "199.58.0.1",   "port": 9001,"bytes": 500_000,   "weight": 1},
    {"app_name": "XMRig Miner",     "app_category": "crypto_mining", "risk": 10,"dst": "pool.xmr.io",  "port": 3333,"bytes": 10_000,    "weight": 1},
    {"app_name": "unknown",         "app_category": "unknown",       "risk": 7, "dst": "203.0.113.1",  "port": 4444,"bytes": 50_000,    "weight": 1},
]

WEIGHTS = [s["weight"] for s in SCENARIOS]


def make_flow(user_profile: dict, scenario: dict) -> dict:
    return {
        "flow_id": f"{user_profile['ip']}:{random.randint(10000,65535)}-{scenario['dst']}:{scenario['port']}",
        "src_ip": user_profile["ip"],
        "dst_ip": scenario["dst"],
        "src_port": random.randint(32768, 65535),
        "dst_port": scenario["port"],
        "src_mac": user_profile["mac"],
        "protocol": "TCP",
        "byte_count": int(scenario["bytes"] * random.uniform(0.5, 2.0)),
        "packet_count": random.randint(10, 5000),
        "tls_sni": scenario["dst"] if scenario["port"] == 443 else None,
        "ja3": None,
        "dns_queries": [scenario["dst"]],
        "duration": random.uniform(1.0, 120.0),
        "identity": {
            "ip": user_profile["ip"],
            "mac": user_profile["mac"],
            "hostname": user_profile["hostname"],
            "user": user_profile["user"],
            "device_type": user_profile["device_type"],
            "manufacturer": user_profile["manufacturer"],
        },
        "app": {
            "app_name": scenario["app_name"],
            "app_category": scenario["app_category"],
            "app_risk_score": scenario["risk"],
        },
        "network_direction": "outbound",
        "ts": datetime.now(timezone.utc).isoformat(),
        "simulated": True,
    }


def publish_identity_snapshots():
    """Pre-seed identity store for all simulated users."""
    for u in USERS:
        key = f"identity:ip:{u['ip']}"
        r.setex(key, 86400, json.dumps(u))
        r.sadd("identity:all_ips", u["ip"])
    log.info("Seeded %d identity records", len(USERS))


def main():
    log.info("Simulator starting (speed=%.1fx)", SIM_SPEED)
    publish_identity_snapshots()

    interval = 1.0 / SIM_SPEED
    flow_count = 0

    while True:
        user = random.choice(USERS)
        scenario = random.choices(SCENARIOS, weights=WEIGHTS, k=1)[0]
        flow = make_flow(user, scenario)

        # Push to both streams: raw enriched flow + live feed
        r.xadd("flows:enriched", {"data": json.dumps(flow)}, maxlen=100_000, approximate=True)
        r.publish("flows:live", json.dumps(flow))

        # Device snapshot
        r.setex(f"device:last_flow:{user['ip']}", 300, json.dumps(flow))

        flow_count += 1
        if flow_count % 50 == 0:
            log.info("Simulator: %d flows published", flow_count)

        time.sleep(interval)


if __name__ == "__main__":
    main()
