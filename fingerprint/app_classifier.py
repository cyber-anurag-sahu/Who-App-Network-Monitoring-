"""
WhoApp — App Classifier
Classifies network flows into (app_name, app_category, risk_score) using
a four-level priority chain:
  1. JA3 hash exact match
  2. TLS SNI regex match
  3. DNS query heuristic
  4. Port-based heuristic
  5. Fallback: unknown / risk=7
"""
import os
import re
import json
import logging
from pathlib import Path
from typing import Tuple

log = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "ja3_database.json"

# SNI pattern → (app_name, category, risk)
SNI_PATTERNS = [
    (r".*\.tiktok\.com$",           ("TikTok",           "social_media",   7)),
    (r".*\.tiktokcdn\.com$",        ("TikTok",           "social_media",   7)),
    (r".*\.signal\.org$",           ("Signal",           "messaging",      3)),
    (r".*\.whatsapp\.net$",         ("WhatsApp",         "messaging",      3)),
    (r".*\.whatsapp\.com$",         ("WhatsApp",         "messaging",      3)),
    (r".*\.telegram\.org$",         ("Telegram",         "messaging",      3)),
    (r".*slack\.com$",              ("Slack",            "messaging",      2)),
    (r".*\.slack-msgs\.com$",       ("Slack",            "messaging",      2)),
    (r".*discord\.com$",            ("Discord",          "messaging",      2)),
    (r".*discord\.gg$",             ("Discord",          "messaging",      2)),
    (r".*zoom\.us$",                ("Zoom",             "video_conf",     2)),
    (r".*zoom\.com$",               ("Zoom",             "video_conf",     2)),
    (r".*teams\.microsoft\.com$",   ("Microsoft Teams",  "video_conf",     2)),
    (r".*meet\.google\.com$",       ("Google Meet",      "video_conf",     2)),
    (r".*netflix\.com$",            ("Netflix",          "streaming",      2)),
    (r".*nflxvideo\.net$",          ("Netflix",          "streaming",      2)),
    (r".*spotify\.com$",            ("Spotify",          "streaming",      2)),
    (r".*spotifycdn\.com$",         ("Spotify",          "streaming",      2)),
    (r".*youtube\.com$",            ("YouTube",          "streaming",      1)),
    (r".*googlevideo\.com$",        ("YouTube",          "streaming",      1)),
    (r".*instagram\.com$",          ("Instagram",        "social_media",   3)),
    (r".*cdninstagram\.com$",       ("Instagram",        "social_media",   3)),
    (r".*twitter\.com$",            ("Twitter/X",        "social_media",   3)),
    (r".*twimg\.com$",              ("Twitter/X",        "social_media",   3)),
    (r".*dropbox\.com$",            ("Dropbox",          "cloud_storage",  4)),
    (r".*dropboxstatic\.com$",      ("Dropbox",          "cloud_storage",  4)),
    (r".*drive\.google\.com$",      ("Google Drive",     "cloud_storage",  3)),
    (r".*onedrive\.live\.com$",     ("OneDrive",         "cloud_storage",  3)),
    (r".*sharepoint\.com$",         ("OneDrive",         "cloud_storage",  3)),
    (r".*mullvad\.net$",            ("Mullvad VPN",      "vpn",            6)),
    (r".*nordvpn\.com$",            ("NordVPN",          "vpn",            6)),
    (r".*expressvpn\.com$",         ("ExpressVPN",       "vpn",            6)),
    (r".*protonvpn\.com$",          ("ProtonVPN",        "vpn",            6)),
    (r".*\.onion\..*$",             ("Tor Hidden Svc",   "dark_web",      10)),
    (r"^torproject\.org$",          ("Tor Browser",      "dark_web",      10)),
    (r".*coinhive\.com$",           ("CoinHive Miner",   "crypto_mining", 10)),
    (r".*xmr\.pool\.minergate.*",   ("XMRig Miner",      "crypto_mining", 10)),
    (r".*ethermine\.org$",          ("EtherMine Pool",   "crypto_mining", 10)),
    (r".*teamviewer\.com$",         ("TeamViewer",       "remote_access",  6)),
    (r".*anydesk\.com$",            ("AnyDesk",          "remote_access",  6)),
    (r".*github\.com$",             ("GitHub",           "dev_tool",       2)),
    (r".*amazonaws\.com$",          ("AWS",              "cloud_infra",    2)),
    (r".*azurewebsites\.net$",      ("Azure",            "cloud_infra",    2)),
    (r".*cloudflare\.com$",         ("Cloudflare",       "cdn",            1)),
]

# DNS query suffix → (category, risk_delta)
DNS_PATTERNS = [
    (r".*\.torproject\.org$",       ("dark_web",        10)),
    (r".*\.(i2p)$",                 ("dark_web",        10)),
    (r".*pool\.(.*mining.*)$",      ("crypto_mining",   10)),
    (r".*\.(bit|zbit)$",            ("crypto_mining",    8)),
    (r".*torrent.*",                ("torrent",          8)),
    (r".*tracker\.*",               ("torrent",          7)),
    (r".*vpn.*",                    ("vpn",              5)),
    (r".*proxy.*",                  ("proxy",            6)),
]

# Port-based heuristics: port → (app_name, category, risk)
PORT_RULES = {
    9001:  ("Tor OR port",      "dark_web",       10),
    9030:  ("Tor Dir Auth",     "dark_web",       10),
    9050:  ("Tor SOCKS",        "dark_web",       10),
    9150:  ("Tor Browser SOCKS","dark_web",       10),
    6881:  ("BitTorrent DHT",   "torrent",         8),
    6882:  ("BitTorrent",       "torrent",         8),
    6883:  ("BitTorrent",       "torrent",         8),
    6889:  ("BitTorrent",       "torrent",         8),
    4444:  ("Metasploit",       "exploit_tool",   10),
    4445:  ("Exploit Tool",     "exploit_tool",    9),
    3389:  ("RDP",              "remote_access",   5),
    5900:  ("VNC",              "remote_access",   5),
    22:    ("SSH",              "remote_access",   4),
    3306:  ("MySQL",            "database",        6),
    5432:  ("PostgreSQL",       "database",        6),
    1194:  ("OpenVPN",          "vpn",             5),
    1723:  ("PPTP VPN",         "vpn",             5),
    4500:  ("IPSec VPN",        "vpn",             5),
    14433: ("Tor obfs4",        "dark_web",       10),
    14444: ("Tor obfs4",        "dark_web",       10),
}


class AppClassifier:
    def __init__(self, db_path: Path = DB_PATH):
        self._ja3_map = {}
        self._sni_compiled = []
        self._dns_compiled = []
        self._load_ja3_db(db_path)
        self._compile_patterns()

    def _load_ja3_db(self, path: Path):
        try:
            with open(path) as f:
                entries = json.load(f)
            for e in entries:
                self._ja3_map[e["ja3"]] = {
                    "app_name": e["app"],
                    "app_category": e["category"],
                    "app_risk_score": e["risk"],
                }
            log.info("Loaded %d JA3 fingerprints", len(self._ja3_map))
        except Exception as ex:
            log.error("Failed to load JA3 DB: %s", ex)

    def _compile_patterns(self):
        for pattern, result in SNI_PATTERNS:
            self._sni_compiled.append((re.compile(pattern, re.I), result))
        for pattern, result in DNS_PATTERNS:
            self._dns_compiled.append((re.compile(pattern, re.I), result))

    def classify(self, flow: dict) -> dict:
        """
        Return app classification dict to merge into the flow.
        Keys: app_name, app_category, app_risk_score
        """
        ja3 = flow.get("ja3")
        sni = flow.get("tls_sni", "")
        dns_queries = flow.get("dns_queries", [])
        dst_port = int(flow.get("dst_port") or 0)
        src_port = int(flow.get("src_port") or 0)

        # 1. JA3 exact match
        if ja3 and ja3 in self._ja3_map:
            return dict(self._ja3_map[ja3])

        # 2. TLS SNI
        if sni:
            for regex, result in self._sni_compiled:
                if regex.match(sni):
                    return {"app_name": result[0], "app_category": result[1], "app_risk_score": result[2]}

        # 3. DNS heuristic
        for query in dns_queries:
            for regex, (category, risk) in self._dns_compiled:
                if regex.match(query):
                    return {"app_name": query.split(".")[0], "app_category": category, "app_risk_score": risk}

        # 4. Port-based
        for port in (dst_port, src_port):
            if port in PORT_RULES:
                app, cat, risk = PORT_RULES[port]
                return {"app_name": app, "app_category": cat, "app_risk_score": risk}

        # 5. Fallback
        return {"app_name": "unknown", "app_category": "unknown", "app_risk_score": 7}
