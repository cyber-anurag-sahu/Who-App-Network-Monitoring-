"""
WhoApp — DHCP Snooper
Passively listens for DHCP ACK packets on the network and extracts
IP ↔ MAC ↔ hostname mappings, writing them to the identity store.

DHCP ACK (server→client): option 53 = 5
Interesting fields:
  - chaddr  : client hardware (MAC) address
  - yiaddr  : IP offered to client
  - option 12: hostname
  - option 60: vendor class
"""
import os
import logging
import threading
from datetime import datetime, timezone

import redis
from scapy.all import sniff, conf
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP

from identity_store import IdentityStore

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [DHCP] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")

store = IdentityStore(REDIS_URL)


def _extract_dhcp_option(options: list, name: str):
    """Extract named option value from DHCP options list."""
    for opt in options:
        if isinstance(opt, tuple) and opt[0] == name:
            return opt[1]
    return None


def process_dhcp(pkt):
    """Process a captured DHCP packet."""
    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return

    dhcp_opts = pkt[DHCP].options
    msg_type = _extract_dhcp_option(dhcp_opts, "message-type")

    # message-type 5 = ACK (server grants IP)
    if msg_type not in (2, 5):  # 2=OFFER, 5=ACK
        return

    bootp = pkt[BOOTP]
    client_ip = str(bootp.yiaddr)
    client_mac = bootp.chaddr.hex()
    # Format MAC: aabbccddeeff → aa:bb:cc:dd:ee:ff
    client_mac = ":".join(client_mac[i:i+2] for i in range(0, 12, 2))

    if client_ip in ("0.0.0.0", "") or client_mac == "00:00:00:00:00:00":
        return

    hostname = _extract_dhcp_option(dhcp_opts, "hostname")
    if isinstance(hostname, bytes):
        hostname = hostname.decode("utf-8", errors="replace")
    vendor_class = _extract_dhcp_option(dhcp_opts, "vendor_class_id")
    if isinstance(vendor_class, bytes):
        vendor_class = vendor_class.decode("utf-8", errors="replace")

    log.info(
        "DHCP %s — IP: %s  MAC: %s  Hostname: %s",
        "ACK" if msg_type == 5 else "OFFER",
        client_ip,
        client_mac,
        hostname or "unknown",
    )

    identity = {
        "ip": client_ip,
        "mac": client_mac,
        "hostname": hostname or "",
        "vendor_class": vendor_class or "",
        "source": "dhcp",
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    store.update(client_ip, client_mac, identity)


def main():
    log.info("Starting DHCP snooper on interface: %s", CAPTURE_INTERFACE)
    # BPF filter: DHCP traffic only (UDP port 67 or 68)
    sniff(
        iface=CAPTURE_INTERFACE,
        filter="udp and (port 67 or port 68)",
        prn=process_dhcp,
        store=False,
    )


if __name__ == "__main__":
    main()
