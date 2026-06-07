"""
WhoApp — mDNS / LLMNR / NetBIOS Passive Resolver
Listens on multicast groups for name resolution traffic and populates
the identity store with hostname ↔ IP mappings.

Protocols:
  - mDNS  : 224.0.0.251:5353 — Apple, Google, Linux Avahi
  - LLMNR : 224.0.0.252:5355 — Windows
  - NetBIOS Name Service: 137/UDP — legacy Windows
"""
import os
import socket
import struct
import threading
import logging
from datetime import datetime, timezone

from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from identity_store import IdentityStore

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [mDNS] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")

store = IdentityStore(REDIS_URL)

MDNS_PORT = 5353
LLMNR_PORT = 5355
NETBIOS_PORT = 137


def _safe_decode(b) -> str:
    if isinstance(b, bytes):
        return b.decode("utf-8", errors="replace").rstrip(".")
    return str(b).rstrip(".")


def process_dns_response(pkt):
    """Extract A/PTR records from mDNS/LLMNR response packets."""
    if not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]
    src_ip = pkt[IP].src if pkt.haslayer(IP) else None

    # Only process responses (QR=1)
    if dns.qr != 1:
        return

    answers = dns.an
    while answers:
        name = _safe_decode(answers.rrname)
        rtype = answers.type

        if rtype == 1:  # A record: name → IP
            resolved_ip = answers.rdata
            hostname = name
            log.info("mDNS A: %s → %s (from %s)", hostname, resolved_ip, src_ip)
            store.update(resolved_ip, None, {
                "ip": resolved_ip,
                "hostname": hostname,
                "source": "mdns",
                "last_seen": datetime.now(timezone.utc).isoformat(),
            })

        elif rtype == 12:  # PTR record: IP → name
            hostname = _safe_decode(answers.rdata)
            if src_ip:
                log.info("mDNS PTR: %s → %s", src_ip, hostname)
                store.update(src_ip, None, {
                    "ip": src_ip,
                    "hostname": hostname,
                    "source": "mdns_ptr",
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                })

        try:
            answers = answers.payload
        except Exception:
            break


def process_netbios(pkt):
    """Minimal NetBIOS Name Service parser for NBNS responses."""
    if not pkt.haslayer(UDP):
        return
    udp = pkt[UDP]
    if udp.dport != NETBIOS_PORT and udp.sport != NETBIOS_PORT:
        return
    src_ip = pkt[IP].src if pkt.haslayer(IP) else None
    # NetBIOS parsing is complex; use DNS layer if Scapy handles it
    process_dns_response(pkt)


def sniff_mdns():
    log.info("Sniffing mDNS (5353) + LLMNR (5355) + NetBIOS (137) on %s", CAPTURE_INTERFACE)
    bpf = (
        "(udp port 5353) or (udp port 5355) or (udp port 137)"
    )
    sniff(
        iface=CAPTURE_INTERFACE,
        filter=bpf,
        prn=process_dns_response,
        store=False,
    )


if __name__ == "__main__":
    sniff_mdns()
