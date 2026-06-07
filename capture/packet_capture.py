"""
WhoApp — Packet Capture Layer
Passively sniffs raw packets on a configurable interface and publishes
raw packet metadata to Redis stream `packets:raw` for downstream processing.
"""
import os
import json
import time
import logging
import threading
from datetime import datetime, timezone

import redis
from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether

from flow_extractor import FlowExtractor
from ja3_hasher import JA3Hasher

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [CAPTURE] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
STREAM_KEY = "packets:raw"
STREAM_MAXLEN = 50_000  # rolling window

r = redis.from_url(REDIS_URL, decode_responses=True)
extractor = FlowExtractor()
ja3 = JA3Hasher()

PACKET_COUNT = 0
FLOW_COUNT = 0


def process_packet(pkt):
    """Extract metadata from a raw packet and publish to Redis."""
    global PACKET_COUNT, FLOW_COUNT
    PACKET_COUNT += 1

    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    ts = datetime.now(timezone.utc).isoformat()
    proto = ip.proto

    meta = {
        "ts": ts,
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "protocol": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto)),
        "ttl": ip.ttl,
        "length": len(pkt),
    }

    # Layer 4
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        meta["src_port"] = tcp.sport
        meta["dst_port"] = tcp.dport
        meta["tcp_flags"] = str(tcp.flags)

        # Attempt JA3 extraction from TLS ClientHello
        ja3_hash, sni = ja3.extract(pkt)
        if ja3_hash:
            meta["ja3"] = ja3_hash
        if sni:
            meta["tls_sni"] = sni

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        meta["src_port"] = udp.sport
        meta["dst_port"] = udp.dport

    # DNS queries
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        queries = []
        dns_layer = pkt[DNS]
        for i in range(dns_layer.qdcount):
            try:
                qname = dns_layer.qd.qname.decode("utf-8").rstrip(".")
                queries.append(qname)
            except Exception:
                pass
        if queries:
            meta["dns_queries"] = queries

    # MAC addresses
    if pkt.haslayer(Ether):
        meta["src_mac"] = pkt[Ether].src
        meta["dst_mac"] = pkt[Ether].dst

    # Publish to Redis stream
    try:
        r.xadd(STREAM_KEY, {"data": json.dumps(meta)}, maxlen=STREAM_MAXLEN, approximate=True)
        FLOW_COUNT += 1
    except Exception as e:
        log.error("Redis publish error: %s", e)


def stats_reporter():
    """Log capture statistics every 30 seconds."""
    while True:
        time.sleep(30)
        log.info("Stats — packets: %d  redis_events: %d", PACKET_COUNT, FLOW_COUNT)


def main():
    log.info("Starting packet capture on interface: %s", CAPTURE_INTERFACE)
    log.info("Publishing to Redis stream: %s", STREAM_KEY)

    # Start stats reporter thread
    t = threading.Thread(target=stats_reporter, daemon=True)
    t.start()

    # BPF filter: capture IP traffic only
    bpf_filter = "ip or ip6"

    try:
        sniff(
            iface=CAPTURE_INTERFACE,
            prn=process_packet,
            store=False,
            filter=bpf_filter,
        )
    except PermissionError:
        log.error("Permission denied. Run as root or with CAP_NET_RAW capability.")
        raise
    except Exception as e:
        log.error("Sniff error: %s", e)
        raise


if __name__ == "__main__":
    main()
