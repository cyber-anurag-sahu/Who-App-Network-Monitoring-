"""
WhoApp — Flow Extractor
Aggregates raw packet events into bi-directional network flows with
enriched metadata. Flows are keyed on the 5-tuple and expire after
an idle timeout.
"""
import time
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

FLOW_IDLE_TIMEOUT = 60   # seconds — export flow after this idle period
FLOW_MAX_DURATION = 300  # seconds — force-export long-running flows


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    ja3: Optional[str] = None
    tls_sni: Optional[str] = None
    dns_queries: List[str] = field(default_factory=list)
    tcp_flags_seen: List[str] = field(default_factory=list)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    exported: bool = False

    def update(self, pkt_meta: dict):
        self.last_seen = time.time()
        self.packet_count += 1
        self.byte_count += pkt_meta.get("length", 0)
        if pkt_meta.get("ja3") and not self.ja3:
            self.ja3 = pkt_meta["ja3"]
        if pkt_meta.get("tls_sni") and not self.tls_sni:
            self.tls_sni = pkt_meta["tls_sni"]
        if pkt_meta.get("dns_queries"):
            for q in pkt_meta["dns_queries"]:
                if q not in self.dns_queries:
                    self.dns_queries.append(q)
        if pkt_meta.get("tcp_flags") and pkt_meta["tcp_flags"] not in self.tcp_flags_seen:
            self.tcp_flags_seen.append(pkt_meta["tcp_flags"])
        if pkt_meta.get("src_mac") and not self.src_mac:
            self.src_mac = pkt_meta["src_mac"]
        if pkt_meta.get("dst_mac") and not self.dst_mac:
            self.dst_mac = pkt_meta["dst_mac"]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["duration"] = self.last_seen - self.first_seen
        return d

    @property
    def is_expired(self) -> bool:
        now = time.time()
        idle = (now - self.last_seen) > FLOW_IDLE_TIMEOUT
        long_run = (now - self.first_seen) > FLOW_MAX_DURATION
        return idle or long_run


def make_flow_key(src_ip: str, dst_ip: str, src_port: int,
                  dst_port: int, protocol: str) -> Tuple[str, bool]:
    """Return canonical flow key (lower IP first) and direction flag."""
    sp, dp = int(src_port or 0), int(dst_port or 0)
    if (src_ip, sp) < (dst_ip, dp):
        return f"{src_ip}:{sp}-{dst_ip}:{dp}/{protocol}", False
    return f"{dst_ip}:{dp}-{src_ip}:{sp}/{protocol}", True


class FlowExtractor:
    def __init__(self):
        self._flows: Dict[str, Flow] = {}

    def ingest(self, pkt_meta: dict) -> Optional[dict]:
        """
        Ingest one packet metadata dict. Returns a completed flow dict
        if a flow just expired, else None.
        """
        src_ip = pkt_meta.get("src_ip", "")
        dst_ip = pkt_meta.get("dst_ip", "")
        src_port = pkt_meta.get("src_port", 0)
        dst_port = pkt_meta.get("dst_port", 0)
        protocol = pkt_meta.get("protocol", "UNKNOWN")

        if not src_ip or not dst_ip:
            return None

        key, _ = make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        if key not in self._flows:
            self._flows[key] = Flow(
                flow_id=key,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
            )

        flow = self._flows[key]
        flow.update(pkt_meta)

        # Export expired flows
        if flow.is_expired and not flow.exported:
            flow.exported = True
            completed = flow.to_dict()
            del self._flows[key]
            return completed

        return None

    def flush_all(self) -> list:
        """Force-export all active flows (e.g. on shutdown)."""
        results = []
        for flow in list(self._flows.values()):
            if not flow.exported:
                flow.exported = True
                results.append(flow.to_dict())
        self._flows.clear()
        return results
