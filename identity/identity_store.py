"""
WhoApp — Identity Store
Redis-backed identity cache. Maps IP addresses to enriched identity
records including MAC, hostname, user, device_type, and manufacturer.

Schema (Redis hash key: identity:ip:<ip>):
{
    ip, mac, hostname, user, device_type, manufacturer,
    source, last_seen, first_seen
}
"""
import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict

import redis

from oui_lookup import get_manufacturer, get_device_type

log = logging.getLogger(__name__)

IDENTITY_TTL = 86400       # 24 hours
IDENTITY_PREFIX = "identity:ip:"
MAC_TO_IP_PREFIX = "identity:mac:"
ALL_DEVICES_KEY = "identity:all_ips"


class IdentityStore:
    def __init__(self, redis_url: str):
        self._r = redis.from_url(redis_url, decode_responses=True)

    def update(self, ip: str, mac: Optional[str], data: dict):
        """Upsert identity record for an IP address."""
        key = IDENTITY_PREFIX + ip
        existing_raw = self._r.get(key)
        existing = json.loads(existing_raw) if existing_raw else {}

        # Enrich with OUI lookup
        effective_mac = mac or data.get("mac") or existing.get("mac", "")
        if effective_mac and not existing.get("manufacturer"):
            manufacturer, device_hint = get_manufacturer(effective_mac)
            hostname = data.get("hostname") or existing.get("hostname", "")
            device_type = get_device_type(manufacturer, hostname)
            data["manufacturer"] = manufacturer
            data["device_type"] = device_hint if device_hint != "unknown" else device_type

        # Merge with existing
        merged = {**existing, **{k: v for k, v in data.items() if v}}
        if "first_seen" not in merged:
            merged["first_seen"] = datetime.now(timezone.utc).isoformat()
        merged["last_seen"] = datetime.now(timezone.utc).isoformat()
        merged["ip"] = ip

        # Derive user from hostname (strip domain suffix)
        if merged.get("hostname") and not merged.get("user"):
            merged["user"] = merged["hostname"].split(".")[0]

        self._r.setex(key, IDENTITY_TTL, json.dumps(merged))
        self._r.sadd(ALL_DEVICES_KEY, ip)

        # Reverse index: MAC → IP
        if effective_mac:
            self._r.setex(MAC_TO_IP_PREFIX + effective_mac, IDENTITY_TTL, ip)

        log.debug("Identity updated: %s → %s", ip, merged.get("hostname", "?"))

    def get(self, ip: str) -> Optional[Dict]:
        """Retrieve identity record for an IP."""
        key = IDENTITY_PREFIX + ip
        raw = self._r.get(key)
        if raw:
            return json.loads(raw)
        return None

    def get_by_mac(self, mac: str) -> Optional[Dict]:
        """Look up identity by MAC address."""
        ip = self._r.get(MAC_TO_IP_PREFIX + mac)
        if ip:
            return self.get(ip)
        return None

    def get_all(self) -> list:
        """Return all known device identity records."""
        ips = self._r.smembers(ALL_DEVICES_KEY)
        results = []
        for ip in ips:
            record = self.get(ip)
            if record:
                results.append(record)
        return results

    def enrich_flow(self, flow: dict) -> dict:
        """
        Enrich a flow dict with identity info from src_ip and optionally src_mac.
        Returns the flow with identity.* fields added.
        """
        src_ip = flow.get("src_ip", "")
        src_mac = flow.get("src_mac", "")

        identity = self.get(src_ip)
        if not identity and src_mac:
            identity = self.get_by_mac(src_mac)

        if not identity:
            # Minimal record from MAC
            manufacturer, device_hint = get_manufacturer(src_mac) if src_mac else ("Unknown", "unknown")
            identity = {
                "ip": src_ip,
                "mac": src_mac,
                "hostname": src_ip,
                "user": src_ip,
                "device_type": device_hint,
                "manufacturer": manufacturer,
            }

        flow["identity"] = {
            "ip": identity.get("ip", src_ip),
            "mac": identity.get("mac", src_mac),
            "hostname": identity.get("hostname", src_ip),
            "user": identity.get("user", src_ip),
            "device_type": identity.get("device_type", "unknown"),
            "manufacturer": identity.get("manufacturer", "Unknown"),
        }
        return flow
