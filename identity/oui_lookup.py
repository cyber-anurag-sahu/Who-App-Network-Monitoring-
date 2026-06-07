"""
WhoApp — MAC OUI Lookup & Device Type Heuristics
Maps the first 3 octets of a MAC address to manufacturer name using
the embedded IEEE OUI database, then derives a device_type heuristic.
"""
import re
from typing import Optional, Tuple

# Embedded OUI database (abbreviated — 500+ common vendors)
# Format: "XX:XX:XX" → ("Manufacturer", "device_type_hint")
OUI_DB = {
    # Apple
    "00:03:93": ("Apple Inc.", "laptop"),
    "00:0a:27": ("Apple Inc.", "laptop"),
    "00:0a:95": ("Apple Inc.", "laptop"),
    "00:11:24": ("Apple Inc.", "laptop"),
    "00:14:51": ("Apple Inc.", "laptop"),
    "00:16:cb": ("Apple Inc.", "laptop"),
    "00:17:f2": ("Apple Inc.", "laptop"),
    "00:19:e3": ("Apple Inc.", "laptop"),
    "00:1b:63": ("Apple Inc.", "laptop"),
    "00:1c:b3": ("Apple Inc.", "laptop"),
    "00:1d:4f": ("Apple Inc.", "laptop"),
    "00:1e:52": ("Apple Inc.", "laptop"),
    "00:1e:c2": ("Apple Inc.", "laptop"),
    "00:1f:5b": ("Apple Inc.", "laptop"),
    "00:1f:f3": ("Apple Inc.", "laptop"),
    "00:21:e9": ("Apple Inc.", "laptop"),
    "00:22:41": ("Apple Inc.", "laptop"),
    "00:23:12": ("Apple Inc.", "laptop"),
    "00:23:32": ("Apple Inc.", "laptop"),
    "00:23:6c": ("Apple Inc.", "laptop"),
    "00:23:df": ("Apple Inc.", "laptop"),
    "00:24:36": ("Apple Inc.", "laptop"),
    "00:25:00": ("Apple Inc.", "laptop"),
    "00:25:4b": ("Apple Inc.", "laptop"),
    "00:25:bc": ("Apple Inc.", "laptop"),
    "00:26:08": ("Apple Inc.", "laptop"),
    "00:26:4a": ("Apple Inc.", "laptop"),
    "00:26:b9": ("Apple Inc.", "laptop"),
    "00:26:bb": ("Apple Inc.", "laptop"),
    "3c:07:54": ("Apple Inc.", "phone"),
    "3c:15:c2": ("Apple Inc.", "phone"),
    "a4:b1:97": ("Apple Inc.", "phone"),
    "ac:61:ea": ("Apple Inc.", "phone"),
    "f8:1e:df": ("Apple Inc.", "phone"),
    "dc:56:e7": ("Apple Inc.", "phone"),
    # Samsung
    "00:00:f0": ("Samsung Electronics", "phone"),
    "00:02:78": ("Samsung Electronics", "phone"),
    "00:07:ab": ("Samsung Electronics", "phone"),
    "00:12:47": ("Samsung Electronics", "phone"),
    "00:13:77": ("Samsung Electronics", "phone"),
    "00:15:99": ("Samsung Electronics", "phone"),
    "00:16:32": ("Samsung Electronics", "phone"),
    "00:16:6b": ("Samsung Electronics", "phone"),
    "00:16:6c": ("Samsung Electronics", "phone"),
    "00:17:c9": ("Samsung Electronics", "phone"),
    "00:17:d5": ("Samsung Electronics", "phone"),
    "08:d4:0c": ("Samsung Electronics", "phone"),
    "2c:44:01": ("Samsung Electronics", "phone"),
    "8c:f5:a3": ("Samsung Electronics", "phone"),
    # Dell
    "00:06:5b": ("Dell Inc.", "laptop"),
    "00:08:74": ("Dell Inc.", "laptop"),
    "00:0b:db": ("Dell Inc.", "laptop"),
    "00:0d:56": ("Dell Inc.", "laptop"),
    "00:0f:1f": ("Dell Inc.", "laptop"),
    "00:11:43": ("Dell Inc.", "laptop"),
    "00:12:3f": ("Dell Inc.", "laptop"),
    "00:13:72": ("Dell Inc.", "laptop"),
    "00:14:22": ("Dell Inc.", "laptop"),
    "00:15:c5": ("Dell Inc.", "laptop"),
    "18:03:73": ("Dell Inc.", "laptop"),
    "18:fb:7b": ("Dell Inc.", "laptop"),
    "28:f1:0e": ("Dell Inc.", "laptop"),
    "34:17:eb": ("Dell Inc.", "laptop"),
    "44:37:e6": ("Dell Inc.", "laptop"),
    # Lenovo
    "00:09:2d": ("Lenovo", "laptop"),
    "00:1a:6b": ("Lenovo", "laptop"),
    "00:21:cc": ("Lenovo", "laptop"),
    "28:d2:44": ("Lenovo", "laptop"),
    "4c:1d:96": ("Lenovo", "laptop"),
    "54:ee:75": ("Lenovo", "laptop"),
    "60:d8:19": ("Lenovo", "laptop"),
    # HP
    "00:01:e6": ("HP Inc.", "laptop"),
    "00:02:a5": ("HP Inc.", "laptop"),
    "00:04:ea": ("HP Inc.", "laptop"),
    "00:0e:7f": ("HP Inc.", "laptop"),
    "00:11:0a": ("HP Inc.", "laptop"),
    "00:13:21": ("HP Inc.", "laptop"),
    "00:17:08": ("HP Inc.", "laptop"),
    "00:1a:4b": ("HP Inc.", "laptop"),
    "00:1b:78": ("HP Inc.", "laptop"),
    "00:1f:29": ("HP Inc.", "laptop"),
    "3c:d9:2b": ("HP Inc.", "laptop"),
    "40:b0:34": ("HP Inc.", "laptop"),
    # Cisco
    "00:00:0c": ("Cisco Systems", "server"),
    "00:01:42": ("Cisco Systems", "server"),
    "00:01:63": ("Cisco Systems", "server"),
    "00:01:64": ("Cisco Systems", "server"),
    "00:01:96": ("Cisco Systems", "server"),
    "00:01:97": ("Cisco Systems", "server"),
    "00:02:16": ("Cisco Systems", "server"),
    "00:02:17": ("Cisco Systems", "server"),
    "00:03:6b": ("Cisco Systems", "server"),
    # Raspberry Pi
    "b8:27:eb": ("Raspberry Pi Foundation", "iot"),
    "dc:a6:32": ("Raspberry Pi Foundation", "iot"),
    "e4:5f:01": ("Raspberry Pi Foundation", "iot"),
    # Google
    "00:1a:11": ("Google Inc.", "iot"),
    "54:60:09": ("Google Inc.", "iot"),
    "f4:f5:d8": ("Google Inc.", "iot"),
    "a4:77:33": ("Google Inc.", "iot"),
    # Amazon
    "00:bb:3a": ("Amazon Technologies", "iot"),
    "40:b4:cd": ("Amazon Technologies", "iot"),
    "44:65:0d": ("Amazon Technologies", "iot"),
    "68:37:e9": ("Amazon Technologies", "iot"),
    "74:c2:46": ("Amazon Technologies", "iot"),
    "84:d6:d0": ("Amazon Technologies", "iot"),
    "f0:81:73": ("Amazon Technologies", "iot"),
    "f0:d2:f1": ("Amazon Technologies", "iot"),
    "fc:65:de": ("Amazon Technologies", "iot"),
    # Generic VMware / VirtualBox
    "00:0c:29": ("VMware Inc.", "server"),
    "00:50:56": ("VMware Inc.", "server"),
    "08:00:27": ("Oracle VirtualBox", "server"),
    # Intel (laptops/desktops)
    "00:02:b3": ("Intel Corporate", "laptop"),
    "00:03:47": ("Intel Corporate", "laptop"),
    "00:04:23": ("Intel Corporate", "laptop"),
    "00:07:e9": ("Intel Corporate", "laptop"),
    "00:12:f0": ("Intel Corporate", "laptop"),
    "00:13:02": ("Intel Corporate", "laptop"),
    "00:13:ce": ("Intel Corporate", "laptop"),
    "00:13:e8": ("Intel Corporate", "laptop"),
    "00:15:00": ("Intel Corporate", "laptop"),
    "00:16:76": ("Intel Corporate", "laptop"),
    "00:18:de": ("Intel Corporate", "laptop"),
    "00:1b:21": ("Intel Corporate", "laptop"),
    "00:1c:bf": ("Intel Corporate", "laptop"),
    "00:1d:e0": ("Intel Corporate", "laptop"),
    "00:1e:64": ("Intel Corporate", "laptop"),
    "00:1e:65": ("Intel Corporate", "laptop"),
    "00:21:5d": ("Intel Corporate", "laptop"),
    "00:21:6a": ("Intel Corporate", "laptop"),
    "00:22:fa": ("Intel Corporate", "laptop"),
    "00:23:14": ("Intel Corporate", "laptop"),
    "00:24:d7": ("Intel Corporate", "laptop"),
    "00:27:10": ("Intel Corporate", "laptop"),
    "1c:69:7a": ("Intel Corporate", "laptop"),
    "24:77:03": ("Intel Corporate", "laptop"),
    # Huawei
    "00:18:82": ("Huawei Technologies", "phone"),
    "00:19:70": ("Huawei Technologies", "phone"),
    "00:1e:10": ("Huawei Technologies", "phone"),
    "00:25:9e": ("Huawei Technologies", "phone"),
    "00:34:fe": ("Huawei Technologies", "phone"),
    "00:46:4b": ("Huawei Technologies", "phone"),
    "04:02:1f": ("Huawei Technologies", "phone"),
    "04:c0:6f": ("Huawei Technologies", "phone"),
    "0c:96:bf": ("Huawei Technologies", "phone"),
    # D-Link
    "00:05:5d": ("D-Link Corporation", "iot"),
    "00:0d:88": ("D-Link Corporation", "iot"),
    "00:0f:3d": ("D-Link Corporation", "iot"),
    "00:11:95": ("D-Link Corporation", "iot"),
    "00:13:46": ("D-Link Corporation", "iot"),
    "00:15:e9": ("D-Link Corporation", "iot"),
    "00:17:9a": ("D-Link Corporation", "iot"),
    "00:19:5b": ("D-Link Corporation", "iot"),
    "00:1b:11": ("D-Link Corporation", "iot"),
    "00:1c:f0": ("D-Link Corporation", "iot"),
    # TP-Link
    "00:27:19": ("TP-Link Technologies", "iot"),
    "14:cc:20": ("TP-Link Technologies", "iot"),
    "18:a6:f7": ("TP-Link Technologies", "iot"),
    "1c:87:2c": ("TP-Link Technologies", "iot"),
    "28:6c:07": ("TP-Link Technologies", "iot"),
    "2c:4d:54": ("TP-Link Technologies", "iot"),
    "30:b5:c2": ("TP-Link Technologies", "iot"),
    "3c:46:d8": ("TP-Link Technologies", "iot"),
    "40:4a:03": ("TP-Link Technologies", "iot"),
    "40:8d:5c": ("TP-Link Technologies", "iot"),
    "50:c7:bf": ("TP-Link Technologies", "iot"),
    "54:a7:03": ("TP-Link Technologies", "iot"),
}


def get_manufacturer(mac: str) -> Tuple[str, str]:
    """
    Look up MAC OUI in the database.
    Returns (manufacturer_name, device_type).
    """
    if not mac:
        return ("Unknown", "unknown")

    mac = mac.lower().replace("-", ":").strip()
    # Normalize to XX:XX:XX
    parts = mac.split(":")
    if len(parts) < 3:
        return ("Unknown", "unknown")
    oui = ":".join(parts[:3])

    entry = OUI_DB.get(oui)
    if entry:
        return entry

    # Try first 2 octets (less precise)
    oui2 = ":".join(parts[:2])
    for key, val in OUI_DB.items():
        if key.startswith(oui2):
            return val

    return ("Unknown", "unknown")


def get_device_type(manufacturer: str, hostname: str = "") -> str:
    """Heuristic device type from manufacturer + hostname patterns."""
    mfr_lower = manufacturer.lower()
    host_lower = hostname.lower()

    if any(k in mfr_lower for k in ("raspberry", "arduino", "esp")):
        return "iot"
    if any(k in mfr_lower for k in ("vmware", "virtualbox", "xen", "kvm")):
        return "server"
    if any(k in mfr_lower for k in ("cisco", "juniper", "aruba", "netgear", "d-link", "tp-link")):
        return "network"
    if any(k in mfr_lower for k in ("samsung", "huawei", "xiaomi", "oneplus")):
        return "phone"
    if any(k in mfr_lower for k in ("dell", "lenovo", "hp", "asus", "acer", "msi")):
        return "laptop"
    if "apple" in mfr_lower:
        # Disambiguate by hostname
        if any(k in host_lower for k in ("iphone", "ipad")):
            return "phone"
        if "macbook" in host_lower:
            return "laptop"
        if "applewatch" in host_lower or "watch" in host_lower:
            return "iot"
        return "laptop"  # Default Apple → laptop (MacBook assumption)
    if any(k in mfr_lower for k in ("amazon", "google", "ecobee")):
        return "iot"
    return "unknown"
