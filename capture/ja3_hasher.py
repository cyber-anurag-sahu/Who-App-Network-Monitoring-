"""
WhoApp — JA3 Fingerprint Hasher
Computes JA3 hashes from TLS ClientHello packets captured by Scapy.

JA3 = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats )

Reference: https://github.com/salesforce/ja3
"""
import hashlib
import struct
from typing import Optional, Tuple


# TLS extension types to ignore when building JA3 string
GREASE_TABLE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
                0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
                0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


class JA3Hasher:
    def extract(self, pkt) -> Tuple[Optional[str], Optional[str]]:
        """
        Try to extract a JA3 hash and TLS SNI from a Scapy packet.
        Returns (ja3_hash, sni) — either may be None.
        """
        try:
            raw = self._get_tls_payload(pkt)
            if raw is None:
                return None, None
            return self._parse_client_hello(raw)
        except Exception:
            return None, None

    def _get_tls_payload(self, pkt):
        """Return raw bytes of TLS record payload if this is a ClientHello."""
        from scapy.layers.inet import TCP
        if not pkt.haslayer(TCP):
            return None
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if len(payload) < 6:
            return None
        # TLS record: content_type=0x16 (handshake), major=0x03
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None
        # Handshake type 0x01 = ClientHello
        if payload[5] != 0x01:
            return None
        return payload

    def _parse_client_hello(self, data: bytes) -> Tuple[Optional[str], Optional[str]]:
        idx = 0
        # TLS record header (5 bytes)
        if len(data) < 5:
            return None, None
        tls_version = struct.unpack("!H", data[1:3])[0]
        idx = 5

        # Handshake header (4 bytes: type + 3-byte length)
        idx += 4
        if len(data) < idx + 2:
            return None, None

        # ClientHello version
        ch_version = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2

        # Random (32 bytes)
        idx += 32

        # Session ID
        if len(data) < idx + 1:
            return None, None
        sid_len = data[idx]
        idx += 1 + sid_len

        # Cipher suites
        if len(data) < idx + 2:
            return None, None
        cs_len = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2
        ciphers = []
        for i in range(cs_len // 2):
            cs = struct.unpack("!H", data[idx:idx+2])[0]
            idx += 2
            if cs not in GREASE_TABLE:
                ciphers.append(str(cs))

        # Compression methods
        if len(data) < idx + 1:
            return None, None
        cm_len = data[idx]
        idx += 1 + cm_len

        # Extensions
        if len(data) < idx + 2:
            # No extensions — still valid
            ja3_str = f"{ch_version},{','.join(ciphers)},,,".encode()
            return hashlib.md5(ja3_str).hexdigest(), None

        ext_total = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2
        ext_end = idx + ext_total

        extensions = []
        curves = []
        curve_formats = []
        sni = None

        while idx < ext_end and idx < len(data) - 3:
            ext_type = struct.unpack("!H", data[idx:idx+2])[0]
            ext_len = struct.unpack("!H", data[idx+2:idx+4])[0]
            ext_data = data[idx+4:idx+4+ext_len]
            idx += 4 + ext_len

            if ext_type in GREASE_TABLE:
                continue
            extensions.append(str(ext_type))

            # SNI (type 0)
            if ext_type == 0 and len(ext_data) > 5:
                name_len = struct.unpack("!H", ext_data[3:5])[0]
                try:
                    sni = ext_data[5:5+name_len].decode("utf-8")
                except Exception:
                    pass

            # Supported groups / elliptic curves (type 10)
            elif ext_type == 10 and len(ext_data) >= 2:
                groups_len = struct.unpack("!H", ext_data[0:2])[0]
                for i in range(groups_len // 2):
                    g = struct.unpack("!H", ext_data[2+i*2:4+i*2])[0]
                    if g not in GREASE_TABLE:
                        curves.append(str(g))

            # EC point formats (type 11)
            elif ext_type == 11 and len(ext_data) >= 1:
                pf_len = ext_data[0]
                curve_formats = [str(ext_data[1+i]) for i in range(pf_len)]

        ja3_str = (
            f"{ch_version},"
            f"{'-'.join(ciphers)},"
            f"{'-'.join(extensions)},"
            f"{'-'.join(curves)},"
            f"{'-'.join(curve_formats)}"
        ).encode()
        ja3_hash = hashlib.md5(ja3_str).hexdigest()
        return ja3_hash, sni
