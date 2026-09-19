"""
adapters/windows/dns.py
=======================
Windows DNS Activity Collector for AEGIS Network Monitor.

Attempts to observe plaintext DNS query and response transactions (UDP port 53).

Privilege & Observability Limitations:
-------------------------------------
- Packet inspection on Windows requires Administrator privileges to open raw sockets
  (WinError 10013: WSAEACCES). Without elevation, this collector gracefully reports
  CollectorStatus.PERMISSION_DENIED.
- Encrypted DNS (DNS over HTTPS / DoH, DNS over TLS / DoT) uses TLS transport (ports 443/853)
  and does not expose plaintext domain query names; such traffic cannot be observed by this collector.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from network_monitor.core.events import (
    CollectorStatus,
    DnsEvent,
    Protocol,
)


class WindowsDnsCollector:
    """
    DNS collector for Windows hosts.

    Inspects plaintext DNS UDP traffic on port 53 when elevated privileges exist.
    Accurately reports PERMISSION_DENIED when running without Administrator privileges.
    """

    COLLECTOR_NAME = "windows_dns"

    def __init__(self, adapter_name: str = "WindowsAdapter") -> None:
        self.adapter_name = adapter_name
        self.status: CollectorStatus = CollectorStatus.UNAVAILABLE
        self.status_reason: Optional[str] = None
        self._raw_sock: Optional[socket.socket] = None

        self._check_privilege_and_init()

    def _check_privilege_and_init(self) -> None:
        """
        Probe raw socket capability on Windows.
        Captures WSAEACCES / PermissionError gracefully without crashing.
        """
        try:
            # On Windows, raw socket creation requires Administrator privilege
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.setblocking(False)
            self._raw_sock = sock
            self.status = CollectorStatus.AVAILABLE
            self.status_reason = None
        except PermissionError as exc:
            self.status = CollectorStatus.PERMISSION_DENIED
            self.status_reason = (
                "Raw packet capture on Windows requires Administrator privileges "
                f"(WinError {getattr(exc, 'winerror', 10013)}). "
                "Plaintext port 53 DNS capture is disabled. "
                "Encrypted DNS (DoH/DoT) is unobservable via plaintext inspection."
            )
        except Exception as exc:
            self.status = CollectorStatus.UNAVAILABLE
            self.status_reason = (
                f"Socket creation failed: {exc}. "
                "Plaintext port 53 DNS capture is unavailable."
            )

    def is_available(self) -> bool:
        return self.status == CollectorStatus.AVAILABLE

    def collect(self) -> list[DnsEvent]:
        """
        Read any pending DNS packets from the raw socket if available.
        Returns a list of parsed DnsEvents.
        """
        if self._raw_sock is None or self.status != CollectorStatus.AVAILABLE:
            return []

        events: list[DnsEvent] = []

        # Read up to 20 packets per poll tick to avoid blocking the event loop
        for _ in range(20):
            try:
                data, addr = self._raw_sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError, OSError):
                break

            parsed_event = self._parse_ip_packet(data)
            if parsed_event:
                events.append(parsed_event)

        return events

    def close(self) -> None:
        """Release socket resources."""
        if self._raw_sock is not None:
            try:
                self._raw_sock.close()
            except Exception:
                pass
            self._raw_sock = None

    # ------------------------------------------------------------------
    # DNS Packet Parsing Helpers
    # ------------------------------------------------------------------

    def _parse_ip_packet(self, data: bytes) -> Optional[DnsEvent]:
        """
        Parse IPv4 packet to extract UDP port 53 DNS payloads.
        """
        if len(data) < 28:  # 20 IP header + 8 UDP header
            return None

        # IPv4 header length
        ip_header_len = (data[0] & 0x0F) * 4
        if len(data) < ip_header_len + 8:
            return None

        proto = data[9]
        if proto != 17:  # UDP protocol number
            return None

        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        udp_header = data[ip_header_len : ip_header_len + 8]
        src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", udp_header)

        # Check if port 53 (DNS)
        if src_port != 53 and dst_port != 53:
            return None

        dns_payload = data[ip_header_len + 8 :]
        if len(dns_payload) < 12:
            return None

        return self._parse_dns_payload(dns_payload, src_ip, dst_ip)

    def _parse_dns_payload(self, payload: bytes, src_ip: str, dst_ip: str) -> Optional[DnsEvent]:
        """
        Extract Query ID, QR flag, query name, and query type from DNS payload.
        """
        try:
            tx_id, flags, qd_count, an_count, _, _ = struct.unpack("!HHHHHH", payload[:12])
            is_response = bool((flags >> 15) & 1)

            query_name = None
            query_type = None

            # Parse question section if present
            offset = 12
            if qd_count > 0:
                name_parts = []
                while offset < len(payload):
                    length = payload[offset]
                    if length == 0:
                        offset += 1
                        break
                    # Compression pointer check
                    if (length & 0xC0) == 0xC0:
                        offset += 2
                        break
                    offset += 1
                    if offset + length > len(payload):
                        break
                    part = payload[offset : offset + length].decode("utf-8", errors="replace")
                    name_parts.append(part)
                    offset += length

                if name_parts:
                    query_name = ".".join(name_parts)

                if offset + 4 <= len(payload):
                    qtype_num, _ = struct.unpack("!HH", payload[offset : offset + 4])
                    query_type = self._qtype_to_str(qtype_num)

            return DnsEvent(
                adapter=self.adapter_name,
                collector=self.COLLECTOR_NAME,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=Protocol.UDP,
                query_name=query_name,
                query_type=query_type,
                query_id=tx_id,
                is_response=is_response,
            )
        except Exception:
            return None

    @staticmethod
    def _qtype_to_str(qtype: int) -> str:
        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            255: "ANY",
        }
        return types.get(qtype, f"TYPE{qtype}")
