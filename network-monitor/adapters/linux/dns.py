"""
adapters/linux/dns.py
=====================
Linux DNS Activity Collector for AEGIS Network Monitor.

Observes plaintext DNS transactions (UDP port 53) on Linux hosts.

Privilege & Observability Limitations:
-------------------------------------
- On Linux, raw socket packet capture (AF_PACKET or SOCK_RAW) requires root or
  CAP_NET_RAW capability. When executed without these privileges, this collector
  gracefully reports CollectorStatus.PERMISSION_DENIED.
- Encrypted DNS protocols (DNS over HTTPS / DoH, DNS over TLS / DoT) operate over
  encrypted TLS channels and do not expose domain query names to plaintext inspection.
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Optional

from network_monitor.core.events import (
    CollectorStatus,
    DnsEvent,
    Protocol,
)


class LinuxDnsCollector:
    """
    DNS collector for Linux hosts.

    Inspects plaintext DNS UDP traffic on port 53 when running with root or CAP_NET_RAW.
    Accurately reports PERMISSION_DENIED when running unprivileged.
    """

    COLLECTOR_NAME = "linux_dns"

    def __init__(self, adapter_name: str = "LinuxAdapter") -> None:
        self.adapter_name = adapter_name
        self.status: CollectorStatus = CollectorStatus.UNAVAILABLE
        self.status_reason: Optional[str] = None
        self._raw_sock: Optional[socket.socket] = None

        self._check_privilege_and_init()

    def _check_privilege_and_init(self) -> None:
        """
        Check privileges and attempt raw socket initialization.
        """
        is_root = False
        try:
            if hasattr(os, "geteuid"):
                is_root = (os.geteuid() == 0)
        except Exception:
            pass

        if not is_root:
            self.status = CollectorStatus.PERMISSION_DENIED
            self.status_reason = (
                "Packet capture on Linux requires root privileges or CAP_NET_RAW. "
                "Plaintext port 53 DNS capture is disabled. "
                "Encrypted DNS (DoH/DoT) is unobservable via plaintext inspection."
            )
            return

        try:
            # On Linux with root, AF_PACKET allows capturing raw Ethernet frames
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
            sock.setblocking(False)
            self._raw_sock = sock
            self.status = CollectorStatus.AVAILABLE
            self.status_reason = None
        except PermissionError:
            self.status = CollectorStatus.PERMISSION_DENIED
            self.status_reason = (
                "Insufficient privileges to open raw socket (CAP_NET_RAW required). "
                "Plaintext port 53 DNS capture is disabled."
            )
        except Exception as exc:
            self.status = CollectorStatus.UNAVAILABLE
            self.status_reason = f"Raw socket initialization failed: {exc}"

    def is_available(self) -> bool:
        return self.status == CollectorStatus.AVAILABLE

    def collect(self) -> list[DnsEvent]:
        """
        Read any pending DNS packets from the socket.
        """
        if self._raw_sock is None or self.status != CollectorStatus.AVAILABLE:
            return []

        events: list[DnsEvent] = []

        for _ in range(20):
            try:
                data, _ = self._raw_sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError, OSError):
                break

            # Ethernet header is 14 bytes
            if len(data) > 14:
                parsed = self._parse_ip_packet(data[14:])
                if parsed:
                    events.append(parsed)

        return events

    def close(self) -> None:
        if self._raw_sock is not None:
            try:
                self._raw_sock.close()
            except Exception:
                pass
            self._raw_sock = None

    def _parse_ip_packet(self, data: bytes) -> Optional[DnsEvent]:
        if len(data) < 28:
            return None

        ip_header_len = (data[0] & 0x0F) * 4
        if len(data) < ip_header_len + 8:
            return None

        proto = data[9]
        if proto != 17:  # UDP
            return None

        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        udp_header = data[ip_header_len : ip_header_len + 8]
        src_port, dst_port, _, _ = struct.unpack("!HHHH", udp_header)

        if src_port != 53 and dst_port != 53:
            return None

        dns_payload = data[ip_header_len + 8 :]
        if len(dns_payload) < 12:
            return None

        return self._parse_dns_payload(dns_payload, src_ip, dst_ip)

    def _parse_dns_payload(self, payload: bytes, src_ip: str, dst_ip: str) -> Optional[DnsEvent]:
        try:
            tx_id, flags, qd_count, _, _, _ = struct.unpack("!HHHHHH", payload[:12])
            is_response = bool((flags >> 15) & 1)

            query_name = None
            query_type = None

            offset = 12
            if qd_count > 0:
                name_parts = []
                while offset < len(payload):
                    length = payload[offset]
                    if length == 0:
                        offset += 1
                        break
                    if (length & 0xC0) == 0xC0:
                        offset += 2
                        break
                    offset += 1
                    if offset + length > len(payload):
                        break
                    name_parts.append(payload[offset : offset + length].decode("utf-8", errors="replace"))
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
        types = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
        return types.get(qtype, f"TYPE{qtype}")
