"""
adapters/macos/dns.py
=====================
macOS DNS Activity Collector for AEGIS Network Monitor.

Observes plaintext DNS transactions (UDP port 53) on macOS hosts.

Privilege & Observability Limitations:
-------------------------------------
- Packet inspection on macOS requires root privileges to access Berkeley Packet Filter
  (/dev/bpf*). Without root, this collector reports CollectorStatus.PERMISSION_DENIED.
- Apple Network Extension requires native app entitlement bundles and is unavailable from
  standard Python interpreters.
- Encrypted DNS (DoH/DoT) is unobservable via plaintext inspection.
"""

from __future__ import annotations

import os
from typing import Optional

from network_monitor.core.events import (
    CollectorStatus,
    DnsEvent,
)


class MacOSDnsCollector:
    """
    DNS collector for macOS hosts.

    Reports PERMISSION_DENIED when running unprivileged.
    """

    COLLECTOR_NAME = "macos_dns"

    def __init__(self, adapter_name: str = "MacOSAdapter") -> None:
        self.adapter_name = adapter_name
        self.status: CollectorStatus = CollectorStatus.UNAVAILABLE
        self.status_reason: Optional[str] = None

        self._check_privilege_and_init()

    def _check_privilege_and_init(self) -> None:
        is_root = False
        try:
            if hasattr(os, "geteuid"):
                is_root = (os.geteuid() == 0)
        except Exception:
            pass

        if not is_root:
            self.status = CollectorStatus.PERMISSION_DENIED
            self.status_reason = (
                "Packet capture on macOS requires root privileges (to access /dev/bpf*). "
                "Plaintext port 53 DNS capture is disabled. "
                "Encrypted DNS (DoH/DoT) is unobservable via plaintext inspection."
            )
        else:
            self.status = CollectorStatus.UNAVAILABLE
            self.status_reason = (
                "Native macOS packet capture backend not configured for current runtime. "
                "Network Extension cannot be loaded from standard Python."
            )

    def is_available(self) -> bool:
        return self.status == CollectorStatus.AVAILABLE

    def collect(self) -> list[DnsEvent]:
        return []

    def close(self) -> None:
        pass
