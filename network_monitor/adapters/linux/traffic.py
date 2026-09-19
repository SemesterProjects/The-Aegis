"""
adapters/linux/traffic.py
=========================
Linux Interface Traffic Collector for AEGIS Network Monitor.

Collects network interface traffic counters (cumulative and interval deltas)
via psutil.net_io_counters() or by parsing /proc/net/dev when psutil is absent.
Suppresses zero-change intervals to prevent flooding the event stream.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from network_monitor.core.events import TrafficEvent

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


class LinuxTrafficCollector:
    """
    Traffic collector for Linux network interfaces.

    Supports psutil and /proc/net/dev fallback.
    Tracks cumulative totals and computes interval deltas.
    """

    COLLECTOR_NAME = "linux_traffic"

    def __init__(self, adapter_name: str = "LinuxAdapter") -> None:
        self.adapter_name = adapter_name
        self._prev_counters: dict[str, tuple[int, int, int, int]] = {}

    @property
    def is_available(self) -> bool:
        return _PSUTIL_AVAILABLE or os.path.exists("/proc/net/dev")

    def collect(self) -> list[TrafficEvent]:
        """
        Poll interface counters and return TrafficEvents for interfaces with traffic changes.
        """
        if not self.is_available:
            return []

        raw_stats = self._get_interface_stats()
        events: list[TrafficEvent] = []

        for iface_name, stat in raw_stats.items():
            prev = self._prev_counters.get(iface_name)
            curr_tuple = (
                stat["bytes_sent"],
                stat["bytes_recv"],
                stat["packets_sent"],
                stat["packets_recv"],
            )

            if prev is None:
                self._prev_counters[iface_name] = curr_tuple
                if stat["bytes_sent"] > 0 or stat["bytes_recv"] > 0:
                    events.append(TrafficEvent(
                        adapter=self.adapter_name,
                        collector=self.COLLECTOR_NAME,
                        interface=iface_name,
                        bytes_sent=stat["bytes_sent"],
                        bytes_received=stat["bytes_recv"],
                        packets_sent=stat["packets_sent"],
                        packets_received=stat["packets_recv"],
                        errors_in=stat.get("errin", 0),
                        errors_out=stat.get("errout", 0),
                        drops_in=stat.get("dropin", 0),
                        drops_out=stat.get("dropout", 0),
                        delta_bytes_sent=0,
                        delta_bytes_received=0,
                        delta_packets_sent=0,
                        delta_packets_received=0,
                    ))
            else:
                d_b_sent = stat["bytes_sent"] - prev[0]
                d_b_recv = stat["bytes_recv"] - prev[1]
                d_p_sent = stat["packets_sent"] - prev[2]
                d_p_recv = stat["packets_recv"] - prev[3]

                self._prev_counters[iface_name] = curr_tuple

                if d_b_sent > 0 or d_b_recv > 0 or d_p_sent > 0 or d_p_recv > 0:
                    events.append(TrafficEvent(
                        adapter=self.adapter_name,
                        collector=self.COLLECTOR_NAME,
                        interface=iface_name,
                        bytes_sent=stat["bytes_sent"],
                        bytes_received=stat["bytes_recv"],
                        packets_sent=stat["packets_sent"],
                        packets_received=stat["packets_recv"],
                        errors_in=stat.get("errin", 0),
                        errors_out=stat.get("errout", 0),
                        drops_in=stat.get("dropin", 0),
                        drops_out=stat.get("dropout", 0),
                        delta_bytes_sent=d_b_sent,
                        delta_bytes_received=d_b_recv,
                        delta_packets_sent=d_p_sent,
                        delta_packets_received=d_p_recv,
                    ))

        return events

    def _get_interface_stats(self) -> dict[str, dict[str, int]]:
        if _PSUTIL_AVAILABLE:
            try:
                ps_stats = psutil.net_io_counters(pernic=True)
                return {
                    name: {
                        "bytes_sent": s.bytes_sent,
                        "bytes_recv": s.bytes_recv,
                        "packets_sent": s.packets_sent,
                        "packets_recv": s.packets_recv,
                        "errin": s.errin,
                        "errout": s.errout,
                        "dropin": s.dropin,
                        "dropout": s.dropout,
                    }
                    for name, s in ps_stats.items()
                }
            except Exception:
                pass

        # Fallback reading /proc/net/dev
        results: dict[str, dict[str, int]] = {}
        if os.path.exists("/proc/net/dev"):
            try:
                with open("/proc/net/dev", "r") as f:
                    lines = f.readlines()
                for line in lines[2:]:
                    if ":" not in line:
                        continue
                    iface, data = line.split(":", 1)
                    iface = iface.strip()
                    fields = [int(x) for x in data.split()]
                    if len(fields) >= 16:
                        results[iface] = {
                            "bytes_recv": fields[0],
                            "packets_recv": fields[1],
                            "errin": fields[2],
                            "dropin": fields[3],
                            "bytes_sent": fields[8],
                            "packets_sent": fields[9],
                            "errout": fields[10],
                            "dropout": fields[11],
                        }
            except Exception:
                pass

        return results
