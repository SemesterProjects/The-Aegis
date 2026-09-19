"""
adapters/macos/traffic.py
=========================
macOS Interface Traffic Collector for AEGIS Network Monitor.

Collects network interface traffic counters (cumulative and interval deltas)
via psutil.net_io_counters(pernic=True). Suppresses zero-change intervals.
"""

from __future__ import annotations

from typing import Optional

from network_monitor.core.events import TrafficEvent

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


class MacOSTrafficCollector:
    """
    Traffic collector for macOS network interfaces.
    """

    COLLECTOR_NAME = "macos_traffic"

    def __init__(self, adapter_name: str = "MacOSAdapter") -> None:
        self.adapter_name = adapter_name
        self._prev_counters: dict[str, tuple[int, int, int, int]] = {}

    @property
    def is_available(self) -> bool:
        return _PSUTIL_AVAILABLE

    def collect(self) -> list[TrafficEvent]:
        if not _PSUTIL_AVAILABLE:
            return []

        events: list[TrafficEvent] = []

        try:
            counters = psutil.net_io_counters(pernic=True)
        except Exception:
            return []

        for iface_name, stat in counters.items():
            prev = self._prev_counters.get(iface_name)
            curr_tuple = (
                stat.bytes_sent,
                stat.bytes_recv,
                stat.packets_sent,
                stat.packets_recv,
            )

            if prev is None:
                self._prev_counters[iface_name] = curr_tuple
                if stat.bytes_sent > 0 or stat.bytes_recv > 0:
                    events.append(TrafficEvent(
                        adapter=self.adapter_name,
                        collector=self.COLLECTOR_NAME,
                        interface=iface_name,
                        bytes_sent=stat.bytes_sent,
                        bytes_received=stat.bytes_recv,
                        packets_sent=stat.packets_sent,
                        packets_received=stat.packets_recv,
                        errors_in=stat.errin,
                        errors_out=stat.errout,
                        drops_in=stat.dropin,
                        drops_out=stat.dropout,
                        delta_bytes_sent=0,
                        delta_bytes_received=0,
                        delta_packets_sent=0,
                        delta_packets_received=0,
                    ))
            else:
                d_b_sent = stat.bytes_sent - prev[0]
                d_b_recv = stat.bytes_recv - prev[1]
                d_p_sent = stat.packets_sent - prev[2]
                d_p_recv = stat.packets_recv - prev[3]

                self._prev_counters[iface_name] = curr_tuple

                if d_b_sent > 0 or d_b_recv > 0 or d_p_sent > 0 or d_p_recv > 0:
                    events.append(TrafficEvent(
                        adapter=self.adapter_name,
                        collector=self.COLLECTOR_NAME,
                        interface=iface_name,
                        bytes_sent=stat.bytes_sent,
                        bytes_received=stat.bytes_recv,
                        packets_sent=stat.packets_sent,
                        packets_received=stat.packets_recv,
                        errors_in=stat.errin,
                        errors_out=stat.errout,
                        drops_in=stat.dropin,
                        drops_out=stat.dropout,
                        delta_bytes_sent=d_b_sent,
                        delta_bytes_received=d_b_recv,
                        delta_packets_sent=d_p_sent,
                        delta_packets_received=d_p_recv,
                    ))

        return events
