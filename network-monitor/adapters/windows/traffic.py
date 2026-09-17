"""
adapters/windows/traffic.py
===========================
Windows Interface Traffic Collector for AEGIS Network Monitor.

Continuously observes network interface traffic statistics via psutil.net_io_counters(pernic=True).
Computes cumulative totals and interval deltas (bytes/packets transferred since previous poll).
Filters out zero-change intervals to prevent flooding the telemetry stream with redundant events.
"""

from __future__ import annotations

from typing import Any, Optional

from network_monitor.core.events import TrafficEvent

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


class WindowsTrafficCollector:
    """
    Traffic collector for Windows network interfaces.

    Tracks cumulative byte and packet counters as well as interval deltas.
    Avoids flooding the event stream with identical zero-delta events.
    """

    COLLECTOR_NAME = "windows_traffic"

    def __init__(self, adapter_name: str = "WindowsAdapter") -> None:
        self.adapter_name = adapter_name
        # Maps interface name -> (bytes_sent, bytes_recv, packets_sent, packets_recv)
        self._prev_counters: dict[str, tuple[int, int, int, int]] = {}
        self._first_poll: bool = True

    @property
    def is_available(self) -> bool:
        return _PSUTIL_AVAILABLE

    def collect(self) -> list[TrafficEvent]:
        """
        Poll interface counters and return TrafficEvents for interfaces that changed.

        On the initial poll, baseline events are emitted for interfaces that have
        non-zero activity. On subsequent polls, events are emitted only when
        counters increment (delta > 0).
        """
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
                # First time seeing this interface
                self._prev_counters[iface_name] = curr_tuple
                # Emit initial baseline only if there has been any traffic on the interface
                if stat.bytes_sent > 0 or stat.bytes_recv > 0:
                    event = TrafficEvent(
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
                    )
                    events.append(event)
            else:
                d_bytes_sent = stat.bytes_sent - prev[0]
                d_bytes_recv = stat.bytes_recv - prev[1]
                d_pkts_sent = stat.packets_sent - prev[2]
                d_pkts_recv = stat.packets_recv - prev[3]

                # Update stored counters
                self._prev_counters[iface_name] = curr_tuple

                # Only emit an event if there was actual traffic movement
                if d_bytes_sent > 0 or d_bytes_recv > 0 or d_pkts_sent > 0 or d_pkts_recv > 0:
                    event = TrafficEvent(
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
                        delta_bytes_sent=d_bytes_sent,
                        delta_bytes_received=d_bytes_recv,
                        delta_packets_sent=d_pkts_sent,
                        delta_packets_received=d_pkts_recv,
                    )
                    events.append(event)

        self._first_poll = False
        return events
