"""
adapters/macos/adapter.py
==========================
macOS-specific Network Monitor adapter.

Detects capabilities available on the current macOS system and exposes them
through the standard ``NetworkAdapter`` interface.

Milestone 1 status:
-------------------
  - System discovery and capability detection: IMPLEMENTED
  - Connection collector (psutil): NOT YET IMPLEMENTED
  - Traffic collector (psutil.net_io_counters): NOT YET IMPLEMENTED
  - DNS collector: NOT YET IMPLEMENTED
  - Process network activity collector: NOT YET IMPLEMENTED

All not-yet-implemented collectors raise ``CollectorNotImplementedError``
rather than returning empty data.

Network Extension limitation:
------------------------------
Apple's Network Extension framework cannot be used from a Python process.
See adapters/macos/network_extension/capability.py for the full explanation.
Fallback mechanisms (psutil, netstat, lsof, dtrace) are detected and
reported instead.
"""

from __future__ import annotations

from typing import Optional

from network_monitor.core.adapter import (
    AdapterInfo,
    CapabilityReport,
    CollectorNotImplementedError,
    NetworkAdapter,
)
from network_monitor.core.events import (
    CollectorInfo,
    CollectorStatus,
    ConnectionEvent,
    DnsEvent,
    ProcessNetworkEvent,
    TrafficEvent,
)
from network_monitor.adapters.macos.connections import MacOSConnectionCollector
from network_monitor.adapters.macos.dns import MacOSDnsCollector
from network_monitor.adapters.macos.traffic import MacOSTrafficCollector
from network_monitor.discovery.system import SystemInfo


class MacOSAdapter(NetworkAdapter):
    """
    Network Monitor adapter for macOS (Darwin) hosts.

    Capability detection strategy:
    - network_extension: always False (Python limitation; documented).
    - psutil:            import probe.
    - netstat:           binary presence check.
    - lsof:              binary presence check.
    - dtrace:            binary presence + root check.
    - pf_log:            /dev/pflog0 existence check.
    """

    OS_NAME = "Darwin"
    OS_DISPLAY_NAME = "macOS"

    def __init__(self, system_info: SystemInfo) -> None:
        super().__init__()
        self._system_info = system_info
        self._capability_report: Optional[CapabilityReport] = None
        self._pending_process_events: list[ProcessNetworkEvent] = []

        # Instantiate Milestone 2 collectors
        self._connection_collector = MacOSConnectionCollector(adapter_name="MacOSAdapter")
        self._traffic_collector = MacOSTrafficCollector(adapter_name="MacOSAdapter")
        self._dns_collector = MacOSDnsCollector(adapter_name="MacOSAdapter")

        self._detect_capabilities()

    # ------------------------------------------------------------------
    # NetworkAdapter interface — metadata
    # ------------------------------------------------------------------

    def get_adapter_info(self) -> AdapterInfo:
        return AdapterInfo(
            adapter_name="MacOSAdapter",
            os_name=self.OS_DISPLAY_NAME,
            os_version=self._system_info.os_version,
            description=(
                "macOS network telemetry adapter. "
                "Continuously collects connection snapshots via psutil, "
                "interface traffic counters with deltas, and process associations."
            ),
            milestone="2",
        )

    # ------------------------------------------------------------------
    # Capability discovery
    # ------------------------------------------------------------------

    def discover_capabilities(self) -> CapabilityReport:
        """Return the cached capability report."""
        assert self._capability_report is not None
        return self._capability_report

    def _detect_capabilities(self) -> None:
        report = CapabilityReport(
            adapter_name="MacOSAdapter",
            os_name=self.OS_DISPLAY_NAME,
        )

        ne_cap = self._check_network_extension()

        # --- Network Extension (always False from Python) ---
        report.capabilities["network_extension"] = ne_cap.available
        report.add_note(
            f"Network Extension: {ne_cap.unavailability_reason}"
        )

        # --- psutil ---
        report.capabilities["psutil"] = ne_cap.psutil_available
        if not ne_cap.psutil_available:
            report.add_note(
                "psutil is not installed.  Install it with: pip install psutil.  "
                "Without psutil, connection and traffic collection will not be "
                "available at this milestone."
            )

        # --- netstat ---
        report.capabilities["netstat"] = ne_cap.netstat_available
        if not ne_cap.netstat_available:
            report.add_note(
                "netstat binary not found at /usr/sbin/netstat or on PATH.  "
                "This is unexpected on macOS."
            )

        # --- lsof ---
        report.capabilities["lsof"] = ne_cap.lsof_available
        if not ne_cap.lsof_available:
            report.add_note("lsof binary not found; process-socket mapping via lsof unavailable.")

        # --- dtrace ---
        report.capabilities["dtrace"] = ne_cap.dtrace_available
        report.capabilities["dtrace_usable"] = ne_cap.dtrace_usable
        if ne_cap.dtrace_available and not ne_cap.dtrace_usable:
            report.add_note(
                "dtrace binary is present but usable only as root.  "
                "Current process is not root; dtrace-based telemetry is unavailable."
            )

        # --- pf_log ---
        report.capabilities["pf_log"] = ne_cap.pf_log_available

        # --- eBPF (N/A on macOS) ---
        report.capabilities["ebpf"] = False
        report.add_note("eBPF is a Linux kernel feature and is not available on macOS.")

        # --- ip_helper (N/A on macOS) ---
        report.capabilities["ip_helper"] = False
        report.add_note("ip_helper (Windows IP Helper API) is not applicable on macOS.")

        # --- Collector status (Milestone 2: implemented) ---
        conn_status = CollectorStatus.AVAILABLE if ne_cap.psutil_available else CollectorStatus.UNAVAILABLE
        traffic_status = CollectorStatus.AVAILABLE if ne_cap.psutil_available else CollectorStatus.UNAVAILABLE
        proc_status = CollectorStatus.AVAILABLE if ne_cap.psutil_available else CollectorStatus.UNAVAILABLE

        dns_status = self._dns_collector.status
        dns_reason = self._dns_collector.status_reason

        report.collectors = [
            CollectorInfo(
                name="connections",
                status=conn_status,
                reason=(
                    "Continuous connection monitoring via psutil snapshot diffing. "
                    "Note: Sub-second ephemeral connections between poll ticks may be missed."
                ) if conn_status == CollectorStatus.AVAILABLE else "psutil required",
            ),
            CollectorInfo(
                name="traffic",
                status=traffic_status,
                reason=(
                    "Interface traffic monitoring via psutil (cumulative & deltas). "
                    "Zero-change intervals suppressed."
                ) if traffic_status == CollectorStatus.AVAILABLE else "psutil required",
            ),
            CollectorInfo(
                name="dns",
                status=dns_status,
                reason=dns_reason,
            ),
            CollectorInfo(
                name="process_network_activity",
                status=proc_status,
                reason=(
                    "Process attribution for open sockets via psutil. "
                    "Restricted to current user without root."
                ) if proc_status == CollectorStatus.AVAILABLE else "psutil required",
            ),
        ]

        self._capability_report = report

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        super().start()

    def stop(self) -> None:
        super().stop()
        if hasattr(self, "_dns_collector"):
            self._dns_collector.close()

    # ------------------------------------------------------------------
    # Collectors (Milestone 2)
    # ------------------------------------------------------------------

    def collect_connections(self) -> list[ConnectionEvent]:
        self._assert_running()
        conns, proc_events = self._connection_collector.collect()
        self._pending_process_events.extend(proc_events)
        return conns

    def collect_traffic(self) -> list[TrafficEvent]:
        self._assert_running()
        return self._traffic_collector.collect()

    def collect_dns(self) -> list[DnsEvent]:
        self._assert_running()
        return self._dns_collector.collect()

    def collect_process_network_activity(self) -> list[ProcessNetworkEvent]:
        self._assert_running()
        events = list(self._pending_process_events)
        self._pending_process_events.clear()
        return events

    # ------------------------------------------------------------------
    # Internal capability probes
    # ------------------------------------------------------------------

    @staticmethod
    def _check_network_extension():
        """Run the Network Extension capability probe and return the result."""
        from network_monitor.adapters.macos.network_extension.capability import detect
        return detect()
