"""
adapters/windows/adapter.py
============================
Windows-specific Network Monitor adapter.

Detects capabilities available on the current Windows system and exposes
them through the standard ``NetworkAdapter`` interface.

Milestone 1 status:
-------------------
  - System discovery and capability detection: IMPLEMENTED
  - Connection collector (psutil / IP Helper fallback): NOT YET IMPLEMENTED
  - Traffic collector (psutil.net_io_counters): NOT YET IMPLEMENTED
  - DNS collector (ETW or fallback): NOT YET IMPLEMENTED
  - Process network activity collector: NOT YET IMPLEMENTED

All not-yet-implemented collectors raise ``CollectorNotImplementedError``
rather than returning empty data, so callers can distinguish "no activity"
from "collector not built yet".

ETW limitation note:
--------------------
Full ETW-based kernel network telemetry (Microsoft-Windows-Kernel-Network
provider) cannot be consumed from a pure Python process.  See the ETW
capability module for the detailed architectural note.
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
from network_monitor.adapters.windows.connections import WindowsConnectionCollector
from network_monitor.adapters.windows.dns import WindowsDnsCollector
from network_monitor.adapters.windows.traffic import WindowsTrafficCollector
from network_monitor.discovery.system import SystemInfo


class WindowsAdapter(NetworkAdapter):
    """
    Network Monitor adapter for Windows hosts.

    Capability detection strategy:
    - psutil:        import probe.
    - etw:           checks admin privilege + Python ETW package availability.
    - ip_helper:     checks iphlpapi.dll accessibility via ctypes.
    - winpcap_npcap: checks for a packet-capture library (informational).
    """

    OS_NAME = "Windows"

    def __init__(self, system_info: SystemInfo) -> None:
        super().__init__()
        self._system_info = system_info
        self._capability_report: Optional[CapabilityReport] = None
        self._pending_process_events: list[ProcessNetworkEvent] = []

        # Instantiate Milestone 2 collectors
        self._connection_collector = WindowsConnectionCollector(adapter_name="WindowsAdapter")
        self._traffic_collector = WindowsTrafficCollector(adapter_name="WindowsAdapter")
        self._dns_collector = WindowsDnsCollector(adapter_name="WindowsAdapter")

        self._detect_capabilities()

    # ------------------------------------------------------------------
    # NetworkAdapter interface — metadata
    # ------------------------------------------------------------------

    def get_adapter_info(self) -> AdapterInfo:
        return AdapterInfo(
            adapter_name="WindowsAdapter",
            os_name=self.OS_NAME,
            os_version=self._system_info.os_version,
            description=(
                "Windows network telemetry adapter. "
                "Continuously collects connection snapshots, interface traffic counters with deltas, "
                "DNS activity (where permitted), and associates network sockets with processes."
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
            adapter_name="WindowsAdapter",
            os_name=self.OS_NAME,
        )

        # --- psutil ---
        psutil_ok = self._check_psutil()
        report.capabilities["psutil"] = psutil_ok
        if not psutil_ok:
            report.add_note(
                "psutil is not installed.  Install it with: pip install psutil.  "
                "Without psutil, connection and traffic collection will not be available "
                "at this milestone."
            )

        # --- ETW ---
        etw_cap = self._check_etw()
        report.capabilities["etw"] = etw_cap.available
        report.capabilities["etw_admin"] = bool(etw_cap.is_admin)
        report.capabilities["etw_python_package"] = etw_cap.python_package_available
        report.add_note(f"ETW prototype limitation: {etw_cap.prototype_limitation_note}")
        for reason in etw_cap.unavailability_reasons:
            report.add_note(f"ETW: {reason}")

        # --- IP Helper ---
        report.capabilities["ip_helper"] = etw_cap.ip_helper_available
        if not etw_cap.ip_helper_available:
            report.add_note(
                "IP Helper (iphlpapi.dll) could not be accessed via ctypes.  "
                "This is unexpected on Windows; connection enumeration may not work."
            )

        # --- WinPcap / Npcap (informational; not used in Milestone 1) ---
        winpcap_ok = self._check_winpcap_npcap()
        report.capabilities["winpcap_npcap"] = winpcap_ok
        if not winpcap_ok:
            report.add_note(
                "No packet-capture library (WinPcap/Npcap Python binding) detected.  "
                "Packet-level capture is not planned for the Network Monitor "
                "(payload collection is out of scope), but Npcap can assist with "
                "interface enumeration."
            )

        # --- eBPF (N/A on Windows) ---
        report.capabilities["ebpf"] = False
        report.add_note("eBPF is a Linux kernel feature and is not applicable on Windows.")

        # --- Collector status (Milestone 2: implemented) ---
        conn_status = CollectorStatus.AVAILABLE if psutil_ok else CollectorStatus.UNAVAILABLE
        traffic_status = CollectorStatus.AVAILABLE if psutil_ok else CollectorStatus.UNAVAILABLE
        proc_status = CollectorStatus.AVAILABLE if psutil_ok else CollectorStatus.UNAVAILABLE

        dns_status = self._dns_collector.status
        dns_reason = self._dns_collector.status_reason

        report.collectors = [
            CollectorInfo(
                name="connections",
                status=conn_status,
                reason=(
                    "Continuous connection monitoring via psutil snapshot diffing and IP Helper. "
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
                    "Associates socket connections with PID, process name, and executable path. "
                    "AccessDenied handled gracefully."
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
    # Collectors (Milestone 2 implementation)
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
    def _check_psutil() -> bool:
        try:
            import psutil  # type: ignore[import]  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def _check_etw():
        """Run the ETW capability probe and return the result."""
        from network_monitor.adapters.windows.etw.capability import detect
        return detect()

    @staticmethod
    def _check_winpcap_npcap() -> bool:
        """
        Check if a WinPcap/Npcap Python binding is importable.

        This is purely informational.  The Network Monitor does not use
        packet capture; payload collection is out of scope.
        """
        for pkg in ("pcapy", "pypcap", "scapy"):
            try:
                __import__(pkg)
                return True
            except ImportError:
                pass
            except Exception:  # noqa: BLE001
                pass
        return False
