"""
adapters/linux/adapter.py
==========================
Linux-specific Network Monitor adapter.

Detects capabilities available on the current Linux system and exposes them
through the standard ``NetworkAdapter`` interface.

Milestone 3 additions:
  - Attempts to load an eBPF TCP connection tracer on startup.
  - Reports actual eBPF load status (not just prerequisites) in the
    capability report.
  - Passes the live tracer to ``LinuxConnectionCollector`` for kernel-level
    event collection.
  - Gracefully falls back to polling-only mode if eBPF cannot be loaded.
  - Calls ``EbpfConnectionTracer.stop()`` on ``stop()`` to release kernel
    resources.

Milestone 1 + 2 architecture is preserved. No platform-specific conditionals
have been moved into core monitoring logic.
"""

from __future__ import annotations

import os
import platform
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
from network_monitor.adapters.linux.connections import LinuxConnectionCollector
from network_monitor.adapters.linux.dns import LinuxDnsCollector
from network_monitor.adapters.linux.traffic import LinuxTrafficCollector
from network_monitor.discovery.system import SystemInfo


class LinuxAdapter(NetworkAdapter):
    """
    Network Monitor adapter for Linux hosts.

    Capability detection strategy:
    - psutil: import probe (cross-platform, no privilege required).
    - eBPF:   actual load attempt via ebpf.loader (Milestone 3); reports
              real runtime status rather than theoretical prerequisites only.
    - proc_net: checks /proc/net/tcp readability.
    - ip_helper: N/A on Linux (Windows-only API); always False.

    eBPF Lifecycle:
    - ``__init__``: attempts ``load_connection_tracer()``; stores result.
    - ``_detect_capabilities()``: reports actual eBPF load status.
    - ``start()``: attaches live tracer to connection collector if available.
    - ``stop()``: calls ``EbpfConnectionTracer.stop()`` to release resources.
    """

    OS_NAME = "Linux"

    def __init__(self, system_info: SystemInfo) -> None:
        super().__init__()
        self._system_info = system_info
        self._capability_report: Optional[CapabilityReport] = None
        self._pending_process_events: list[ProcessNetworkEvent] = []

        # --- Attempt eBPF tracer load (Milestone 3) ---
        # This is done BEFORE collector construction so we can pass the tracer.
        self._ebpf_tracer = None
        self._ebpf_load_reason: str = ""
        self._try_load_ebpf()

        # --- Instantiate Milestone 2 collectors ---
        self._connection_collector = LinuxConnectionCollector(
            adapter_name="LinuxAdapter",
            ebpf_tracer=self._ebpf_tracer,  # None if eBPF unavailable
        )
        self._traffic_collector = LinuxTrafficCollector(adapter_name="LinuxAdapter")
        self._dns_collector = LinuxDnsCollector(adapter_name="LinuxAdapter")

        # Detect capabilities eagerly at construction time so that
        # discover_capabilities() is always fast and idempotent.
        self._detect_capabilities()

    # ------------------------------------------------------------------
    # NetworkAdapter interface — metadata
    # ------------------------------------------------------------------

    def get_adapter_info(self) -> AdapterInfo:
        ebpf_active = self._ebpf_tracer is not None
        return AdapterInfo(
            adapter_name="LinuxAdapter",
            os_name=self.OS_NAME,
            os_version=self._system_info.os_version,
            description=(
                "Linux network telemetry adapter (Milestone 3). "
                + (
                    "eBPF TCP connection tracing via sock:inet_sock_set_state tracepoint is ACTIVE. "
                    "Kernel-level events are supplemented by polling for UDP and long-lived connections."
                    if ebpf_active else
                    "eBPF tracer INACTIVE — using polling-only mode (psutil / /proc/net). "
                    f"Reason: {self._ebpf_load_reason or 'see capability notes.'}"
                )
            ),
            milestone="3",
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
            adapter_name="LinuxAdapter",
            os_name=self.OS_NAME,
        )

        # --- psutil ---
        psutil_ok = self._check_psutil()
        report.capabilities["psutil"] = psutil_ok
        if not psutil_ok:
            report.add_note(
                "psutil is not installed.  Install it with: pip install psutil.  "
                "Without psutil, connection and traffic collection will rely solely "
                "on /proc filesystem interfaces."
            )

        # --- eBPF prerequisite check ---
        ebpf_cap = self._check_ebpf()
        report.capabilities["ebpf_prerequisites"] = ebpf_cap.available
        report.capabilities["ebpf_kernel_sufficient"] = ebpf_cap.kernel_sufficient
        report.capabilities["ebpf_has_privilege"] = ebpf_cap.has_privilege
        report.capabilities["ebpf_python_binding"] = ebpf_cap.python_binding_available
        report.capabilities["ebpf_tracepoint_visible"] = ebpf_cap.tracepoint_available
        report.capabilities["ebpf_btf_available"] = ebpf_cap.btf_available

        # --- eBPF ACTUAL load status (Milestone 3: key distinction) ---
        ebpf_loaded = self._ebpf_tracer is not None
        report.capabilities["ebpf_loaded"] = ebpf_loaded
        if ebpf_loaded:
            report.add_note(
                "eBPF Connection Tracer: ACTIVE  "
                "(tracepoint: sock:inet_sock_set_state)  "
                "Kernel-level TCP state changes are observed in real time."
            )
        else:
            short = (self._ebpf_load_reason or "").split(".")[0]
            report.add_note(
                f"eBPF Connection Tracer: INACTIVE  "
                f"Reason: {short}.  Fallback: polling."
            )
            for reason in ebpf_cap.unavailability_reasons:
                report.add_note(f"eBPF prerequisite: {reason}")

        # --- /proc/net ---
        proc_net_ok = self._check_proc_net()
        report.capabilities["proc_net"] = proc_net_ok
        if not proc_net_ok:
            report.add_note(
                "/proc/net/tcp is not readable.  "
                "Connection enumeration via /proc will not be available."
            )

        # --- ip_helper (N/A on Linux) ---
        report.capabilities["ip_helper"] = False
        report.add_note("ip_helper (Windows IP Helper API) is not applicable on Linux.")

        # --- Collector status ---
        conn_ok = self._connection_collector.is_available
        traffic_ok = self._traffic_collector.is_available
        collector_mode = self._connection_collector.collector_mode

        conn_status = CollectorStatus.AVAILABLE if conn_ok else CollectorStatus.UNAVAILABLE
        traffic_status = CollectorStatus.AVAILABLE if traffic_ok else CollectorStatus.UNAVAILABLE
        proc_status = CollectorStatus.AVAILABLE if conn_ok else CollectorStatus.UNAVAILABLE

        dns_status = self._dns_collector.status
        dns_reason = self._dns_collector.status_reason

        # Build a rich description for the connections collector
        if conn_ok:
            if collector_mode == "ebpf+polling":
                conn_reason = (
                    "eBPF kernel tracing (sock:inet_sock_set_state) + polling baseline. "
                    "Sub-second ephemeral TCP connections are captured. "
                    "UDP connections covered by polling."
                )
            else:
                conn_reason = (
                    "Polling-only mode: continuous connection monitoring via psutil "
                    "snapshot diffing with /proc/net fallback. "
                    "Note: Sub-second ephemeral connections between poll ticks may be missed."
                )
        else:
            conn_reason = "psutil or /proc/net required"

        report.collectors = [
            CollectorInfo(
                name="connections",
                status=conn_status,
                reason=conn_reason,
            ),
            CollectorInfo(
                name="traffic",
                status=traffic_status,
                reason=(
                    "Interface traffic monitoring via psutil / /proc/net/dev (cumulative & deltas). "
                    "Zero-change intervals suppressed."
                ) if traffic_ok else "psutil or /proc/net/dev required",
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
                    "Socket process attribution via psutil and /proc/{pid}/comm. "
                    "Requires root/CAP_SYS_PTRACE for sockets owned by other users."
                ) if conn_ok else "psutil or /proc required",
            ),
        ]

        self._capability_report = report

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        super().start()
        # Tracer is already attached in __init__; nothing additional to start here.

    def stop(self) -> None:
        super().stop()
        # Stop eBPF tracer (releases kernel resources)
        if self._ebpf_tracer is not None:
            try:
                self._ebpf_tracer.stop()
            except Exception:
                pass
        # Stop DNS collector (closes file handles if any)
        if hasattr(self, "_dns_collector"):
            self._dns_collector.close()

    # ------------------------------------------------------------------
    # Collectors (Milestone 2 + 3)
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
    # Internal helpers
    # ------------------------------------------------------------------

    def _try_load_ebpf(self) -> None:
        """
        Attempt to load the eBPF connection tracer.  Never raises.

        Sets ``self._ebpf_tracer`` and ``self._ebpf_load_reason``.
        """
        try:
            from network_monitor.adapters.linux.ebpf.loader import (
                load_connection_tracer,
            )
            self._ebpf_tracer, self._ebpf_load_reason = load_connection_tracer()
        except Exception as exc:
            self._ebpf_tracer = None
            self._ebpf_load_reason = f"Loader import error: {exc}"

    @staticmethod
    def _check_psutil() -> bool:
        try:
            import psutil  # type: ignore[import]  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def _check_ebpf():
        """Run the eBPF capability probe and return the result."""
        from network_monitor.adapters.linux.ebpf.capability import detect
        return detect()

    @staticmethod
    def _check_proc_net() -> bool:
        """Return True if /proc/net/tcp exists and is readable."""
        try:
            with open("/proc/net/tcp", "r") as f:
                f.read(1)
            return True
        except (FileNotFoundError, PermissionError, OSError):
            return False
