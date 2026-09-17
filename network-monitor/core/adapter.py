"""
core/adapter.py
===============
Abstract base class for all AEGIS Network Monitor OS adapters.

Every OS-specific adapter (Linux, Windows, macOS) MUST subclass
``NetworkAdapter`` and implement its interface.  The core and sensors layer
interact ONLY through this interface — they never import OS-specific adapter
classes directly.

Design rules:
- This file must remain completely OS-independent.
- No platform, ctypes, or OS-specific imports here.
- Concrete adapters override methods for the capabilities they support.
- Methods that are not yet implemented by a concrete adapter should NOT
  silently return empty data; they must raise ``CollectorNotImplementedError``
  so that callers can distinguish "no data" from "collector not built yet".
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from network_monitor.core.events import (
    CollectorInfo,
    CollectorStatus,
    ConnectionEvent,
    DnsEvent,
    ProcessNetworkEvent,
    TrafficEvent,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CollectorNotImplementedError(NotImplementedError):
    """
    Raised by an adapter method that has not yet been built.

    This is intentionally distinct from Python's built-in ``NotImplementedError``
    so that callers can specifically catch and handle the "not yet implemented"
    case without masking genuine programming errors.
    """

    def __init__(self, adapter_name: str, collector_name: str) -> None:
        self.adapter_name = adapter_name
        self.collector_name = collector_name
        super().__init__(
            f"[{adapter_name}] The '{collector_name}' collector has not been "
            f"implemented yet.  It is planned for a future milestone."
        )


class AdapterNotRunningError(RuntimeError):
    """Raised when a collection method is called before ``start()``."""

    def __init__(self, adapter_name: str) -> None:
        super().__init__(
            f"[{adapter_name}] Adapter has not been started.  "
            f"Call start() before collecting data."
        )


# ---------------------------------------------------------------------------
# Capability report
# ---------------------------------------------------------------------------


@dataclass
class CapabilityReport:
    """
    Describes which observation mechanisms are available on the current system.

    Adapters populate this at init time via actual runtime detection.
    Callers must treat each field as a reflection of real detection, NOT
    an assumption.

    The ``collectors`` list enumerates each collector that the adapter knows
    about, together with its current status.
    """

    adapter_name: str = "unknown"
    os_name: str = "unknown"

    # High-level flags (populated by the concrete adapter)
    capabilities: dict[str, bool] = field(default_factory=dict)

    # Per-collector status
    collectors: list[CollectorInfo] = field(default_factory=list)

    # Human-readable notes (e.g. why a capability is absent)
    notes: list[str] = field(default_factory=list)

    def is_capable(self, capability_key: str) -> bool:
        """Return True only if the named capability was positively detected."""
        return self.capabilities.get(capability_key, False)

    def add_note(self, note: str) -> None:
        self.notes.append(note)


# ---------------------------------------------------------------------------
# Adapter information
# ---------------------------------------------------------------------------


@dataclass
class AdapterInfo:
    """Static metadata about an adapter."""

    adapter_name: str
    os_name: str
    os_version: Optional[str] = None
    description: str = ""
    milestone: str = "1"    # which milestone this adapter was introduced in


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class NetworkAdapter(ABC):
    """
    Common interface for all AEGIS Network Monitor OS adapters.

    Lifecycle
    ---------
    1. Instantiate the adapter (``__init__`` detects capabilities).
    2. Call ``discover_capabilities()`` to get the ``CapabilityReport``.
    3. Call ``start()`` to begin monitoring.
    4. Call collect_*() methods repeatedly to retrieve telemetry.
    5. Call ``stop()`` to release resources.

    Error contract
    --------------
    - ``collect_*`` methods that have NOT been implemented by the subclass
      MUST raise ``CollectorNotImplementedError``.
    - ``collect_*`` methods that ARE implemented but the capability is absent
      on this system MUST raise ``CollectorNotAvailableError`` or return an
      empty list with a logged warning (adapter's choice, but must not silently
      pretend to succeed).
    - Adapters must never fabricate telemetry.
    """

    def __init__(self) -> None:
        self._running: bool = False
        self._capability_report: Optional[CapabilityReport] = None

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @abstractmethod
    def get_adapter_info(self) -> AdapterInfo:
        """Return static metadata about this adapter."""
        ...

    # ------------------------------------------------------------------
    # Capability discovery
    # ------------------------------------------------------------------

    @abstractmethod
    def discover_capabilities(self) -> CapabilityReport:
        """
        Detect and return the capabilities available on the current system.

        This method is idempotent; calling it multiple times returns the
        same report (capabilities are detected once at init/first call and
        cached).

        Must not raise; detection failures should be captured in
        ``CapabilityReport.notes``.
        """
        ...

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Prepare the adapter for data collection.

        Default implementation sets the running flag.  Subclasses should
        call ``super().start()`` then perform their own initialisation.
        """
        self._running = True

    def stop(self) -> None:
        """
        Release resources and cease monitoring.

        Default implementation clears the running flag.  Subclasses should
        perform their own teardown then call ``super().stop()``.
        """
        self._running = False

    @property
    def is_running(self) -> bool:
        """True if ``start()`` has been called and ``stop()`` has not."""
        return self._running

    def get_collector_info(self, collector_name: str) -> Optional[CollectorInfo]:
        """Return the CollectorInfo for a specific collector name, or None if unknown."""
        report = self.discover_capabilities()
        for col in report.collectors:
            if col.name == collector_name:
                return col
        return None

    # ------------------------------------------------------------------
    # Collection methods
    # ------------------------------------------------------------------

    def collect_connections(self) -> list[ConnectionEvent]:
        """
        Return a snapshot of currently observable network connections.

        Raises ``CollectorNotImplementedError`` if not implemented by the
        concrete adapter.
        """
        raise CollectorNotImplementedError(
            self.get_adapter_info().adapter_name, "connections"
        )

    def collect_traffic(self) -> list[TrafficEvent]:
        """
        Return current network interface traffic statistics.

        Raises ``CollectorNotImplementedError`` if not implemented.
        """
        raise CollectorNotImplementedError(
            self.get_adapter_info().adapter_name, "traffic"
        )

    def collect_dns(self) -> list[DnsEvent]:
        """
        Return recently observed DNS transactions where available.

        Raises ``CollectorNotImplementedError`` if not implemented.
        """
        raise CollectorNotImplementedError(
            self.get_adapter_info().adapter_name, "dns"
        )

    def collect_process_network_activity(self) -> list[ProcessNetworkEvent]:
        """
        Return network activity attributed to specific processes.

        Requires OS-level permission to read process information.
        Raises ``CollectorNotImplementedError`` if not implemented.
        """
        raise CollectorNotImplementedError(
            self.get_adapter_info().adapter_name, "process_network_activity"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_running(self) -> None:
        """
        Guard used by collect_* implementations to enforce lifecycle order.
        """
        if not self._running:
            raise AdapterNotRunningError(self.get_adapter_info().adapter_name)
