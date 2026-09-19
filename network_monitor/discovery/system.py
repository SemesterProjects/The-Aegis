"""
discovery/system.py
===================
System Discovery for AEGIS Network Monitor.

Probes the current execution environment and returns a structured
``SystemInfo`` object that the Adapter Factory and OS adapters can
interrogate to make evidence-based capability decisions.

Design rules:
- No capability is assumed from the OS name alone.
- Individual probes are isolated; a failure in one does not abort the rest.
- All results are populated from actual runtime detection.
- This module is OS-independent: it will run on Linux, Windows, and macOS
  without modification.
"""

from __future__ import annotations

import os
import platform
import socket
import sys
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Result structures
# ---------------------------------------------------------------------------


@dataclass
class NetworkInterfaceInfo:
    """Minimal information about a single network interface."""

    name: str
    addresses: list[str] = field(default_factory=list)    # IPv4/IPv6 addresses
    is_up: Optional[bool] = None


@dataclass
class PrivilegeInfo:
    """
    Privilege level of the current process.

    On Unix-like systems, ``is_root`` reflects whether the effective UID is 0.
    On Windows, ``is_admin`` reflects the result of the IsUserAnAdmin check.
    Both may be ``None`` if the probe could not be performed.
    """

    is_root: Optional[bool] = None     # Unix: effective UID == 0
    is_admin: Optional[bool] = None    # Windows: IsUserAnAdmin()
    effective_uid: Optional[int] = None   # Unix only
    effective_gid: Optional[int] = None   # Unix only


@dataclass
class SystemInfo:
    """
    Structured snapshot of the execution environment.

    Produced by ``SystemDiscovery.discover()``.  Consumers should treat
    ``None`` values as "could not be determined" rather than "not applicable".
    """

    # Operating system
    os_name: str = "unknown"             # e.g. "Linux", "Windows", "Darwin"
    os_version: str = "unknown"          # full version string
    os_release: str = "unknown"          # e.g. "22.04" on Ubuntu, "10" on Windows
    os_edition: Optional[str] = None     # e.g. "Home", "Pro", "Server" on Windows

    # Hardware / interpreter
    architecture: str = "unknown"        # e.g. "x86_64", "arm64"
    machine: str = "unknown"             # platform.machine()
    hostname: str = "unknown"
    python_version: str = "unknown"      # e.g. "3.12.2"
    python_implementation: str = "unknown"  # e.g. "CPython"

    # Network
    network_interfaces: list[NetworkInterfaceInfo] = field(default_factory=list)

    # Privileges
    privilege: PrivilegeInfo = field(default_factory=PrivilegeInfo)

    # Raw platform data for adapter-level deep inspection
    raw_platform: dict[str, Any] = field(default_factory=dict)

    # Discovery metadata
    psutil_available: bool = False
    discovery_errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Discovery engine
# ---------------------------------------------------------------------------


class SystemDiscovery:
    """
    Probes the live execution environment.

    Each probe is wrapped in its own try/except so that partial failures
    are recorded without aborting the whole discovery pass.

    Usage::

        info = SystemDiscovery().discover()
        print(info.os_name, info.architecture)
    """

    def discover(self) -> SystemInfo:
        """
        Run all probes and return a populated ``SystemInfo`` object.

        Never raises.  Probe failures are recorded in
        ``SystemInfo.discovery_errors``.
        """
        info = SystemInfo()

        self._probe_os(info)
        self._probe_python(info)
        self._probe_hostname(info)
        self._probe_architecture(info)
        self._probe_network_interfaces(info)
        self._probe_privileges(info)
        self._probe_raw_platform(info)

        return info

    # ------------------------------------------------------------------
    # Individual probes
    # ------------------------------------------------------------------

    def _probe_os(self, info: SystemInfo) -> None:
        try:
            info.os_name = platform.system() or "unknown"
            info.os_release = platform.release() or "unknown"
            info.os_version = platform.version() or "unknown"

            # Windows edition is surfaced separately by platform.win32_edition()
            # (Python 3.8+); fall back gracefully on other platforms.
            if info.os_name == "Windows":
                try:
                    info.os_edition = platform.win32_edition()
                except AttributeError:
                    info.os_edition = None
        except Exception as exc:  # noqa: BLE001
            info.discovery_errors.append(f"os_probe: {exc}")

    def _probe_python(self, info: SystemInfo) -> None:
        try:
            info.python_version = platform.python_version()
            info.python_implementation = platform.python_implementation()
        except Exception as exc:  # noqa: BLE001
            info.discovery_errors.append(f"python_probe: {exc}")

    def _probe_hostname(self, info: SystemInfo) -> None:
        try:
            info.hostname = socket.gethostname()
        except Exception as exc:  # noqa: BLE001
            info.discovery_errors.append(f"hostname_probe: {exc}")

    def _probe_architecture(self, info: SystemInfo) -> None:
        try:
            # platform.machine() gives the hardware type; platform.architecture()
            # gives the Python binary bitness which is less useful here.
            info.machine = platform.machine() or "unknown"
            info.architecture = info.machine
        except Exception as exc:  # noqa: BLE001
            info.discovery_errors.append(f"architecture_probe: {exc}")

    def _probe_network_interfaces(self, info: SystemInfo) -> None:
        """
        Enumerate network interfaces.

        Preferred source: psutil (richer data).
        Fallback: socket.getaddrinfo on the hostname (limited but stdlib-only).
        """
        psutil_available = self._check_psutil_available()
        info.psutil_available = psutil_available

        if psutil_available:
            self._probe_interfaces_via_psutil(info)
        else:
            self._probe_interfaces_via_socket(info)

    def _probe_interfaces_via_psutil(self, info: SystemInfo) -> None:
        try:
            import psutil  # type: ignore[import]

            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()

            for iface_name, addr_list in net_if_addrs.items():
                addresses: list[str] = []
                for addr in addr_list:
                    # AF_INET = 2, AF_INET6 = 10/30 depending on OS
                    # psutil uses socket.AddressFamily; we just check the name.
                    family_name = addr.family.name if hasattr(addr.family, "name") else str(addr.family)
                    if "INET" in family_name:
                        addresses.append(addr.address)

                stats = net_if_stats.get(iface_name)
                is_up = stats.isup if stats is not None else None

                info.network_interfaces.append(
                    NetworkInterfaceInfo(
                        name=iface_name,
                        addresses=addresses,
                        is_up=is_up,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            info.discovery_errors.append(f"psutil_interfaces: {exc}")

    def _probe_interfaces_via_socket(self, info: SystemInfo) -> None:
        """
        Fallback interface probe when psutil is absent.

        Uses socket.getaddrinfo on the local hostname to discover at least
        the primary interface address.  This is deliberately limited but
        honest about what it can detect without psutil.
        """
        try:
            hostname = socket.gethostname()
            results = socket.getaddrinfo(hostname, None)
            seen: set[str] = set()
            for res in results:
                addr = res[4][0]
                if addr not in seen and not addr.startswith("127."):
                    seen.add(addr)
                    info.network_interfaces.append(
                        NetworkInterfaceInfo(name="(via socket)", addresses=[addr])
                    )
        except Exception as exc:  # noqa: BLE001
            info.discovery_errors.append(f"socket_interfaces: {exc}")
            # Ensure at least loopback is recorded
            info.network_interfaces.append(
                NetworkInterfaceInfo(name="loopback", addresses=["127.0.0.1"])
            )

    def _probe_privileges(self, info: SystemInfo) -> None:
        """
        Probe the privilege level of the current process.

        Unix: checks effective UID (0 = root).
        Windows: calls IsUserAnAdmin via ctypes.
        Partial failures are recorded; the other platform's fields remain None.
        """
        priv = PrivilegeInfo()

        # --- Unix-like (Linux, macOS) ---
        if hasattr(os, "geteuid"):
            try:
                priv.effective_uid = os.geteuid()
                priv.effective_gid = os.getegid()
                priv.is_root = (priv.effective_uid == 0)
            except Exception as exc:  # noqa: BLE001
                info.discovery_errors.append(f"unix_priv_probe: {exc}")

        # --- Windows ---
        if platform.system() == "Windows":
            try:
                import ctypes
                priv.is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception as exc:  # noqa: BLE001
                info.discovery_errors.append(f"windows_admin_probe: {exc}")

        info.privilege = priv

    def _probe_raw_platform(self, info: SystemInfo) -> None:
        """Capture raw platform data for adapter-level inspection."""
        try:
            info.raw_platform = {
                "system": platform.system(),
                "node": platform.node(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python_build": platform.python_build(),
                "python_compiler": platform.python_compiler(),
                "python_branch": platform.python_branch(),
                "uname": platform.uname()._asdict(),
            }
        except Exception as exc:  # noqa: BLE001
            info.discovery_errors.append(f"raw_platform: {exc}")

    @staticmethod
    def _check_psutil_available() -> bool:
        """Return True if psutil can be imported, False otherwise."""
        try:
            import psutil  # type: ignore[import]  # noqa: F401
            return True
        except ImportError:
            return False
