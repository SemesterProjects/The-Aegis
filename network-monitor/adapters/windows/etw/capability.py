"""
adapters/windows/etw/capability.py
====================================
ETW (Event Tracing for Windows) capability detection for the Windows adapter.

ETW is Windows' kernel-level event tracing infrastructure.  At this
prototype stage the following is important to understand:

  ETW CANNOT be fully used from a pure Python prototype.

Consuming ETW network sessions (Microsoft-Windows-NDIS-PacketCapture,
Microsoft-Windows-Kernel-Network, etc.) requires:

  - A real-time ETW consumer implemented in C/C++ or via a compiled
    Windows API wrapper.
  - The 'pyetw' or 'pywintrace' Python package, which is an optional
    thin wrapper that must be installed separately and does not expose
    the full raw-packet ETW provider surface.
  - Administrator privilege.

This module honestly detects what is actually available and documents the
limitation so that future milestone work can build the correct integration.
It does NOT fake ETW capability.
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EtwCapability:
    """
    Result of an ETW availability probe on Windows.

    Attributes
    ----------
    available:
        True only when ALL of the following are true:
        - ``is_windows``
        - ``is_admin``
        - ``python_package_available``
        Even when True, ETW network telemetry in a Python-only prototype
        is limited; see ``prototype_limitation_note``.

    is_windows:
        True if platform.system() == "Windows".

    is_admin:
        True if the process has Administrator privilege.

    is_admin_detection_error:
        True if the admin check itself failed (e.g. ctypes unavailable).

    python_package_available:
        True if a supported Python ETW wrapper (pyetw or pywintrace) is
        importable.

    python_package_name:
        Name of the importable package, or None.

    ip_helper_available:
        True if the Windows IP Helper API (iphlpapi.dll) is accessible via
        ctypes.  This is a lighter-weight alternative for connection/socket
        enumeration without full ETW.

    prototype_limitation_note:
        Documents the architectural gap between what this Python prototype
        can do and what full ETW-based network monitoring would require.

    unavailability_reasons:
        Human-readable list of reasons why ETW is not fully available.

    detection_errors:
        Errors encountered during the detection probes.
    """

    available: bool = False
    is_windows: bool = False
    is_admin: Optional[bool] = None
    is_admin_detection_error: bool = False
    python_package_available: bool = False
    python_package_name: Optional[str] = None
    ip_helper_available: bool = False
    unavailability_reasons: list[str] = field(default_factory=list)
    detection_errors: list[str] = field(default_factory=list)
    prototype_limitation_note: str = (
        "Full ETW network telemetry (e.g. Microsoft-Windows-Kernel-Network provider) "
        "requires a compiled native consumer or a C extension.  "
        "A pure-Python prototype can use pyetw/pywintrace for a limited subset of "
        "ETW events, but cannot consume raw kernel network ETW sessions.  "
        "This limitation is intentional and must be addressed in a future milestone "
        "via a compiled Windows service or Cython/ctypes integration."
    )


def detect() -> EtwCapability:
    """
    Probe ETW availability.  Never raises.

    Returns a fully populated ``EtwCapability`` dataclass.
    """
    result = EtwCapability()

    # 1. Platform check
    result.is_windows = platform.system() == "Windows"
    if not result.is_windows:
        result.unavailability_reasons.append(
            "Not running on Windows; ETW is a Windows-only kernel feature."
        )
        return result

    # 2. Administrator check
    _probe_admin(result)

    # 3. Python ETW package
    _probe_python_etw_package(result)

    # 4. IP Helper (lighter alternative)
    _probe_ip_helper(result)

    # 5. Compute summary
    result.available = (
        result.is_windows
        and bool(result.is_admin)
        and result.python_package_available
    )

    if not result.available:
        _add_unavailability_reasons(result)

    return result


# ---------------------------------------------------------------------------
# Internal probes
# ---------------------------------------------------------------------------


def _probe_admin(result: EtwCapability) -> None:
    try:
        import ctypes
        result.is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except AttributeError:
        # windll or shell32 not available
        result.is_admin = None
        result.is_admin_detection_error = True
        result.detection_errors.append(
            "ctypes.windll.shell32.IsUserAnAdmin() is not accessible.  "
            "Cannot determine administrator status."
        )
    except Exception as exc:  # noqa: BLE001
        result.is_admin = None
        result.is_admin_detection_error = True
        result.detection_errors.append(f"admin_probe: {exc}")


def _probe_python_etw_package(result: EtwCapability) -> None:
    for pkg_name in ("pyetw", "pywintrace"):
        try:
            __import__(pkg_name)
            result.python_package_available = True
            result.python_package_name = pkg_name
            return
        except ImportError:
            pass
        except Exception as exc:  # noqa: BLE001
            result.detection_errors.append(f"etw_package_probe({pkg_name}): {exc}")

    result.python_package_available = False
    result.python_package_name = None


def _probe_ip_helper(result: EtwCapability) -> None:
    """
    Check if the Windows IP Helper API (iphlpapi.dll) is accessible.

    IP Helper provides connection enumeration via GetExtendedTcpTable /
    GetExtendedUdpTable, which is lighter than ETW and sufficient for
    connection-level telemetry without packet-level access.
    """
    try:
        import ctypes
        import ctypes.wintypes

        # Attempt to load the DLL — this succeeds on any modern Windows.
        iphlpapi = ctypes.windll.LoadLibrary("iphlpapi.dll")
        # Verify at least one relevant function is present.
        _ = iphlpapi.GetExtendedTcpTable
        result.ip_helper_available = True
    except (AttributeError, OSError, Exception) as exc:  # noqa: BLE001
        result.ip_helper_available = False
        result.detection_errors.append(f"ip_helper_probe: {exc}")


def _add_unavailability_reasons(result: EtwCapability) -> None:
    if not result.is_admin and not result.is_admin_detection_error:
        result.unavailability_reasons.append(
            "Process does not have Administrator privilege.  "
            "ETW real-time consumers require elevated rights.  "
            "Re-run as Administrator."
        )
    if result.is_admin_detection_error:
        result.unavailability_reasons.append(
            "Administrator status could not be determined."
        )
    if not result.python_package_available:
        result.unavailability_reasons.append(
            "No Python ETW wrapper (pyetw, pywintrace) is installed.  "
            "Install one to enable ETW event consumption: "
            "'pip install pyetw' or 'pip install pywintrace'."
        )
    result.unavailability_reasons.append(
        "Prototype limitation: see prototype_limitation_note for architectural gap."
    )
