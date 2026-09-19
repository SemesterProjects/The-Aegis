"""
adapters/macos/network_extension/capability.py
===============================================
macOS Network Extension capability detection.

THE FUNDAMENTAL LIMITATION — READ THIS FIRST:
---------------------------------------------
Apple's Network Extension framework (NEFilterDataProvider,
NEAppProxyProvider, etc.) is a KERNEL EXTENSION entitlement.  It requires:

  1. A code-signed System Extension (*.systemextension bundle).
  2. An explicit entitlement granted by Apple
     (com.apple.developer.network-extension.system-extension).
  3. Installation via OSSystemExtensionRequest.
  4. User approval through the macOS System Settings UI.

NONE of the above can be satisfied by a Python script.  Python cannot
load, sign, or install a System Extension.  There is no "import" statement
that gives Python access to this API.

This module detects whether the host is macOS and what alternative
observation mechanisms ARE available to a Python process:

  - psutil: cross-platform connection/traffic enumeration (no packet data).
  - netstat: BSD utility available on macOS (/usr/sbin/netstat).
  - lsof:   list open files/sockets (/usr/sbin/lsof).
  - dtrace: DTrace framework; requires SIP disabled or root + entitlement.
  - pf_log: Packet Filter log interface; requires root and PF enabled.

The ``available`` flag on ``NetworkExtensionCapability`` will always be
``False`` in a Python-only prototype and documents the reason clearly.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NetworkExtensionCapability:
    """
    Result of the macOS Network Extension availability probe.

    The ``available`` field will always be ``False`` from a Python process.
    The remaining fields describe what fallback mechanisms ARE accessible.
    """

    # Network Extension status (always False from Python — see module docstring)
    available: bool = False
    unavailability_reason: str = (
        "macOS Network Extension (NEFilterDataProvider / NEAppProxyProvider) "
        "requires a code-signed System Extension bundle with an Apple-granted "
        "entitlement.  This cannot be loaded from a Python process.  "
        "Network monitoring on macOS will use supported fallback mechanisms."
    )

    # Platform context
    is_macos: bool = False
    macos_version: Optional[str] = None   # e.g. "14.4.1" (Sonoma)

    # Privilege
    is_root: Optional[bool] = None
    effective_uid: Optional[int] = None

    # Available fallback mechanisms
    psutil_available: bool = False
    netstat_available: bool = False
    lsof_available: bool = False
    dtrace_available: bool = False     # dtrace binary present on PATH
    dtrace_usable: bool = False        # dtrace + root (SIP restrictions aside)
    pf_log_available: bool = False     # /dev/pflog0 exists

    # Errors encountered during detection
    detection_errors: list[str] = field(default_factory=list)


def detect() -> NetworkExtensionCapability:
    """
    Probe macOS network observation capabilities.  Never raises.

    Returns a fully populated ``NetworkExtensionCapability`` dataclass.
    The ``available`` (Network Extension) field is always ``False``.
    """
    result = NetworkExtensionCapability()

    # 1. Platform check
    result.is_macos = platform.system() == "Darwin"
    if not result.is_macos:
        return result   # All False — this probe is meaningless off macOS

    # 2. macOS version
    _probe_macos_version(result)

    # 3. Privilege
    _probe_privilege(result)

    # 4. Fallback mechanisms
    _probe_psutil(result)
    _probe_binary(result, "netstat", "/usr/sbin/netstat", "netstat_available")
    _probe_binary(result, "lsof",    "/usr/sbin/lsof",    "lsof_available")
    _probe_dtrace(result)
    _probe_pf_log(result)

    # Network Extension: always False — reason already set in field default.
    result.available = False

    return result


# ---------------------------------------------------------------------------
# Internal probes
# ---------------------------------------------------------------------------


def _probe_macos_version(result: NetworkExtensionCapability) -> None:
    try:
        result.macos_version = platform.mac_ver()[0] or None
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"macos_version_probe: {exc}")


def _probe_privilege(result: NetworkExtensionCapability) -> None:
    try:
        result.effective_uid = os.geteuid()
        result.is_root = (result.effective_uid == 0)
    except AttributeError:
        result.detection_errors.append("os.geteuid() unavailable.")
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"privilege_probe: {exc}")


def _probe_psutil(result: NetworkExtensionCapability) -> None:
    try:
        import psutil  # type: ignore[import]  # noqa: F401
        result.psutil_available = True
    except ImportError:
        result.psutil_available = False
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"psutil_probe: {exc}")


def _probe_binary(
    result: NetworkExtensionCapability,
    name: str,
    preferred_path: str,
    attr: str,
) -> None:
    """Check if a binary is available at its expected path or on PATH."""
    try:
        found = os.path.isfile(preferred_path) or shutil.which(name) is not None
        setattr(result, attr, found)
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"{name}_probe: {exc}")


def _probe_dtrace(result: NetworkExtensionCapability) -> None:
    """
    Check dtrace binary presence and whether it's usable.

    dtrace on modern macOS (Big Sur+) requires System Integrity Protection
    (SIP) to be partially disabled for kernel probes, OR a specific
    entitlement.  We can only reliably report that the binary exists.
    Actual usability requires a runtime attempt.
    """
    try:
        dtrace_path = shutil.which("dtrace") or "/usr/sbin/dtrace"
        result.dtrace_available = os.path.isfile(dtrace_path)
        # dtrace is practically usable only as root
        result.dtrace_usable = result.dtrace_available and bool(result.is_root)
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"dtrace_probe: {exc}")


def _probe_pf_log(result: NetworkExtensionCapability) -> None:
    """Check if the Packet Filter log interface exists."""
    try:
        result.pf_log_available = os.path.exists("/dev/pflog0")
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"pf_log_probe: {exc}")
