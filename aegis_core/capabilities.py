"""Runtime platform discovery and conservative collector selection."""
from __future__ import annotations

from dataclasses import dataclass
import os
import platform
import shutil
from typing import FrozenSet


@dataclass(frozen=True, slots=True)
class HostCapabilities:
    os_name: str
    release: str
    machine: str
    is_elevated: bool
    features: FrozenSet[str]
    limitations: tuple[str, ...]


def discover_capabilities() -> HostCapabilities:
    """Discover only what can be honestly established on the current host."""
    os_name = platform.system()
    features: set[str] = {"process_snapshot", "file_polling", "sqlite_store"}
    limitations: list[str] = []
    if os_name == "Linux":
        if os.path.exists("/proc"):
            features.add("procfs")
        if shutil.which("journalctl"):
            features.add("journalctl")
        elevated = os.geteuid() == 0
        if not elevated:
            limitations.append("process details may be restricted without CAP_SYS_PTRACE")
    elif os_name == "Windows":
        elevated = _windows_is_admin()
        if shutil.which("powershell") or shutil.which("powershell.exe"):
            features.add("powershell")
        features.add("etw_capability_probe")
        limitations.append("ETW consumption requires a dedicated, signed Windows implementation")
    elif os_name == "Darwin":
        elevated = os.geteuid() == 0
        features.add("endpoint_security_capability_probe")
        limitations.append("Endpoint Security requires Apple-granted entitlement and a system extension")
    else:
        elevated = False
        limitations.append(f"unsupported OS: {os_name}")
    try:
        import psutil  # noqa: F401
        features.add("psutil")
    except ImportError:
        limitations.append("psutil unavailable; using standard-library fallbacks")
    return HostCapabilities(os_name, platform.release(), platform.machine(), elevated,
                            frozenset(features), tuple(limitations))


def _windows_is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # capability detection must never stop monitoring
        return False
