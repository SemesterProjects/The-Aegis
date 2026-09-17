"""
discovery/__init__.py
=====================
Public re-exports for the AEGIS Network Monitor discovery package.
"""

from network_monitor.discovery.system import (
    NetworkInterfaceInfo,
    PrivilegeInfo,
    SystemDiscovery,
    SystemInfo,
)

__all__ = [
    "SystemDiscovery",
    "SystemInfo",
    "NetworkInterfaceInfo",
    "PrivilegeInfo",
]
