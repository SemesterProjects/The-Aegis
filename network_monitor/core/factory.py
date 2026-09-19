"""
core/factory.py
===============
Adapter Factory for AEGIS Network Monitor.

This is the ONLY place in the codebase responsible for selecting and
instantiating the correct OS-specific adapter.  No other module should
contain OS dispatch logic.

Design rules:
- Accept a ``SystemInfo`` object produced by ``SystemDiscovery``.
- Read ``system_info.os_name`` to select the adapter class.
- Instantiate and return the adapter — do NOT call ``start()``.
- Raise ``UnsupportedOSError`` for unrecognised operating systems.
- Do NOT import any OS-specific monitoring logic here.
- OS adapter imports are deferred (inside the factory method) to avoid
  cross-platform import errors when the module is loaded on a mismatched OS.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from network_monitor.core.adapter import NetworkAdapter
    from network_monitor.discovery.system import SystemInfo


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class UnsupportedOSError(RuntimeError):
    """
    Raised when the factory cannot find an adapter for the detected OS.

    This is a hard failure: the Network Monitor cannot operate without a
    suitable adapter.  The error message identifies the detected OS and
    lists the operating systems that are currently supported.
    """

    SUPPORTED = ("Linux", "Windows", "Darwin")

    def __init__(self, os_name: str) -> None:
        self.os_name = os_name
        supported_str = ", ".join(self.SUPPORTED)
        super().__init__(
            f"No Network Monitor adapter exists for OS '{os_name}'.  "
            f"Supported operating systems: {supported_str}.  "
            f"To add support for '{os_name}', implement a NetworkAdapter "
            f"subclass in adapters/{os_name.lower()}/ and register it here."
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class AdapterFactory:
    """
    Instantiates the correct ``NetworkAdapter`` subclass for the current OS.

    Usage::

        from network_monitor.discovery.system import SystemDiscovery
        from network_monitor.core.factory import AdapterFactory

        info = SystemDiscovery().discover()
        adapter = AdapterFactory.create(info)
        report = adapter.discover_capabilities()
    """

    # Map platform.system() strings → import paths.
    # Darwin is macOS's platform.system() value.
    _OS_MAP: dict[str, tuple[str, str]] = {
        "Linux":   ("network_monitor.adapters.linux.adapter",   "LinuxAdapter"),
        "Windows": ("network_monitor.adapters.windows.adapter", "WindowsAdapter"),
        "Darwin":  ("network_monitor.adapters.macos.adapter",   "MacOSAdapter"),
    }

    @classmethod
    def create(cls, system_info: "SystemInfo") -> "NetworkAdapter":
        """
        Create and return the appropriate adapter for ``system_info.os_name``.

        Parameters
        ----------
        system_info:
            The ``SystemInfo`` object produced by ``SystemDiscovery.discover()``.

        Returns
        -------
        NetworkAdapter
            A concrete adapter instance.  ``start()`` has NOT been called.

        Raises
        ------
        UnsupportedOSError
            If ``system_info.os_name`` does not map to a known adapter.
        ImportError
            If the adapter module cannot be imported (indicates a packaging
            or installation problem, not an unsupported OS).
        """
        os_name = system_info.os_name

        if os_name not in cls._OS_MAP:
            raise UnsupportedOSError(os_name)

        module_path, class_name = cls._OS_MAP[os_name]

        # Deferred import: only load the OS-specific module when needed.
        # This prevents Windows-only imports from running on Linux, etc.
        import importlib
        module = importlib.import_module(module_path)
        adapter_class = getattr(module, class_name)

        return adapter_class(system_info=system_info)

    @classmethod
    def supported_os_names(cls) -> list[str]:
        """Return the list of OS names for which an adapter is registered."""
        return list(cls._OS_MAP.keys())
