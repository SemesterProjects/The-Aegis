"""
adapters/__init__.py
====================
Top-level adapters package.

IMPORTANT: Do NOT import OS-specific adapter subpackages here.
Cross-platform import errors would occur if, for example, the Windows
adapter tried to import ctypes.windll on Linux.

The Adapter Factory uses deferred (importlib) imports to load only the
adapter appropriate for the current OS.
"""
