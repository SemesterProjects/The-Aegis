"""
adapters/linux/ebpf/capability.py
==================================
eBPF capability detection for the Linux adapter.

Checks whether eBPF-based network observation is technically feasible in the
current environment.  Detection is based on:

1. Platform is Linux (necessary precondition).
2. Kernel version is recent enough for socket/tracepoint eBPF programs
   (Linux 4.4+ for basic socket filtering; 4.7+ for tracepoints;
   5.8+ for ring buffer).  We require >= 4.4 as the minimal useful baseline.
3. The current process has the required privilege:
   - Effective UID == 0  (traditional root), OR
   - /proc/sys/kernel/unprivileged_bpf_disabled is 0 (non-root eBPF permitted)
4. A Python eBPF binding (bcc or bpf) is importable.
   NOTE: Even if bcc/bpf is absent, eBPF might still be usable via a
   compiled C helper in a future milestone.  This flag reflects Python-only
   availability.

Milestone 3 additions:
5. The ``sock:inet_sock_set_state`` tracepoint is probed via debugfs.
6. BTF (BPF Type Format) availability is checked via /sys/kernel/btf/vmlinux.

IMPORTANT: This module does NOT actually load any eBPF programs.  It only
checks whether the environment meets the prerequisites.  Do not treat
``kernel_sufficient`` alone as meaning eBPF is ready to use.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EbpfCapability:
    """
    Result of an eBPF availability probe on Linux.

    Attributes
    ----------
    available:
        True only when ALL of the following are true:
        - ``is_linux``
        - ``kernel_sufficient``
        - ``has_privilege``
        The Python binding flag (``python_binding_available``) is informational
        and does not gate ``available``, because a C helper could substitute.

    is_linux:
        True if platform.system() == "Linux".

    kernel_version:
        The raw kernel release string (e.g. "6.1.0-21-amd64").

    kernel_tuple:
        Parsed (major, minor, patch) or None if parsing failed.

    kernel_sufficient:
        True if kernel_tuple >= (4, 4, 0).

    has_privilege:
        True if effective UID is 0 OR unprivileged_bpf_disabled is 0.

    effective_uid:
        The effective UID of the running process, or None on error.

    unprivileged_bpf_disabled:
        Value of /proc/sys/kernel/unprivileged_bpf_disabled, or None if
        the file is absent or unreadable.

    python_binding_available:
        True if ``bcc`` or ``bpf`` can be imported.  Informational only.

    python_binding_name:
        The name of the importable binding ("bcc", "bpf", or None).

    tracepoint_available:
        True if the ``sock/inet_sock_set_state`` tracepoint directory exists
        in ``/sys/kernel/debug/tracing/events/sock/inet_sock_set_state/``.
        The tracepoint was introduced in Linux 4.16.  Absence of the debugfs
        path may indicate debugfs is not mounted, not a true absence.

    btf_available:
        True if ``/sys/kernel/btf/vmlinux`` exists, indicating that the kernel
        was compiled with BTF support.  Required for CO-RE / libbpf; BCC can
        work without it on older kernels.

    unavailability_reasons:
        Human-readable list of reasons why eBPF is not available (empty
        when ``available`` is True).

    detection_errors:
        Non-fatal internal errors encountered during probing.
    """

    available: bool = False
    is_linux: bool = False
    kernel_version: Optional[str] = None
    kernel_tuple: Optional[tuple] = None   # (major, minor, patch) or None
    kernel_sufficient: bool = False
    has_privilege: bool = False
    effective_uid: Optional[int] = None
    unprivileged_bpf_disabled: Optional[int] = None
    python_binding_available: bool = False
    python_binding_name: Optional[str] = None
    tracepoint_available: bool = False
    btf_available: bool = False
    unavailability_reasons: list = field(default_factory=list)
    detection_errors: list = field(default_factory=list)


def detect() -> EbpfCapability:
    """
    Probe eBPF availability.  Never raises.

    Returns a fully populated ``EbpfCapability`` dataclass.
    """
    result = EbpfCapability()

    # 1. Platform check
    result.is_linux = platform.system() == "Linux"
    if not result.is_linux:
        result.unavailability_reasons.append(
            "Not running on Linux; eBPF is a Linux kernel feature."
        )
        return result

    # 2. Kernel version
    _probe_kernel_version(result)

    # 3. Privilege
    _probe_privilege(result)

    # 4. Python binding (informational)
    _probe_python_binding(result)

    # 5. Tracepoint presence (Milestone 3)
    _probe_tracepoint(result)

    # 6. BTF availability (informational, Milestone 3)
    _probe_btf(result)

    # 7. Compute summary availability
    result.available = result.kernel_sufficient and result.has_privilege
    if not result.available and not result.unavailability_reasons:
        result.unavailability_reasons.append(
            "eBPF prerequisites not fully met (see kernel_sufficient and has_privilege fields)."
        )

    return result


# ---------------------------------------------------------------------------
# Internal probes
# ---------------------------------------------------------------------------


def _probe_kernel_version(result: EbpfCapability) -> None:
    try:
        result.kernel_version = platform.release()
        result.kernel_tuple = _parse_kernel_version(result.kernel_version)
        if result.kernel_tuple is not None:
            result.kernel_sufficient = result.kernel_tuple >= (4, 4, 0)
            if not result.kernel_sufficient:
                result.unavailability_reasons.append(
                    f"Kernel {result.kernel_version} is below the minimum "
                    f"required version 4.4.0 for eBPF socket programs."
                )
        else:
            result.unavailability_reasons.append(
                f"Could not parse kernel version string: '{result.kernel_version}'.  "
                f"Treating eBPF as unavailable."
            )
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"kernel_version_probe: {exc}")
        result.unavailability_reasons.append("Kernel version could not be determined.")


def _probe_privilege(result: EbpfCapability) -> None:
    # Effective UID
    try:
        result.effective_uid = os.geteuid()
        if result.effective_uid == 0:
            result.has_privilege = True
            return
    except AttributeError:
        result.detection_errors.append(
            "os.geteuid() not available (unexpected on Linux)."
        )

    # Check unprivileged_bpf_disabled
    bpf_disabled_path = "/proc/sys/kernel/unprivileged_bpf_disabled"
    try:
        with open(bpf_disabled_path, "r") as f:
            raw = f.read().strip()
            result.unprivileged_bpf_disabled = int(raw)
            if result.unprivileged_bpf_disabled == 0:
                result.has_privilege = True
            else:
                result.unavailability_reasons.append(
                    f"Unprivileged eBPF is disabled "
                    f"({bpf_disabled_path} = {result.unprivileged_bpf_disabled}) "
                    f"and process is not root (UID={result.effective_uid}).  "
                    f"Run as root or set unprivileged_bpf_disabled=0."
                )
    except FileNotFoundError:
        # File may not exist on older kernels; absence means the kernel does
        # not restrict non-root eBPF by this sysctl.
        result.unprivileged_bpf_disabled = None
        if result.effective_uid is not None and result.effective_uid != 0:
            result.unavailability_reasons.append(
                f"Process is not root (UID={result.effective_uid}) and "
                f"{bpf_disabled_path} does not exist.  "
                f"eBPF privilege requirement cannot be determined; treating as unavailable."
            )
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"privilege_probe: {exc}")
        result.unavailability_reasons.append(
            "Could not determine eBPF privilege status."
        )


def _probe_python_binding(result: EbpfCapability) -> None:
    for binding_name in ("bcc", "bpf"):
        try:
            __import__(binding_name)
            result.python_binding_available = True
            result.python_binding_name = binding_name
            return
        except ImportError:
            pass
        except Exception as exc:  # noqa: BLE001
            result.detection_errors.append(f"python_binding_probe({binding_name}): {exc}")

    # Neither found — this is informational, not a hard blocker
    result.python_binding_available = False
    result.python_binding_name = None


def _probe_tracepoint(result: EbpfCapability) -> None:
    """
    Check whether the ``sock:inet_sock_set_state`` tracepoint directory exists
    in the kernel debug filesystem.

    The tracepoint was introduced in Linux 4.16.  Its debugfs entry is at:
        /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/

    Note: debugfs must be mounted for this path to exist. Absence of the path
    does NOT definitively prove the tracepoint is missing — it may just not be
    mounted. We record what we observe without treating absence as a fatal block
    on ``available``.
    """
    tracepoint_path = "/sys/kernel/debug/tracing/events/sock/inet_sock_set_state"
    try:
        result.tracepoint_available = os.path.isdir(tracepoint_path)
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"tracepoint_probe: {exc}")
        result.tracepoint_available = False


def _probe_btf(result: EbpfCapability) -> None:
    """
    Check for ``/sys/kernel/btf/vmlinux`` to confirm BTF support.

    BTF is required by CO-RE libbpf programs.  BCC can work without it on
    older kernels.  We record this as informational only.
    """
    btf_path = "/sys/kernel/btf/vmlinux"
    try:
        result.btf_available = os.path.isfile(btf_path)
    except Exception as exc:  # noqa: BLE001
        result.detection_errors.append(f"btf_probe: {exc}")
        result.btf_available = False


def _parse_kernel_version(release: str) -> Optional[tuple]:
    """
    Parse a kernel release string into (major, minor, patch).

    Handles formats like:
        6.1.0-21-amd64
        5.15.0-91-generic
        4.4.0
        6.6.9
    Returns None if parsing fails.
    """
    try:
        # Take the leading numeric portion only
        numeric_part = release.split("-")[0]
        parts = numeric_part.split(".")
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return None
