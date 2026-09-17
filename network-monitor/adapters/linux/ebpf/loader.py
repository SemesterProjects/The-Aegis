"""
adapters/linux/ebpf/loader.py
==============================
Safe eBPF loader for the AEGIS Network Monitor.

Provides a single public function ``load_connection_tracer()`` that:
1. Runs a complete prerequisite check (platform, kernel, privilege, BCC).
2. Attempts to load and attach the eBPF connection tracing program.
3. Returns either a live ``EbpfConnectionTracer`` or ``None`` with a
   human-readable reason — it NEVER raises.

This layer exists to cleanly separate "can we load?" (capability.py) from
"did we actually load?" (this module) so that ``LinuxAdapter`` can reliably
report the true runtime eBPF status rather than a theoretical one.

Typical usage inside ``LinuxAdapter.__init__``:
    from network_monitor.adapters.linux.ebpf.loader import load_connection_tracer
    self._ebpf_tracer, self._ebpf_reason = load_connection_tracer()

The adapter should:
- Use ``self._ebpf_tracer`` if it is not None to collect kernel-level events.
- Fall back to the polling collector when it is None.
- Log ``self._ebpf_reason`` in capability report notes.
"""

from __future__ import annotations

from typing import Optional, Tuple

from network_monitor.adapters.linux.ebpf.capability import detect as _detect_capability
from network_monitor.adapters.linux.ebpf.connection_tracer import EbpfConnectionTracer


def load_connection_tracer() -> Tuple[Optional[EbpfConnectionTracer], str]:
    """
    Perform capability checks then attempt eBPF tracer load.

    Returns
    -------
    (tracer, reason)
        tracer  — ``EbpfConnectionTracer`` instance if successful, else ``None``.
        reason  — Empty string on success; human-readable failure reason on failure.

    This function never raises.
    """
    # ------------------------------------------------------------------
    # Step 1: Run capability probe
    # ------------------------------------------------------------------
    try:
        cap = _detect_capability()
    except Exception as exc:
        return None, f"eBPF capability probe raised an unexpected exception: {exc}"

    if not cap.is_linux:
        return None, "Not on Linux; eBPF is not available."

    if not cap.kernel_sufficient:
        kv = cap.kernel_version or "unknown"
        return None, (
            f"Kernel {kv} is below the required minimum (4.4.0).  "
            "Upgrade your kernel to enable eBPF network tracing."
        )

    if not cap.has_privilege:
        reasons = "; ".join(cap.unavailability_reasons) if cap.unavailability_reasons else "unknown"
        return None, (
            f"Insufficient privilege for eBPF (UID={cap.effective_uid}).  "
            f"Detail: {reasons}  Run as root or with CAP_BPF."
        )

    if not cap.python_binding_available:
        return None, (
            "BCC Python library not importable.  "
            "Install with: sudo apt-get install bpfcc-tools python3-bpfcc  "
            "(or: sudo dnf install bcc-tools python3-bcc on Fedora/RHEL).  "
            "Falling back to polling-only collection."
        )

    # ------------------------------------------------------------------
    # Step 2: Attempt eBPF program load + tracepoint attach
    # ------------------------------------------------------------------
    tracer, reason = EbpfConnectionTracer.try_load()
    if tracer is None:
        return None, f"eBPF tracer load failed: {reason}"

    return tracer, ""


def describe_ebpf_status(tracer: Optional[EbpfConnectionTracer], reason: str) -> str:
    """
    Return a one-line human-readable status string for display in sensors.py.

    Examples:
        "ACTIVE    (tracepoint: sock:inet_sock_set_state)"
        "INACTIVE  Reason: BCC library not installed; Fallback: polling"
    """
    if tracer is not None:
        uptime = round(tracer.uptime_seconds, 1)
        dropped = tracer.dropped_events
        drop_str = f", {dropped} dropped" if dropped else ""
        return f"ACTIVE    (tracepoint: sock:inet_sock_set_state, up {uptime}s{drop_str})"
    else:
        short_reason = reason.split(".")[0] if reason else "unknown"
        return f"INACTIVE  Reason: {short_reason}; Fallback: polling"
