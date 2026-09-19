"""
adapters/linux/ebpf/connection_tracer.py
=========================================
eBPF-based TCP connection state tracer for Linux.

Uses the ``sock:inet_sock_set_state`` kernel tracepoint (introduced in Linux
4.16) via the BCC Python library to observe every TCP socket state transition
at kernel level — including sub-millisecond ephemeral connections that a
polling-based collector would miss.

Architecture
------------
- The embedded C eBPF program is compiled and loaded by BCC.
- A BPF perf event buffer is used to pass events from kernel-space to
  user-space with minimal overhead.
- The tracer exposes a ``poll(timeout_ms)`` generator that yields raw
  ``KernelConnectionEvent`` named objects.
- Integration with the rest of the Network Monitor happens through
  ``LinuxConnectionCollector``, which consumes these events and converts them
  to ``ConnectionEvent`` dataclasses.

Usage (privileged Linux only)
------------------------------
    tracer = EbpfConnectionTracer.try_load()
    if tracer:
        for raw in tracer.poll(timeout_ms=100):
            print(raw.pid, raw.saddr, raw.dport, raw.newstate)
        tracer.stop()

Limitations
-----------
- Requires Linux kernel >= 4.16 (tracepoint), BCC library, and CAP_BPF / root.
- IPv6 addresses are represented as 16-byte packed strings; the tracer decodes
  them automatically.
- UDP is not traced via this tracepoint (which is TCP-only).  UDP connections
  continue to be handled by the polling collector.
- BCC compilation can take 1–5 seconds on first load (LLVM JIT).  Subsequent
  loads of the same program may be cached by the kernel.

NOTE: This file is designed to be importable on ANY platform (Windows, macOS,
Linux without BCC) without crashing.  All BCC imports are guarded.  The
``try_load()`` classmethod returns ``None`` with a reason string when the
tracer cannot be initialized.
"""

from __future__ import annotations

import ctypes
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

# ---------------------------------------------------------------------------
# BCC import guard — the tracer is fully optional
# ---------------------------------------------------------------------------

try:
    from bcc import BPF as _BCC_BPF
    _BCC_AVAILABLE = True
except (ImportError, Exception):
    _BCC_BPF = None  # type: ignore[misc,assignment]
    _BCC_AVAILABLE = False


# ---------------------------------------------------------------------------
# TCP state constants (mirroring Linux kernel tcp_states.h)
# These map the ``newstate`` integer from the tracepoint to a human label.
# ---------------------------------------------------------------------------

_TCP_STATE_MAP: dict[int, str] = {
    1:  "ESTABLISHED",
    2:  "SYN_SENT",
    3:  "SYN_RECEIVED",
    4:  "FIN_WAIT_1",
    5:  "FIN_WAIT_2",
    6:  "TIME_WAIT",
    7:  "CLOSE",
    8:  "CLOSE_WAIT",
    9:  "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}

# ---------------------------------------------------------------------------
# BCC eBPF C program
# ---------------------------------------------------------------------------

# This C code is compiled on-the-fly by BCC using LLVM.
# The tracepoint ``sock:inet_sock_set_state`` fires on every TCP state change.
# We capture the fields we need and push them to user-space via a perf buffer.
#
# The struct layout MUST stay in sync with the ``_RawEvent`` ctypes struct below.
#
# Note on IPv6: saddr/daddr are 16-byte arrays (struct in6_addr).  For IPv4
# sockets, only the first 4 bytes carry the address (in network byte order).
# The ``family`` field (AF_INET = 2, AF_INET6 = 10) tells us how to decode.
_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>

// ---------------------------------------------------------------------------
// Output event structure — must match _RawEvent in Python
// ---------------------------------------------------------------------------
struct conn_event_t {
    u64  timestamp_ns;   // ktime_get_boot_ns()
    u32  pid;            // tgid (user-visible PID)
    u32  tid;            // tid
    u32  oldstate;       // previous TCP state
    u32  newstate;       // new TCP state
    u16  sport;          // source (local) port, host byte order
    u16  dport;          // destination (remote) port, host byte order
    u16  family;         // AF_INET (2) or AF_INET6 (10)
    u8   saddr[16];      // source address (IPv4 in first 4 bytes)
    u8   daddr[16];      // destination address (IPv4 in first 4 bytes)
    char comm[16];       // process comm name
};

BPF_PERF_OUTPUT(conn_events);

// ---------------------------------------------------------------------------
// Tracepoint handler: sock:inet_sock_set_state
// ---------------------------------------------------------------------------
TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    // Only trace TCP sockets
    if (args->protocol != IPPROTO_TCP)
        return 0;

    struct conn_event_t ev = {};

    ev.timestamp_ns = bpf_ktime_get_boot_ns();
    ev.pid          = bpf_get_current_pid_tgid() >> 32;
    ev.tid          = (u32)bpf_get_current_pid_tgid();
    ev.oldstate     = args->oldstate;
    ev.newstate     = args->newstate;
    ev.sport        = args->sport;
    ev.dport        = args->dport;
    ev.family       = args->family;

    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    // Copy addresses — BCC helpers handle safe user-space memory access
    if (args->family == AF_INET) {
        bpf_probe_read_kernel(ev.saddr, 4, args->saddr);
        bpf_probe_read_kernel(ev.daddr, 4, args->daddr);
    } else if (args->family == AF_INET6) {
        bpf_probe_read_kernel(ev.saddr, 16, args->saddr);
        bpf_probe_read_kernel(ev.daddr, 16, args->daddr);
    }

    conn_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

# ---------------------------------------------------------------------------
# ctypes struct matching conn_event_t
# ---------------------------------------------------------------------------

class _RawEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid",          ctypes.c_uint32),
        ("tid",          ctypes.c_uint32),
        ("oldstate",     ctypes.c_uint32),
        ("newstate",     ctypes.c_uint32),
        ("sport",        ctypes.c_uint16),
        ("dport",        ctypes.c_uint16),
        ("family",       ctypes.c_uint16),
        ("saddr",        ctypes.c_uint8 * 16),
        ("daddr",        ctypes.c_uint8 * 16),
        ("comm",         ctypes.c_char * 16),
    ]


@dataclass
class KernelConnectionEvent:
    """
    A decoded kernel TCP state-change event from the eBPF perf buffer.

    All address fields are human-readable strings ready for use in
    ``ConnectionEvent`` construction.
    """
    timestamp_ns: int      # kernel boot-relative nanoseconds
    pid: int
    comm: str              # process comm (up to 15 chars), may be empty
    oldstate: str          # TCP state name (e.g. "SYN_SENT")
    newstate: str          # TCP state name (e.g. "ESTABLISHED")
    family: int            # socket.AF_INET or socket.AF_INET6
    saddr: str             # source IP string
    daddr: str             # destination IP string
    sport: int             # source port (0–65535)
    dport: int             # destination port (0–65535)

    @property
    def is_ipv6(self) -> bool:
        return self.family == socket.AF_INET6

    @property
    def connection_id(self) -> str:
        """Stable identifier for correlating events across state transitions."""
        proto = "tcp6" if self.is_ipv6 else "tcp"
        return f"{proto}:{self.saddr}:{self.sport}-{self.daddr}:{self.dport}"


# ---------------------------------------------------------------------------
# EbpfConnectionTracer
# ---------------------------------------------------------------------------

class EbpfConnectionTracer:
    """
    Manages BCC compilation, eBPF program loading, tracepoint attachment, and
    perf buffer polling for TCP connection state changes.

    Do not instantiate directly — use ``EbpfConnectionTracer.try_load()``.
    """

    def __init__(self, bpf_instance) -> None:
        """
        Internal constructor.  ``bpf_instance`` is a live ``bcc.BPF`` object
        with the program already loaded and the tracepoint attached.
        """
        self._bpf = bpf_instance
        self._events: list[KernelConnectionEvent] = []
        self._lock = threading.Lock()
        self._dropped_events: int = 0
        self._is_running: bool = True
        self._load_time: float = time.monotonic()

        # Register the Python callback with BCC's perf buffer
        self._bpf["conn_events"].open_perf_buffer(
            self._handle_event,
            lost_cb=self._handle_lost,
        )

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def try_load(cls) -> Tuple[Optional["EbpfConnectionTracer"], str]:
        """
        Attempt to compile, load, and attach the eBPF program.

        Returns
        -------
        (tracer, reason)
            - If successful: (EbpfConnectionTracer instance, "")
            - If failed: (None, human-readable reason string)

        This method never raises.
        """
        if not _BCC_AVAILABLE:
            return None, (
                "BCC Python library is not installed.  "
                "Install with: sudo apt-get install bpfcc-tools python3-bpfcc"
            )

        import platform
        if platform.system() != "Linux":
            return None, "eBPF requires Linux; current platform is not Linux."

        try:
            import os
            uid = os.geteuid()
            if uid != 0:
                return None, (
                    f"eBPF tracepoint attachment requires root (current UID={uid}).  "
                    "Run with sudo or grant CAP_BPF capability."
                )
        except AttributeError:
            return None, "os.geteuid() unavailable; cannot verify eBPF privilege."

        try:
            bpf = _BCC_BPF(text=_BPF_PROGRAM)
        except Exception as exc:
            return None, (
                f"BCC program compilation or kernel verification failed: {exc}.  "
                "Check kernel headers are installed and kernel version >= 4.16."
            )

        try:
            tracer = cls(bpf)
        except Exception as exc:
            return None, f"Failed to attach perf buffer: {exc}"

        return tracer, ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def dropped_events(self) -> int:
        """Number of events dropped by the kernel perf buffer (capacity exceeded)."""
        return self._dropped_events

    @property
    def uptime_seconds(self) -> float:
        """Seconds since the tracer was successfully loaded."""
        return time.monotonic() - self._load_time

    def poll(self, timeout_ms: int = 100) -> Iterator[KernelConnectionEvent]:
        """
        Poll the BCC perf buffer and yield decoded kernel events.

        This is a generator.  Call it in a loop:

            for event in tracer.poll(timeout_ms=100):
                process(event)

        The generator yields all events accumulated since the last poll,
        then returns.  It does NOT block beyond ``timeout_ms``.
        """
        if not self._is_running:
            return

        try:
            self._bpf.perf_buffer_poll(timeout=timeout_ms)
        except Exception:
            # Perf buffer errors are non-fatal — skip this cycle
            pass

        with self._lock:
            events = list(self._events)
            self._events.clear()

        yield from events

    def stop(self) -> None:
        """
        Stop the tracer and release BCC resources.

        Safe to call multiple times.  After calling ``stop()``, ``poll()``
        will yield nothing.
        """
        if not self._is_running:
            return
        self._is_running = False
        try:
            self._bpf.cleanup()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # BCC perf buffer callbacks (called on the polling thread)
    # ------------------------------------------------------------------

    def _handle_event(self, cpu: int, data, size: int) -> None:
        """BCC perf buffer callback: decode and enqueue one event."""
        try:
            raw = ctypes.cast(data, ctypes.POINTER(_RawEvent)).contents
            event = _decode_raw_event(raw)
            with self._lock:
                self._events.append(event)
        except Exception:
            pass  # never crash the polling loop

    def _handle_lost(self, lost: int) -> None:
        """BCC lost-event callback: accumulate drop counter."""
        self._dropped_events += lost


# ---------------------------------------------------------------------------
# Decoding helper
# ---------------------------------------------------------------------------

def _decode_raw_event(raw: _RawEvent) -> KernelConnectionEvent:
    """Convert a ctypes ``_RawEvent`` struct to a ``KernelConnectionEvent``."""
    family = raw.family

    if family == socket.AF_INET:
        saddr = socket.inet_ntoa(bytes(raw.saddr[:4]))
        daddr = socket.inet_ntoa(bytes(raw.daddr[:4]))
    elif family == socket.AF_INET6:
        saddr = socket.inet_ntop(socket.AF_INET6, bytes(raw.saddr))
        daddr = socket.inet_ntop(socket.AF_INET6, bytes(raw.daddr))
    else:
        saddr = str(bytes(raw.saddr[:4]))
        daddr = str(bytes(raw.daddr[:4]))

    comm_raw = raw.comm
    if isinstance(comm_raw, bytes):
        comm = comm_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
    else:
        comm = str(comm_raw).strip("\x00")

    oldstate = _TCP_STATE_MAP.get(raw.oldstate, f"UNKNOWN_{raw.oldstate}")
    newstate = _TCP_STATE_MAP.get(raw.newstate, f"UNKNOWN_{raw.newstate}")

    return KernelConnectionEvent(
        timestamp_ns=raw.timestamp_ns,
        pid=raw.pid,
        comm=comm,
        oldstate=oldstate,
        newstate=newstate,
        family=family,
        saddr=saddr,
        daddr=daddr,
        sport=raw.sport,
        dport=raw.dport,
    )
