"""
UEM (Universal Event Model) Normalization Layer.

Converts platform-specific telemetry events from every collector into
canonical aegis_core.Event objects.

Rules enforced here:
- NEVER fabricate an unavailable field: absent key = field not collected.
- All enum values extracted with .value before storage.
- All timestamps coerced to UTC-aware datetimes.
- Provenance preserved: source, collection_mechanism, host_id on every event.

Every normalized event answers:
    WHAT happened (data["action"])
    WHEN (observed_at — UTC)
    WHERE (host_id)
    WHICH collector (source, data["collection_mechanism"])
    WHICH process/file/endpoint (pid/path/local_ip+port/remote_ip+port)
    WHAT was actually observed (remaining data keys)
    WHAT was unavailable (absent keys)
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .models import Event, EventKind


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime | None) -> datetime:
    """Make a datetime UTC-aware; fall back to utcnow() if None."""
    if dt is None:
        return _utcnow()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe_str(value: Any) -> str | None:
    """Return str, extracting .value from enums. Returns None for None/empty."""
    if value is None:
        return None
    if hasattr(value, "value"):
        value = value.value
    s = str(value).strip()
    return s if s else None


def _compact(d: dict[str, Any]) -> dict[str, Any]:
    """Remove None values — absent key means 'field not available'."""
    return {k: v for k, v in d.items() if v is not None}


# ---------------------------------------------------------------------------
# Network normalization  (network_monitor events → aegis_core.Event)
# ---------------------------------------------------------------------------

def normalize_connection_event(
    conn_evt: Any,
    host_id: str,
    collector_name: str = "network_bridge",
) -> Event:
    """Convert a network_monitor.ConnectionEvent to a canonical aegis_core.Event."""
    data: dict[str, Any] = {
        "action": "connection_snapshot",
        "protocol": _safe_str(getattr(conn_evt, "protocol", None)),
        "direction": _safe_str(getattr(conn_evt, "direction", None)),
        "local_ip": _safe_str(getattr(conn_evt, "local_ip", None)),
        "local_port": getattr(conn_evt, "local_port", None),
        "remote_ip": _safe_str(getattr(conn_evt, "remote_ip", None)),
        "remote_port": getattr(conn_evt, "remote_port", None),
        "state": _safe_str(getattr(conn_evt, "state", None)),
        "pid": getattr(conn_evt, "pid", None),
        "process_name": _safe_str(getattr(conn_evt, "process_name", None)),
        "executable_path": _safe_str(getattr(conn_evt, "executable_path", None)),
        "user": _safe_str(getattr(conn_evt, "user", None)),
        "connection_id": _safe_str(getattr(conn_evt, "connection_id", None)),
        "nm_collector": _safe_str(getattr(conn_evt, "collector", None)),
        "collection_mechanism": "network_monitor_adapter",
    }
    return Event(
        kind=EventKind.NETWORK,
        source=collector_name,
        data=_compact(data),
        observed_at=_ensure_utc(getattr(conn_evt, "timestamp", None)),
        host_id=host_id,
    )


def normalize_traffic_event(
    traffic_evt: Any,
    host_id: str,
    collector_name: str = "network_bridge",
) -> Event:
    """Convert a network_monitor.TrafficEvent to a canonical aegis_core.Event."""
    data: dict[str, Any] = {
        "action": "traffic_stats",
        "interface": _safe_str(getattr(traffic_evt, "interface", None)),
        "bytes_sent": getattr(traffic_evt, "bytes_sent", None),
        "bytes_received": getattr(traffic_evt, "bytes_received", None),
        "packets_sent": getattr(traffic_evt, "packets_sent", None),
        "packets_received": getattr(traffic_evt, "packets_received", None),
        "delta_bytes_sent": getattr(traffic_evt, "delta_bytes_sent", None),
        "delta_bytes_received": getattr(traffic_evt, "delta_bytes_received", None),
        "delta_packets_sent": getattr(traffic_evt, "delta_packets_sent", None),
        "delta_packets_received": getattr(traffic_evt, "delta_packets_received", None),
        "errors_in": getattr(traffic_evt, "errors_in", None),
        "errors_out": getattr(traffic_evt, "errors_out", None),
        "drops_in": getattr(traffic_evt, "drops_in", None),
        "drops_out": getattr(traffic_evt, "drops_out", None),
        "collection_mechanism": "network_monitor_adapter",
    }
    return Event(
        kind=EventKind.NETWORK,
        source=collector_name,
        data=_compact(data),
        observed_at=_ensure_utc(getattr(traffic_evt, "timestamp", None)),
        host_id=host_id,
    )


def normalize_dns_event(
    dns_evt: Any,
    host_id: str,
    collector_name: str = "network_bridge",
) -> Event:
    """Convert a network_monitor.DnsEvent to a canonical aegis_core.Event."""
    is_response = bool(getattr(dns_evt, "is_response", False))
    action = "dns_response" if is_response else "dns_query"
    resp_addrs = getattr(dns_evt, "response_addresses", None) or []
    data: dict[str, Any] = {
        "action": action,
        "query_name": _safe_str(getattr(dns_evt, "query_name", None)),
        "query_type": _safe_str(getattr(dns_evt, "query_type", None)),
        "query_id": getattr(dns_evt, "query_id", None),
        "response_code": _safe_str(getattr(dns_evt, "response_code", None)),
        "response_addresses": resp_addrs if resp_addrs else None,
        "source_ip": _safe_str(getattr(dns_evt, "source_ip", None)),
        "destination_ip": _safe_str(getattr(dns_evt, "destination_ip", None)),
        "pid": getattr(dns_evt, "pid", None),
        "process_name": _safe_str(getattr(dns_evt, "process_name", None)),
        "collection_mechanism": "network_monitor_adapter",
    }
    return Event(
        kind=EventKind.NETWORK,
        source=collector_name,
        data=_compact(data),
        observed_at=_ensure_utc(getattr(dns_evt, "timestamp", None)),
        host_id=host_id,
    )


def normalize_process_network_event(
    pne: Any,
    host_id: str,
    collector_name: str = "network_bridge",
) -> Event:
    """Convert a network_monitor.ProcessNetworkEvent to a canonical aegis_core.Event."""
    data: dict[str, Any] = {
        "action": "process_network_activity",
        "pid": getattr(pne, "pid", None),
        "process_name": _safe_str(getattr(pne, "process_name", None)),
        "executable_path": _safe_str(getattr(pne, "executable_path", None)),
        "user": _safe_str(getattr(pne, "user", None)),
        "connection_id": _safe_str(getattr(pne, "connection_id", None)),
        "local_ip": _safe_str(getattr(pne, "local_ip", None)),
        "local_port": getattr(pne, "local_port", None),
        "remote_ip": _safe_str(getattr(pne, "remote_ip", None)),
        "remote_port": getattr(pne, "remote_port", None),
        "protocol": _safe_str(getattr(pne, "protocol", None)),
        "collection_mechanism": "network_monitor_adapter",
    }
    return Event(
        kind=EventKind.NETWORK,
        source=collector_name,
        data=_compact(data),
        observed_at=_ensure_utc(getattr(pne, "timestamp", None)),
        host_id=host_id,
    )


# ---------------------------------------------------------------------------
# Process normalization
# ---------------------------------------------------------------------------

def _proc_base(pid: int, info: Mapping[str, Any], mechanism: str) -> dict[str, Any]:
    """Build a base process data dict from an info mapping."""
    cmdline = info.get("cmdline")
    if isinstance(cmdline, list):
        cmdline = " ".join(str(c) for c in cmdline) if cmdline else None
    return {
        "pid": pid,
        "ppid": info.get("ppid"),
        "name": _safe_str(info.get("name")),
        "exe": _safe_str(info.get("exe")),
        "cmdline": _safe_str(cmdline),
        "user": _safe_str(info.get("user") or info.get("username")),
        "create_time": info.get("create_time"),
        "collection_mechanism": mechanism,
    }


def normalize_process_start(
    pid: int, info: Mapping[str, Any], host_id: str,
    collector_name: str, mechanism: str,
) -> Event:
    """Create a PROCESS_START canonical event.

    Short-lived processes that complete between polls cannot be observed
    by snapshot-diffing collectors; this limitation is documented in the
    capability report, not papered over.
    """
    data = {"action": "start", **_proc_base(pid, info, mechanism)}
    return Event(
        kind=EventKind.PROCESS, source=collector_name,
        data=_compact(data), host_id=host_id,
    )


def normalize_process_exit(
    pid: int, info: Mapping[str, Any], host_id: str,
    collector_name: str, mechanism: str,
) -> Event:
    """Create a PROCESS_EXIT canonical event."""
    data: dict[str, Any] = {
        "action": "exit",
        "pid": pid,
        "name": _safe_str(info.get("name")),
        "exe": _safe_str(info.get("exe")),
        "user": _safe_str(info.get("user") or info.get("username")),
        "create_time": info.get("create_time"),
        "exit_code": info.get("exit_code"),
        "collection_mechanism": mechanism,
    }
    return Event(
        kind=EventKind.PROCESS, source=collector_name,
        data=_compact(data), host_id=host_id,
    )


def normalize_process_snapshot(
    pid: int, info: Mapping[str, Any], host_id: str,
    collector_name: str, mechanism: str,
) -> Event:
    """Create a periodic full PROCESS snapshot event (not a lifecycle transition)."""
    data = {"action": "snapshot", **_proc_base(pid, info, mechanism)}
    data["status"] = _safe_str(info.get("status"))
    data["num_threads"] = info.get("num_threads")
    return Event(
        kind=EventKind.PROCESS, source=collector_name,
        data=_compact(data), host_id=host_id,
    )


# ---------------------------------------------------------------------------
# File normalization
# ---------------------------------------------------------------------------

def normalize_file_event(
    action: str, path: str, host_id: str, collector_name: str,
    mechanism: str, extra: Mapping[str, Any] | None = None,
    observed_at: datetime | None = None,
) -> Event:
    """Create a FILE canonical event (create/modify/delete/rename).

    action: one of 'create', 'modify', 'delete', 'rename'.
    extra: optional supplementary fields (e.g. dest_path for rename).
    File contents are NEVER read — privacy-preserving by design.
    """
    p = Path(path)
    data: dict[str, Any] = {
        "action": action,
        "path": path,
        "name": p.name,
        "suffix": p.suffix.lower() if p.suffix else None,
        "parent": str(p.parent),
        "collection_mechanism": mechanism,
        "process_attribution": "unavailable",
    }
    if extra:
        data.update({k: v for k, v in extra.items() if v is not None})
    return Event(
        kind=EventKind.FILE, source=collector_name,
        data=_compact(data),
        observed_at=_ensure_utc(observed_at),
        host_id=host_id,
    )


# ---------------------------------------------------------------------------
# Authentication / Security normalization
# ---------------------------------------------------------------------------

def normalize_auth_event(
    action: str, fields: Mapping[str, Any], host_id: str,
    collector_name: str, mechanism: str,
    observed_at: datetime | None = None,
) -> Event:
    """Create an AUTHENTICATION canonical event.

    Standard action values:
        login_success, login_failure, session_start, session_end,
        privilege_change, sudo_command, service_start, service_stop,
        password_change, account_locked, account_unlocked.

    Standard fields keys:
        user, pid, uid, auth_mechanism, source_ip, message,
        hostname, service, logon_type, windows_event_id.
    """
    data: dict[str, Any] = {
        "action": action,
        "collection_mechanism": mechanism,
    }
    for k, v in fields.items():
        if v is not None:
            data[k] = v
    return Event(
        kind=EventKind.AUTHENTICATION, source=collector_name,
        data=_compact(data),
        observed_at=_ensure_utc(observed_at),
        host_id=host_id,
    )


# ---------------------------------------------------------------------------
# Health / capability normalization
# ---------------------------------------------------------------------------

def normalize_collector_error(
    collector_name: str, error_type: str, error_message: str,
    host_id: str, retry_after_seconds: float | None = None,
) -> Event:
    """Create a HEALTH event for a collector error (failures are never silently swallowed)."""
    data: dict[str, Any] = {
        "action": "collector_error",
        "collector": collector_name,
        "status": "error",
        "error_type": error_type,
        "error_message": str(error_message)[:500],
        "retry_after_seconds": retry_after_seconds,
    }
    return Event(
        kind=EventKind.HEALTH, source="engine",
        data=_compact(data), host_id=host_id,
    )


def normalize_capability_status(
    collector_name: str, status: str, reason: str | None,
    host_id: str, mechanism: str | None = None,
) -> Event:
    """Create a HEALTH event reporting a collector's capability status.

    status: AVAILABLE | UNAVAILABLE | PERMISSION_DENIED | ERROR | NOT_IMPLEMENTED
    """
    data: dict[str, Any] = {
        "action": "capability_status",
        "collector": collector_name,
        "status": status,
        "reason": reason,
        "mechanism": mechanism,
    }
    return Event(
        kind=EventKind.HEALTH, source="engine",
        data=_compact(data), host_id=host_id,
    )
