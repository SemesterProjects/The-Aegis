"""Deterministic Telemetry Context & Analysis layer for AEGIS.

Transforms normalized UEM Events into structured, evidence-backed analysis.
Every conclusion references a real Event field.  No AI/LLM reasoning.
No fabricated telemetry.  If a field is absent in the event, the analysis
reports it as UNAVAILABLE.

Pipeline
--------
  raw telemetry
      ↓ (collectors)
  normalized Event (UEM)
      ↓ (EvidenceStore)
  EventAnalysis
      ↓ (Correlator)
  related_events filled in
      ↓ (format_analysis)
  human-readable text
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import PurePath
from typing import Any, List, Optional, Sequence

from .models import Event, EventKind

_UNAVAILABLE = "UNAVAILABLE"


# ---------------------------------------------------------------------------
# Core analysis dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ChangeDescription:
    """What actually changed, expressed only in terms of observed evidence."""
    field_name: str
    previous: Any
    current: Any
    delta: Any = None

    def __str__(self) -> str:
        if self.delta is not None:
            sign = "+" if self.delta >= 0 else ""
            return f"{self.field_name}: {self.previous} -> {self.current} ({sign}{self.delta})"
        return f"{self.field_name}: {self.previous} -> {self.current}"


@dataclass
class EvidenceRef:
    """A traceable reference to an actual stored event."""
    event_id: str
    kind: str
    source: str
    observed_at: str
    host_id: str
    summary: str


@dataclass
class EventAnalysis:
    """Structured analysis of a single UEM Event.

    All attributes default to UNAVAILABLE so callers never see KeyError.
    related_event_ids are populated later by the Correlator.
    """
    # Identity
    event_id: str
    event_kind: str
    observed_at: str
    host_id: str
    source: str

    summary: str = _UNAVAILABLE

    subject: dict = field(default_factory=dict)
    location: dict = field(default_factory=dict)
    actor: dict = field(default_factory=dict)

    changes: list = field(default_factory=list)
    reason: str = _UNAVAILABLE
    related_event_ids: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    confidence: float = 1.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(data: dict, *keys: str) -> Any:
    """Return first found key value, else UNAVAILABLE."""
    for k in keys:
        v = data.get(k)
        if v is not None:
            return v
    return _UNAVAILABLE


def _fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _evidence_ref(event: Event, label: str) -> EvidenceRef:
    return EvidenceRef(
        event_id=event.event_id,
        kind=event.kind.value,
        source=event.source,
        observed_at=_fmt_ts(event.observed_at),
        host_id=event.host_id,
        summary=label,
    )


# ---------------------------------------------------------------------------
# Kind-specific analyzers
# ---------------------------------------------------------------------------

class _ProcessAnalyzer:
    """Analyze a PROCESS-kind event.

    Guaranteed fields (ProcessSnapshotCollector): pid, name
    Optional fields (psutil): exe, user, started (Unix epoch float)
    Not present: ppid (marked UNAVAILABLE)
    """

    def analyze(self, event: Event) -> EventAnalysis:
        d = event.data
        pid = _get(d, "pid")
        name = _get(d, "name")
        exe = _get(d, "exe")
        user = _get(d, "user")
        ppid = _get(d, "ppid", "parent_pid")

        started = d.get("started")
        if isinstance(started, (int, float)):
            started_str = datetime.fromtimestamp(started, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif started is None:
            started_str = _UNAVAILABLE
        else:
            started_str = str(started)

        summary = (
            f"Process activity detected: {name}"
            if name != _UNAVAILABLE
            else "Process activity detected"
        )

        reason = (
            "A process lifecycle snapshot was observed by the process collector. "
            "No causal relationship to other events is asserted from telemetry alone."
        )

        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={
                "process_name": name,
                "pid": pid,
                "parent_pid": ppid,
                "executable": exe,
                "user": user,
                "started_at": started_str,
            },
            location={"host_id": event.host_id},
            actor={},
            changes=[],
            reason=reason,
            evidence=[_evidence_ref(event, f"Process snapshot — {name} (PID {pid})")],
        )


class _FileAnalyzer:
    """Analyze a FILE-kind event.

    Guaranteed fields: path, operation, suffix
    Present on modify: size, previous_size
    Present on create: size
    Present on delete: previous_size
    NOT available: acting process identity
    """

    def analyze(self, event: Event) -> EventAnalysis:
        d = event.data
        path = _get(d, "path")
        operation = _get(d, "operation")
        size = d.get("size")
        prev_size = d.get("previous_size")
        suffix = _get(d, "suffix")

        filename = _UNAVAILABLE
        directory = _UNAVAILABLE
        if path != _UNAVAILABLE:
            pp = PurePath(path)
            filename = pp.name or _UNAVAILABLE
            directory = str(pp.parent) if str(pp.parent) != str(pp) else _UNAVAILABLE

        changes: list[ChangeDescription] = []
        if operation == "modified" and prev_size is not None and size is not None:
            delta = size - prev_size
            changes.append(ChangeDescription("size", f"{prev_size} bytes", f"{size} bytes", delta))
        elif operation == "created" and size is not None:
            changes.append(ChangeDescription("size", "not observed", f"{size} bytes"))
        elif operation == "deleted" and prev_size is not None:
            changes.append(ChangeDescription("size", f"{prev_size} bytes", "file removed"))

        op_upper = operation.upper() if operation != _UNAVAILABLE else _UNAVAILABLE
        summary = f"File {op_upper}: {filename}" if filename != _UNAVAILABLE else f"File {op_upper}"

        reason = (
            f"A filesystem {operation} event was observed by the file-polling collector "
            f"in the monitored directory tree. "
            "No process attribution is available from this telemetry source."
        )

        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={"operation": op_upper, "extension": suffix},
            location={
                "path": path,
                "filename": filename,
                "directory": directory,
                "host_id": event.host_id,
            },
            actor={},
            changes=changes,
            reason=reason,
            evidence=[_evidence_ref(event, f"File {operation} — {path}")],
        )


class _NetworkAnalyzer:
    """Analyze a NETWORK-kind event.

    Sub-types determined by action field:
      connection_open / connection_close / listen / connection_snapshot
      traffic_update
      dns_query / dns_response
      process_network_association
    """

    def analyze(self, event: Event) -> EventAnalysis:
        d = event.data
        action = _get(d, "action")
        if action in {"connection_open", "connection_close", "connection_snapshot", "listen"}:
            return self._connection(event, d, action)
        elif action == "traffic_update":
            return self._traffic(event, d)
        elif action in {"dns_query", "dns_response"}:
            return self._dns(event, d, action)
        elif action == "process_network_association":
            return self._process_network(event, d)
        else:
            return self._generic(event, d, action)

    def _connection(self, event: Event, d: dict, action: str) -> EventAnalysis:
        direction = _get(d, "direction")
        protocol = _get(d, "protocol")
        local_ip = _get(d, "local_ip")
        local_port = _get(d, "local_port")
        remote_ip = _get(d, "remote_ip")
        remote_port = _get(d, "remote_port")
        state = _get(d, "state")
        pid = _get(d, "pid")
        process = _get(d, "process", "process_name")

        local_ep = (
            f"{local_ip}:{local_port}"
            if local_ip != _UNAVAILABLE and local_port != _UNAVAILABLE
            else _UNAVAILABLE
        )
        remote_ep = (
            f"{remote_ip}:{remote_port}"
            if remote_ip != _UNAVAILABLE and remote_port != _UNAVAILABLE
            else _UNAVAILABLE
        )

        dir_label = direction.upper() if direction != _UNAVAILABLE else _UNAVAILABLE
        proto_label = protocol.upper() if protocol != _UNAVAILABLE else ""
        summary = f"Network {dir_label} {proto_label} connection — {action}"

        prev_state = "no observed connection"
        cur_state = (
            "connection established" if action == "connection_open"
            else action.replace("_", " ")
        )

        reason = (
            f"A network {action.replace('_', ' ')} event was observed by the network collector. "
            "No malice is asserted; this is a factual observation of connection state."
        )

        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={"process": process, "pid": pid},
            location={
                "local_endpoint": local_ep,
                "remote_endpoint": remote_ep,
                "direction": dir_label,
                "protocol": protocol,
                "state": state,
                "host_id": event.host_id,
            },
            actor={"process": process, "pid": pid},
            changes=[ChangeDescription("connection_state", prev_state, cur_state)],
            reason=reason,
            evidence=[_evidence_ref(event, f"Network {action} — {remote_ep}")],
        )

    def _traffic(self, event: Event, d: dict) -> EventAnalysis:
        interface = _get(d, "interface")
        delta_sent = _get(d, "delta_bytes_sent")
        delta_recv = _get(d, "delta_bytes_received")
        summary = f"Network traffic update on {interface}"
        changes: list[ChangeDescription] = []
        if delta_sent != _UNAVAILABLE:
            changes.append(ChangeDescription("bytes_sent_delta", 0, delta_sent, delta_sent))
        if delta_recv != _UNAVAILABLE:
            changes.append(ChangeDescription("bytes_received_delta", 0, delta_recv, delta_recv))
        reason = "A periodic network traffic counter update was observed on the interface."
        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={"interface": interface},
            location={"interface": interface, "host_id": event.host_id},
            actor={},
            changes=changes,
            reason=reason,
            evidence=[_evidence_ref(event, f"Traffic update — {interface}")],
        )

    def _dns(self, event: Event, d: dict, action: str) -> EventAnalysis:
        query_name = _get(d, "query_name")
        query_type = _get(d, "query_type")
        pid = _get(d, "pid")
        process = _get(d, "process", "process_name")
        response_code = _get(d, "response_code")
        answers = d.get("response_addresses") or []
        label = "DNS query" if action == "dns_query" else "DNS response"
        summary = f"{label}: {query_name}"
        reason = (
            f"A {label.lower()} was observed by the DNS monitor. "
            "Query content is logged; no threat verdict is issued."
        )
        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={"process": process, "pid": pid},
            location={
                "query_name": query_name,
                "query_type": query_type,
                "response_code": response_code,
                "response_addresses": answers,
                "host_id": event.host_id,
            },
            actor={"process": process, "pid": pid},
            changes=[ChangeDescription("dns_state", "none", action.replace("_", " "))],
            reason=reason,
            evidence=[_evidence_ref(event, f"{label} — {query_name}")],
        )

    def _process_network(self, event: Event, d: dict) -> EventAnalysis:
        pid = _get(d, "pid")
        process = _get(d, "process", "process_name")
        exe = _get(d, "executable_path")
        user = _get(d, "user")
        local_port = _get(d, "local_port")
        remote_ip = _get(d, "remote_ip")
        remote_port = _get(d, "remote_port")
        protocol = _get(d, "protocol")
        summary = f"Process-to-network association: {process} (PID {pid})"
        reason = (
            "A process-socket association was observed by the process-network collector. "
            "This records which process owns which socket, not any malicious activity."
        )
        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={"process": process, "pid": pid, "executable": exe, "user": user},
            location={
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": protocol,
                "host_id": event.host_id,
            },
            actor={"process": process, "pid": pid},
            changes=[],
            reason=reason,
            evidence=[_evidence_ref(event, f"Process-network — {process}:{pid}")],
        )

    def _generic(self, event: Event, d: dict, action: str) -> EventAnalysis:
        summary = f"Network event: {action}"
        reason = "A network event was observed by the network collector."
        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={},
            location={"host_id": event.host_id},
            actor={},
            changes=[],
            reason=reason,
            evidence=[_evidence_ref(event, f"Network — {action}")],
        )


class _AuthAnalyzer:
    """Analyze an AUTHENTICATION-kind event.

    Fields expected: action, user, source_ip (optional).
    The existing detection pipeline handles burst-auth detection;
    this analyzer does NOT duplicate that logic.
    """

    def analyze(self, event: Event) -> EventAnalysis:
        d = event.data
        action = _get(d, "action")
        user = _get(d, "user", "username")
        src = _get(d, "source_ip", "source", "remote_ip")
        summary = f"Authentication event: {action}"
        if user != _UNAVAILABLE:
            summary += f" — user: {user}"
        reason = (
            f"An authentication event ({action}) was observed. "
            "Success/failure verdict requires the detection-pipeline finding."
        )
        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={"user": user},
            location={"source": src, "host_id": event.host_id},
            actor={"user": user},
            changes=[ChangeDescription("auth_state", "none", action.replace("_", " "))],
            reason=reason,
            evidence=[_evidence_ref(event, f"Auth — {action} for {user}")],
        )


class _HealthAnalyzer:
    def analyze(self, event: Event) -> EventAnalysis:
        d = event.data
        status = _get(d, "status")
        collector_name = d.get("collector", "")
        summary = f"Health event: {status}" + (f" [{collector_name}]" if collector_name else "")
        reason = "An internal engine health or lifecycle event was emitted."
        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=summary,
            subject={"status": status},
            location={"host_id": event.host_id},
            actor={},
            changes=[],
            reason=reason,
            evidence=[_evidence_ref(event, f"Health — {status}")],
        )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_KIND_MAP: dict[EventKind, Any] = {
    EventKind.PROCESS: _ProcessAnalyzer(),
    EventKind.FILE: _FileAnalyzer(),
    EventKind.NETWORK: _NetworkAnalyzer(),
    EventKind.AUTHENTICATION: _AuthAnalyzer(),
    EventKind.HEALTH: _HealthAnalyzer(),
}


def analyze_event(event: Event) -> EventAnalysis:
    """Produce a deterministic EventAnalysis for any canonical UEM Event."""
    analyzer = _KIND_MAP.get(event.kind)
    if analyzer is None:
        return EventAnalysis(
            event_id=event.event_id,
            event_kind=event.kind.value,
            observed_at=_fmt_ts(event.observed_at),
            host_id=event.host_id,
            source=event.source,
            summary=f"Event of kind {event.kind.value}",
            reason="No specific analyzer is registered for this event kind.",
            evidence=[_evidence_ref(event, f"Event — {event.kind.value}")],
        )
    return analyzer.analyze(event)


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

class Correlator:
    """Deterministic, rule-based event correlation.

    Rules (all require same host + within time window):
      1. PROCESS + NETWORK  — same PID
      2. NETWORK + PROCESS  — same PID (symmetric)
      3. PROCESS + PROCESS  — same PID (lifecycle companions)
      4. FILE + any nearby  — same host within window
      5. AUTH + AUTH        — same user

    No relationship is created without an explicit rule.
    """

    def __init__(self, correlation_window_seconds: float = 30.0) -> None:
        self.window = timedelta(seconds=correlation_window_seconds)

    def correlate(self, analyses: Sequence[EventAnalysis]) -> list[EventAnalysis]:
        """Fill in related_event_ids for each analysis, returning a new list."""
        result = [self._copy(a) for a in analyses]
        n = len(result)
        for i in range(n):
            a = result[i]
            for j in range(n):
                if i == j:
                    continue
                b = result[j]
                if self._are_related(a, b):
                    if b.event_id not in a.related_event_ids:
                        a.related_event_ids.append(b.event_id)
        return result

    def _copy(self, a: EventAnalysis) -> EventAnalysis:
        cloned = copy.copy(a)
        cloned.related_event_ids = list(a.related_event_ids)
        cloned.evidence = list(a.evidence)
        cloned.changes = list(a.changes)
        cloned.subject = dict(a.subject)
        cloned.location = dict(a.location)
        cloned.actor = dict(a.actor)
        return cloned

    def _within_window(self, a: EventAnalysis, b: EventAnalysis) -> bool:
        try:
            ta = datetime.fromisoformat(a.observed_at.rstrip("Z")).replace(tzinfo=timezone.utc)
            tb = datetime.fromisoformat(b.observed_at.rstrip("Z")).replace(tzinfo=timezone.utc)
            return abs(ta - tb) <= self.window
        except (ValueError, AttributeError):
            return False

    def _same_host(self, a: EventAnalysis, b: EventAnalysis) -> bool:
        return a.host_id == b.host_id and a.host_id not in ("unknown", "")

    def _shared_pid(self, a: EventAnalysis, b: EventAnalysis) -> bool:
        pid_a = a.subject.get("pid") or a.actor.get("pid")
        pid_b = b.subject.get("pid") or b.actor.get("pid")
        return (
            pid_a is not None
            and pid_b is not None
            and pid_a != _UNAVAILABLE
            and pid_b != _UNAVAILABLE
            and pid_a == pid_b
        )

    def _are_related(self, a: EventAnalysis, b: EventAnalysis) -> bool:
        if not self._same_host(a, b):
            return False
        if not self._within_window(a, b):
            return False
        ka, kb = a.event_kind, b.event_kind
        # Rule 1 & 2 — Process <-> Network on same PID
        if ka in {"process", "network"} and kb in {"process", "network"} and ka != kb:
            return self._shared_pid(a, b)
        # Rule 3 — Process + Process on same PID
        if ka == "process" and kb == "process":
            return self._shared_pid(a, b)
        # Rule 4 — File + nearby events
        if ka == "file" and kb in {"file", "process", "network"}:
            return True
        # Rule 5 — Auth + Auth on same user
        if ka == "authentication" and kb == "authentication":
            user_a = a.subject.get("user")
            user_b = b.subject.get("user")
            return (
                user_a is not None
                and user_a != _UNAVAILABLE
                and user_a == user_b
            )
        return False


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

_WIDTH = 62


def _box_header(title: str) -> str:
    inner = f" {title} "
    pad_total = _WIDTH - 2
    pad_left = (pad_total - len(inner)) // 2
    pad_right = pad_total - pad_left - len(inner)
    return "+" + "-" * pad_left + inner + "-" * pad_right + "+"


def _box_div() -> str:
    return "+" + "-" * (_WIDTH - 2) + "+"


def _box_footer() -> str:
    return "+" + "-" * (_WIDTH - 2) + "+"


def _box_line(label: str, value: str) -> str:
    content = f"| {label:<16}: {value}"
    padding = _WIDTH - len(content) - 1
    return content + (" " * max(0, padding)) + "|"


def _box_text(text: str) -> str:
    max_inner = _WIDTH - 4
    result = []
    for chunk in text.split("\n"):
        while len(chunk) > max_inner:
            result.append(chunk[:max_inner])
            chunk = chunk[max_inner:]
        result.append(chunk)
    out = []
    for ln in result:
        content = f"| {ln}"
        padding = _WIDTH - len(content) - 1
        out.append(content + (" " * max(0, padding)) + "|")
    return "\n".join(out)


def _val(v: Any) -> str:
    if v is None or v == _UNAVAILABLE:
        return _UNAVAILABLE
    return str(v)


def format_analysis(analysis: EventAnalysis) -> str:
    """Render an EventAnalysis as a human-readable bordered box."""
    kind = analysis.event_kind.upper()
    lines: list[str] = [_box_header(f"{kind} ACTIVITY")]

    lines.append(_box_line("Event ID", analysis.event_id[:36]))
    lines.append(_box_line("Time (UTC)", analysis.observed_at))
    lines.append(_box_line("Host", analysis.host_id[:36]))
    lines.append(_box_line("Source", analysis.source[:36]))
    lines.append(_box_div())

    subj = analysis.subject
    loc = analysis.location
    actor = analysis.actor

    if analysis.event_kind == "process":
        lines.append(_box_text("PROCESS"))
        lines.append(_box_line("Name", _val(subj.get("process_name"))))
        lines.append(_box_line("PID", _val(subj.get("pid"))))
        lines.append(_box_line("Parent PID", _val(subj.get("parent_pid"))))
        lines.append(_box_line("Executable", _val(subj.get("executable"))))
        lines.append(_box_line("User", _val(subj.get("user"))))
        lines.append(_box_line("Started", _val(subj.get("started_at"))))

    elif analysis.event_kind == "file":
        lines.append(_box_text("FILE"))
        lines.append(_box_line("Path", _val(loc.get("path"))))
        lines.append(_box_line("Filename", _val(loc.get("filename"))))
        lines.append(_box_line("Directory", _val(loc.get("directory"))))
        lines.append(_box_line("Operation", _val(subj.get("operation"))))
        lines.append(_box_line("Extension", _val(subj.get("extension"))))

    elif analysis.event_kind == "network":
        lines.append(_box_text("NETWORK"))
        lines.append(_box_line("Process", _val(actor.get("process"))))
        lines.append(_box_line("PID", _val(actor.get("pid"))))
        lines.append(_box_line("Direction", _val(loc.get("direction"))))
        lines.append(_box_line("Protocol", _val(loc.get("protocol"))))
        lines.append(_box_line("Local EP", _val(loc.get("local_endpoint"))))
        lines.append(_box_line("Remote EP", _val(loc.get("remote_endpoint"))))
        lines.append(_box_line("State", _val(loc.get("state"))))
        if loc.get("query_name"):
            lines.append(_box_line("Query", _val(loc.get("query_name"))))
        if loc.get("response_code"):
            lines.append(_box_line("Resp Code", _val(loc.get("response_code"))))
        if loc.get("interface"):
            lines.append(_box_line("Interface", _val(loc.get("interface"))))

    elif analysis.event_kind == "authentication":
        lines.append(_box_text("AUTHENTICATION"))
        lines.append(_box_line("User", _val(subj.get("user"))))
        lines.append(_box_line("Source", _val(loc.get("source"))))

    elif analysis.event_kind == "health":
        lines.append(_box_text("HEALTH"))
        lines.append(_box_line("Status", _val(subj.get("status"))))

    if analysis.changes:
        lines.append(_box_div())
        lines.append(_box_text("CHANGE"))
        for ch in analysis.changes:
            lines.append(_box_text(f"  {ch}"))

    lines.append(_box_div())
    lines.append(_box_text("WHY"))
    lines.append(_box_text(f"  {analysis.reason}"))

    if analysis.related_event_ids:
        lines.append(_box_div())
        lines.append(_box_text("RELATED EVENTS"))
        for eid in analysis.related_event_ids[:5]:
            lines.append(_box_text(f"  -> {eid}"))
        if len(analysis.related_event_ids) > 5:
            lines.append(_box_text(f"  ... and {len(analysis.related_event_ids) - 5} more"))

    lines.append(_box_div())
    lines.append(_box_text("EVIDENCE"))
    for ev in analysis.evidence:
        lines.append(_box_text(f"  event_id : {ev.event_id}"))
        lines.append(_box_text(f"  source   : {ev.source}"))
        lines.append(_box_text(f"  observed : {ev.observed_at}"))

    lines.append(_box_footer())
    return "\n".join(lines)


def format_analyses(analyses: Sequence[EventAnalysis]) -> str:
    """Render a sequence of analyses separated by blank lines."""
    return "\n\n".join(format_analysis(a) for a in analyses)
