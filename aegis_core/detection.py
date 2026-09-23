"""Explainable behaviour detections; not signature or exploit detection claims."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import timedelta
from typing import Iterable, Protocol

from .models import Event, EventKind, Finding, Severity, utc_now


class Detector(Protocol):
    def evaluate(self, event: Event) -> Iterable[Finding]: ...


class FileChangeBurstDetector:
    """Detects ransomware-like burst behaviour across independently named files.

    This is intentionally a finding, not an automatic rollback: mass editing can
    be legitimate, and the Core has no authority to overwrite production data.
    """
    rule_id = "AEGIS-FILE-001"

    def __init__(self, window_seconds: int = 60, threshold: int = 25) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self._events: deque[Event] = deque()

    def evaluate(self, event: Event) -> Iterable[Finding]:
        # Accept both old "operation" key and new "action" key
        action = event.data.get("action") or event.data.get("operation") or ""
        if event.kind is not EventKind.FILE or action not in {"modified", "created", "modify", "create"}:
            return ()
        now = event.observed_at
        self._events.append(event)
        while self._events and self._events[0].observed_at < now - self.window:
            self._events.popleft()
        paths = {str(item.data.get("path", "")) for item in self._events}
        suffixes = Counter(str(item.data.get("suffix", "")) for item in self._events)
        if len(paths) < self.threshold:
            return ()
        dominant_suffix, count = suffixes.most_common(1)[0]
        confidence = min(0.95, 0.45 + (len(paths) / self.threshold) * 0.25 + (count / len(paths)) * 0.2)
        evidence = tuple(item.event_id for item in self._events)
        return (Finding(self.rule_id, "Unusual burst of file changes", Severity.HIGH, confidence, evidence,
            f"{len(paths)} files changed in {self.window.seconds} seconds; dominant suffix is {dominant_suffix!r}.",
            "Pause automated workflows, preserve evidence, and have an authorized responder review available file versions."),)


class NetworkRateDetector:
    """Detects unexpectedly high connection creation rates from supplied network events."""
    rule_id = "AEGIS-NET-001"

    def __init__(self, window_seconds: int = 60, threshold: int = 100) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self._by_process: dict[str, deque[Event]] = defaultdict(deque)

    def evaluate(self, event: Event) -> Iterable[Finding]:
        action = event.data.get("action", "")
        if event.kind is not EventKind.NETWORK or action not in {"connect", "connection_open", "connection_snapshot"}:
            return ()
        identity = str(event.data.get("pid") or event.data.get("process") or "unknown")
        events = self._by_process[identity]
        events.append(event)
        while events and events[0].observed_at < event.observed_at - self.window:
            events.popleft()
        if len(events) < self.threshold:
            return ()
        return (Finding(self.rule_id, "Unusual outbound connection rate", Severity.MEDIUM, 0.7,
            tuple(item.event_id for item in events),
            f"Process identity {identity!r} opened {len(events)} connections in {self.window.seconds} seconds.",
            "Validate the process owner and workload; investigate destinations before any containment action."),)


class NewProcessWithNetworkDetector:
    """Detects processes that start and immediately establish network connections.

    Correlates PROCESS_START events (action='start') with subsequent NETWORK
    events sharing the same PID within a time window. This pattern occurs in
    legitimate software (updaters, browsers) but is also consistent with
    malware that spawns a child process to phone home.

    Rule: AEGIS-PROC-NET-001
    Severity: LOW (requires investigation; not conclusive on its own)
    """
    rule_id = "AEGIS-PROC-NET-001"

    def __init__(self, window_seconds: int = 60) -> None:
        self.window = timedelta(seconds=window_seconds)
        # pid -> (start_event, list_of_network_events)
        self._process_starts: dict[int, tuple[Event, list[Event]]] = {}

    def evaluate(self, event: Event) -> Iterable[Finding]:
        now = event.observed_at

        # Expire old tracked entries
        expired = [
            pid for pid, (start_evt, _) in self._process_starts.items()
            if now - start_evt.observed_at > self.window
        ]
        for pid in expired:
            del self._process_starts[pid]

        # Track new PROCESS_START events
        if event.kind is EventKind.PROCESS and event.data.get("action") == "start":
            pid = event.data.get("pid")
            if pid is not None:
                self._process_starts[int(pid)] = (event, [])
            return ()

        # Correlate NETWORK events to tracked starts
        if event.kind is EventKind.NETWORK:
            pid_raw = event.data.get("pid")
            if pid_raw is None:
                return ()
            pid = int(pid_raw)
            if pid not in self._process_starts:
                return ()
            start_evt, net_events = self._process_starts[pid]
            net_events.append(event)

            # Fire exactly once per process (at first network event)
            if len(net_events) == 1:
                proc_name = start_evt.data.get("name", "unknown")
                remote_ip = event.data.get("remote_ip", "unknown")
                return (Finding(
                    rule_id=self.rule_id,
                    title="New process established network connection",
                    severity=Severity.LOW,
                    confidence=0.55,
                    evidence_event_ids=(start_evt.event_id, event.event_id),
                    explanation=(
                        f"Process {proc_name!r} (PID {pid}) started and immediately "
                        f"established a network connection to {remote_ip}."
                    ),
                    recommendation=(
                        "Verify the process is expected to make outbound connections. "
                        "Investigate if it is a newly installed or unknown binary."
                    ),
                ),)

        return ()


class AuthFailureBurstDetector:
    """Detects rapid authentication failure bursts consistent with brute force.

    Monitors AUTHENTICATION events with action='login_failure'.
    Threshold: configured number of failures per user within the window.

    Rule: AEGIS-AUTH-001
    Severity: HIGH
    """
    rule_id = "AEGIS-AUTH-001"

    def __init__(self, window_seconds: int = 60, threshold: int = 5) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self._by_user: dict[str, deque[Event]] = defaultdict(deque)

    def evaluate(self, event: Event) -> Iterable[Finding]:
        if event.kind is not EventKind.AUTHENTICATION:
            return ()
        if event.data.get("action") != "login_failure":
            return ()

        now = event.observed_at
        user = str(event.data.get("user", "unknown"))

        user_q = self._by_user[user]
        user_q.append(event)
        while user_q and user_q[0].observed_at < now - self.window:
            user_q.popleft()

        # Fire exactly at threshold (not on every subsequent failure)
        if len(user_q) == self.threshold:
            evidence = tuple(e.event_id for e in user_q)
            return (Finding(
                rule_id=self.rule_id,
                title="Authentication failure burst detected",
                severity=Severity.HIGH,
                confidence=0.85,
                evidence_event_ids=evidence,
                explanation=(
                    f"{len(user_q)} failed login attempts for user {user!r} "
                    f"in {self.window.seconds} seconds."
                ),
                recommendation=(
                    "Investigate the source of authentication attempts. "
                    "Consider blocking the source IP if this is SSH brute force. "
                    "Verify the targeted account is not compromised."
                ),
            ),)

        return ()


class DetectionPipeline:
    def __init__(self, detectors: Iterable[Detector] | None = None) -> None:
        self._detectors = tuple(detectors or (
            FileChangeBurstDetector(),
            NetworkRateDetector(),
            NewProcessWithNetworkDetector(),
            AuthFailureBurstDetector(),
        ))

    def evaluate(self, event: Event) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.evaluate(event))
        return tuple(findings)
