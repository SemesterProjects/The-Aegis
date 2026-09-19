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
        if event.kind is not EventKind.FILE or event.data.get("operation") not in {"modified", "created"}:
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
        if event.kind is not EventKind.NETWORK or event.data.get("action") not in {"connect", "connection_open"}:
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


class DetectionPipeline:
    def __init__(self, detectors: Iterable[Detector] | None = None) -> None:
        self._detectors = tuple(detectors or (FileChangeBurstDetector(), NetworkRateDetector()))

    def evaluate(self, event: Event) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.evaluate(event))
        return tuple(findings)
