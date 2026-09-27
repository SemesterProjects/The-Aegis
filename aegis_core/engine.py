"""Lifecycle orchestration for safe, continuously running monitoring."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
import threading
import time
import uuid
from typing import Iterable

from .capabilities import HostCapabilities, discover_capabilities
from .collectors import Collector, ProcessSnapshotCollector, stable_host_id
from .correlation import CorrelationIndex
from .detection import DetectionPipeline
from .models import Environment, Event, EventKind, Finding, utc_now
from .storage import EvidenceStore


@dataclass(frozen=True, slots=True)
class MonitoringConfig:
    environment: Environment
    data_directory: Path
    interval_seconds: float = 10.0
    health_interval_seconds: float = 60.0
    max_collector_backoff_seconds: float = 300.0
    host_id: str = field(default_factory=stable_host_id)
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self) -> None:
        if self.interval_seconds <= 0 or self.health_interval_seconds <= 0:
            raise ValueError("monitoring intervals must be positive")
        if self.max_collector_backoff_seconds < self.interval_seconds:
            raise ValueError("max collector backoff must be at least one collection interval")


@dataclass(slots=True)
class CollectorRuntime:
    failures: int = 0
    next_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error_type: str | None = None

    def as_event_data(self, name: str, now: datetime) -> dict[str, object]:
        return {
            "collector": name,
            "failures": self.failures,
            "backing_off": bool(self.next_attempt_at and self.next_attempt_at > now),
            "last_success_at": self.last_success_at.isoformat() if self.last_success_at else None,
            "last_error_type": self.last_error_type,
        }


class MonitoringEngine:
    """Coordinates read-only collectors and explainable detections.

    Production mode is designed for a supervised service process. It does not
    contain response execution APIs: findings enter an external approval
    workflow rather than modifying a monitored endpoint.

    Creating via build_from_capability() is the preferred production entry point.
    The __init__ constructor remains available for explicit control (tests, etc.).
    """
    def __init__(
        self,
        config: MonitoringConfig,
        *,
        collectors: Iterable[Collector] | None = None,
        pipeline: DetectionPipeline | None = None,
        capabilities: HostCapabilities | None = None,
        correlation: CorrelationIndex | None = None,
    ) -> None:
        self.config = config
        self.capabilities = capabilities or discover_capabilities()
        self.store = EvidenceStore(config.data_directory / "evidence.sqlite3")
        self.collectors = tuple(collectors or (ProcessSnapshotCollector(),))
        self.pipeline = pipeline or DetectionPipeline()
        self.correlation = correlation or CorrelationIndex()
        self._stopped = threading.Event()
        self._started = False
        self._closed = False
        self._last_health_at: datetime | None = None
        self._collector_runtime = {collector.name: CollectorRuntime() for collector in self.collectors}

    # ------------------------------------------------------------------
    # Production factory (preferred entry point)
    # ------------------------------------------------------------------

    @classmethod
    def build_from_capability(
        cls,
        config: MonitoringConfig,
        watch_roots: Iterable[Path] = (),
        enable_auth: bool = True,
        extra_collectors: Iterable[Collector] | None = None,
    ) -> "MonitoringEngine":
        """Factory that auto-discovers and initializes all available collectors.

        Capability detection is honest:
        - Collectors that cannot initialize on this OS are skipped.
        - NetworkBridgeCollector is always included in the list; if the OS has
          no supported network adapter it initializes but yields nothing (and
          emits a HEALTH capability_status event on first collect()).

        Args:
            config: MonitoringConfig with data directory, environment, intervals.
            watch_roots: File system roots to monitor for changes.
            enable_auth: Include the AuthEventCollector if OS supports it.
            extra_collectors: Additional collectors to include.

        Returns:
            A fully initialized MonitoringEngine ready to call start()/run_once().
        """
        from .collectors import (
            NetworkBridgeCollector,
            ProcessLifecycleCollector,
            FileEventCollector,
            AuthEventCollector,
        )

        collectors: list[Collector] = []

        # Process lifecycle (richer than simple ProcessSnapshotCollector)
        proc_col = ProcessLifecycleCollector()
        if proc_col.is_available:
            collectors.append(proc_col)
        else:
            # Fall back to legacy snapshot collector
            collectors.append(ProcessSnapshotCollector())

        # File events with watchdog or polling fallback
        watch_roots_list = list(watch_roots)
        if watch_roots_list:
            file_col = FileEventCollector(roots=tuple(watch_roots_list))
            file_col.initialize()
            collectors.append(file_col)

        # Network bridge (always added; reports UNAVAILABLE gracefully)
        net_col = NetworkBridgeCollector()
        net_col.initialize()
        collectors.append(net_col)

        # Authentication events — cursor persisted in data directory
        if enable_auth:
            auth_col = AuthEventCollector()
            cursor_file = config.data_directory / ".aegis_auth_cursor"
            auth_col.initialize(cursor_file=cursor_file)
            collectors.append(auth_col)

        # Extra collectors from caller
        if extra_collectors:
            collectors.extend(extra_collectors)

        return cls(config, collectors=collectors)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Record a transparent capability report before collecting telemetry."""
        if self._closed:
            raise RuntimeError("cannot restart a stopped MonitoringEngine; create a new instance")
        if self._started:
            return
        self._started = True
        self._ingest(Event(EventKind.HEALTH, "engine", {
            "status": "started", "environment": self.config.environment.value,
            "os": self.capabilities.os_name, "release": self.capabilities.release,
            "features": sorted(self.capabilities.features), "limitations": self.capabilities.limitations,
            "elevated": self.capabilities.is_elevated,
            "collectors": [c.name for c in self.collectors],
        }, host_id=self.config.host_id))

    def run_once(self) -> tuple[Finding, ...]:
        if not self._started:
            raise RuntimeError("call start() before collecting telemetry")
        findings: list[Finding] = []
        now = utc_now()
        for collector in self.collectors:
            runtime = self._collector_runtime[collector.name]
            if runtime.next_attempt_at and runtime.next_attempt_at > now:
                continue
            try:
                for event in collector.collect(self.config.host_id):
                    findings.extend(self._ingest(event))
                runtime.failures = 0
                runtime.next_attempt_at = None
                runtime.last_success_at = now
                runtime.last_error_type = None
            except Exception as exc:  # collectors are isolated so one failure cannot blind the engine
                runtime.failures += 1
                runtime.last_error_type = type(exc).__name__
                delay = min(self.config.max_collector_backoff_seconds,
                            self.config.interval_seconds * (2 ** min(runtime.failures - 1, 16)))
                runtime.next_attempt_at = now + timedelta(seconds=delay)
                self._ingest(Event(EventKind.HEALTH, "engine", {"collector": collector.name,
                    "status": "error", "error_type": runtime.last_error_type,
                    "retry_after_seconds": delay}, host_id=self.config.host_id))
        self._emit_health_if_due(now)
        return tuple(findings)

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stopped.is_set():
                self.run_once()
                self._stopped.wait(self.config.interval_seconds)
        finally:
            self.stop()

    def run_for(self, duration_seconds: float) -> None:
        """Run the same production loop for a bounded demonstration or integration test."""
        if duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive")
        self.start()
        deadline = time.monotonic() + duration_seconds
        try:
            while not self._stopped.is_set() and time.monotonic() < deadline:
                self.run_once()
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    self._stopped.wait(min(self.config.interval_seconds, remaining))
        finally:
            self.stop()

    def status(self) -> dict[str, object]:
        now = utc_now()
        return {
            "started": self._started,
            "stopped": self._stopped.is_set(),
            "environment": self.config.environment.value,
            "collector_count": len(self.collectors),
            "collectors": [runtime.as_event_data(name, now) for name, runtime in self._collector_runtime.items()],
            "evidence_chain_valid": self.store.verify_chain() if not self._closed else None,
        }

    def stop(self) -> None:
        self._stopped.set()
        if self._closed:
            return
        # Close any collectors that have a close() method
        for collector in self.collectors:
            if hasattr(collector, "close"):
                try:
                    collector.close()
                except Exception:
                    pass
        self._ingest(Event(EventKind.HEALTH, "engine", {"status": "stopped"}, host_id=self.config.host_id))
        self.store.close()
        self._closed = True

    def _emit_health_if_due(self, now: datetime) -> None:
        if self._last_health_at and now - self._last_health_at < timedelta(seconds=self.config.health_interval_seconds):
            return
        self._last_health_at = now
        self._ingest(Event(EventKind.HEALTH, "engine", {
            "status": "healthy",
            "collectors": [runtime.as_event_data(name, now) for name, runtime in self._collector_runtime.items()],
            "evidence_chain_valid": self.store.verify_chain(),
        }, host_id=self.config.host_id))

    def _ingest(self, event: Event) -> tuple[Finding, ...]:
        # Collectors remain independent of sessions; the engine stamps the
        # canonical run and receipt time at the single ingestion boundary.
        event = replace(event, run_id=self.config.run_id, ingested_at=utc_now())
        self.store.append_event(event)
        try:
            self.correlation.ingest(event.canonical())
        except Exception as exc:
            # The index is derived and disposable; durable evidence remains
            # authoritative even when correlation code fails.
            self.store.append_event(Event(
                EventKind.HEALTH,
                "engine",
                {"action": "correlation_error", "error_type": type(exc).__name__,
                 "error": str(exc)[:300]},
                host_id=self.config.host_id,
                run_id=self.config.run_id,
            ))
        findings = self.pipeline.evaluate(event)
        for finding in findings:
            finding = replace(finding, run_id=self.config.run_id)
            self.store.append_finding(finding)
        return findings
