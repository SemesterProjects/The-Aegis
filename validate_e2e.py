"""
Aegis Core - E2E Validation & Evidence Report
==============================================

Runs a real host monitoring session for a configurable duration, then prints
a structured evidence report showing every event that was actually observed,
not just summary counts.

Key guarantees:
  - All queries are scoped to the CURRENT run via `since=run_start`.
    Historical data from previous runs is never counted or displayed.
  - Watch roots are security-relevant OS paths, never cloud-sync directories.
  - Process events reflect only genuine new / exited processes after baseline.
  - Auth events reflect only new journal entries since the persisted cursor.

Usage:
    python validate_e2e.py [--seconds N] [--fresh] [--no-auth]

Options:
    --seconds N   Monitoring window in seconds (default: 30)
    --fresh       Delete the evidence database before the run (clean slate)
    --no-auth     Disable authentication log collection
"""

from __future__ import annotations

import argparse
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Make project root importable when run directly
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment
from aegis_core.storage import EvidenceStore


# ---------------------------------------------------------------------------
# Platform-appropriate security-relevant watch roots
# ---------------------------------------------------------------------------

def _security_watch_roots() -> list[Path]:
    """Return OS-appropriate security-relevant directories to monitor.

    These are paths where security-relevant changes actually occur:
    config files, binaries, user home dirs, log directories.

    Cloud-sync directories (OneDrive, Dropbox, etc.) are intentionally
    excluded - they generate high-frequency non-security sync activity.
    """
    os_name = platform.system()

    if os_name == "Linux":
        candidates = [
            Path("/etc"),           # System configuration
            Path("/bin"),           # Core binaries
            Path("/usr/bin"),       # User binaries
            Path("/usr/sbin"),      # Superuser binaries
            Path("/sbin"),          # System binaries
            Path("/var/log"),       # System logs
            Path("/tmp"),           # Temp directory (common malware landing zone)
            Path("/home"),          # User home directories
            Path("/root"),          # Root home
        ]
    elif os_name == "Windows":
        sys_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        candidates = [
            sys_root / "System32",
            sys_root / "SysWOW64",
            Path(os.environ.get("TEMP", r"C:\Windows\Temp")),
            Path(r"C:\Users"),      # User profiles (may be slow on large installs)
        ]
    elif os_name == "Darwin":
        candidates = [
            Path("/etc"),
            Path("/usr/bin"),
            Path("/usr/sbin"),
            Path("/var/log"),
            Path("/tmp"),
            Path("/Users"),
        ]
    else:
        candidates = []

    # Only include directories that actually exist on this host
    return [p for p in candidates if p.is_dir() and not p.is_symlink()]


# ---------------------------------------------------------------------------
# Report rendering helpers
# ---------------------------------------------------------------------------

_COL_SEP = "  "
_MISSING = "-"


def _trunc(value: object, width: int) -> str:
    s = str(value) if value not in (None, "") else _MISSING
    if len(s) > width:
        return s[: width - 1] + ">"
    return s


def _header(title: str, width: int = 80) -> str:
    pad = max(0, width - len(title) - 2)
    left = pad // 2
    right = pad - left
    return f"\n{'=' * left} {title} {'=' * right}"


def _table(headers: list[str], rows: list[list], widths: list[int]) -> str:
    """Render an ASCII table with fixed-width columns."""
    if not rows:
        return "  (no events recorded in this session)\n"

    sep_line = _COL_SEP.join("-" * w for w in widths)
    hdr_line = _COL_SEP.join(h.ljust(w) for h, w in zip(headers, widths))

    lines = ["  " + hdr_line, "  " + sep_line]
    for row in rows:
        line = _COL_SEP.join(_trunc(cell, w).ljust(w) for cell, w in zip(row, widths))
        lines.append("  " + line)
    return "\n".join(lines) + "\n"


def _fmt_ts(ts: str) -> str:
    """Shorten an ISO timestamp to HH:MM:SS for display."""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%H:%M:%S")
    except Exception:
        return ts[:8] if ts else _MISSING


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n:,} {singular if n == 1 else (plural or singular + 's')}"


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def _report_summary(
    run_id: str,
    run_start: datetime,
    run_end: datetime,
    counts: dict[str, int],
    finding_count: int,
    chain_valid: bool,
    host_id: str,
    watch_roots: list[Path],
    skipped_roots: list[str],
    collectors: list[str],
) -> str:
    total = sum(counts.values())
    elapsed = (run_end - run_start).total_seconds()

    lines = [
        "",
        "+" + "=" * 72 + "+",
        "|" + "  AEGIS CORE - MONITORING SESSION REPORT".center(72) + "|",
        "+" + "=" * 72 + "+",
        "",
        f"  Run ID         : {run_id}",
        f"  Hostname       : {platform.node()}",
        f"  Host ID        : {host_id}",
        f"  OS             : {platform.system()} {platform.release()} ({platform.version()})",
        f"  Session start  : {run_start.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"  Session end    : {run_end.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"  Duration       : {elapsed:.1f} seconds",
        f"  Evidence scope : events observed at or after {run_start.isoformat()}",
        f"  Hash chain     : {'[OK] VALID' if chain_valid else '[!!] BROKEN - evidence may be tampered'}",
        f"  Collectors     : {', '.join(collectors) or 'none'}",
        "",
        "  Monitored paths:",
    ]
    for root in watch_roots:
        lines.append(f"    [+]  {root}")
    for skip in skipped_roots:
        lines.append(f"    [-]  {skip}  (excluded)")

    lines += [
        "",
        "  +-" + "-" * 20 + "-+-" + "-" * 13 + "-+",
        "  | " + "  EVENT SUMMARY".ljust(20) + " |" + "".ljust(14) + "|",
        "  +-" + "-" * 20 + "-+-" + "-" * 13 + "-+",
        "  | " + "  Kind".ljust(20) + " |  " + "Count".ljust(12) + "|",
        "  +-" + "-" * 20 + "-+-" + "-" * 13 + "-+",
    ]
    kind_order = ["process", "network", "file", "authentication", "health"]
    for kind in kind_order:
        n = counts.get(kind, 0)
        lines.append(f"  |  {kind.capitalize():<19}|  {n:<12}|")
    lines += [
        "  +-" + "-" * 20 + "-+-" + "-" * 13 + "-+",
        f"  |  {'TOTAL':<19}|  {sum(counts.values()):<12}|",
        "  +-" + "-" * 20 + "-+-" + "-" * 13 + "-+",
        f"  |  {'Findings':<19}|  {finding_count:<12}|",
        "  +-" + "-" * 20 + "-+-" + "-" * 13 + "-+",
        "",
    ]
    return "\n".join(lines)


def _report_telemetry_summary(events_by_kind: dict[str, list[dict]], totals: dict[str, int], max_rows: int | None) -> str:
    lines = [_header("TELEMETRY SUMMARY")]
    lines.append("  Counts are scoped to this run. No rows are hidden unless --max-rows is supplied.")
    headers = ["KIND", "TOTAL", "DISPLAYED", "FIRST OBSERVED", "LAST OBSERVED", "SOURCES / MECHANISMS"]
    widths = [18, 10, 10, 25, 25, 60]
    rows = []
    for kind, events in events_by_kind.items():
        timestamps = [e.get("observed_at") for e in events if e.get("observed_at")]
        sources = sorted({
            f"{e.get('source', '?')} / {e.get('data', {}).get('collection_mechanism', 'direct')}"
            for e in events
        })
        displayed = len(events)
        rows.append([
            kind,
            totals.get(kind, 0),
            displayed if max_rows is None else f"{displayed} of {totals.get(kind, 0)}",
            min(timestamps) if timestamps else "-",
            max(timestamps) if timestamps else "-",
            "; ".join(sources) or "-",
        ])
    lines.append(_table(headers, rows, widths))
    return "\n".join(lines)


def _report_capabilities(engine: MonitoringEngine) -> str:
    lines = [_header("CAPABILITY REPORT")]
    lines.append(f"  OS: {engine.capabilities.os_name} {engine.capabilities.release}")
    lines.append(f"  Elevated: {engine.capabilities.is_elevated}")
    lines.append(f"  Dependencies/features: {', '.join(sorted(engine.capabilities.features)) or '-'}")
    lines.append(f"  Host limitations: {'; '.join(engine.capabilities.limitations) or '-'}")
    lines.append("  Collector status is reported in HEALTH evidence; unavailable sensors are not treated as zero telemetry.")
    return "\n".join(lines)


def _report_limitations(events_by_kind: dict[str, list[dict]], engine: MonitoringEngine) -> str:
    limitations = [
        "File process attribution is unavailable with watchdog/polling and is explicitly recorded as unavailable.",
        "Process lifecycle is snapshot-difference based; short-lived processes and PID reuse can be missed or ambiguous.",
        "Network polling can miss connections that start and end between polls; ETW is capability-detected, not consumed by this Python path.",
        "Authentication results depend on the host Security Event Log/journal source and permissions; zero matching events is distinct from unavailable capability.",
        "IP geolocation is report-time enrichment only; raw evidence remains IP addresses and timestamps, so geographic movement is not asserted.",
    ]
    if not events_by_kind.get("authentication"):
        limitations.append("No authentication events were observed in this run; inspect HEALTH capability/status evidence for the reason.")
    if engine.capabilities.limitations:
        limitations.extend(engine.capabilities.limitations)
    lines = [_header("LIMITATIONS")]
    lines.extend(f"  - {item}" for item in dict.fromkeys(limitations))
    return "\n".join(lines)


def _report_processes(events: list[dict]) -> str:
    lines = [_header(f"PROCESS EVENTS  ({_plural(len(events), 'event')})")]
    if not events:
        lines.append("  (no process events in this session)\n")
        return "\n".join(lines)

    headers = ["TIME", "ACTION", "PID", "NAME", "USER", "STARTED", "STATUS", "EXE / CMDLINE"]
    widths  = [8,      9,        6,    20,    14,     19,        8,        40]

    rows = []
    for ev in events:
        d = ev.get("data", {})
        ts = _fmt_ts(ev.get("observed_at", ""))
        action = d.get("action", "snapshot")
        pid    = d.get("pid", _MISSING)
        name   = d.get("name", _MISSING)
        user   = d.get("user", _MISSING)

        started = d.get("started") or d.get("create_time") or _MISSING
        if isinstance(started, (int, float)):
            try:
                started = datetime.fromtimestamp(started, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                started = str(started)
        elif isinstance(started, str) and started != _MISSING:
            started = started.replace("T", " ")[:19]

        status = d.get("status", _MISSING)

        # Prefer cmdline for snapshots, fall back to exe
        detail = d.get("cmdline") or d.get("exe") or _MISSING
        rows.append([ts, action, pid, name, user, started, status, detail])

    lines.append(_table(headers, rows, widths))
    return "\n".join(lines)


_GEO_CACHE = {}
def _get_geo_ip(ip: str) -> str:
    import urllib.request, json
    if not ip or ip == "*" or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip.startswith("::") or ip.startswith("fe80"):
        return "-"
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=0.5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                geo = f"{data.get('city', '')}, {data.get('country', '')} ({data.get('isp', '')})"
                _GEO_CACHE[ip] = geo
                return geo
    except Exception:
        pass
    _GEO_CACHE[ip] = "-"
    return "-"

def _report_network(events: list[dict]) -> str:
    lines = [_header(f"NETWORK EVENTS  ({_plural(len(events), 'event')})")]
    if not events:
        lines.append("  (no network events in this session)\n")
        return "\n".join(lines)

    headers = ["TIME", "ACTION", "PROTOCOL", "LOCAL ADDR", "REMOTE ADDR", "REMOTE GEO / ISP", "PROCESS", "DIRECTION"]
    widths  = [8,      20,       9,           21,           15,            30,                 18,        11]

    rows = []
    for ev in events:
        d = ev.get("data", {})
        ts       = _fmt_ts(ev.get("observed_at", ""))
        action   = d.get("action", _MISSING)
        proto    = d.get("protocol", _MISSING)
        l_ip     = d.get("local_ip", "*")
        l_port   = d.get("local_port", "*")
        r_ip     = d.get("remote_ip", "*")
        r_port   = d.get("remote_port", "*")
        local    = f"{l_ip}:{l_port}"
        remote   = f"{r_ip}:{r_port}"
        geo      = _get_geo_ip(r_ip)
        process  = d.get("name") or d.get("process_name") or _MISSING
        direction = d.get("direction", _MISSING)
        rows.append([ts, action, proto, local, remote, geo, process, direction])

    lines.append(_table(headers, rows, widths))
    return "\n".join(lines)


def _report_files(events: list[dict]) -> str:
    lines = [_header(f"FILE EVENTS  ({_plural(len(events), 'event')})")]
    lines.append("  Note: Process attribution for files requires ETW (Windows) / eBPF (Linux) which will be added in v2.")
    if not events:
        lines.append("  (no file events in this session)\n")
        return "\n".join(lines)

    headers = ["TIME", "ACTION", "EXT", "SIZE (B)", "PROCESS", "PATH"]
    widths  = [8,      8,        6,     10,         16,       60]

    rows = []
    for ev in events:
        d = ev.get("data", {})
        ts     = _fmt_ts(ev.get("observed_at", ""))
        action = d.get("action", _MISSING)
        ext    = d.get("suffix", _MISSING)
        size   = d.get("size", _MISSING)
        path   = d.get("path", _MISSING)
        process = d.get("process_name") or d.get("process_attribution") or _MISSING
        rows.append([ts, action, ext, size, process, path])

    lines.append(_table(headers, rows, widths))
    return "\n".join(lines)


def _report_auth(events: list[dict]) -> str:
    lines = [_header(f"AUTHENTICATION EVENTS  ({_plural(len(events), 'event')})")]
    if not events:
        import os
        is_admin = os.name == 'nt' and (os.environ.get('USERNAME') == 'SYSTEM' or 'Administrator' in os.environ.get('USERNAME', '')) # basic check, not perfect but good enough for note
        lines.append("  (no authentication events in this session)")
        lines.append("  Note: On Windows, capturing auth events requires the script to be run "
                     "as Administrator (to read the Security Event Log), and requires an actual login/logout "
                     "event to occur during the monitoring window.\n")
        return "\n".join(lines)

    headers = ["TIME", "ACTION", "USER", "SOURCE IP", "MECHANISM", "MESSAGE"]
    widths  = [8,      18,       16,     16,           16,          50]

    rows = []
    for ev in events:
        d = ev.get("data", {})
        ts       = _fmt_ts(ev.get("observed_at", ""))
        action   = d.get("action", _MISSING)
        user     = d.get("user", _MISSING)
        src_ip   = d.get("source_ip", _MISSING)
        mech     = d.get("auth_mechanism", _MISSING)
        message  = d.get("message", _MISSING)
        rows.append([ts, action, user, src_ip, mech, message])

    lines.append(_table(headers, rows, widths))
    return "\n".join(lines)


def _report_findings(findings: list[dict]) -> str:
    lines = [_header(f"FINDINGS  ({_plural(len(findings), 'finding')})")]
    if not findings:
        lines.append("  (no findings generated in this session)\n")
        return "\n".join(lines)

    for i, f in enumerate(findings, 1):
        sev       = f.get("severity", "?").upper()
        rule      = f.get("rule_id", "?")
        title     = f.get("title", "?")
        conf      = f.get("confidence", 0.0)
        conf_pct  = f"{conf * 100:.0f}%"
        expl      = f.get("explanation", "")
        rec       = f.get("recommendation", "")
        ev_ids    = f.get("evidence_event_ids", [])
        ts        = _fmt_ts(f.get("created_at", ""))

        lines += [
            f"",
            f"  [{i}] {sev}  {rule}  (confidence {conf_pct})  @ {ts}",
            f"      Title:          {title}",
            f"      Explanation:    {expl}",
            f"      Recommendation: {rec}",
            f"      Evidence IDs:   {', '.join(str(e) for e in ev_ids[:3])}"
            + (f"  ... +{len(ev_ids)-3} more" if len(ev_ids) > 3 else ""),
        ]

    lines.append("")
    return "\n".join(lines)


def _report_health(events: list[dict]) -> str:
    lines = [_header(f"HEALTH EVENTS  ({_plural(len(events), 'event')})")]
    if not events:
        lines.append("  (no health events in this session)\n")
        return "\n".join(lines)

    headers = ["TIME", "SOURCE", "STATUS / ACTION", "DETAIL"]
    widths  = [8,      18,       24,                 60]

    rows = []
    for ev in events:
        d = ev.get("data", {})
        ts     = _fmt_ts(ev.get("observed_at", ""))
        source = ev.get("source", _MISSING)
        action = d.get("action") or d.get("status") or _MISSING
        # Combine interesting fields into detail
        parts = []
        for k in ("collectors", "os", "features", "error", "warning", "reason"):
            v = d.get(k)
            if v is not None:
                parts.append(f"{k}={v!r}" if not isinstance(v, str) else f"{k}={v}")
        detail = " | ".join(parts) if parts else _MISSING
        rows.append([ts, source, action, detail])

    lines.append(_table(headers, rows, widths))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seconds", type=float, default=30.0,
                   help="Monitoring window duration in seconds (default: 30)")
    p.add_argument("--fresh", action="store_true",
                   help="Delete the evidence database before this run for a clean slate")
    p.add_argument("--no-auth", action="store_true",
                   help="Disable authentication log collection")
    p.add_argument("--max-rows", type=int, default=None,
                   help="Optional display limit per evidence table (default: all rows)")
    p.add_argument("--data-dir", type=Path, default=Path("./e2e_data"),
                   help="Directory for evidence database (default: ./e2e_data)")
    p.add_argument("--watch", type=Path, action="append", default=[],
                   help="Explicit filesystem root to monitor; repeatable")
    p.add_argument("--report-file", type=Path,
                   help="Write the generated evidence report to this path")
    return p.parse_args()


def run_e2e(args: argparse.Namespace) -> int:
    print("\n  Aegis Core - Real Host Telemetry Validation")
    print("  " + "-" * 50)

    data_dir = args.data_dir
    db_path  = data_dir / "evidence.sqlite3"
    cursor_path = data_dir / ".aegis_auth_cursor"

    # ------------------------------------------------------------------
    # Fresh run: wipe persistent state so this run starts completely clean
    # ------------------------------------------------------------------
    if args.fresh:
        for p in [db_path, cursor_path]:
            if p.exists():
                p.unlink()
                print(f"  [fresh] Deleted {p}")

    # ------------------------------------------------------------------
    # Discover security-relevant watch roots for this OS
    # ------------------------------------------------------------------
    watch_roots = list(args.watch) if args.watch else _security_watch_roots()
    if not watch_roots:
        print("  [warn] No security-relevant watch roots found for this OS.")

    print(f"\n  Monitoring {len(watch_roots)} path(s):")
    for r in watch_roots:
        print(f"    * {r}")

    # ------------------------------------------------------------------
    # Build engine
    # ------------------------------------------------------------------
    config = MonitoringConfig(
        environment=Environment.DEVELOPMENT,
        data_directory=data_dir,
        interval_seconds=2.0,
    )

    print("\n  Initializing monitoring pipeline...")
    try:
        engine = MonitoringEngine.build_from_capability(
            config=config,
            watch_roots=watch_roots,
            enable_auth=not args.no_auth,
        )
    except Exception as e:
        print(f"\n  ERROR: Failed to build engine: {e}")
        return 1

    collectors_active = [c.name for c in engine.collectors]
    print(f"  Active collectors: {', '.join(collectors_active)}")

    # ------------------------------------------------------------------
    # Run - capture the exact start time BEFORE the engine runs
    # ------------------------------------------------------------------
    run_id = config.run_id
    run_start = datetime.now(timezone.utc)
    print(f"\n  Run ID: {run_id}")
    print(f"  Starting collection for {args.seconds:.0f} seconds...  (started {run_start.strftime('%H:%M:%S UTC')})")

    try:
        engine.run_for(args.seconds)
    except Exception as e:
        print(f"\n  ERROR during collection: {e}")
        return 1

    run_end = datetime.now(timezone.utc)
    print(f"  Collection complete.  (ended {run_end.strftime('%H:%M:%S UTC')})\n")

    # ------------------------------------------------------------------
    # Open a fresh read connection to the (now-closed) DB
    # ------------------------------------------------------------------
    store = EvidenceStore(db_path)

    # Verify chain integrity over the whole DB
    chain_valid = store.verify_chain()

    # ------------------------------------------------------------------
    # Query ONLY this run's events using since=run_start
    # This eliminates all historical data from previous runs.
    # ------------------------------------------------------------------
    kind_counts: dict[str, int] = {}
    for kind in ["process", "network", "file", "authentication", "health"]:
        kind_counts[kind] = store.count_events(since=run_start, kinds=[kind], run_id=run_id)

    # Retrieve actual event payloads (capped at --max-rows for display)
    proc_events  = store.query_events(since=run_start, kinds=["process"], run_id=run_id,
                                       limit=args.max_rows)
    net_events   = store.query_events(since=run_start, kinds=["network"], run_id=run_id,
                                       limit=args.max_rows)
    file_events  = store.query_events(since=run_start, kinds=["file"], run_id=run_id,
                                       limit=args.max_rows)
    auth_events  = store.query_events(since=run_start, kinds=["authentication"], run_id=run_id,
                                       limit=args.max_rows)
    health_events = store.query_events(since=run_start, kinds=["health"], run_id=run_id,
                                        limit=args.max_rows)

    # Findings scoped to this run
    findings = store.get_findings(since=run_start, run_id=run_id, limit=args.max_rows)
    store.close()

    # ------------------------------------------------------------------
    # Compute skipped roots (cloud-sync exclusions reported in health events)
    # ------------------------------------------------------------------
    skipped_roots: list[str] = []
    for ev in health_events:
        d = ev.get("data", {})
        if d.get("action") == "root_skipped":
            path   = d.get("path", "?")
            reason = d.get("reason", "?")
            skipped_roots.append(f"{path}  [{reason}]")

    # ------------------------------------------------------------------
    # Print report
    # ------------------------------------------------------------------
    events_by_kind = {
        "process": proc_events,
        "network": net_events,
        "file": file_events,
        "authentication": auth_events,
        "health": health_events,
    }
    report_parts = [
        _report_summary(run_id, run_start, run_end, kind_counts, len(findings),
                        chain_valid, config.host_id, watch_roots, skipped_roots,
                        collectors_active),
        _report_capabilities(engine),
        _report_telemetry_summary(events_by_kind, kind_counts, args.max_rows),
        _report_processes(proc_events),
        _report_network(net_events),
        _report_files(file_events),
        _report_auth(auth_events),
        _report_findings(findings),
        _report_health(health_events),
        _report_limitations(events_by_kind, engine),
    ]

    report_text = "\n".join(report_parts)
    if args.report_file:
        args.report_file.parent.mkdir(parents=True, exist_ok=True)
        args.report_file.write_text(report_text + "\n", encoding="utf-8")
        print(f"  Evidence report written to: {args.report_file}")
    print(report_text)

    # ------------------------------------------------------------------
    # Exit code
    # ------------------------------------------------------------------
    total = sum(kind_counts.values())

    if not chain_valid:
        print("  [FATAL] Hash chain is broken - evidence may have been tampered with.\n")
        return 1

    if total == 0:
        print("  [FAIL] No events collected during the monitoring window.\n")
        return 1

    # Sanity checks: verify that counts come from real sources
    proc_count = kind_counts.get("process", 0)
    net_count  = kind_counts.get("network",  0)

    warnings = []
    if proc_count == 0 and "process_lifecycle" in collectors_active:
        warnings.append("Process collector was active but emitted no events. Investigate.")
    if net_count == 0 and "network_bridge" in collectors_active:
        warnings.append("Network collector was active but emitted no events. Investigate.")

    if warnings:
        print("  [WARN] Warnings:")
        for w in warnings:
            print(f"     - {w}")
        print()

    print(f"  [OK] SUCCESS -- {total:,} events captured in {(run_end - run_start).total_seconds():.1f}s  |  "
          f"Hash chain: {'VALID' if chain_valid else 'BROKEN'}  |  "
          f"Findings: {len(findings)}\n")
    return 0


if __name__ == "__main__":
    import os
    sys.exit(run_e2e(parse_args()))
