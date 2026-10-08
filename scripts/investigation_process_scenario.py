"""Bounded Aegis test scenario: rapid process creation, no external I/O."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS TEST SCENARIO")
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--hold-seconds", type=float, default=3.0)
    args = parser.parse_args()
    if not 1 <= args.count <= 20 or args.interval < 0 or args.hold_seconds < 0:
        parser.error("--count must be 1..20; intervals and hold time must be non-negative")

    children: list[subprocess.Popen[bytes]] = []
    try:
        for _ in range(args.count):
            if sys.platform == "win32":
                command = ["cmd.exe", "/c", "ping", "-n", "3", "127.0.0.1"]
            else:
                command = [sys.executable, "-c", "import time; time.sleep(2)"]
            children.append(subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=Path.cwd(),
            ))
            time.sleep(args.interval)
        time.sleep(args.hold_seconds)
    finally:
        for child in children:
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
