#!/usr/bin/env python3
"""
PC-Optimizer
Python-first Windows PC audit and optimization toolkit.

The application stays in Python and invokes native Windows tooling only
when it is the appropriate interface for a Windows feature.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


APP_NAME = "PC-Optimizer"
ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
BACKUPS = ROOT / "backups"


@dataclass
class SystemInfo:
    timestamp: str
    administrator: bool
    windows: str
    machine: str
    processor: str
    python: str


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_native(command: list[str]) -> tuple[int, str, str]:
    """Run a native Windows command without hiding its output/errors."""
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def collect_basic_info() -> SystemInfo:
    return SystemInfo(
        timestamp=datetime.now().isoformat(timespec="seconds"),
        administrator=is_admin(),
        windows=platform.platform(),
        machine=platform.machine(),
        processor=platform.processor(),
        python=platform.python_version(),
    )


def save_report(info: SystemInfo) -> Path:
    REPORTS.mkdir(exist_ok=True)
    filename = REPORTS / f"audit_{datetime.now():%Y%m%d_%H%M%S}.json"
    filename.write_text(
        json.dumps(asdict(info), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return filename


def main() -> int:
    print("=" * 60)
    print(f" {APP_NAME} - V1")
    print("=" * 60)
    print()
    print("Python-first Windows optimizer")
    print("No changes are made by the initial audit.\n")

    if os.name != "nt":
        print("WARNING: This version is designed for Windows.")
        return 1

    info = collect_basic_info()

    print(f"Administrator : {'YES' if info.administrator else 'NO'}")
    print(f"Windows       : {info.windows}")
    print(f"Architecture  : {info.machine}")
    print(f"CPU           : {info.processor or 'Unknown'}")
    print(f"Python        : {info.python}")

    report = save_report(info)
    print(f"\nAudit saved to: {report}")

    if not info.administrator:
        print("\nTip: run the program as Administrator before applying system changes.")

    print("\nV1 currently performs an audit only.")
    print("Optimization modules will be added incrementally with rollback support.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
