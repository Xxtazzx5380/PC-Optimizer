#!/usr/bin/env python3
"""PC-Optimizer command-line entry point.

The default command is read-only. No optimization is applied automatically.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from core.logging_utils import configure
from core.system import snapshot


APP_NAME = "PC-Optimizer"
ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
LOGS = ROOT / "logs"


def save_report(data: dict) -> Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    filename = REPORTS / f"audit_{datetime.now():%Y%m%d_%H%M%S}.json"
    filename.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return filename


def main() -> int:
    logger = configure(LOGS)
    print("=" * 64)
    print(f" {APP_NAME}")
    print("=" * 64)
    print("Read-only audit mode. No system changes are made.\n")

    if os.name != "nt":
        print("This version is designed for Windows.")
        return 1

    try:
        system = snapshot()
    except Exception as exc:
        logger.exception("System audit failed")
        print(f"Audit failed: {exc}")
        return 1

    data = asdict(system)
    report = save_report(data)
    logger.info("Audit report created: %s", report)

    print(f"Administrator : {'YES' if system.administrator else 'NO'}")
    print(f"Windows       : {system.os}")
    print(f"Architecture  : {system.architecture}")
    print(f"CPU           : {system.processor}")
    print(f"RAM           : {system.ram_used_mb} / {system.ram_total_mb} MB")
    print(f"Running svcs  : {len(system.services)}")
    print(f"Startup items : {len(system.startup)}")
    print(f"Power plan    : {system.power_plan}")
    print(f"\nAudit saved to: {report}")

    if not system.administrator:
        print("\nSystem-level mutations will require Administrator privileges.")

    print("\nNo optimization has been applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
