from __future__ import annotations

import ctypes
import os
import platform
from dataclasses import dataclass


@dataclass(frozen=True)
class SystemSnapshot:
    os: str
    architecture: str
    processor: str
    python: str
    administrator: bool


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def snapshot() -> SystemSnapshot:
    return SystemSnapshot(
        os=platform.platform(),
        architecture=platform.machine(),
        processor=platform.processor(),
        python=platform.python_version(),
        administrator=is_admin(),
    )
