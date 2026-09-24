from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run(command: list[str], timeout: int = 30) -> CommandResult:
    """Run a native command without a shell.

    Commands must be passed as an argument list. The environment is inherited
    intentionally so Windows tools behave normally.
    """
    if not command:
        raise ValueError("command must not be empty")
    completed = subprocess.run(
        command,
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return CommandResult(
        completed.returncode,
        completed.stdout.strip(),
        completed.stderr.strip(),
    )


def powershell(script: str, timeout: int = 30) -> CommandResult:
    """Execute a fixed PowerShell script through powershell.exe.

    No user-provided string should be interpolated into the script without
    validation. ExecutionPolicy is not changed.
    """
    if os.name != "nt":
        raise OSError("PowerShell execution is only supported on Windows.")
    return run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        timeout=timeout,
    )
