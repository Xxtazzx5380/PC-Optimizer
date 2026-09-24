from __future__ import annotations

import ctypes
import json
import os
import platform
from dataclasses import asdict, dataclass
from typing import Any

from core.runner import powershell


@dataclass(frozen=True)
class ProcessInfo:
    name: str
    pid: int
    cpu_percent: float
    memory_mb: float


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    display_name: str
    status: str
    start_type: str


@dataclass(frozen=True)
class StartupInfo:
    name: str
    command: str
    source: str


@dataclass(frozen=True)
class SystemSnapshot:
    os: str
    architecture: str
    processor: str
    python: str
    administrator: bool
    ram_total_mb: int
    ram_free_mb: int
    ram_used_mb: int
    top_processes: tuple[ProcessInfo, ...]
    top_cpu_processes: tuple[ProcessInfo, ...]
    services: tuple[ServiceInfo, ...]
    startup: tuple[StartupInfo, ...]
    power_plan: str
    power_plan_guid: str


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _json_from_powershell(script: str) -> Any:
    result = powershell(script, timeout=45)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "PowerShell command failed.")
    if not result.stdout:
        return None
    return json.loads(result.stdout)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def snapshot() -> SystemSnapshot:
    if os.name != "nt":
        raise OSError("System audit currently supports Windows only.")

    data = _json_from_powershell(
        r"""
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

$memory = Get-Process | ForEach-Object {
    [pscustomobject]@{
        Name = $_.ProcessName
        Pid = $_.Id
        CPU = 0
        MemoryMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
    }
} | Sort-Object MemoryMB -Descending | Select-Object -First 25

$cpuSamples = @()
try {
    $cpuSamples = (Get-Counter 'Process(*)% Processor Time').CounterSamples |
        Where-Object { $_.InstanceName -ne '_Total' -and $_.InstanceName -ne 'Idle' } |
        Sort-Object CookedValue -Descending |
        Select-Object -First 25 |
        ForEach-Object {
            [pscustomobject]@{
                Name = $_.InstanceName
                Pid = 0
                CPU = [math]::Round([double]$_.CookedValue / [Environment]::ProcessorCount, 1)
                MemoryMB = 0
            }
        }
} catch {}

$services = Get-Service | Where-Object Status -eq 'Running' | ForEach-Object {
    $c = Get-CimInstance Win32_Service -Filter ("Name='" + $_.Name.Replace("'", "''") + "'")
    [pscustomobject]@{
        Name = $_.Name
        DisplayName = $_.DisplayName
        Status = $_.Status.ToString()
        StartType = if ($c) { $c.StartMode } else { "Unknown" }
    }
} | Sort-Object Name

$startup = Get-CimInstance Win32_StartupCommand | ForEach-Object {
    [pscustomobject]@{
        Name = $_.Name
        Command = $_.Command
        Source = $_.Location
    }
}

$scheduled = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object {$_.State -ne 'Disabled'} |
    ForEach-Object {
        [pscustomobject]@{
            Name = $_.TaskName
            Command = ($_.Actions | ForEach-Object {$_.Execute + ' ' + $_.Arguments}) -join ' | '
            Source = $_.TaskPath
        }
    }

$startup = @($startup) + @($scheduled)

$power = powercfg /getactivescheme 2>$null

[pscustomobject]@{
    TotalMemoryMB = [int][math]::Round($os.TotalVisibleMemorySize / 1024)
    FreeMemoryMB = [int][math]::Round($os.FreePhysicalMemory / 1024)
    Processor = $cpu.Name
    Processes = @($memory)
    CpuProcesses = @($cpuSamples)
    Services = @($services)
    Startup = @($startup)
    Power = $power
} | ConvertTo-Json -Depth 7 -Compress
"""
    )

    total = _safe_int(data.get("TotalMemoryMB"))
    free = _safe_int(data.get("FreeMemoryMB"))
    used = max(total - free, 0)

    def process_list(items: list[dict[str, Any]]) -> tuple[ProcessInfo, ...]:
        return tuple(
            ProcessInfo(
                name=str(item.get("Name", "")),
                pid=_safe_int(item.get("Pid")),
                cpu_percent=_safe_float(item.get("CPU")),
                memory_mb=_safe_float(item.get("MemoryMB")),
            )
            for item in items
        )

    processes = process_list(data.get("Processes", []))
    cpu_processes = process_list(data.get("CpuProcesses", []))
    services = tuple(
        ServiceInfo(
            name=str(item.get("Name", "")),
            display_name=str(item.get("DisplayName", "")),
            status=str(item.get("Status", "")),
            start_type=str(item.get("StartType", "")),
        )
        for item in data.get("Services", [])
    )
    startup = tuple(
        StartupInfo(
            name=str(item.get("Name", "")),
            command=str(item.get("Command", "")),
            source=str(item.get("Source", "")),
        )
        for item in data.get("Startup", [])
    )

    power = str(data.get("Power", ""))
    guid = ""
    if "{" in power and "}" in power:
        guid = power[power.find("{") : power.find("}") + 1]

    return SystemSnapshot(
        os=platform.platform(),
        architecture=platform.machine(),
        processor=str(data.get("Processor") or platform.processor()),
        python=platform.python_version(),
        administrator=is_admin(),
        ram_total_mb=total,
        ram_free_mb=free,
        ram_used_mb=used,
        top_processes=processes,
        top_cpu_processes=cpu_processes,
        services=services,
        startup=startup,
        power_plan=power,
        power_plan_guid=guid,
    )


def snapshot_dict() -> dict[str, Any]:
    value = asdict(snapshot())
    return value
