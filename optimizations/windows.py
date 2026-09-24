from __future__ import annotations

import json
import os
import re
import winreg
from dataclasses import asdict
from pathlib import Path
from typing import Any

from core.backup import load_manifest
from core.policy import Risk
from core.registry import RegistryValueState, read_value, restore_value, write_value
from core.runner import powershell, run
from optimizations.base import CheckResult, Optimization


ROOT = Path(__file__).resolve().parents[1]
BACKUPS = ROOT / "backups"
LOGS = ROOT / "logs"


class RegistryOptimization(Optimization):
    hive: str
    key: str
    value_name: str
    target: Any
    value_type: int

    def _state(self) -> RegistryValueState:
        return read_value(self.hive, self.key, self.value_name)

    def _check_value(self) -> CheckResult:
        state = self._state()
        if state.exists and state.value == self.target:
            return self.log_check(CheckResult(False, "Target value already active",
                                               state.value, self.target))
        return self.log_check(CheckResult(True, "Registry value can be changed",
                                           state.value if state.exists else None,
                                           self.target))

    def apply(self) -> None:
        self.guard_apply()
        state = self._state()
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id,
            "registry_state": asdict(state),
        })
        write_value(self.hive, self.key, self.value_name, self.target, self.value_type)
        self.verify_after_apply()

    def verify_after_apply(self) -> None:
        state = self._state()
        if state.value != self.target:
            raise RuntimeError(f"{self.id}: post-change verification failed")
        self.logger.info("VERIFY %s OK", self.id)

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        data = load_manifest(self.last_manifest)
        state = RegistryValueState(**data["items"]["registry_state"]["value"])
        restore_value(state)
        if read_value(self.hive, self.key, self.value_name) != state:
            # Compare semantic state because registry wrappers can normalize types.
            restored = self._state()
            if (restored.exists != state.exists or
                    restored.value != state.value or
                    restored.value_type != state.value_type):
                raise RuntimeError(f"{self.id}: rollback verification failed")


class VisualEffectsOptimization(RegistryOptimization):
    id = "visual-effects"
    name = "Disable unnecessary visual effects"
    risk = Risk.SAFE
    hive = "HKCU"
    key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    value_name = "VisualFXSetting"
    target = 2
    value_type = winreg.REG_DWORD

    def check(self) -> CheckResult:
        return self._check_value()

    def apply(self) -> None:
        # Also back up the two related user settings in the same manifest.
        self.guard_apply()
        states = [
            read_value("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting"),
            read_value("HKCU", r"Control Panel\Desktop\WindowMetrics", "MinAnimate"),
            read_value("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency"),
        ]
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id,
            "registry_states": [asdict(x) for x in states],
        })
        write_value("HKCU", states[0].path, states[0].name, 2)
        write_value("HKCU", states[1].path, states[1].name, "0", winreg.REG_SZ)
        write_value("HKCU", states[2].path, states[2].name, 0)
        self.logger.info("VERIFY %s visual effects applied", self.id)

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        data = load_manifest(self.last_manifest)
        for raw in data["items"]["registry_states"]["value"]:
            restore_value(RegistryValueState(**raw))


class TrimOptimization(Optimization):
    id = "trim"
    name = "Ensure TRIM notifications are enabled"
    risk = Risk.SAFE

    @staticmethod
    def _query() -> str:
        result = run(["fsutil.exe", "behavior", "query", "DisableDeleteNotify"])
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "fsutil query failed")
        return result.stdout

    def check(self) -> CheckResult:
        output = self._query()
        match = re.search(r"NTFS\s+DisableDeleteNotify\s*=\s*(\d+)", output, re.I)
        current = int(match.group(1)) if match else None
        return self.log_check(CheckResult(
            current != 0, "TRIM is enabled" if current == 0 else "TRIM is disabled or unknown",
            current, 0,
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = self._query()
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "fsutil_before": before
        })
        result = run(["fsutil.exe", "behavior", "set", "DisableDeleteNotify", "0"])
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "Unable to enable TRIM")
        self.logger.info("VERIFY %s OK", self.id)

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        data = load_manifest(self.last_manifest)
        before = data["items"]["fsutil_before"]["value"]
        match = re.search(r"NTFS\s+DisableDeleteNotify\s*=\s*(\d+)", before, re.I)
        if not match:
            raise RuntimeError("Cannot determine original TRIM state")
        run(["fsutil.exe", "behavior", "set", "DisableDeleteNotify", match.group(1)])


class PagefileOptimization(Optimization):
    id = "pagefile-system-managed"
    name = "Use a Windows-managed page file"
    risk = Risk.SAFE

    @staticmethod
    def _state() -> dict[str, Any]:
        script = (
            "$c=Get-CimInstance Win32_ComputerSystem; "
            "$p=@(Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue | "
            "Select-Object Name,InitialSize,MaximumSize); "
            "[pscustomobject]@{Automatic=[bool]$c.AutomaticManagedPagefile; "
            "PageFiles=$p} | ConvertTo-Json -Depth 5 -Compress"
        )
        result = powershell(script)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout)

    def check(self) -> CheckResult:
        current = self._state()
        return self.log_check(CheckResult(
            not current.get("Automatic", False),
            "Windows already manages the page file" if current.get("Automatic")
            else "Page file is manually configured",
            current, {"Automatic": True},
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = self._state()
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "pagefile_state": before
        })
        result = powershell(
            "$c=Get-CimInstance Win32_ComputerSystem; "
            "$c.AutomaticManagedPagefile=$true; Set-CimInstance -InputObject $c"
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "Unable to set pagefile policy")
        after = self._state()
        if not after.get("Automatic", False):
            raise RuntimeError("Pagefile verification failed")
        self.logger.info("VERIFY %s OK; Windows now manages the page file", self.id)

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        original = load_manifest(self.last_manifest)["items"]["pagefile_state"]["value"]
        automatic = "$true" if original.get("Automatic") else "$false"
        script = (
            f"$c=Get-CimInstance Win32_ComputerSystem; "
            f"$c.AutomaticManagedPagefile={automatic}; "
            "Set-CimInstance -InputObject $c; "
            "Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue | "
            "Remove-CimInstance -ErrorAction SilentlyContinue"
        )
        if original.get("Automatic"):
            result = powershell(script)
        else:
            pagefiles = original.get("PageFiles") or []
            if isinstance(pagefiles, dict):
                pagefiles = [pagefiles]
            additions = "".join(
                f"; New-CimInstance -ClassName Win32_PageFileSetting -Property "
                f"@{{Name={json.dumps(str(p['Name']))};InitialSize={int(p.get('InitialSize') or 0)};"
                f"MaximumSize={int(p.get('MaximumSize') or 0)}}} | Out-Null"
                for p in pagefiles
            )
            result = powershell(script + additions)
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "Pagefile rollback failed")


class PowerPlanOptimization(Optimization):
    id = "power-plan-high-performance"
    name = "Use High performance power plan on AC"
    risk = Risk.CAUTION

    HIGH_PERFORMANCE = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

    @staticmethod
    def _active() -> str:
        result = run(["powercfg.exe", "/getactivescheme"])
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        match = re.search(r"([0-9a-fA-F]{8}-[0-9a-fA-F-]{27})", result.stdout)
        return match.group(1).lower() if match else ""

    def check(self) -> CheckResult:
        current = self._active()
        return self.log_check(CheckResult(
            current != self.HIGH_PERFORMANCE, "High performance is already active"
            if current == self.HIGH_PERFORMANCE else "Another power plan is active",
            current, self.HIGH_PERFORMANCE
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = self._active()
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "active_scheme": before
        })
        result = run(["powercfg.exe", "/setactive", self.HIGH_PERFORMANCE])
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "Unable to activate power plan")
        if self._active() != self.HIGH_PERFORMANCE:
            raise RuntimeError("Power plan verification failed")

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        original = load_manifest(self.last_manifest)["items"]["active_scheme"]["value"]
        if original:
            run(["powercfg.exe", "/setactive", original])


class ProcessorPerformanceOptimization(Optimization):
    id = "processor-ac-performance"
    name = "Remove AC processor performance cap and core parking"
    risk = Risk.CAUTION

    SETTINGS = ("PROCTHROTTLEMIN", "PROCTHROTTLEMAX", "CPMINCORES")

    @staticmethod
    def _query(alias: str) -> int:
        result = run([
            "powercfg.exe", "/query", "scheme_current", "sub_processor", alias
        ])
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        matches = re.findall(r"Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)", result.stdout)
        if not matches:
            raise RuntimeError(f"Could not read {alias}")
        return int(matches[-1], 16)

    def check(self) -> CheckResult:
        current = {x: self._query(x) for x in self.SETTINGS}
        target = {x: 100 for x in self.SETTINGS}
        return self.log_check(CheckResult(
            current != target,
            "AC processor settings can be tuned" if current != target else
            "AC processor settings already at requested values",
            current, target,
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = {x: self._query(x) for x in self.SETTINGS}
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "settings": before
        })
        for alias in self.SETTINGS:
            result = run([
                "powercfg.exe", "-setacvalueindex", "scheme_current",
                "sub_processor", alias, "100"
            ])
            if result.returncode != 0:
                raise RuntimeError(result.stderr or f"Failed: {alias}")
        run(["powercfg.exe", "-setactive", "scheme_current"])
        self.logger.info("VERIFY %s OK", self.id)

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        settings = load_manifest(self.last_manifest)["items"]["settings"]["value"]
        for alias, value in settings.items():
            run([
                "powercfg.exe", "-setacvalueindex", "scheme_current",
                "sub_processor", alias, str(value)
            ])
        run(["powercfg.exe", "-setactive", "scheme_current"])


class ServiceOptimization(Optimization):
    id = "optional-windows-services"
    name = "Disable selected non-security Windows services"
    risk = Risk.CAUTION

    ALLOWLIST = {"SysMain", "WSearch", "DiagTrack"}

    def __init__(self, service_name: str = "SysMain", logger=None):
        super().__init__(logger)
        if service_name not in self.ALLOWLIST:
            raise ValueError("Service is not in the conservative allowlist.")
        self.service_name = service_name
        self.last_manifest = None

    def _query(self) -> dict[str, str]:
        result = powershell(
            f"$s=Get-CimInstance Win32_Service -Filter "
            f"\"Name='{self.service_name}'\"; "
            f"$s | Select-Object Name,State,StartMode | ConvertTo-Json -Compress"
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        if not result.stdout:
            return {}
        return json.loads(result.stdout)

    def check(self) -> CheckResult:
        current = self._query()
        if not current:
            return self.log_check(CheckResult(False, "Service is not installed"))
        applicable = current.get("StartMode") in {"Auto", "Automatic"}
        return self.log_check(CheckResult(
            applicable, "Allowlisted service is automatic" if applicable else
            "Service is already demand/disabled", current, "Disabled"
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = self._query()
        if not before:
            raise RuntimeError("Service is not installed")
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "service": before
        })
        result = run(["sc.exe", "config", self.service_name, "start=", "disabled"])
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)
        if before.get("State") == "Running":
            run(["sc.exe", "stop", self.service_name])
        self.logger.info("VERIFY %s OK", self.id)

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        original = load_manifest(self.last_manifest)["items"]["service"]["value"]
        start_map = {
            "Auto": "auto", "Manual": "demand", "Disabled": "disabled",
            "Boot": "boot", "System": "system"
        }
        start = start_map.get(original.get("StartMode"), "demand")
        run(["sc.exe", "config", self.service_name, "start=", start])
        if original.get("State") == "Running":
            run(["sc.exe", "start", self.service_name])


class BackgroundAppsOptimization(RegistryOptimization):
    id = "background-apps"
    name = "Disable Windows background app execution"
    risk = Risk.CAUTION
    hive = "HKCU"
    key = r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    value_name = "GlobalUserDisabled"
    target = 1
    value_type = winreg.REG_DWORD

    def check(self) -> CheckResult:
        return self._check_value()


class GameModeOptimization(RegistryOptimization):
    id = "game-mode"
    name = "Enable Windows Game Mode"
    risk = Risk.CAUTION
    hive = "HKCU"
    key = r"Software\Microsoft\GameBar"
    value_name = "AutoGameModeEnabled"
    target = 1
    value_type = winreg.REG_DWORD

    def check(self) -> CheckResult:
        return self._check_value()


class GameDvrOptimization(RegistryOptimization):
    id = "game-dvr-off"
    name = "Disable Windows Game DVR background capture"
    risk = Risk.CAUTION
    hive = "HKCU"
    key = r"System\GameConfigStore"
    value_name = "GameDVR_Enabled"
    target = 0
    value_type = winreg.REG_DWORD

    def check(self) -> CheckResult:
        return self._check_value()


class TelemetryOptimization(RegistryOptimization):
    id = "diagnostic-data-minimum"
    name = "Limit Windows diagnostic data"
    risk = Risk.CAUTION
    hive = "HKLM"
    key = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    value_name = "AllowTelemetry"
    target = 1
    value_type = winreg.REG_DWORD

    def check(self) -> CheckResult:
        return self._check_value()


class MultimediaNetworkOptimization(Optimization):
    id = "multimedia-network"
    name = "Use conservative multimedia network scheduling"
    risk = Risk.EXPERIMENTAL

    KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"

    def _states(self) -> list[RegistryValueState]:
        return [
            read_value("HKLM", self.KEY, "NetworkThrottlingIndex"),
            read_value("HKLM", self.KEY, "SystemResponsiveness"),
        ]

    def check(self) -> CheckResult:
        states = self._states()
        return self.log_check(CheckResult(
            False,
            "Experimental network registry tweak is disabled by policy",
            [x.value if x.exists else None for x in states],
            [0xFFFFFFFF, 10],
        ))

    def apply(self) -> None:
        self.guard_apply()
        states = self._states()
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id,
            "registry_states": [asdict(x) for x in states],
        })
        write_value("HKLM", self.KEY, "NetworkThrottlingIndex", 0xFFFFFFFF)
        write_value("HKLM", self.KEY, "SystemResponsiveness", 10)
        self.logger.info("VERIFY %s applied; reboot required", self.id)

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        for raw in load_manifest(self.last_manifest)["items"]["registry_states"]["value"]:
            restore_value(RegistryValueState(**raw))


class HagsOptimization(RegistryOptimization):
    id = "hags"
    name = "Enable hardware accelerated GPU scheduling"
    risk = Risk.EXPERIMENTAL
    hive = "HKLM"
    key = r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    value_name = "HwSchMode"
    target = 2
    value_type = winreg.REG_DWORD

    def check(self) -> CheckResult:
        return self._check_value()


class TikTokProcessOptimization(Optimization):
    id = "tiktok-process"
    name = "Tune TikTok LIVE Studio process priority"
    risk = Risk.CAUTION

    PROCESS_NAMES = ("TikTok LIVE Studio", "TikTokLiveStudio", "TikTok LIVE Studio.exe")

    @staticmethod
    def _find() -> dict[str, Any] | None:
        names = ",".join(json.dumps(x) for x in TikTokProcessOptimization.PROCESS_NAMES)
        script = (
            f"$names=@({names}); Get-Process | Where-Object {{$names -contains "
            "$_.ProcessName -or $names -contains ($_.ProcessName + '.exe')}} | "
            "Select-Object -First 1 Id,ProcessName,PriorityClass,ProcessorAffinity | "
            "ConvertTo-Json -Compress"
        )
        result = powershell(script)
        if result.returncode != 0 or not result.stdout:
            return None
        return json.loads(result.stdout)

    def check(self) -> CheckResult:
        current = self._find()
        if not current:
            return self.log_check(CheckResult(False, "TikTok LIVE Studio is not running"))
        return self.log_check(CheckResult(
            current.get("PriorityClass") != "AboveNormal",
            "Process is running and can be set to AboveNormal",
            current, "AboveNormal; affinity unchanged",
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = self._find()
        if not before:
            raise RuntimeError("TikTok LIVE Studio is not running")
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "process": before
        })
        pid = int(before["Id"])
        result = powershell(
            f"$p=Get-Process -Id {pid} -ErrorAction Stop; "
            "$p.PriorityClass='AboveNormal'"
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "Unable to set process priority")
        self.logger.info(
            "VERIFY %s OK; CPU affinity intentionally unchanged for stability",
            self.id,
        )

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        original = load_manifest(self.last_manifest)["items"]["process"]["value"]
        pid = int(original["Id"])
        priority = str(original.get("PriorityClass", "Normal"))
        result = powershell(
            f"$p=Get-Process -Id {pid} -ErrorAction Stop; "
            f"$p.PriorityClass='{priority}'"
        )
        if result.returncode != 0:
            self.logger.warning("TikTok process no longer exists; rollback skipped")


class TikTokGpuPreferenceOptimization(Optimization):
    id = "tiktok-gpu-preference"
    name = "Prefer high-performance GPU for TikTok LIVE Studio"
    risk = Risk.CAUTION

    KEY = r"Software\Microsoft\DirectX\UserGpuPreferences"

    def __init__(self, executable: str | None = None, logger=None):
        super().__init__(logger)
        self.executable = executable

    def _state(self) -> RegistryValueState | None:
        if not self.executable:
            return None
        return read_value("HKCU", self.KEY, self.executable)

    def check(self) -> CheckResult:
        if not self.executable:
            return self.log_check(CheckResult(
                False, "No TikTok LIVE Studio executable path supplied"
            ))
        state = self._state()
        return self.log_check(CheckResult(
            not state.exists or state.value != "GpuPreference=2;",
            "GPU preference can be set to high performance",
            state.value if state and state.exists else None,
            "GpuPreference=2;",
        ))

    def apply(self) -> None:
        self.guard_apply()
        if not self.executable:
            raise ValueError("Executable path is required")
        state = self._state()
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id,
            "registry_state": asdict(state),
        })
        write_value("HKCU", self.KEY, self.executable, "GpuPreference=2;", winreg.REG_SZ)
        self.logger.info("VERIFY %s OK", self.id)

    def rollback(self) -> None:
        self.log_rollback()
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        state = RegistryValueState(
            **load_manifest(self.last_manifest)["items"]["registry_state"]["value"]
        )
        restore_value(state)
