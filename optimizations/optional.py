from __future__ import annotations

import json
import winreg
from dataclasses import asdict
from pathlib import Path

from core.backup import create_manifest, load_manifest
from core.registry import RegistryValueState, read_value, restore_value, write_value
from core.runner import powershell, run
from core.policy import Risk
from optimizations.base import CheckResult, Optimization


ROOT = Path(__file__).resolve().parents[1]
BACKUPS = ROOT / "backups"


class StartupRegistryOptimization(Optimization):
    """Disable one explicitly selected Run/RunOnce entry.

    The caller must provide the exact hive, key and value name. There is no
    automatic guessing of what a user considers unnecessary.
    """

    id = "startup-registry-entry"
    name = "Disable selected startup registry entry"
    risk = Risk.CAUTION

    def __init__(self, hive: str, value_name: str, run_once: bool = False, logger=None):
        super().__init__(logger)
        self.hive = hive
        self.value_name = value_name
        self.key = (
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
            if run_once else
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        )

    def _state(self) -> RegistryValueState:
        return read_value(self.hive, self.key, self.value_name)

    def check(self) -> CheckResult:
        state = self._state()
        return self.log_check(CheckResult(
            state.exists,
            "Selected startup entry exists" if state.exists else "Startup entry not found",
            state.value if state.exists else None,
            None,
        ))

    def apply(self) -> None:
        self.guard_apply()
        state = self._state()
        if not state.exists:
            return
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "registry_state": asdict(state)
        })
        with winreg.OpenKey(
            {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[self.hive],
            self.key, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, self.value_name)
        if self._state().exists:
            raise RuntimeError("Startup entry deletion verification failed")

    def rollback(self) -> None:
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        state = RegistryValueState(
            **load_manifest(self.last_manifest)["items"]["registry_state"]["value"]
        )
        restore_value(state)


class ScheduledTaskOptimization(Optimization):
    id = "scheduled-task"
    name = "Disable one explicitly selected scheduled task"
    risk = Risk.CAUTION

    def __init__(self, task_path: str, logger=None):
        super().__init__(logger)
        self.task_path = task_path

    def _state(self) -> bool:
        result = powershell(
            f"$t=Get-ScheduledTask -TaskName {json.dumps(self.task_path.split('\\')[-1])} "
            f"-TaskPath {json.dumps('\\'.join(self.task_path.split('\\')[:-1]) + '\\')} "
            "-ErrorAction SilentlyContinue; "
            "if ($t) { $t.State.ToString() }"
        )
        return result.stdout.strip().lower() != "disabled" if result.stdout else False

    def check(self) -> CheckResult:
        current = self._state()
        return self.log_check(CheckResult(
            current, "Task is enabled" if current else "Task is absent or disabled",
            current, False
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = self._state()
        if not before:
            return
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "task_path": self.task_path,
            "was_enabled": before,
        })
        result = run(["schtasks.exe", "/Change", "/TN", self.task_path, "/Disable"])
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)
        if self._state():
            raise RuntimeError("Scheduled task disable verification failed")

    def rollback(self) -> None:
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        data = load_manifest(self.last_manifest)
        if data["items"]["was_enabled"]["value"]:
            result = run(["schtasks.exe", "/Change", "/TN",
                          data["items"]["task_path"]["value"], "/Enable"])
            if result.returncode != 0:
                raise RuntimeError(result.stderr or result.stdout)


class WindowsUpdateSafetyOptimization(Optimization):
    """Repair a disabled Windows Update service; never disables updates."""

    id = "windows-update-safety"
    name = "Keep Windows Update service available"
    risk = Risk.SAFE

    @staticmethod
    def _state() -> dict[str, str]:
        result = powershell(
            '$s=Get-CimInstance Win32_Service -Filter "Name=''wuauserv''"; '
            '$s | Select-Object State,StartMode | ConvertTo-Json -Compress'
        )
        if result.returncode != 0 or not result.stdout:
            raise RuntimeError(result.stderr or "Windows Update service not found")
        return json.loads(result.stdout)

    def check(self) -> CheckResult:
        current = self._state()
        disabled = current.get("StartMode") == "Disabled"
        return self.log_check(CheckResult(
            disabled, "Windows Update is disabled" if disabled else
            "Windows Update is not disabled", current, "Manual/Auto"
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = self._state()
        if before.get("StartMode") != "Disabled":
            return
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "service": before
        })
        result = run(["sc.exe", "config", "wuauserv", "start=", "demand"])
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)
        self.logger.info("VERIFY %s restored Windows Update availability", self.id)

    def rollback(self) -> None:
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        original = load_manifest(self.last_manifest)["items"]["service"]["value"]
        mapping = {"Auto": "auto", "Manual": "demand", "Disabled": "disabled"}
        start = mapping.get(original.get("StartMode"), "demand")
        result = run(["sc.exe", "config", "wuauserv", "start=", start])
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)


class DnsOptimization(Optimization):
    id = "dns-servers"
    name = "Set explicit DNS servers for one adapter"
    risk = Risk.CAUTION

    def __init__(self, interface_alias: str, servers: tuple[str, ...], logger=None):
        super().__init__(logger)
        self.interface_alias = interface_alias
        self.servers = servers

    def _current(self) -> list[str]:
        result = powershell(
            f"(Get-DnsClientServerAddress -InterfaceAlias {json.dumps(self.interface_alias)} "
            "-AddressFamily IPv4 -ErrorAction Stop).ServerAddresses | ConvertTo-Json -Compress"
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        if not result.stdout:
            return []
        value = json.loads(result.stdout)
        return value if isinstance(value, list) else [value]

    def check(self) -> CheckResult:
        current = self._current()
        return self.log_check(CheckResult(
            current != list(self.servers), "DNS differs from requested servers",
            current, list(self.servers)
        ))

    def apply(self) -> None:
        self.guard_apply()
        before = self._current()
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id, "interface_alias": self.interface_alias,
            "dns": before
        })
        script = (
            f"Set-DnsClientServerAddress -InterfaceAlias {json.dumps(self.interface_alias)} "
            f"-ServerAddresses @({','.join(json.dumps(x) for x in self.servers)})"
        )
        result = powershell(script)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        if self._current() != list(self.servers):
            raise RuntimeError("DNS verification failed")

    def rollback(self) -> None:
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        data = load_manifest(self.last_manifest)["items"]
        servers = data["dns"]["value"]
        script = (
            f"Set-DnsClientServerAddress -InterfaceAlias "
            f"{json.dumps(data['interface_alias']['value'])} "
            f"-ServerAddresses @({','.join(json.dumps(x) for x in servers)})"
        )
        if not servers:
            script = (
                f"Set-DnsClientServerAddress -InterfaceAlias "
                f"{json.dumps(data['interface_alias']['value'])} -ResetServerAddresses"
            )
        result = powershell(script)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)


class NagleOptimization(Optimization):
    id = "tcp-nagle"
    name = "Disable Nagle for an explicitly selected TCP interface"
    risk = Risk.EXPERIMENTAL

    def __init__(self, interface_guid: str, logger=None):
        super().__init__(logger)
        self.interface_guid = interface_guid
        self.key = (
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\"
            + interface_guid
        )

    def _states(self) -> list[RegistryValueState]:
        return [
            read_value("HKLM", self.key, "TcpAckFrequency"),
            read_value("HKLM", self.key, "TCPNoDelay"),
            read_value("HKLM", self.key, "TcpDelAckTicks"),
        ]

    def check(self) -> CheckResult:
        states = self._states()
        return self.log_check(CheckResult(
            True,
            "Experimental TCP settings are available but policy blocks them by default",
            [x.value if x.exists else None for x in states],
            [1, 1, 0],
        ))

    def apply(self) -> None:
        self.guard_apply()
        states = self._states()
        self.last_manifest = create_manifest(BACKUPS, {
            "optimization": self.id,
            "registry_states": [asdict(x) for x in states],
        })
        write_value("HKLM", self.key, "TcpAckFrequency", 1)
        write_value("HKLM", self.key, "TCPNoDelay", 1)
        write_value("HKLM", self.key, "TcpDelAckTicks", 0)

    def rollback(self) -> None:
        if not self.last_manifest:
            raise RuntimeError("No manifest is associated with this instance.")
        for raw in load_manifest(self.last_manifest)["items"]["registry_states"]["value"]:
            restore_value(RegistryValueState(**raw))


class NetworkQosAudit(Optimization):
    id = "network-qos-audit"
    name = "Audit Windows QoS policies without changing them"
    risk = Risk.SAFE

    def check(self) -> CheckResult:
        result = powershell(
            "Get-NetQosPolicy -ErrorAction SilentlyContinue | "
            "Select-Object Name,AppPathNameMatchCondition,DSCPAction,ThrottleRateAction | "
            "ConvertTo-Json -Depth 4 -Compress"
        )
        policies = result.stdout if result.returncode == 0 else ""
        return self.log_check(CheckResult(
            False, "QoS is audit-only; no generic policy is imposed",
            policies, None
        ))

    def apply(self) -> None:
        raise RuntimeError(
            "No generic QoS mutation is safe: QoS must be configured for the actual network."
        )

    def rollback(self) -> None:
        self.logger.info("ROLLBACK %s: nothing changed", self.id)


class StreamingEncodingAudit(Optimization):
    id = "streaming-encoding-audit"
    name = "Audit CPU streaming encoder pressure"
    risk = Risk.SAFE

    def check(self) -> CheckResult:
        result = powershell(
            "Get-Process | Where-Object {$_.ProcessName -match "
            "'TikTok|Streamlabs|obs'} | "
            "Select-Object ProcessName,CPU,WorkingSet64 | "
            "ConvertTo-Json -Compress"
        )
        data = result.stdout if result.returncode == 0 else ""
        return self.log_check(CheckResult(
            False,
            "Encoding configuration is application-specific; audit only",
            data, None
        ))

    def apply(self) -> None:
        raise RuntimeError(
            "There is no stable Windows-wide encoding setting to mutate safely. "
            "Use the application encoder settings after measuring CPU load."
        )

    def rollback(self) -> None:
        self.logger.info("ROLLBACK %s: nothing changed", self.id)
