from __future__ import annotations

import winreg
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RegistryValueState:
    hive: str
    path: str
    name: str
    exists: bool
    value: Any = None
    value_type: int | None = None


_HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}


def _key(hive: str, path: str, access: int):
    if hive not in _HIVES:
        raise ValueError(f"Unsupported registry hive: {hive}")
    return winreg.OpenKey(_HIVES[hive], path, 0, access)


def read_value(hive: str, path: str, name: str) -> RegistryValueState:
    try:
        with _key(hive, path, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, name)
            return RegistryValueState(hive, path, name, True, value, value_type)
    except FileNotFoundError:
        return RegistryValueState(hive, path, name, False)


def write_value(hive: str, path: str, name: str, value: Any,
                value_type: int = winreg.REG_DWORD) -> None:
    with winreg.CreateKeyEx(_HIVES[hive], path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, value_type, value)


def restore_value(state: RegistryValueState) -> None:
    if state.exists:
        write_value(state.hive, state.path, state.name, state.value,
                    state.value_type or winreg.REG_DWORD)
        return
    try:
        with _key(state.hive, state.path, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, state.name)
    except FileNotFoundError:
        pass
