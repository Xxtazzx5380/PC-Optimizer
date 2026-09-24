from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.policy import OptimizationPolicy, PolicyViolation, Risk
from optimizations.base import CheckResult
from optimizations.windows import (
    BackgroundAppsOptimization, GameDvrOptimization, GameModeOptimization,
    HagsOptimization, PagefileOptimization, PowerPlanOptimization,
    ProcessorPerformanceOptimization, ServiceOptimization, TelemetryOptimization,
    TikTokGpuPreferenceOptimization, TikTokProcessOptimization, TrimOptimization,
    VisualEffectsOptimization,
)
from optimizations.optional import (
    DnsOptimization, NagleOptimization, NetworkQosAudit,
    ScheduledTaskOptimization, StartupRegistryOptimization,
    StreamingEncodingAudit, WindowsUpdateSafetyOptimization,
)


class OptimizationCheckTests(unittest.TestCase):
    def assert_check(self, optimization):
        result = optimization.check()
        self.assertIsInstance(result, CheckResult)

    @patch("optimizations.windows.read_value")
    def test_visual_effects_check(self, read):
        read.return_value = type("S", (), {"exists": True, "value": 1})()
        self.assert_check(VisualEffectsOptimization())

    @patch("optimizations.windows.run")
    def test_trim_check(self, run):
        run.return_value = type("R", (), {"returncode": 0, "stdout": "NTFS DisableDeleteNotify = 0", "stderr": ""})()
        self.assert_check(TrimOptimization())

    @patch("optimizations.windows.powershell")
    def test_pagefile_check(self, ps):
        ps.return_value = type("R", (), {"returncode": 0, "stdout": '{"Automatic":true,"PageFiles":[]}', "stderr": ""})()
        self.assert_check(PagefileOptimization())

    @patch("optimizations.windows.run")
    def test_power_plan_check(self, run):
        run.return_value = type("R", (), {"returncode": 0, "stdout": "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)", "stderr": ""})()
        self.assert_check(PowerPlanOptimization())

    @patch("optimizations.windows.run")
    def test_processor_check(self, run):
        run.return_value = type("R", (), {"returncode": 0, "stdout": "Current AC Power Setting Index: 0x00000064", "stderr": ""})()
        self.assert_check(ProcessorPerformanceOptimization())

    @patch("optimizations.windows.ServiceOptimization._query")
    def test_service_check(self, query):
        query.return_value = {"Name": "SysMain", "State": "Running", "StartMode": "Auto"}
        self.assert_check(ServiceOptimization("SysMain"))

    @patch("optimizations.windows.read_value")
    def test_registry_checks(self, read):
        state = type("S", (), {"exists": True, "value": 0})()
        read.return_value = state
        for cls in (BackgroundAppsOptimization, GameModeOptimization, GameDvrOptimization,
                    TelemetryOptimization, HagsOptimization):
            self.assert_check(cls())

    @patch("optimizations.windows.TikTokProcessOptimization._find")
    def test_tiktok_process_check(self, find):
        find.return_value = {"Id": 1234, "ProcessName": "TikTokLiveStudio",
                             "PriorityClass": "Normal", "ProcessorAffinity": 15}
        self.assert_check(TikTokProcessOptimization())

    @patch("optimizations.windows.read_value")
    def test_tiktok_gpu_check(self, read):
        read.return_value = type("S", (), {"exists": False, "value": None})()
        self.assert_check(TikTokGpuPreferenceOptimization(r"C:\TikTok LIVE Studio.exe"))

    @patch("optimizations.optional.StartupRegistryOptimization._state")
    def test_startup_check(self, state):
        state.return_value = type("S", (), {"exists": True, "value": "example.exe"})()
        self.assert_check(StartupRegistryOptimization("HKCU", "Example"))

    @patch("optimizations.optional.ScheduledTaskOptimization._state", return_value=True)
    def test_scheduled_task_check(self, _state):
        self.assert_check(ScheduledTaskOptimization(r"\Example\Task"))

    @patch("optimizations.optional.DnsOptimization._current", return_value=["1.1.1.1"])
    def test_dns_check(self, _current):
        self.assert_check(DnsOptimization("Ethernet", ("8.8.8.8",)))

    @patch("optimizations.optional.NagleOptimization._states")
    def test_nagle_check(self, states):
        states.return_value = [
            type("S", (), {"exists": False, "value": None})(),
            type("S", (), {"exists": False, "value": None})(),
            type("S", (), {"exists": False, "value": None})(),
        ]
        self.assert_check(NagleOptimization("00000000-0000-0000-0000-000000000000"))

    @patch("optimizations.optional.powershell")
    def test_update_safety_check(self, ps):
        ps.return_value = type("R", (), {"returncode": 0, "stdout": '{"State":"Running","StartMode":"Manual"}', "stderr": ""})()
        self.assert_check(WindowsUpdateSafetyOptimization())

    @patch("optimizations.optional.powershell")
    def test_qos_audit_check(self, ps):
        ps.return_value = type("R", (), {"returncode": 0, "stdout": "[]", "stderr": ""})()
        self.assert_check(NetworkQosAudit())

    @patch("optimizations.optional.powershell")
    def test_streaming_audit_check(self, ps):
        ps.return_value = type("R", (), {"returncode": 0, "stdout": "[]", "stderr": ""})()
        self.assert_check(StreamingEncodingAudit())


class MutationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = Path(tempfile.gettempdir()) / "pc_optimizer_test_manifest.json"
        self.states = [
            {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
             "name": "VisualFXSetting", "exists": True, "value": 1, "value_type": 4},
            {"hive": "HKCU", "path": r"Control Panel\Desktop\WindowMetrics",
             "name": "MinAnimate", "exists": True, "value": "1", "value_type": 1},
            {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
             "name": "EnableTransparency", "exists": True, "value": 1, "value_type": 4},
        ]

    def _manifest_data(self, optimization: str, **items):
        raw = {"optimization": {"value": optimization}}
        raw.update({k: {"value": v} for k, v in items.items()})
        return {"items": raw}

    @patch("optimizations.windows.restore_value")
    @patch("optimizations.windows.load_manifest")
    @patch("optimizations.windows.write_value")
    @patch("optimizations.windows.read_value")
    @patch("core.mutation.OptimizationPolicy.check_mutation")
    @patch("core.mutation.create_manifest")
    @patch("core.mutation.is_admin", return_value=True)
    def test_visual_effects_apply_and_rollback(
        self, _admin, create_manifest, check_mutation, read_value,
        write_value, load_manifest, restore_value
    ):
        read_value.side_effect = [
            type("S", (), s)() for s in self.states
        ]
        create_manifest.return_value = self.manifest
        load_manifest.return_value = self._manifest_data(
            "visual-effects", registry_states=self.states
        )

        opt = VisualEffectsOptimization()
        opt.apply()
        self.assertEqual(opt.last_manifest, self.manifest)
        self.assertEqual(write_value.call_count, 3)
        check_mutation.assert_called_once_with(
            risk=Risk.SAFE, is_admin=True, backup_created=True
        )

        opt.rollback()
        self.assertEqual(restore_value.call_count, 3)

    @patch("optimizations.windows.run")
    @patch("optimizations.windows.load_manifest")
        @patch("core.mutation.create_manifest")
    @patch("core.mutation.is_admin", return_value=True)
    def test_service_apply_and_rollback(
        self, _admin, create_manifest, windows_load_manifest, run
    ):
        before = {"Name": "SysMain", "State": "Running", "StartMode": "Auto"}
        with patch.object(ServiceOptimization, "_query", return_value=before):
            create_manifest.return_value = self.manifest
            windows_load_manifest.return_value = {
                "items": {"service": {"value": before}}
            }
            opt = ServiceOptimization("SysMain")
            opt.apply()
            self.assertEqual(opt.last_manifest, self.manifest)
            self.assertTrue(any(c.args and c.args[0][:4] == ["sc.exe", "config", "SysMain", "start="]
                                for c in run.call_args_list))
            opt.rollback()
            self.assertTrue(any(c.args and c.args[0][:2] == ["sc.exe", "start"] for c in run.call_args_list))

    @patch("optimizations.windows.powershell")
    @patch("optimizations.windows.load_manifest")
    @patch("core.mutation.create_manifest")
    @patch("core.mutation.is_admin", return_value=True)
    def test_tiktok_process_apply_and_rollback(
        self, _admin, create_manifest, load_manifest, powershell
    ):
        before = {"Id": 1234, "ProcessName": "TikTokLiveStudio",
                  "PriorityClass": "Normal", "ProcessorAffinity": 15}
        create_manifest.return_value = self.manifest
        load_manifest.return_value = {"items": {"process": {"value": before}}}
        with patch.object(TikTokProcessOptimization, "_find", return_value=before):
            powershell.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            opt = TikTokProcessOptimization()
            opt.apply()
            self.assertEqual(opt.last_manifest, self.manifest)
            opt.rollback()
            self.assertEqual(powershell.call_count, 2)

    def test_rollback_without_apply_is_clean_error(self):
        for opt in (
            VisualEffectsOptimization(),
            ServiceOptimization("SysMain"),
            TikTokProcessOptimization(),
        ):
            with self.subTest(opt=opt.id), self.assertRaisesRegex(
                RuntimeError, "No manifest is associated"
            ):
                opt.rollback()


class PolicyTests(unittest.TestCase):
    def test_experimental_is_blocked(self):
        with self.assertRaises(PolicyViolation):
            OptimizationPolicy.check_risk(Risk.EXPERIMENTAL)

    def test_default_policy_is_conservative(self):
        self.assertFalse(OptimizationPolicy.allow_experimental)
        self.assertTrue(OptimizationPolicy.require_backup_for_mutation)
        self.assertTrue(OptimizationPolicy.require_verification)

    @patch("core.mutation.is_admin", return_value=True)
    def test_experimental_apply_is_blocked_before_manifest(self, _admin):
        with self.assertRaises(PolicyViolation):
            HagsOptimization().apply()


if __name__ == "__main__":
    unittest.main()
