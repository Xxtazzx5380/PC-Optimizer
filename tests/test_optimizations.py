from __future__ import annotations

import unittest
from unittest.mock import patch

from core.policy import OptimizationPolicy, PolicyViolation, Risk
from optimizations.base import CheckResult
from optimizations.windows import (
    BackgroundAppsOptimization,
    GameDvrOptimization,
    GameModeOptimization,
    HagsOptimization,
    PagefileOptimization,
    PowerPlanOptimization,
    ProcessorPerformanceOptimization,
    ServiceOptimization,
    TelemetryOptimization,
    TrimOptimization,
    VisualEffectsOptimization,
)
from optimizations.optional import (
    DnsOptimization,
    NetworkQosAudit,
    StreamingEncodingAudit,
    WindowsUpdateSafetyOptimization,
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
        ps.return_value = type("R", (), {"returncode": 0, "stdout": "True", "stderr": ""})()
        self.assert_check(PagefileOptimization())

    @patch("optimizations.windows.run")
    def test_power_plan_check(self, run):
        run.return_value = type("R", (), {
            "returncode": 0,
            "stdout": "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)",
            "stderr": "",
        })()
        self.assert_check(PowerPlanOptimization())

    @patch("optimizations.windows.run")
    def test_processor_check(self, run):
        run.return_value = type("R", (), {
            "returncode": 0,
            "stdout": "Current AC Power Setting Index: 0x00000064",
            "stderr": "",
        })()
        self.assert_check(ProcessorPerformanceOptimization())

    @patch("optimizations.windows.ServiceOptimization._query")
    def test_service_check(self, query):
        query.return_value = {"Name": "SysMain", "State": "Running", "StartMode": "Auto"}
        self.assert_check(ServiceOptimization("SysMain"))

    @patch("optimizations.windows.read_value")
    def test_registry_checks(self, read):
        state = type("S", (), {"exists": True, "value": 0})()
        read.return_value = state
        for cls in (
            BackgroundAppsOptimization,
            GameModeOptimization,
            GameDvrOptimization,
            TelemetryOptimization,
            HagsOptimization,
        ):
            self.assert_check(cls())

    @patch("optimizations.optional.DnsOptimization._current")
    def test_dns_check(self, current):
        current.return_value = ["1.1.1.1"]
        self.assert_check(DnsOptimization("Ethernet", ("8.8.8.8",)))

    @patch("optimizations.optional.powershell")
    def test_update_safety_check(self, ps):
        ps.return_value = type("R", (), {
            "returncode": 0,
            "stdout": '{"State":"Running","StartMode":"Manual"}',
            "stderr": "",
        })()
        self.assert_check(WindowsUpdateSafetyOptimization())

    @patch("optimizations.optional.powershell")
    def test_qos_audit_check(self, ps):
        ps.return_value = type("R", (), {"returncode": 0, "stdout": "[]", "stderr": ""})()
        self.assert_check(NetworkQosAudit())

    @patch("optimizations.optional.powershell")
    def test_streaming_audit_check(self, ps):
        ps.return_value = type("R", (), {"returncode": 0, "stdout": "[]", "stderr": ""})()
        self.assert_check(StreamingEncodingAudit())


class PolicyTests(unittest.TestCase):
    def test_experimental_is_blocked(self):
        with self.assertRaises(PolicyViolation):
            OptimizationPolicy.check_risk(Risk.EXPERIMENTAL)

    def test_default_policy_is_conservative(self):
        self.assertFalse(OptimizationPolicy.allow_experimental)
        self.assertTrue(OptimizationPolicy.require_backup_for_mutation)
        self.assertTrue(OptimizationPolicy.require_verification)


if __name__ == "__main__":
    unittest.main()
