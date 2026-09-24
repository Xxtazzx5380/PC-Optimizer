from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from core.backup import create_manifest
from core.logging_utils import configure
from core.policy import OptimizationPolicy, Risk
from core.system import is_admin


class MutationContext:
    """Guard every mutation with policy, backup, logging and verification."""

    def __init__(self, backup_root: Path, log_root: Path):
        self.backup_root = backup_root
        self.logger = configure(log_root)
        self.manifest: Path | None = None

    def prepare(self, risk: Risk, items: dict[str, Any]) -> Path:
        OptimizationPolicy.check_risk(risk)
        if OptimizationPolicy.require_admin_for_mutation and not is_admin():
            raise PermissionError("Administrator privileges are required.")
        self.manifest = create_manifest(self.backup_root, items)
        self.logger.info("Backup manifest created: %s", self.manifest)
        return self.manifest

    def require_success(self, ok: bool, message: str) -> None:
        if not ok:
            self.logger.error(message)
            raise RuntimeError(message)

    def verify(self, check: Callable[[], bool], message: str) -> None:
        if OptimizationPolicy.require_verification and not check():
            self.logger.error("Verification failed: %s", message)
            raise RuntimeError(message)
        self.logger.info("Verification passed: %s", message)
