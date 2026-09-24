from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.logging_utils import configure
from core.policy import OptimizationPolicy, Risk


@dataclass(frozen=True)
class CheckResult:
    applicable: bool
    reason: str
    current: Any = None
    target: Any = None


class Optimization(ABC):
    id: str
    name: str
    risk: Risk

    def __init__(self, logger=None):
        self.logger = logger or configure(
            Path(__file__).resolve().parents[1] / "logs"
        )

    def log_check(self, result: CheckResult) -> CheckResult:
        self.logger.info(
            "CHECK %s applicable=%s reason=%s current=%r target=%r",
            self.id, result.applicable, result.reason,
            result.current, result.target,
        )
        return result

    def guard_apply(self) -> None:
        OptimizationPolicy.check_risk(self.risk)
        self.logger.info("APPLY %s risk=%s", self.id, self.risk.value)

    def log_rollback(self) -> None:
        self.logger.info("ROLLBACK %s", self.id)

    @abstractmethod
    def check(self) -> CheckResult:
        raise NotImplementedError

    @abstractmethod
    def apply(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def rollback(self) -> None:
        raise NotImplementedError
