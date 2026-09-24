from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.logging_utils import configure
from core.mutation import MutationContext
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
        self.last_manifest: Path | None = None

    def prepare_mutation(self, items: dict[str, Any]) -> Path:
        """Create the mandatory manifest and enforce mutation policy centrally."""
        context = MutationContext(
            Path(__file__).resolve().parents[1] / "backups",
            Path(__file__).resolve().parents[1] / "logs",
        )
        self.last_manifest = context.prepare(self.risk, items)
        return self.last_manifest

    def log_check(self, result: CheckResult) -> CheckResult:
        self.logger.info(
            "CHECK %s applicable=%s reason=%s current=%r target=%r",
            self.id, result.applicable, result.reason,
            result.current, result.target,
        )
        return result

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
