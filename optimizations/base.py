from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from core.policy import Risk


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

    @abstractmethod
    def check(self) -> CheckResult:
        raise NotImplementedError

    @abstractmethod
    def apply(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def rollback(self) -> None:
        raise NotImplementedError
