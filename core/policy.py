from __future__ import annotations

from enum import Enum


class Risk(str, Enum):
    SAFE = "safe"
    CAUTION = "caution"
    EXPERIMENTAL = "experimental"


class PolicyViolation(RuntimeError):
    """Raised when an optimization violates the active safety policy."""


class OptimizationPolicy:
    """Central safety policy.

    Experimental changes are always blocked unless explicitly enabled by a
    caller. Mutating operations also require administrator privileges,
    a backup manifest, and post-change verification.
    """

    allow_experimental = False
    require_admin_for_mutation = True
    require_backup_for_mutation = True
    require_verification = True

    @classmethod
    def check_risk(cls, risk: Risk) -> None:
        if risk == Risk.EXPERIMENTAL and not cls.allow_experimental:
            raise PolicyViolation(
                "Experimental optimizations are disabled by policy."
            )

    @classmethod
    def check_mutation(
        cls,
        *,
        risk: Risk,
        is_admin: bool,
        backup_created: bool,
    ) -> None:
        cls.check_risk(risk)
        if cls.require_admin_for_mutation and not is_admin:
            raise PolicyViolation("Administrator privileges are required.")
        if cls.require_backup_for_mutation and not backup_created:
            raise PolicyViolation("A backup manifest is required before mutation.")
