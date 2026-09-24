from __future__ import annotations

from enum import Enum


class Risk(str, Enum):
    SAFE = "safe"
    CAUTION = "caution"
    EXPERIMENTAL = "experimental"


class OptimizationPolicy:
    """Central safety policy.

    The default behavior is conservative: no experimental changes are
    permitted, and every mutating operation must provide a rollback plan.
    """

    allow_experimental = False
    require_admin_for_mutation = True
    require_backup_for_mutation = True
    require_verification = True
