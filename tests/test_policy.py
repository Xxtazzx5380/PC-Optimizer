from core.policy import OptimizationPolicy


def test_experimental_changes_are_disabled():
    assert OptimizationPolicy.allow_experimental is False


def test_mutations_require_backup_and_verification():
    assert OptimizationPolicy.require_backup_for_mutation is True
    assert OptimizationPolicy.require_verification is True
