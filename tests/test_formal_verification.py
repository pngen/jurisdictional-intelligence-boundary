"""
Tests for formal verification components.
"""

import pytest
from jib.core.formal_verification import (
    BoundaryAlgebra,
    TemporalBoundary,
    InvariantChecker,
    SMTEncoder,
    ModelChecker
)
from jib.core.types import (
    Jurisdiction,
    ExecutionDomain,
    Boundary,
    JurisdictionType
)


def test_boundary_algebra_composition():
    """Test boundary composition properties."""
    
    # Create two boundaries
    b1 = Boundary(
        id="b1",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Allowed by policy"
    )
    
    b2 = Boundary(
        id="b2",
        source_jurisdiction_id="us-tx",
        target_jurisdiction_id="us-nv",
        allowed=False,
        reason="Denied by policy"
    )
    
    # Test composition (simplified)
    composed = BoundaryAlgebra.compose(b1, b2)
    
    assert composed.id == "b1:b2"
    assert composed.source_jurisdiction_id == "us-ca"
    assert composed.target_jurisdiction_id == "us-nv"
    assert composed.allowed is False  # AND of True and False


def test_temporal_boundary_validity():
    """Test temporal boundary validity checks."""
    
    import time
    
    # Create a boundary with time constraints
    boundary = TemporalBoundary(
        id="temp-boundary",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Time-limited access",
        valid_from=int(time.time()) - 3600,  # 1 hour ago
        valid_until=int(time.time()) + 3600   # 1 hour from now
    )
    
    current_time = int(time.time())
    
    # Should be valid now
    assert boundary.is_valid_at(current_time) is True
    
    # Test before valid_from
    past_time = current_time - 7200  # 2 hours ago
    assert boundary.is_valid_at(past_time) is False
    
    # Test after valid_until
    future_time = current_time + 7200  # 2 hours from now
    assert boundary.is_valid_at(future_time) is False


def test_invariant_checker():
    """Test invariant checking."""
    
    # Create a mock enforcer for testing
    class MockEnforcer:
        def __init__(self):
            self.bound_artifacts = {"model-x": [{"id": "binding-1"}]}
            self.boundaries = {}
    
    # Test I1: No artifact executes without binding
    enforcer = MockEnforcer()
    try:
        InvariantChecker.check_no_unbound_execution(enforcer, "model-x")
        assert True  # Should not raise
    except AssertionError:
        pytest.fail("Invariant I1 check failed unexpectedly")
    
    # Test I4: Fail-closed on ambiguity
    try:
        InvariantChecker.check_fail_closed_ambiguity(True, "ambiguous decision")
        pytest.fail("Should have raised assertion error for ambiguous case")
    except AssertionError:
        assert True  # Expected


def test_smt_encoder():
    """Test SMT encoder."""
    
    encoder = SMTEncoder()
    encoder.add_constraint("forall x: allowed(x) -> jurisdiction(x) == source_jurisdiction")
    
    # Should not raise
    result = encoder.solve()
    assert result is True  # Simplified for testing


def test_model_checker():
    """Test model checker."""
    
    checker = ModelChecker()
    checker.add_property("safety", "No unauthorized boundary crossing")
    checker.add_property("liveness", "Eventually decides on all proposals")
    
    results = checker.verify_all()
    
    # Should return dict with verification results
    assert isinstance(results, dict)
    assert "safety" in results
    assert "liveness" in results