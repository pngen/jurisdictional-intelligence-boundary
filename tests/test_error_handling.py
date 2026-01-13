"""
Tests for error handling components.
"""

import pytest
from jib.core.error_handling import (
    JIBError,
    BoundaryEnforcementError,
    UnauthorizedJurisdictionAccess,
    BindingIntegrityViolation,
    TemporalConstraintViolation,
    ConsensusFailure,
    InvariantViolation,
    JIBRecoveryContext
)


def test_base_jib_error():
    """Test base JIB error."""
    
    error = JIBError("Test error", {"context": "test"})
    
    assert str(error) == "Test error"
    assert error.message == "Test error"
    assert error.context["context"] == "test"


def test_boundary_enforcement_error():
    """Test boundary enforcement error with recovery context."""
    
    error = BoundaryEnforcementError(
        "Access denied",
        {"artifact": "model-x", "user": "user-123"},
        "Check permissions and bindings"
    )
    
    assert isinstance(error, JIBError)
    assert error.message == "Access denied"
    assert error.context["artifact"] == "model-x"
    assert error.recovery_hint == "Check permissions and bindings"


def test_specific_error_types():
    """Test specific error types."""
    
    # Test UnauthorizedJurisdictionAccess
    try:
        raise UnauthorizedJurisdictionAccess(
            "Unauthorized access",
            {"artifact": "model-x", "jurisdiction": "us-tx"}
        )
    except UnauthorizedJurisdictionAccess as e:
        assert str(e) == "Unauthorized access"
        assert e.context["jurisdiction"] == "us-tx"
    
    # Test BindingIntegrityViolation
    try:
        raise BindingIntegrityViolation(
            "Binding integrity violated",
            {"binding_id": "binding-123"}
        )
    except BindingIntegrityViolation as e:
        assert str(e) == "Binding integrity violated"
        assert e.context["binding_id"] == "binding-123"
    
    # Test TemporalConstraintViolation
    try:
        raise TemporalConstraintViolation(
            "Temporal constraint violated",
            {"boundary": "temp-boundary"}
        )
    except TemporalConstraintViolation as e:
        assert str(e) == "Temporal constraint violated"
        assert e.context["boundary"] == "temp-boundary"


def test_recovery_context():
    """Test recovery context functionality."""
    
    error = JIBError("Test error", {"test": "context"})
    ctx = JIBRecoveryContext(error)
    
    # Add recovery actions
    ctx.add_recovery_action("check_bindings", {"artifact": "model-x"})
    ctx.add_recovery_action("verify_permissions", {"user": "user-123"})
    
    # Get recovery plan
    plan = ctx.get_recovery_plan()
    
    assert plan["error_message"] == "Test error"
    assert len(plan["recovery_actions"]) == 2
    assert plan["recovery_actions"][0]["action"] == "check_bindings"
    assert plan["recovery_actions"][1]["action"] == "verify_permissions"


def test_error_inheritance():
    """Test error inheritance hierarchy."""
    
    # All specific errors should inherit from JIBError
    errors = [
        UnauthorizedJurisdictionAccess("test", {}),
        BindingIntegrityViolation("test", {}),
        TemporalConstraintViolation("test", {}),
        ConsensusFailure("test", {}),
        InvariantViolation("test", {})
    ]
    
    for error in errors:
        assert isinstance(error, JIBError)