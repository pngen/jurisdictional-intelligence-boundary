"""
Tests for boundary enforcer.
"""

import pytest
from jib.core.types import (
    Jurisdiction,
    ExecutionDomain,
    CryptographicBinding,
    Boundary,
    JurisdictionType,
    JurisdictionalViolation,
    InvalidJurisdictionBinding
)
from jib.core.boundary_enforcer import BoundaryEnforcer
from cryptography.hazmat.primitives.asymmetric import ed25519


def test_register_jurisdiction():
    """Test registering a jurisdiction."""
    enforcer = BoundaryEnforcer()
    
    j = Jurisdiction(
        id="us-ca",
        name="California, USA",
        type=JurisdictionType.SOVEREIGN
    )
    
    enforcer.register_jurisdiction(j)
    
    assert "us-ca" in enforcer.jurisdictions


def test_register_execution_domain():
    """Test registering an execution domain."""
    enforcer = BoundaryEnforcer()
    
    d = ExecutionDomain(
        id="prod-us-west",
        name="Production US West",
        jurisdiction_id="us-ca"
    )
    
    enforcer.register_execution_domain(d)
    
    assert "prod-us-west" in enforcer.execution_domains


def test_bind_artifact():
    """Test binding an artifact to a jurisdiction."""
    enforcer = BoundaryEnforcer()
    
    # Register jurisdiction
    j = Jurisdiction(
        id="us-ca",
        name="California, USA",
        type=JurisdictionType.SOVEREIGN
    )
    enforcer.register_jurisdiction(j)
    
    # Generate key pair for binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Bind artifact
    binding = enforcer.bind_artifact_to_jurisdiction(
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        private_key=private_key,
        artifact_hash="abc123def456"
    )
    
    assert binding.artifact_id == "model-x"
    assert binding.jurisdiction_id == "us-ca"
    assert len(enforcer.bound_artifacts["model-x"]) == 1


def test_bind_invalid_jurisdiction():
    """Test binding to invalid jurisdiction raises error."""
    enforcer = BoundaryEnforcer()
    
    # Generate key pair for binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    with pytest.raises(InvalidJurisdictionBinding):
        enforcer.bind_artifact_to_jurisdiction(
            artifact_id="model-x",
            jurisdiction_id="nonexistent",
            private_key=private_key,
            artifact_hash="abc123def456"
        )


def test_check_boundary_allowed():
    """Test checking a boundary that is allowed."""
    enforcer = BoundaryEnforcer()
    
    # Register jurisdictions
    j1 = Jurisdiction(
        id="us-ca",
        name="California, USA",
        type=JurisdictionType.SOVEREIGN
    )
    j2 = Jurisdiction(
        id="us-tx",
        name="Texas, USA",
        type=JurisdictionType.SOVEREIGN
    )
    
    enforcer.register_jurisdiction(j1)
    enforcer.register_jurisdiction(j2)
    
    # Register domains
    d1 = ExecutionDomain(
        id="prod-us-west",
        name="Production US West",
        jurisdiction_id="us-ca"
    )
    d2 = ExecutionDomain(
        id="prod-us-east",
        name="Production US East",
        jurisdiction_id="us-tx"
    )
    
    enforcer.register_execution_domain(d1)
    enforcer.register_execution_domain(d2)
    
    # Generate key pair for binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Bind artifact
    enforcer.bind_artifact_to_jurisdiction(
        "model-x",
        "us-ca",
        private_key,
        "abc123def456"
    )
    
    # Create boundary (allowing cross-domain)
    boundary = Boundary(
        id="ca-to-tx",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Explicitly allowed by policy"
    )
    enforcer.boundaries["us-ca:us-tx"] = boundary
    
    # Check boundary
    proof = enforcer.check_boundary("model-x", "prod-us-west", "prod-us-east")
    
    assert proof.allowed is True
    assert proof.reason == "Explicitly allowed by policy"


def test_check_boundary_denied():
    """Test checking a boundary that is denied."""
    enforcer = BoundaryEnforcer()
    
    # Register jurisdictions
    j1 = Jurisdiction(
        id="us-ca",
        name="California, USA",
        type=JurisdictionType.SOVEREIGN
    )
    j2 = Jurisdiction(
        id="us-tx",
        name="Texas, USA",
        type=JurisdictionType.SOVEREIGN
    )
    
    enforcer.register_jurisdiction(j1)
    enforcer.register_jurisdiction(j2)
    
    # Register domains
    d1 = ExecutionDomain(
        id="prod-us-west",
        name="Production US West",
        jurisdiction_id="us-ca"
    )
    d2 = ExecutionDomain(
        id="prod-us-east",
        name="Production US East",
        jurisdiction_id="us-tx"
    )
    
    enforcer.register_execution_domain(d1)
    enforcer.register_execution_domain(d2)
    
    # Generate key pair for binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Bind artifact
    enforcer.bind_artifact_to_jurisdiction(
        "model-x",
        "us-ca",
        private_key,
        "abc123def456"
    )
    
    # No boundary defined - should default to deny
    proof = enforcer.check_boundary("model-x", "prod-us-west", "prod-us-east")
    
    assert proof.allowed is False
    assert proof.reason == "No explicit boundary rule defined"


def test_enforce_boundary_allowed():
    """Test enforcing a boundary that is allowed."""
    enforcer = BoundaryEnforcer()
    
    # Register jurisdictions
    j1 = Jurisdiction(
        id="us-ca",
        name="California, USA",
        type=JurisdictionType.SOVEREIGN
    )
    j2 = Jurisdiction(
        id="us-tx",
        name="Texas, USA",
        type=JurisdictionType.SOVEREIGN
    )
    
    enforcer.register_jurisdiction(j1)
    enforcer.register_jurisdiction(j2)
    
    # Register domains
    d1 = ExecutionDomain(
        id="prod-us-west",
        name="Production US West",
        jurisdiction_id="us-ca"
    )
    d2 = ExecutionDomain(
        id="prod-us-east",
        name="Production US East",
        jurisdiction_id="us-tx"
    )
    
    enforcer.register_execution_domain(d1)
    enforcer.register_execution_domain(d2)
    
    # Generate key pair for binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Bind artifact
    enforcer.bind_artifact_to_jurisdiction(
        "model-x",
        "us-ca",
        private_key,
        "abc123def456"
    )
    
    # Create boundary (allowing cross-domain)
    boundary = Boundary(
        id="ca-to-tx",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Explicitly allowed by policy"
    )
    enforcer.boundaries["us-ca:us-tx"] = boundary
    
    # Should not raise
    enforcer.enforce_boundary("model-x", "prod-us-west", "prod-us-east")


def test_enforce_boundary_denied():
    """Test enforcing a boundary that is denied."""
    enforcer = BoundaryEnforcer()
    
    # Register jurisdictions
    j1 = Jurisdiction(
        id="us-ca",
        name="California, USA",
        type=JurisdictionType.SOVEREIGN
    )
    j2 = Jurisdiction(
        id="us-tx",
        name="Texas, USA",
        type=JurisdictionType.SOVEREIGN
    )
    
    enforcer.register_jurisdiction(j1)
    enforcer.register_jurisdiction(j2)
    
    # Register domains
    d1 = ExecutionDomain(
        id="prod-us-west",
        name="Production US West",
        jurisdiction_id="us-ca"
    )
    d2 = ExecutionDomain(
        id="prod-us-east",
        name="Production US East",
        jurisdiction_id="us-tx"
    )
    
    enforcer.register_execution_domain(d1)
    enforcer.register_execution_domain(d2)
    
    # Generate key pair for binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Bind artifact
    enforcer.bind_artifact_to_jurisdiction(
        "model-x",
        "us-ca",
        private_key,
        "abc123def456"
    )
    
    # No boundary defined - should default to deny
    with pytest.raises(JurisdictionalViolation):
        enforcer.enforce_boundary("model-x", "prod-us-west", "prod-us-east")