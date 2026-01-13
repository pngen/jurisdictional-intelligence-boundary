"""
Tests for integration adapter.
"""

import pytest
from jib.core.types import (
    Jurisdiction,
    ExecutionDomain,
    CryptographicBinding,
    JurisdictionType
)
from jib.core.integration import IntegrationAdapter


def test_prepare_execution_context():
    """Test preparing execution context."""
    adapter = IntegrationAdapter()
    
    # Register binding
    b = CryptographicBinding(
        id="binding-123",
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        binding_type="static",
        signature_algorithm="Ed25519",
        public_key=b"public_key_bytes",
        signature=b"signature_bytes",
        artifact_hash="hash123",
        timestamp=1234567890
    )
    adapter.bindings["binding-123"] = b
    
    # Prepare context
    context = adapter.prepare_execution_context("model-x", "prod-us-west")
    
    assert context["artifact_id"] == "model-x"
    assert context["domain_id"] == "prod-us-west"
    assert len(context["jurisdiction_bindings"]) == 1
    assert context["jurisdiction_bindings"][0]["id"] == "binding-123"


def test_emit_and_get_proof():
    """Test emitting and retrieving a proof."""
    adapter = IntegrationAdapter()
    
    # Create proof
    from jib.core.types import BoundaryProof
    import hashlib
    
    proof = BoundaryProof(
        id="proof-123",
        artifact_id="model-x",
        source_domain_id="prod-us-west",
        target_domain_id="dev-us-east",
        jurisdiction_id="us-ca",
        allowed=True,
        reason="Allowed by policy",
        timestamp=1234567890,
        evidence=[]
    )
    
    # Emit proof
    adapter.emit_proof(proof)
    
    # Retrieve proof
    retrieved = adapter.get_proof("proof-123")
    
    assert retrieved is not None
    assert retrieved.id == "proof-123"
    assert retrieved.artifact_id == "model-x"


def test_validate_execution_domain():
    """Test validating execution domain."""
    adapter = IntegrationAdapter()
    
    # Should return True for valid domain (simplified)
    result = adapter.validate_execution_domain(
        ExecutionDomain(
            id="prod-us-west",
            name="Production US West",
            jurisdiction_id="us-ca"
        )
    )
    
    assert result is True


def test_get_jurisdiction_info():
    """Test getting jurisdiction info."""
    adapter = IntegrationAdapter()
    
    # Should return basic info
    info = adapter.get_jurisdiction_info("us-ca")
    
    assert info["id"] == "us-ca"
    assert info["name"] == "Unknown Jurisdiction"
    assert info["type"] == "unknown"