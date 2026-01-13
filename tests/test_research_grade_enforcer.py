"""
Tests for research-grade enforcer.
"""

import pytest
from jib.core.research_grade_enforcer import ResearchGradeBoundaryEnforcer
from cryptography.hazmat.primitives.asymmetric import ed25519


def test_research_grade_enforcer_initialization():
    """Test initialization of research-grade enforcer."""
    
    peers = {"node-1", "node-2"}
    enforcer = ResearchGradeBoundaryEnforcer("node-1", peers)
    
    assert hasattr(enforcer, 'base_enforcer')
    assert hasattr(enforcer, 'key_manager')
    assert hasattr(enforcer, 'merkle_tree')
    assert hasattr(enforcer, 'temporal_manager')
    assert hasattr(enforcer, 'distributed_enforcer')
    assert hasattr(enforcer, 'provenance_tracker')
    assert hasattr(enforcer, 'invariant_checker')
    assert hasattr(enforcer, 'policy_manager')


def test_bind_artifact_with_crypto():
    """Test binding artifact with cryptographic signature."""
    
    peers = {"node-1", "node-2"}
    enforcer = ResearchGradeBoundaryEnforcer("node-1", peers)
    
    # Generate key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Create jurisdiction and domain for testing
    from jib.core.types import Jurisdiction, JurisdictionType
    jurisdiction = Jurisdiction(
        id="us-ca",
        name="California",
        type=JurisdictionType.SOVEREIGN
    )
    enforcer.base_enforcer.register_jurisdiction(jurisdiction)
    
    # Bind artifact
    binding = enforcer.bind_artifact_with_crypto(
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        private_key=private_key,
        artifact_hash="abc123def456"
    )
    
    assert binding.artifact_id == "model-x"
    assert binding.jurisdiction_id == "us-ca"
    assert binding.verify() is True


def test_decision_log():
    """Test decision log functionality."""
    
    peers = {"node-1", "node-2"}
    enforcer = ResearchGradeBoundaryEnforcer("node-1", peers)
    
    # Should have empty log initially
    log = enforcer.get_decision_log()
    assert isinstance(log, list)


def test_flow_summary():
    """Test flow summary functionality."""
    
    peers = {"node-1", "node-2"}
    enforcer = ResearchGradeBoundaryEnforcer("node-1", peers)
    
    # Should have initial summary
    summary = enforcer.get_flow_summary()
    assert isinstance(summary, dict)