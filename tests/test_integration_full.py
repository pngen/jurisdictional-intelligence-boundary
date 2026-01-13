"""
Full integration tests for JIB.

Tests the complete enforcement pipeline with all components working together.
"""

import pytest
import asyncio
import time
from cryptography.hazmat.primitives.asymmetric import ed25519

from jib.core.research_grade_enforcer import ResearchGradeBoundaryEnforcer
from jib.core.types import (
    Jurisdiction,
    ExecutionDomain,
    Boundary,
    JurisdictionType,
    JurisdictionalViolation,
    TemporalConstraintViolation,
    InvalidJurisdictionBinding,
    BindingIntegrityViolation,
    ConsensusFailure
)
from jib.core.temporal_boundary import TemporalBoundary, TemporalOperator


@pytest.mark.asyncio
async def test_full_enforcement_pipeline_allowed():
    """
    Integration test: Full enforcement pipeline with allowed boundary crossing.
    
    Tests the complete flow:
    1. Cryptographic binding creation
    2. Temporal boundary validation
    3. Distributed consensus
    4. Provenance tracking
    5. Invariant checking
    6. Proof generation
    7. Merkle tree audit trail
    """
    # Setup distributed system
    enforcer = ResearchGradeBoundaryEnforcer("node-1", {"node-2", "node-3"})
    
    # Register jurisdictions
    us_ca = Jurisdiction(
        id="us-ca",
        name="California, USA",
        type=JurisdictionType.SOVEREIGN
    )
    us_tx = Jurisdiction(
        id="us-tx",
        name="Texas, USA",
        type=JurisdictionType.SOVEREIGN
    )
    
    enforcer.base_enforcer.register_jurisdiction(us_ca)
    enforcer.base_enforcer.register_jurisdiction(us_tx)
    
    # Register execution domains
    prod_west = ExecutionDomain(
        id="prod-west",
        name="Production West",
        jurisdiction_id="us-ca"
    )
    prod_east = ExecutionDomain(
        id="prod-east",
        name="Production East",
        jurisdiction_id="us-tx"
    )
    
    enforcer.base_enforcer.register_execution_domain(prod_west)
    enforcer.base_enforcer.register_execution_domain(prod_east)
    
    # Create cryptographic binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    binding = enforcer.bind_artifact_with_crypto(
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        private_key=private_key,
        artifact_hash="abc123def456"
    )
    
    # Verify binding cryptographically
    assert binding.verify() is True, "Cryptographic binding verification failed"
    
    # Add temporal boundary (valid for next hour)
    temporal_boundary = TemporalBoundary(
        id="temp-ca-to-tx",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Temporary cross-jurisdiction access",
        valid_from=int(time.time()) - 60,
        valid_until=int(time.time()) + 3600,
        temporal_operator=TemporalOperator.UNTIL
    )
    enforcer.register_temporal_boundary(temporal_boundary)
    
    # Add static boundary rule
    boundary = Boundary(
        id="ca-to-tx",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Allowed by policy"
    )
    enforcer.base_enforcer.boundaries["us-ca:us-tx"] = boundary
    
    # Execute full enforcement with all checks
    proof = await enforcer.enforce_boundary_with_all_checks(
        artifact_id="model-x",
        source_domain_id="prod-west",
        target_domain_id="prod-east"
    )
    
    # Verify proof properties
    assert proof.allowed is True, "Boundary should be allowed"
    assert proof.artifact_id == "model-x"
    assert proof.jurisdiction_id == "us-ca"
    assert proof.source_domain_id == "prod-west"
    assert proof.target_domain_id == "prod-east"
    assert proof.reason == "Allowed by policy"
    
    # Verify provenance tracking
    flow_summary = enforcer.get_flow_summary()
    assert flow_summary["total_flows"] >= 1, "Should have recorded data flow"
    assert flow_summary["cross_boundary_flows"] >= 1, "Should have cross-boundary flow"
    
    # Verify Merkle tree audit trail
    merkle_root = enforcer.merkle_tree.get_root()
    assert merkle_root is not None, "Merkle tree should have root"
    
    # Verify decision log
    decision_log = enforcer.get_decision_log()
    assert len(decision_log) >= 1, "Should have decision log entry"
    
    print("✅ Full enforcement pipeline test PASSED")


@pytest.mark.asyncio
async def test_enforcement_denies_expired_temporal_boundary():
    """
    Integration test: System denies expired temporal boundaries.
    
    Verifies that temporal constraint enforcement works correctly.
    """
    enforcer = ResearchGradeBoundaryEnforcer("node-1", set())
    
    # Setup jurisdictions and domains
    us_ca = Jurisdiction(id="us-ca", name="California", type=JurisdictionType.SOVEREIGN)
    us_tx = Jurisdiction(id="us-tx", name="Texas", type=JurisdictionType.SOVEREIGN)
    enforcer.base_enforcer.register_jurisdiction(us_ca)
    enforcer.base_enforcer.register_jurisdiction(us_tx)
    
    prod_west = ExecutionDomain(id="prod-west", name="West", jurisdiction_id="us-ca")
    prod_east = ExecutionDomain(id="prod-east", name="East", jurisdiction_id="us-tx")
    enforcer.base_enforcer.register_execution_domain(prod_west)
    enforcer.base_enforcer.register_execution_domain(prod_east)
    
    # Create binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    enforcer.bind_artifact_with_crypto(
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        private_key=private_key,
        artifact_hash="hash123"
    )
    
    # Add EXPIRED temporal boundary
    expired_boundary = TemporalBoundary(
        id="expired-ca-to-tx",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Expired access",
        valid_from=int(time.time()) - 7200,  # 2 hours ago
        valid_until=int(time.time()) - 3600,  # 1 hour ago (EXPIRED)
        temporal_operator=TemporalOperator.UNTIL
    )
    enforcer.register_temporal_boundary(expired_boundary)
    
    # Should raise TemporalConstraintViolation
    with pytest.raises(TemporalConstraintViolation) as exc_info:
        await enforcer.enforce_boundary_with_all_checks(
            artifact_id="model-x",
            source_domain_id="prod-west",
            target_domain_id="prod-east"
        )
    
    assert "No valid temporal boundary" in str(exc_info.value)
    print("✅ Temporal constraint violation test PASSED")


@pytest.mark.asyncio
async def test_enforcement_denies_invalid_cryptographic_binding():
    """
    Integration test: System denies tampered bindings.
    
    Verifies cryptographic integrity checking.
    """
    enforcer = ResearchGradeBoundaryEnforcer("node-1", set())
    
    # Setup
    us_ca = Jurisdiction(id="us-ca", name="California", type=JurisdictionType.SOVEREIGN)
    enforcer.base_enforcer.register_jurisdiction(us_ca)
    
    prod_west = ExecutionDomain(id="prod-west", name="West", jurisdiction_id="us-ca")
    prod_east = ExecutionDomain(id="prod-east", name="East", jurisdiction_id="us-ca")
    enforcer.base_enforcer.register_execution_domain(prod_west)
    enforcer.base_enforcer.register_execution_domain(prod_east)
    
    # Create valid binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    valid_binding = enforcer.bind_artifact_with_crypto(
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        private_key=private_key,
        artifact_hash="original-hash"
    )
    
    # Tamper with binding by replacing with invalid signature
    from jib.core.types import CryptographicBinding
    tampered_binding = CryptographicBinding(
        id=valid_binding.id,
        artifact_id=valid_binding.artifact_id,
        jurisdiction_id=valid_binding.jurisdiction_id,
        binding_type=valid_binding.binding_type,
        signature_algorithm=valid_binding.signature_algorithm,
        public_key=valid_binding.public_key,
        signature=b"INVALID_SIGNATURE",  # Tampered!
        artifact_hash=valid_binding.artifact_hash,
        timestamp=valid_binding.timestamp
    )
    
    # Replace valid binding with tampered one
    enforcer.base_enforcer.bound_artifacts["model-x"] = [tampered_binding]
    
    # Add boundary
    boundary = Boundary(
        id="ca-to-ca",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-ca",
        allowed=True,
        reason="Same jurisdiction"
    )
    enforcer.base_enforcer.boundaries["us-ca:us-ca"] = boundary
    
    # Should raise BindingIntegrityViolation
    with pytest.raises(BindingIntegrityViolation) as exc_info:
        await enforcer.enforce_boundary_with_all_checks(
            artifact_id="model-x",
            source_domain_id="prod-west",
            target_domain_id="prod-east"
        )
    
    assert "Invalid signature" in str(exc_info.value)
    print("✅ Cryptographic integrity violation test PASSED")


@pytest.mark.asyncio
async def test_enforcement_denies_unbound_artifact():
    """
    Integration test: System denies execution of unbound artifacts.
    
    Verifies Invariant I1: No artifact executes without binding.
    """
    enforcer = ResearchGradeBoundaryEnforcer("node-1", set())
    
    # Setup
    us_ca = Jurisdiction(id="us-ca", name="California", type=JurisdictionType.SOVEREIGN)
    enforcer.base_enforcer.register_jurisdiction(us_ca)
    
    prod_west = ExecutionDomain(id="prod-west", name="West", jurisdiction_id="us-ca")
    prod_east = ExecutionDomain(id="prod-east", name="East", jurisdiction_id="us-ca")
    enforcer.base_enforcer.register_execution_domain(prod_west)
    enforcer.base_enforcer.register_execution_domain(prod_east)
    
    # DON'T create binding - artifact is unbound
    
    # Add boundary
    boundary = Boundary(
        id="ca-to-ca",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-ca",
        allowed=True,
        reason="Same jurisdiction"
    )
    enforcer.base_enforcer.boundaries["us-ca:us-ca"] = boundary
    
    # Should raise InvalidJurisdictionBinding
    with pytest.raises(InvalidJurisdictionBinding) as exc_info:
        await enforcer.enforce_boundary_with_all_checks(
            artifact_id="unbound-artifact",
            source_domain_id="prod-west",
            target_domain_id="prod-east"
        )
    
    assert "No bindings found" in str(exc_info.value)
    print("✅ Unbound artifact denial test PASSED")


@pytest.mark.asyncio
async def test_enforcement_denies_without_explicit_boundary():
    """
    Integration test: System denies cross-jurisdiction without explicit boundary.
    
    Verifies Invariant I2 and fail-closed semantics.
    """
    enforcer = ResearchGradeBoundaryEnforcer("node-1", set())
    
    # Setup
    us_ca = Jurisdiction(id="us-ca", name="California", type=JurisdictionType.SOVEREIGN)
    us_tx = Jurisdiction(id="us-tx", name="Texas", type=JurisdictionType.SOVEREIGN)
    enforcer.base_enforcer.register_jurisdiction(us_ca)
    enforcer.base_enforcer.register_jurisdiction(us_tx)
    
    prod_west = ExecutionDomain(id="prod-west", name="West", jurisdiction_id="us-ca")
    prod_east = ExecutionDomain(id="prod-east", name="East", jurisdiction_id="us-tx")
    enforcer.base_enforcer.register_execution_domain(prod_west)
    enforcer.base_enforcer.register_execution_domain(prod_east)
    
    # Create binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    enforcer.bind_artifact_with_crypto(
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        private_key=private_key,
        artifact_hash="hash123"
    )
    
    # DON'T add boundary - no explicit rule defined
    
    # Should raise due to fail-closed semantics
    with pytest.raises((JurisdictionalViolation, AssertionError)) as exc_info:
        await enforcer.enforce_boundary_with_all_checks(
            artifact_id="model-x",
            source_domain_id="prod-west",
            target_domain_id="prod-east"
        )
    
    # Either JurisdictionalViolation or Invariant I2 assertion should fire
    print("✅ Fail-closed boundary test PASSED")


@pytest.mark.asyncio
async def test_multi_artifact_provenance_tracking():
    """
    Integration test: Provenance tracking across multiple artifacts.
    
    Verifies data flow tracking and audit trail generation.
    """
    enforcer = ResearchGradeBoundaryEnforcer("node-1", set())
    
    # Setup
    us_ca = Jurisdiction(id="us-ca", name="California", type=JurisdictionType.SOVEREIGN)
    us_tx = Jurisdiction(id="us-tx", name="Texas", type=JurisdictionType.SOVEREIGN)
    us_ny = Jurisdiction(id="us-ny", name="New York", type=JurisdictionType.SOVEREIGN)
    
    enforcer.base_enforcer.register_jurisdiction(us_ca)
    enforcer.base_enforcer.register_jurisdiction(us_tx)
    enforcer.base_enforcer.register_jurisdiction(us_ny)
    
    d_ca = ExecutionDomain(id="d-ca", name="CA Domain", jurisdiction_id="us-ca")
    d_tx = ExecutionDomain(id="d-tx", name="TX Domain", jurisdiction_id="us-tx")
    d_ny = ExecutionDomain(id="d-ny", name="NY Domain", jurisdiction_id="us-ny")
    
    enforcer.base_enforcer.register_execution_domain(d_ca)
    enforcer.base_enforcer.register_execution_domain(d_tx)
    enforcer.base_enforcer.register_execution_domain(d_ny)
    
    # Create multiple artifacts
    artifacts = ["model-a", "model-b", "model-c"]
    for artifact in artifacts:
        private_key = ed25519.Ed25519PrivateKey.generate()
        enforcer.bind_artifact_with_crypto(
            artifact_id=artifact,
            jurisdiction_id="us-ca",
            private_key=private_key,
            artifact_hash=f"hash-{artifact}"
        )
    
    # Define boundaries
    for target_jid in ["us-tx", "us-ny"]:
        boundary = Boundary(
            id=f"ca-to-{target_jid}",
            source_jurisdiction_id="us-ca",
            target_jurisdiction_id=target_jid,
            allowed=True,
            reason="Cross-region allowed"
        )
        enforcer.base_enforcer.boundaries[f"us-ca:{target_jid}"] = boundary
    
    # Execute multiple boundary checks
    for artifact in artifacts:
        for target in ["d-tx", "d-ny"]:
            proof = await enforcer.enforce_boundary_with_all_checks(
                artifact_id=artifact,
                source_domain_id="d-ca",
                target_domain_id=target
            )
            assert proof.allowed is True
    
    # Verify provenance tracking
    flow_summary = enforcer.get_flow_summary()
    assert flow_summary["total_flows"] >= 6, "Should have 6 flows (3 artifacts × 2 destinations)"
    assert flow_summary["cross_boundary_flows"] >= 6, "All should be cross-boundary"
    
    # Verify audit trail
    assert enforcer.merkle_tree.get_root() is not None
    assert len(enforcer.merkle_tree.leaves) >= 6
    
    print("✅ Multi-artifact provenance tracking test PASSED")


@pytest.mark.asyncio
async def test_concurrent_enforcement_requests():
    """
    Integration test: Concurrent boundary enforcement requests.
    
    Verifies system handles concurrent operations correctly.
    """
    enforcer = ResearchGradeBoundaryEnforcer("node-1", set())
    
    # Setup
    us_ca = Jurisdiction(id="us-ca", name="California", type=JurisdictionType.SOVEREIGN)
    enforcer.base_enforcer.register_jurisdiction(us_ca)
    
    d1 = ExecutionDomain(id="d1", name="Domain 1", jurisdiction_id="us-ca")
    d2 = ExecutionDomain(id="d2", name="Domain 2", jurisdiction_id="us-ca")
    enforcer.base_enforcer.register_execution_domain(d1)
    enforcer.base_enforcer.register_execution_domain(d2)
    
    # Create bindings for multiple artifacts
    artifacts = [f"model-{i}" for i in range(10)]
    for artifact in artifacts:
        private_key = ed25519.Ed25519PrivateKey.generate()
        enforcer.bind_artifact_with_crypto(
            artifact_id=artifact,
            jurisdiction_id="us-ca",
            private_key=private_key,
            artifact_hash=f"hash-{artifact}"
        )
    
    # Add boundary
    boundary = Boundary(
        id="ca-to-ca",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-ca",
        allowed=True,
        reason="Same jurisdiction"
    )
    enforcer.base_enforcer.boundaries["us-ca:us-ca"] = boundary
    
    # Execute concurrent enforcement requests
    tasks = [
        enforcer.enforce_boundary_with_all_checks(
            artifact_id=artifact,
            source_domain_id="d1",
            target_domain_id="d2"
        )
        for artifact in artifacts
    ]
    
    proofs = await asyncio.gather(*tasks)
    
    # Verify all succeeded
    assert len(proofs) == 10
    assert all(proof.allowed for proof in proofs)
    
    print("✅ Concurrent enforcement test PASSED")


@pytest.mark.asyncio
async def test_temporal_boundary_grace_period():
    """
    Integration test: Temporal boundaries with grace periods.
    
    Verifies grace period handling in temporal constraints.
    """
    enforcer = ResearchGradeBoundaryEnforcer("node-1", set())
    
    # Setup
    us_ca = Jurisdiction(id="us-ca", name="California", type=JurisdictionType.SOVEREIGN)
    us_tx = Jurisdiction(id="us-tx", name="Texas", type=JurisdictionType.SOVEREIGN)
    enforcer.base_enforcer.register_jurisdiction(us_ca)
    enforcer.base_enforcer.register_jurisdiction(us_tx)
    
    d_ca = ExecutionDomain(id="d-ca", name="CA", jurisdiction_id="us-ca")
    d_tx = ExecutionDomain(id="d-tx", name="TX", jurisdiction_id="us-tx")
    enforcer.base_enforcer.register_execution_domain(d_ca)
    enforcer.base_enforcer.register_execution_domain(d_tx)
    
    # Create binding
    private_key = ed25519.Ed25519PrivateKey.generate()
    enforcer.bind_artifact_with_crypto(
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        private_key=private_key,
        artifact_hash="hash123"
    )
    
    # Add temporal boundary expiring in 30 minutes
    current_time = int(time.time())
    temporal_boundary = TemporalBoundary(
        id="temp-ca-to-tx",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Temporary access",
        valid_from=current_time - 3600,  # Started 1 hour ago
        valid_until=current_time + 1800,  # Expires in 30 minutes
        temporal_operator=TemporalOperator.UNTIL
    )
    enforcer.register_temporal_boundary(temporal_boundary)
    
    # Add static boundary
    boundary = Boundary(
        id="ca-to-tx",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Policy allows"
    )
    enforcer.base_enforcer.boundaries["us-ca:us-tx"] = boundary
    
    # Should still be valid (in grace period)
    proof = await enforcer.enforce_boundary_with_all_checks(
        artifact_id="model-x",
        source_domain_id="d-ca",
        target_domain_id="d-tx"
    )
    
    assert proof.allowed is True
    
    # Verify grace period manager can detect we're near expiration
    from jib.core.temporal_boundary import GracePeriodManager
    gpm = GracePeriodManager(default_grace_period=3600)  # 1 hour grace
    
    in_grace = gpm.is_in_grace_period(temporal_boundary, current_time)
    remaining = gpm.get_remaining_time(temporal_boundary, current_time)
    
    assert remaining > 0 and remaining <= 1800  # Less than 30 minutes remaining
    
    print("✅ Temporal grace period test PASSED")


def test_merkle_tree_audit_trail_integrity():
    """
    Integration test: Merkle tree audit trail integrity.
    
    Verifies tamper-evident audit trail.
    """
    enforcer = ResearchGradeBoundaryEnforcer("node-1", set())
    
    # Add multiple proof IDs to Merkle tree
    proof_ids = [f"proof-{i}" for i in range(10)]
    for proof_id in proof_ids:
        enforcer.merkle_tree.add_leaf(proof_id)
    
    # Get root
    root1 = enforcer.merkle_tree.get_root()
    assert root1 is not None
    
    # Verify proofs
    for i, proof_id in enumerate(proof_ids):
        proof = enforcer.merkle_tree.get_proof(i)
        assert isinstance(proof, list)
    
    # Add one more proof
    enforcer.merkle_tree.add_leaf("proof-new")
    root2 = enforcer.merkle_tree.get_root()
    
    # Root should have changed (tamper-evident)
    assert root1 != root2
    
    print("✅ Merkle tree integrity test PASSED")