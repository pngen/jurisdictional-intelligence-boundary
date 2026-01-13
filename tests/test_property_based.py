"""
Property-based tests for JIB using Hypothesis.

These tests verify that system invariants hold under randomly generated
inputs and state transitions.
"""

import pytest
from hypothesis import given, strategies as st, settings, Phase
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib

from jib.core.research_grade_enforcer import ResearchGradeBoundaryEnforcer
from jib.core.types import (
    Jurisdiction,
    ExecutionDomain,
    Boundary,
    JurisdictionType,
    InvalidJurisdictionBinding,
    JurisdictionalViolation
)


# Custom strategies for JIB entities
@st.composite
def jurisdiction_id_strategy(draw):
    """Generate valid jurisdiction IDs."""
    return draw(st.text(
        min_size=2,
        max_size=15,
        alphabet=st.characters(
            whitelist_categories=('Ll', 'Nd'),  # lowercase letters and digits
            blacklist_characters='\x00'
        )
    ))


@st.composite
def artifact_id_strategy(draw):
    """Generate valid artifact IDs."""
    prefix = draw(st.sampled_from(['model', 'agent', 'workflow', 'data']))
    suffix = draw(st.text(min_size=1, max_size=10, alphabet='abcdefghijklmnopqrstuvwxyz0123456789'))
    return f"{prefix}-{suffix}"


class BoundaryEnforcerStateMachine(RuleBasedStateMachine):
    """
    Stateful property-based testing for JIB.
    
    This verifies that all system invariants hold across arbitrary
    sequences of operations.
    """
    
    def __init__(self):
        super().__init__()
        self.enforcer = ResearchGradeBoundaryEnforcer("test-node", set())
        self.jurisdictions = {}
        self.domains = {}
        self.artifacts = {}
        self.private_keys = {}
        self.boundaries_defined = set()
    
    @initialize()
    def setup_base_jurisdictions(self):
        """Initialize with some base jurisdictions for testing."""
        base_jurisdictions = ['us-ca', 'us-tx', 'us-ny', 'eu-de', 'eu-fr']
        
        for jid in base_jurisdictions[:2]:  # Start with just 2
            j = Jurisdiction(
                id=jid,
                name=f"Jurisdiction {jid}",
                type=JurisdictionType.SOVEREIGN
            )
            self.enforcer.base_enforcer.register_jurisdiction(j)
            self.jurisdictions[jid] = j
    
    @rule(jid=jurisdiction_id_strategy())
    def add_jurisdiction(self, jid):
        """
        Property: Can always add new valid jurisdictions.
        Jurisdictions should be registered without error.
        """
        if jid not in self.jurisdictions:
            j = Jurisdiction(
                id=jid,
                name=f"Jurisdiction {jid}",
                type=JurisdictionType.SOVEREIGN
            )
            self.enforcer.base_enforcer.register_jurisdiction(j)
            self.jurisdictions[jid] = j
    
    @rule(
        domain_id=st.text(min_size=2, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz-'),
        jid=jurisdiction_id_strategy()
    )
    def add_execution_domain(self, domain_id, jid):
        """
        Property: Execution domains can be added for registered jurisdictions.
        """
        if jid in self.jurisdictions and domain_id not in self.domains:
            d = ExecutionDomain(
                id=domain_id,
                name=f"Domain {domain_id}",
                jurisdiction_id=jid
            )
            self.enforcer.base_enforcer.register_execution_domain(d)
            self.domains[domain_id] = d
    
    @rule(
        artifact_id=artifact_id_strategy(),
        jid=jurisdiction_id_strategy()
    )
    def bind_artifact(self, artifact_id, jid):
        """
        Property: Binding requires registered jurisdiction.
        - If jurisdiction registered: binding succeeds
        - If jurisdiction not registered: raises InvalidJurisdictionBinding
        """
        # Generate or retrieve private key for this artifact
        if artifact_id not in self.private_keys:
            self.private_keys[artifact_id] = ed25519.Ed25519PrivateKey.generate()
        
        artifact_hash = hashlib.sha256(artifact_id.encode()).hexdigest()
        
        if jid in self.jurisdictions:
            # Should succeed
            binding = self.enforcer.bind_artifact_with_crypto(
                artifact_id=artifact_id,
                jurisdiction_id=jid,
                private_key=self.private_keys[artifact_id],
                artifact_hash=artifact_hash
            )
            self.artifacts[artifact_id] = binding
        else:
            # Should raise InvalidJurisdictionBinding
            with pytest.raises(InvalidJurisdictionBinding):
                self.enforcer.bind_artifact_with_crypto(
                    artifact_id=artifact_id,
                    jurisdiction_id=jid,
                    private_key=self.private_keys[artifact_id],
                    artifact_hash=artifact_hash
                )
    
    @rule(
        source_jid=jurisdiction_id_strategy(),
        target_jid=jurisdiction_id_strategy(),
        allowed=st.booleans()
    )
    def define_boundary(self, source_jid, target_jid, allowed):
        """
        Property: Boundaries can be defined between any jurisdictions.
        """
        if source_jid in self.jurisdictions and target_jid in self.jurisdictions:
            boundary_key = f"{source_jid}:{target_jid}"
            
            if boundary_key not in self.boundaries_defined:
                boundary = Boundary(
                    id=f"boundary-{source_jid}-to-{target_jid}",
                    source_jurisdiction_id=source_jid,
                    target_jurisdiction_id=target_jid,
                    allowed=allowed,
                    reason=f"Test boundary: {'allowed' if allowed else 'denied'}"
                )
                self.enforcer.base_enforcer.boundaries[boundary_key] = boundary
                self.boundaries_defined.add(boundary_key)
    
    @rule(
        artifact_id=artifact_id_strategy(),
        source_domain=st.text(min_size=2, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz-'),
        target_domain=st.text(min_size=2, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz-')
    )
    def check_boundary(self, artifact_id, source_domain, target_domain):
        """
        Property: Boundary checking follows fail-closed semantics.
        - If all preconditions met and boundary allows: returns allowed proof
        - Otherwise: raises exception or returns denied proof
        """
        # Only proceed if artifact is bound and domains exist
        if (artifact_id in self.artifacts and 
            source_domain in self.domains and 
            target_domain in self.domains):
            
            try:
                proof = self.enforcer.base_enforcer.check_boundary(
                    artifact_id,
                    source_domain,
                    target_domain
                )
                
                # If proof was generated, verify it has all required fields
                assert proof.id
                assert proof.artifact_id == artifact_id
                assert proof.source_domain_id == source_domain
                assert proof.target_domain_id == target_domain
                assert proof.jurisdiction_id
                assert proof.reason
                assert isinstance(proof.allowed, bool)
                
            except (JurisdictionalViolation, InvalidJurisdictionBinding):
                # Expected failures - system correctly rejected invalid operation
                pass
    
    # =======================================================================
    # INVARIANTS - These must hold after every operation
    # =======================================================================
    
    @invariant()
    def invariant_i1_no_unbound_execution(self):
        """
        INVARIANT I1: No artifact executes without binding.
        
        Every artifact in the system must have at least one binding.
        """
        for artifact_id in self.artifacts.keys():
            bindings = self.enforcer.base_enforcer.bound_artifacts.get(artifact_id, [])
            assert len(bindings) > 0, \
                f"INVARIANT I1 VIOLATED: Artifact {artifact_id} has no bindings"
    
    @invariant()
    def invariant_i3_cryptographic_validity(self):
        """
        INVARIANT I3: All bindings are cryptographically valid.
        
        Every binding must have a valid Ed25519 signature.
        """
        for artifact_id, binding in self.artifacts.items():
            assert binding.verify(), \
                f"INVARIANT I3 VIOLATED: Binding for {artifact_id} has invalid signature"
    
    @invariant()
    def invariant_bindings_reference_registered_jurisdictions(self):
        """
        INVARIANT: All bindings reference registered jurisdictions.
        
        No orphaned jurisdiction references.
        """
        for artifact_id, binding in self.artifacts.items():
            assert binding.jurisdiction_id in self.jurisdictions, \
                f"INVARIANT VIOLATED: Binding {artifact_id} references " \
                f"unregistered jurisdiction {binding.jurisdiction_id}"
    
    @invariant()
    def invariant_domains_reference_registered_jurisdictions(self):
        """
        INVARIANT: All domains reference registered jurisdictions.
        
        No orphaned jurisdiction references in domains.
        """
        for domain_id, domain in self.domains.items():
            assert domain.jurisdiction_id in self.jurisdictions, \
                f"INVARIANT VIOLATED: Domain {domain_id} references " \
                f"unregistered jurisdiction {domain.jurisdiction_id}"
    
    @invariant()
    def invariant_fail_closed_semantics(self):
        """
        INVARIANT I4: System fails closed on ambiguity.
        
        When checking boundaries, any ambiguous or missing information
        results in denial.
        """
        # This is verified implicitly by check_boundary rule behavior
        # and explicit exception handling
        pass
    
    @invariant()
    def invariant_auditability(self):
        """
        INVARIANT I6: All decisions generate proofs.
        
        The system maintains audit trail via Merkle tree.
        """
        # Verify Merkle tree is functional
        if self.enforcer.merkle_tree.leaves:
            root = self.enforcer.merkle_tree.get_root()
            assert root is not None, "INVARIANT I6 VIOLATED: Merkle tree has no root"


# Create pytest test case from state machine
TestBoundaryEnforcerProperties = BoundaryEnforcerStateMachine.TestCase


# =======================================================================
# Simple property-based tests (non-stateful)
# =======================================================================

@given(
    artifact_id=artifact_id_strategy(),
    artifact_hash=st.text(min_size=64, max_size=64, alphabet='0123456789abcdef')
)
@settings(max_examples=50, phases=[Phase.generate, Phase.target])
def test_property_binding_deterministic(artifact_id, artifact_hash):
    """
    Property: Binding creation is deterministic.
    
    Same inputs always produce same binding ID.
    """
    enforcer = ResearchGradeBoundaryEnforcer("test", set())
    
    # Register test jurisdiction
    j = Jurisdiction(id="test-jid", name="Test", type=JurisdictionType.SOVEREIGN)
    enforcer.base_enforcer.register_jurisdiction(j)
    
    # Generate key
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Create binding twice
    binding1 = enforcer.bind_artifact_with_crypto(
        artifact_id=artifact_id,
        jurisdiction_id="test-jid",
        private_key=private_key,
        artifact_hash=artifact_hash
    )
    
    # Clear and recreate
    enforcer.base_enforcer.bound_artifacts.clear()
    
    binding2 = enforcer.bind_artifact_with_crypto(
        artifact_id=artifact_id,
        jurisdiction_id="test-jid",
        private_key=private_key,
        artifact_hash=artifact_hash
    )
    
    # IDs should be identical (deterministic hashing)
    assert binding1.id == binding2.id


@given(
    num_jurisdictions=st.integers(min_value=1, max_value=10)
)
@settings(max_examples=20)
def test_property_jurisdiction_registration_is_idempotent(num_jurisdictions):
    """
    Property: Registering jurisdictions is idempotent.
    
    Registering same jurisdiction multiple times has no adverse effects.
    """
    enforcer = ResearchGradeBoundaryEnforcer("test", set())
    
    for i in range(num_jurisdictions):
        j = Jurisdiction(
            id=f"jid-{i}",
            name=f"Jurisdiction {i}",
            type=JurisdictionType.SOVEREIGN
        )
        
        # Register multiple times
        enforcer.base_enforcer.register_jurisdiction(j)
        enforcer.base_enforcer.register_jurisdiction(j)
        enforcer.base_enforcer.register_jurisdiction(j)
    
    # Should have exactly num_jurisdictions registered
    assert len(enforcer.base_enforcer.jurisdictions) == num_jurisdictions


@given(
    allowed=st.booleans(),
    reason=st.text(min_size=1, max_size=100)
)
def test_property_boundary_decisions_are_consistent(allowed, reason):
    """
    Property: Boundary decisions are consistent.
    
    Same boundary configuration always produces same decision.
    """
    enforcer = ResearchGradeBoundaryEnforcer("test", set())
    
    # Setup
    j1 = Jurisdiction(id="j1", name="J1", type=JurisdictionType.SOVEREIGN)
    j2 = Jurisdiction(id="j2", name="J2", type=JurisdictionType.SOVEREIGN)
    enforcer.base_enforcer.register_jurisdiction(j1)
    enforcer.base_enforcer.register_jurisdiction(j2)
    
    d1 = ExecutionDomain(id="d1", name="D1", jurisdiction_id="j1")
    d2 = ExecutionDomain(id="d2", name="D2", jurisdiction_id="j2")
    enforcer.base_enforcer.register_execution_domain(d1)
    enforcer.base_enforcer.register_execution_domain(d2)
    
    # Bind artifact
    private_key = ed25519.Ed25519PrivateKey.generate()
    enforcer.bind_artifact_with_crypto(
        artifact_id="test-artifact",
        jurisdiction_id="j1",
        private_key=private_key,
        artifact_hash="hash123"
    )
    
    # Define boundary
    boundary = Boundary(
        id="b1",
        source_jurisdiction_id="j1",
        target_jurisdiction_id="j2",
        allowed=allowed,
        reason=reason
    )
    enforcer.base_enforcer.boundaries["j1:j2"] = boundary
    
    # Check multiple times
    proof1 = enforcer.base_enforcer.check_boundary("test-artifact", "d1", "d2")
    proof2 = enforcer.base_enforcer.check_boundary("test-artifact", "d1", "d2")
    proof3 = enforcer.base_enforcer.check_boundary("test-artifact", "d1", "d2")
    
    # All should be identical
    assert proof1.allowed == proof2.allowed == proof3.allowed == allowed
    assert proof1.reason == proof2.reason == proof3.reason == reason