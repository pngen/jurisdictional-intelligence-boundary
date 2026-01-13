"""
Integrated research-grade boundary enforcer.
"""

from typing import Set, Optional, Dict, Any
from .boundary_enforcer import BoundaryEnforcer
from .cryptographic_binding import KeyManager, MerkleTree, BindingRevocation
from .temporal_boundary import TemporalBoundaryManager
from .distributed_enforcer import DistributedBoundaryEnforcer
from .provenance_tracking import DataFlowTracker
from .policy_algebra import PolicyManager
from .formal_verification import InvariantChecker
from .types import (
    InvalidJurisdictionBinding,
    BindingIntegrityViolation,
    JurisdictionalViolation,
    TemporalConstraintViolation,
    ConsensusFailure,
    InvariantViolation
)


class ResearchGradeBoundaryEnforcer:
    """
    Integrated enforcer with all research-grade features.
    
    Combines cryptographic binding, temporal logic, distributed consensus,
    provenance tracking, and policy algebra.
    """
    
    def __init__(self, node_id: str, peers: Set[str]):
        # Core enforcement
        self.base_enforcer = BoundaryEnforcer()
        
        # Cryptographic layer
        self.key_manager = KeyManager()
        self.merkle_tree = MerkleTree()
        self.binding_revocation = BindingRevocation()
        
        # Temporal logic
        self.temporal_manager = TemporalBoundaryManager()
        
        # Distribution
        self.distributed_enforcer = DistributedBoundaryEnforcer(node_id, peers)
        
        # Provenance
        self.provenance_tracker = DataFlowTracker()
        
        # Invariants
        self.invariant_checker = InvariantChecker()
        
        # Policy algebra
        self.policy_manager = PolicyManager()
    
    async def enforce_boundary_with_all_checks(
        self,
        artifact_id: str,
        source_domain_id: str,
        target_domain_id: str,
        private_key: Optional['ed25519.Ed25519PrivateKey'] = None,
        artifact_hash: Optional[str] = None
    ) -> 'BoundaryProof':
        """Full enforcement with all research-grade checks."""

        bindings = self.base_enforcer.bound_artifacts.get(artifact_id, [])
        if not bindings:
            raise InvalidJurisdictionBinding(f"No bindings found for {artifact_id}")

        for binding in bindings:
            if not binding.verify():
                raise BindingIntegrityViolation(
                    f"Invalid signature on binding {binding.id}",
                    {"binding_id": binding.id, "artifact_id": artifact_id}
                )

        source_domain = self.base_enforcer.execution_domains.get(source_domain_id)
        target_domain = self.base_enforcer.execution_domains.get(target_domain_id)

        if not source_domain or not target_domain:
            raise JurisdictionalViolation("Invalid execution domains")

        boundary_key = f"{source_domain.jurisdiction_id}:{target_domain.jurisdiction_id}"

        temporal_boundaries = [
            b for b in self.temporal_manager.get_valid_boundaries()
            if f"{b.source_jurisdiction_id}:{b.target_jurisdiction_id}" == boundary_key
        ]

        if temporal_boundaries:
            import time
            current_time = int(time.time())
            if not any(tb.is_valid_at(current_time) for tb in temporal_boundaries):
                raise TemporalConstraintViolation(
                    f"No valid temporal boundary for {boundary_key}",
                    {"boundary_key": boundary_key, "timestamp": current_time}
                )

        try:
            self.invariant_checker.check_no_unbound_execution(
                self.base_enforcer, artifact_id
            )
            self.invariant_checker.check_explicit_boundaries(
                self.base_enforcer,
                source_domain.jurisdiction_id,
                target_domain.jurisdiction_id
            )
        except AssertionError as e:
            raise InvariantViolation(str(e), {"artifact_id": artifact_id})

        decision = await self.distributed_enforcer.propose_boundary_decision(
            artifact_id, source_domain_id, target_domain_id
        )

        if not decision:
            raise ConsensusFailure(
                "Distributed consensus denied boundary crossing",
                {"artifact_id": artifact_id, "source": source_domain_id, "target": target_domain_id}
            )

        self.provenance_tracker.record_data_flow(
            artifact_id, "boundary_check",
            source_domain.jurisdiction_id,
            target_domain.jurisdiction_id
        )

        proof = self.base_enforcer.check_boundary(
            artifact_id, source_domain_id, target_domain_id
        )

        self.invariant_checker.check_auditability(proof)
        self.merkle_tree.add_leaf(proof.id)

        return proof
    
    def bind_artifact_with_crypto(
        self,
        artifact_id: str,
        jurisdiction_id: str,
        private_key: 'ed25519.Ed25519PrivateKey',
        artifact_hash: str,
        binding_type: str = "static"
    ) -> 'CryptographicBinding':
        """
        Bind an artifact with cryptographic signature.
        
        Returns the signed binding object.
        """
        return self.base_enforcer.bind_artifact_to_jurisdiction(
            artifact_id=artifact_id,
            jurisdiction_id=jurisdiction_id,
            private_key=private_key,
            artifact_hash=artifact_hash,
            binding_type=binding_type
        )
    
    def register_temporal_boundary(self, boundary: 'TemporalBoundary'):
        """Register a time-bounded boundary."""
        self.temporal_manager.register_boundary(boundary)
    
    def get_decision_log(self):
        """Get distributed decision log."""
        return self.distributed_enforcer.get_decision_log()
    
    def get_flow_summary(self):
        """Get data flow summary."""
        return self.provenance_tracker.get_flow_summary()