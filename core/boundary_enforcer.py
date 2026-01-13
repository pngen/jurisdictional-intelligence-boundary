"""
Enforcement engine for Jurisdictional Intelligence Boundary (JIB).
"""

from typing import Optional, List, Set
from .types import (
    Jurisdiction,
    ExecutionDomain,
    Boundary,
    CryptographicBinding,
    BoundaryProof,
    JurisdictionalViolation,
    AmbiguousJurisdiction,
    InvalidJurisdictionBinding
)
import hashlib
import time
from cryptography.hazmat.primitives import serialization


class BoundaryEnforcer:
    """
    Enforces jurisdictional boundaries on intelligence execution.
    
    Operates below orchestration and above infrastructure.
    """

    def __init__(self):
        self.jurisdictions: dict[str, Jurisdiction] = {}
        self.execution_domains: dict[str, ExecutionDomain] = {}
        self.bound_artifacts: dict[str, List[CryptographicBinding]] = {}
        self.boundaries: dict[str, Boundary] = {}

    def register_jurisdiction(self, jurisdiction: Jurisdiction):
        """Register a jurisdiction."""
        self.jurisdictions[jurisdiction.id] = jurisdiction

    def register_execution_domain(self, domain: ExecutionDomain):
        """Register an execution domain."""
        self.execution_domains[domain.id] = domain

    def bind_artifact_to_jurisdiction(
        self,
        artifact_id: str,
        jurisdiction_id: str,
        private_key: 'ed25519.Ed25519PrivateKey',
        artifact_hash: str,
        binding_type: str = "static"
    ) -> CryptographicBinding:
        """
        Bind an artifact to a jurisdiction with cryptographic signature.
        
        Returns the signed binding object.
        """
        if jurisdiction_id not in self.jurisdictions:
            raise InvalidJurisdictionBinding(
                f"Jurisdiction {jurisdiction_id} not registered"
            )

        timestamp = int(time.time())
        
        # Create canonical form
        binding = CryptographicBinding(
            id=hashlib.sha256(f"{artifact_id}:{jurisdiction_id}".encode()).hexdigest(),
            artifact_id=artifact_id,
            jurisdiction_id=jurisdiction_id,
            binding_type=binding_type,
            signature_algorithm="Ed25519",
            public_key=private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            signature=b"",  # Will sign below
            artifact_hash=artifact_hash,
            timestamp=timestamp
        )

        # Sign it
        canonical = binding._canonical_form()
        signature = private_key.sign(canonical.encode())
        
        # Return signed binding
        signed_binding = CryptographicBinding(
            id=binding.id,
            artifact_id=binding.artifact_id,
            jurisdiction_id=binding.jurisdiction_id,
            binding_type=binding.binding_type,
            signature_algorithm=binding.signature_algorithm,
            public_key=binding.public_key,
            signature=signature,
            artifact_hash=binding.artifact_hash,
            timestamp=binding.timestamp
        )

        if artifact_id not in self.bound_artifacts:
            self.bound_artifacts[artifact_id] = []
        self.bound_artifacts[artifact_id].append(signed_binding)

        return signed_binding

    def resolve_jurisdiction_for_artifact(self, artifact_id: str) -> List[str]:
        """
        Resolve the jurisdiction(s) bound to an artifact.
        
        Returns list of jurisdiction IDs.
        """
        bindings = self.bound_artifacts.get(artifact_id, [])
        return [b.jurisdiction_id for b in bindings]

    def check_boundary(
        self,
        artifact_id: str,
        source_domain_id: str,
        target_domain_id: str
    ) -> BoundaryProof:
        """
        Check if execution across domains is allowed.
        
        Returns a proof of the decision.
        """
        # Get source and target domains
        source_domain = self.execution_domains.get(source_domain_id)
        target_domain = self.execution_domains.get(target_domain_id)

        if not source_domain or not target_domain:
            raise JurisdictionalViolation(
                "Invalid execution domain(s) provided"
            )

        # Check if artifact is bound to jurisdiction of source domain
        artifact_jurisdictions = self.resolve_jurisdiction_for_artifact(artifact_id)
        if source_domain.jurisdiction_id not in artifact_jurisdictions:
            raise JurisdictionalViolation(
                f"Artifact {artifact_id} not bound to source jurisdiction "
                f"{source_domain.jurisdiction_id}"
            )

        # Check if target domain is allowed by jurisdiction
        boundary_key = f"{source_domain.jurisdiction_id}:{target_domain.jurisdiction_id}"
        boundary = self.boundaries.get(boundary_key)

        if boundary:
            allowed = boundary.allowed
            reason = boundary.reason
        else:
            # Default to deny if no explicit boundary defined
            allowed = False
            reason = "No explicit boundary rule defined"

        return BoundaryProof(
            id=hashlib.sha256(f"{artifact_id}:{source_domain_id}:{target_domain_id}".encode()).hexdigest(),
            artifact_id=artifact_id,
            source_domain_id=source_domain_id,
            target_domain_id=target_domain_id,
            jurisdiction_id=source_domain.jurisdiction_id,
            allowed=allowed,
            reason=reason,
            timestamp=0,  # In real system, would be timestamp
            evidence=[]
        )

    def enforce_boundary(
        self,
        artifact_id: str,
        source_domain_id: str,
        target_domain_id: str
    ):
        """
        Enforce boundary check and raise if not allowed.
        
        Raises JurisdictionalViolation if execution is not permitted.
        """
        proof = self.check_boundary(artifact_id, source_domain_id, target_domain_id)
        if not proof.allowed:
            raise JurisdictionalViolation(
                f"Cross-domain execution denied: {proof.reason}"
            )