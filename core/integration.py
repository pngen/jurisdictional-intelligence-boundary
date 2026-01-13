"""
Integration points for JIB with execution and governance layers.
"""

from typing import Dict, Any, Optional
from .types import (
    CryptographicBinding,
    BoundaryProof,
    ExecutionDomain,
    Jurisdiction
)
import json


class IntegrationAdapter:
    """
    Adapter for integrating JIB with external systems.
    
    Handles interaction with orchestrators, sandboxes, etc.
    """

    def __init__(self):
        self.bindings: dict[str, CryptographicBinding] = {}
        self.proofs: dict[str, BoundaryProof] = {}

    def prepare_execution_context(
        self,
        artifact_id: str,
        domain_id: str
    ) -> Dict[str, Any]:
        """
        Prepare execution context for an artifact in a domain.
        
        Returns metadata needed by execution systems.
        """
        # Get bindings for this artifact
        bindings = [b for b in self.bindings.values() if b.artifact_id == artifact_id]
        
        return {
            "artifact_id": artifact_id,
            "domain_id": domain_id,
            "jurisdiction_bindings": [
                {
                    "id": b.id,
                    "jurisdiction_id": b.jurisdiction_id,
                    "binding_type": b.binding_type
                }
                for b in bindings
            ]
        }

    def emit_proof(self, proof: BoundaryProof):
        """
        Emit a boundary proof to external systems.
        
        In real system, this might log to audit trail or send to compliance system.
        """
        self.proofs[proof.id] = proof

    def get_proof(self, proof_id: str) -> Optional[BoundaryProof]:
        """Retrieve a previously emitted proof."""
        return self.proofs.get(proof_id)

    def validate_execution_domain(
        self,
        domain: ExecutionDomain
    ) -> bool:
        """
        Validate that an execution domain is properly configured.
        
        Returns True if valid, False otherwise.
        """
        # In real system, would check domain metadata against jurisdiction requirements
        return True

    def get_jurisdiction_info(self, jurisdiction_id: str) -> Optional[Dict[str, Any]]:
        """
        Get jurisdiction information for integration purposes.
        
        Returns jurisdiction metadata or None if not found.
        """
        # Placeholder - in real system would fetch from registry
        return {
            "id": jurisdiction_id,
            "name": "Unknown Jurisdiction",
            "type": "unknown"
        }