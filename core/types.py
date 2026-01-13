"""
Core data structures for Jurisdictional Intelligence Boundary (JIB).
"""

from typing import Dict, List, Optional, Set, Union
from dataclasses import dataclass
from enum import Enum
import hashlib
import json


class JurisdictionType(Enum):
    """Type of jurisdiction."""
    SOVEREIGN = "sovereign"
    LEGAL = "legal"
    REGULATORY = "regulatory"


@dataclass(frozen=True)
class Jurisdiction:
    """
    A legally or sovereignly defined execution domain.
    
    Jurisdiction is declared, bound, and enforced.
    """
    id: str
    name: str
    type: JurisdictionType
    parent_id: Optional[str] = None
    attributes: Dict[str, Union[str, int, bool]] = None

    def __post_init__(self):
        if self.attributes is None:
            object.__setattr__(self, 'attributes', {})


@dataclass(frozen=True)
class ExecutionDomain:
    """
    A concrete environment where intelligence runs.
    
    Bound to a jurisdiction via JIB.
    """
    id: str
    name: str
    jurisdiction_id: str
    metadata: Dict[str, Union[str, int, bool]] = None

    def __post_init__(self):
        if self.metadata is None:
            object.__setattr__(self, 'metadata', {})


@dataclass(frozen=True)
class Boundary:
    """
    A hard constraint preventing cross-domain execution or data flow.
    
    Enforced by JIB.
    """
    id: str
    source_jurisdiction_id: str
    target_jurisdiction_id: str
    allowed: bool
    reason: str


@dataclass(frozen=True)
class JurisdictionalClaim:
    """
    A declaration of where execution is allowed or prohibited.
    
    Used to bind intelligence artifacts to jurisdictions.
    """
    id: str
    artifact_id: str
    jurisdiction_id: str
    claim_type: str  # e.g., "execution", "data-access"
    metadata: Dict[str, Union[str, int, bool]] = None

    def __post_init__(self):
        if self.metadata is None:
            object.__setattr__(self, 'metadata', {})


@dataclass(frozen=True)
class CryptographicBinding:
    """
    Non-repudiable cryptographic binding between artifact and jurisdiction.
    
    Security properties:
    - Unforgeability: Cannot create binding without private key
    - Non-repudiation: Signer cannot deny creating binding
    - Tamper-evidence: Any modification invalidates signature
    - Binding integrity: Links artifact hash to jurisdiction
    """
    
    # Core binding fields
    id: str
    artifact_id: str
    jurisdiction_id: str
    binding_type: str  # e.g., "static", "dynamic"
    
    # Cryptographic fields
    signature_algorithm: str  # e.g., "Ed25519"
    public_key: bytes         # Verifying key
    signature: bytes          # Actual signature over canonical form
    artifact_hash: str        # SHA-256 of artifact content
    timestamp: int            # Unix timestamp of binding creation
    
    def verify(self) -> bool:
        """Cryptographically verify binding integrity."""
        try:
            canonical = self._canonical_form()
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(self.public_key)
            public_key.verify(self.signature, canonical.encode())
            return True
        except Exception:
            return False
    
    def _canonical_form(self) -> str:
        """Deterministic serialization for signing."""
        return json.dumps({
            "artifact_id": self.artifact_id,
            "artifact_hash": self.artifact_hash,
            "jurisdiction_id": self.jurisdiction_id,
            "binding_type": self.binding_type,
            "timestamp": self.timestamp
        }, sort_keys=True, separators=(',', ':'))


@dataclass(frozen=True)
class BoundaryProof:
    """
    A machine-verifiable explanation of why execution was permitted or denied.
    
    Used for auditability and compliance.
    """
    id: str
    artifact_id: str
    source_domain_id: str
    target_domain_id: str
    jurisdiction_id: str
    allowed: bool
    reason: str
    timestamp: int
    evidence: List[str]  # list of hashes or references to logs


class JIBError(Exception):
    """Base exception for JIB errors."""
    pass


class JurisdictionalViolation(JIBError):
    """Raised when a jurisdictional boundary is violated."""
    pass


class InvalidJurisdictionBinding(JIBError):
    """Raised when a binding is invalid."""
    pass


class AmbiguousJurisdiction(JIBError):
    """Raised when jurisdiction resolution is ambiguous."""
    pass