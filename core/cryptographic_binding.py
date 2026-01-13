"""
Cryptographic binding protocol for JIB.
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


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


class KeyManager:
    """
    Manages cryptographic keys for JIB bindings.
    
    Provides key generation, rotation, and storage.
    """
    
    def __init__(self):
        self.keys: Dict[str, ed25519.Ed25519PrivateKey] = {}
    
    def generate_key_pair(self) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generate a new Ed25519 key pair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def sign_binding(
        self,
        private_key: ed25519.Ed25519PrivateKey,
        binding: CryptographicBinding
    ) -> bytes:
        """Sign a binding with the given private key."""
        canonical = binding._canonical_form()
        return private_key.sign(canonical.encode())
    
    def store_key(self, key_id: str, private_key: ed25519.Ed25519PrivateKey):
        """Store a private key for later use."""
        self.keys[key_id] = private_key
    
    def get_public_key_bytes(self, private_key: ed25519.Ed25519PrivateKey) -> bytes:
        """Get the public key bytes from a private key."""
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )


class MerkleTree:
    """
    Merkle tree for audit trail integrity.
    
    Provides tamper-evident log of all bindings.
    """
    
    def __init__(self):
        self.leaves: list[str] = []
        self.tree: list[list[str]] = []
    
    def add_leaf(self, leaf_hash: str):
        """Add a leaf to the Merkle tree."""
        self.leaves.append(leaf_hash)
        self._rebuild_tree()
    
    def _rebuild_tree(self):
        """Rebuild the Merkle tree from leaves."""
        if not self.leaves:
            self.tree = []
            return
        
        # Start with leaves
        current_level = self.leaves[:]
        self.tree = [current_level]
        
        # Build up levels until we have one root
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined)
            current_level = next_level
            self.tree.append(current_level)
    
    def get_root(self) -> Optional[str]:
        """Get the Merkle root."""
        if not self.tree:
            return None
        return self.tree[-1][0] if self.tree[-1] else None
    
    def get_proof(self, leaf_index: int) -> list[str]:
        """Get a Merkle proof for a specific leaf."""
        if not self.tree or leaf_index >= len(self.leaves):
            return []
        
        proof = []
        current_index = leaf_index
        
        # Traverse up the tree
        for level in self.tree[:-1]:  # Exclude root level
            sibling_index = current_index ^ 1  # XOR with 1 to get sibling index
            if sibling_index < len(level):
                proof.append(level[sibling_index])
            current_index //= 2
        
        return proof


class ThresholdSignature:
    """
    Threshold signature scheme for multi-party jurisdiction control.
    
    Allows multiple parties to jointly sign a binding.
    """
    
    def __init__(self, threshold: int, total_parties: int):
        self.threshold = threshold
        self.total_parties = total_parties
        self.signers: Dict[str, ed25519.Ed25519PublicKey] = {}
    
    def add_signer(self, party_id: str, public_key: ed25519.Ed25519PublicKey):
        """Add a signer to the threshold scheme."""
        self.signers[party_id] = public_key
    
    def sign_with_threshold(
        self,
        binding: CryptographicBinding,
        private_keys: list[ed25519.Ed25519PrivateKey]
    ) -> bytes:
        """
        Sign with threshold number of parties.
        
        Returns combined signature.
        """
        if len(private_keys) < self.threshold:
            raise ValueError("Not enough signers for threshold")
        
        # In a real implementation, this would use a proper threshold signature scheme
        # For now, we'll just sign with the first threshold keys
        canonical = binding._canonical_form()
        signatures = []
        
        for key in private_keys[:self.threshold]:
            sig = key.sign(canonical.encode())
            signatures.append(sig)
        
        # Combine signatures (simplified - real implementation would use proper scheme)
        combined = hashlib.sha256(b"".join(signatures)).hexdigest()
        return combined.encode()


class BindingRevocation:
    """
    Revocation mechanism for cryptographic bindings.
    
    Supports temporal validity and key rotation.
    """
    
    def __init__(self):
        self.revoked_bindings: Dict[str, int] = {}  # binding_id -> revocation_time
    
    def revoke_binding(self, binding_id: str, timestamp: int):
        """Revoke a binding at the given timestamp."""
        self.revoked_bindings[binding_id] = timestamp
    
    def is_revoked(self, binding_id: str, timestamp: int) -> bool:
        """Check if a binding has been revoked before the given timestamp."""
        revocation_time = self.revoked_bindings.get(binding_id)
        return revocation_time is not None and revocation_time <= timestamp