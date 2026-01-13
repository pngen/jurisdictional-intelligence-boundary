"""
Tests for cryptographic binding components.
"""

import pytest
from jib.core.cryptographic_binding import (
    CryptographicBinding,
    KeyManager,
    MerkleTree,
    ThresholdSignature,
    BindingRevocation
)
from cryptography.hazmat.primitives.asymmetric import ed25519
import time


def test_cryptographic_binding_verification():
    """Test cryptographic binding verification."""
    
    # Generate key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Create a binding
    binding = CryptographicBinding(
        id="binding-123",
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        binding_type="static",
        signature_algorithm="Ed25519",
        public_key=public_key.public_bytes(
            encoding=public_key.__class__.Encoding.Raw,
            format=public_key.__class__.PublicFormat.Raw
        ),
        signature=b"",  # Will be signed below
        artifact_hash="abc123def456",
        timestamp=int(time.time())
    )
    
    # Sign the binding
    canonical = binding._canonical_form()
    signature = private_key.sign(canonical.encode())
    
    # Update binding with signature
    binding_with_sig = CryptographicBinding(
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
    
    # Verify the signature
    assert binding_with_sig.verify() is True


def test_key_manager():
    """Test key manager functionality."""
    
    km = KeyManager()
    
    # Generate key pair
    private_key, public_key = km.generate_key_pair()
    
    # Test getting public key bytes
    pub_bytes = km.get_public_key_bytes(private_key)
    assert len(pub_bytes) == 32  # Ed25519 public key size


def test_merkle_tree():
    """Test Merkle tree functionality."""
    
    mt = MerkleTree()
    
    # Add some leaves
    leaf1_hash = "hash1"
    leaf2_hash = "hash2"
    leaf3_hash = "hash3"
    
    mt.add_leaf(leaf1_hash)
    mt.add_leaf(leaf2_hash)
    mt.add_leaf(leaf3_hash)
    
    # Get root
    root = mt.get_root()
    assert root is not None
    
    # Get proof for first leaf
    proof = mt.get_proof(0)
    assert isinstance(proof, list)


def test_threshold_signature():
    """Test threshold signature functionality."""
    
    # Create threshold scheme (2-of-3)
    ts = ThresholdSignature(threshold=2, total_parties=3)
    
    # Generate keys for 3 parties
    private_keys = []
    public_keys = []
    
    for i in range(3):
        priv_key, pub_key = ed25519.Ed25519PrivateKey.generate(), None
        private_keys.append(priv_key)
        public_keys.append(priv_key.public_key())
    
    # Add signers to threshold scheme
    for i, pub_key in enumerate(public_keys):
        ts.add_signer(f"party-{i}", pub_key)
    
    # Create binding
    binding = CryptographicBinding(
        id="test-binding",
        artifact_id="model-x",
        jurisdiction_id="us-ca",
        binding_type="static",
        signature_algorithm="Ed25519",
        public_key=public_keys[0].public_bytes(
            encoding=public_keys[0].__class__.Encoding.Raw,
            format=public_keys[0].__class__.PublicFormat.Raw
        ),
        signature=b"",
        artifact_hash="abc123def456",
        timestamp=int(time.time())
    )
    
    # Sign with threshold (should work with 2 keys)
    try:
        signature = ts.sign_with_threshold(binding, private_keys[:2])
        assert isinstance(signature, bytes)
    except Exception as e:
        pytest.fail(f"Threshold signing failed: {e}")


def test_binding_revocation():
    """Test binding revocation."""
    
    revoker = BindingRevocation()
    
    # Revoke a binding
    timestamp = int(time.time())
    revoker.revoke_binding("binding-123", timestamp)
    
    # Check if revoked
    assert revoker.is_revoked("binding-123", timestamp) is True
    assert revoker.is_revoked("binding-123", timestamp - 1) is False
    
    # Check non-revoked binding
    assert revoker.is_revoked("nonexistent", timestamp) is False