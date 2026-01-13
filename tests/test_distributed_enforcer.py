"""
Tests for distributed enforcer components.
"""

import pytest
from jib.core.distributed_enforcer import (
    DistributedBoundaryEnforcer,
    GossipProtocol,
    PartitionDetector,
    CRDTManager
)
import asyncio


def test_distributed_enforcer():
    """Test basic distributed enforcer functionality."""
    
    # Create a simple distributed enforcer
    peers = {"node-1", "node-2", "node-3"}
    enforcer = DistributedBoundaryEnforcer("node-1", peers)
    
    # Test quorum calculation
    votes = {"node-1": True, "node-2": True, "node-3": False}
    assert enforcer._has_quorum(votes) is True  # 3 nodes, f=0, quorum=1
    
    # Test decision computation
    decision = enforcer._compute_decision(votes)
    assert decision is False  # Fail closed - not all agree


def test_gossip_protocol():
    """Test gossip protocol."""
    
    peers = {"node-1", "node-2", "node-3"}
    gossip = GossipProtocol("node-1", peers)
    
    # Test state synchronization
    test_state = {"boundaries": ["boundary-1"], "jurisdictions": ["us-ca"]}
    gossip.state.update(test_state)
    
    # Simulate receiving gossip
    message = {"state": {"boundaries": ["boundary-2"]}}
    asyncio.run(gossip.receive_gossip(message))
    
    # Test sync
    gossip.sync_state()
    assert "boundary-2" in gossip.state["boundaries"]


def test_partition_detector():
    """Test partition detector."""
    
    detector = PartitionDetector()
    
    # Record heartbeats
    detector.record_heartbeat("node-1")
    detector.record_heartbeat("node-2")
    
    # Test partition detection
    assert detector.is_partitioned("node-1") is False
    assert detector.is_partitioned("node-2") is False
    
    # Simulate node going offline
    import time
    time.sleep(35)  # Wait longer than timeout
    
    # Should now be considered partitioned
    assert detector.is_partitioned("node-1") is True


def test_crdt_manager():
    """Test CRDT manager."""
    
    crdt = CRDTManager()
    
    # Test boundary updates
    boundary_data = {
        "id": "boundary-1",
        "source": "us-ca",
        "target": "us-tx",
        "allowed": True
    }
    
    crdt.update_boundary("boundary-1", boundary_data)
    
    # Retrieve boundary
    retrieved = crdt.get_boundary("boundary-1")
    assert retrieved is not None
    assert retrieved["id"] == "boundary-1"
    
    # Test merge
    other_crdt = CRDTManager()
    other_boundary = {
        "id": "boundary-2",
        "source": "us-nv",
        "target": "us-ca",
        "allowed": False
    }
    other_crdt.update_boundary("boundary-2", other_boundary)
    
    crdt.merge_state(other_crdt)
    assert crdt.get_boundary("boundary-2") is not None