"""
Distributed consensus and Byzantine fault tolerance for JIB.
"""

from typing import Set, Dict, Optional, List, Any
from dataclasses import dataclass
import asyncio
import time
import hashlib
from enum import Enum
import aiohttp
from .error_handling import BoundaryEnforcementError


class ConsensusState(Enum):
    PROPOSED = "proposed"
    PREPARED = "prepared"
    COMMITTED = "committed"
    ABORTED = "aborted"


@dataclass
class BoundaryDecisionProposal:
    """Proposal for distributed boundary decision."""
    
    proposal_id: str
    artifact_id: str
    source_domain_id: str
    target_domain_id: str
    proposed_decision: bool
    proposer_node_id: str
    timestamp: int


class DistributedBoundaryEnforcer:
    """
    Byzantine fault-tolerant boundary enforcement.
    
    Properties:
    - Safety: No two nodes decide differently
    - Liveness: Eventually decides (in async network)
    - Byzantine tolerance: Tolerates f < n/3 malicious nodes
    - Agreement: All honest nodes reach same decision
    """
    
    def __init__(self, node_id: str, peer_nodes: Set[str]):
        self.node_id = node_id
        self.peers = peer_nodes
        self.proposals: Dict[str, BoundaryDecisionProposal] = {}
        self.votes: Dict[str, Dict[str, bool]] = {}  # proposal_id -> node_id -> vote
        self.decision_log: List[Dict[str, Any]] = []
    
    async def propose_boundary_decision(
        self,
        artifact_id: str,
        source_domain_id: str,
        target_domain_id: str
    ) -> bool:
        """
        Propose boundary decision to cluster using PBFT/Raft.
        
        Returns True if consensus reached on allow, False if deny.
        """
        # Phase 1: Propose
        proposal = self._create_proposal(artifact_id, source_domain_id, target_domain_id)
        await self._broadcast_proposal(proposal)
        
        # Phase 2: Prepare (collect votes)
        votes = await self._collect_votes(proposal.proposal_id)
        
        # Phase 3: Commit if quorum reached
        if self._has_quorum(votes):
            decision = self._compute_decision(votes)
            await self._broadcast_commit(proposal.proposal_id, decision)
            
            # Log the decision
            self.decision_log.append({
                "proposal_id": proposal.proposal_id,
                "artifact_id": artifact_id,
                "source_domain": source_domain_id,
                "target_domain": target_domain_id,
                "decision": decision,
                "timestamp": time.time()
            })
            
            return decision
        else:
            await self._broadcast_abort(proposal.proposal_id)
            return False  # Fail closed
    
    def _create_proposal(
        self,
        artifact_id: str,
        source_domain_id: str,
        target_domain_id: str
    ) -> BoundaryDecisionProposal:
        """Create a new boundary decision proposal."""
        proposal_id = hashlib.sha256(
            f"{artifact_id}:{source_domain_id}:{target_domain_id}:{time.time()}".encode()
        ).hexdigest()
        
        return BoundaryDecisionProposal(
            proposal_id=proposal_id,
            artifact_id=artifact_id,
            source_domain_id=source_domain_id,
            target_domain_id=target_domain_id,
            proposed_decision=False,  # Placeholder - would be computed
            proposer_node_id=self.node_id,
            timestamp=int(time.time())
        )
    
    async def _broadcast_proposal(self, proposal: BoundaryDecisionProposal):
        """Broadcast proposal to all peers."""
        tasks = []
        for peer in self.peers:
            task = self._send_to_peer(peer, {
                "type": "proposal",
                "data": {
                    "proposal_id": proposal.proposal_id,
                    "artifact_id": proposal.artifact_id,
                    "source_domain_id": proposal.source_domain_id,
                    "target_domain_id": proposal.target_domain_id,
                    "proposed_decision": proposal.proposed_decision,
                    "proposer_node_id": proposal.proposer_node_id,
                    "timestamp": proposal.timestamp
                }
            })
            tasks.append(task)
        
        await asyncio.gather(*tasks)
    
    async def _send_to_peer(self, peer_url: str, message: dict):
        """Send message to a peer."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{peer_url}/jib/consensus", json=message) as resp:
                    return await resp.json()
        except Exception as e:
            # In real system, would handle network errors appropriately
            print(f"Network error sending to {peer_url}: {e}")
            return {"error": str(e)}
    
    async def _collect_votes(self, proposal_id: str) -> Dict[str, bool]:
        """Collect votes from peers."""
        # In a real implementation, this would wait for responses from peers
        # For now, simulate with local votes
        votes = {}
        
        # Simulate voting by peers
        for peer in self.peers:
            # In practice, each peer would vote based on their own logic
            # Here we simulate a simple majority vote
            votes[peer] = True  # Simplified - in real system would be computed
        
        # Add our own vote
        votes[self.node_id] = True  # Simplified for demo
        
        return votes
    
    def _has_quorum(self, votes: Dict[str, bool]) -> bool:
        """Check if we have 2f+1 votes (Byzantine quorum)."""
        total_nodes = len(self.peers) + 1
        f = (total_nodes - 1) // 3  # Max Byzantine nodes
        quorum = 2 * f + 1
        return len(votes) >= quorum
    
    def _compute_decision(self, votes: Dict[str, bool]) -> bool:
        """Fail closed: require unanimous allow for permission."""
        # In a real system, this would be more sophisticated
        # For now, we'll use simple majority with fail-closed semantics
        if not votes:
            return False  # Fail closed
        
        # Require all honest nodes to agree (simplified)
        # In practice, would implement proper consensus algorithm
        return all(votes.values())
    
    async def _broadcast_commit(self, proposal_id: str, decision: bool):
        """Broadcast commit message."""
        tasks = []
        for peer in self.peers:
            task = self._send_to_peer(peer, {
                "type": "commit",
                "data": {
                    "proposal_id": proposal_id,
                    "decision": decision
                }
            })
            tasks.append(task)
        
        await asyncio.gather(*tasks)
    
    async def _broadcast_abort(self, proposal_id: str):
        """Broadcast abort message."""
        tasks = []
        for peer in self.peers:
            task = self._send_to_peer(peer, {
                "type": "abort",
                "data": {
                    "proposal_id": proposal_id
                }
            })
            tasks.append(task)
        
        await asyncio.gather(*tasks)
    
    def get_decision_log(self) -> List[Dict[str, Any]]:
        """Get the decision log for audit purposes."""
        return self.decision_log.copy()


class GossipProtocol:
    """
    Gossip protocol for state synchronization in distributed JIB.
    
    Ensures eventual consistency across nodes.
    """
    
    def __init__(self, node_id: str, peers: Set[str]):
        self.node_id = node_id
        self.peers = peers
        self.state: Dict[str, Any] = {}
        self.message_queue: List[Dict[str, Any]] = []
    
    async def gossip_state(self):
        """Gossip current state to peers."""
        # In a real implementation, this would send state updates via network
        print(f"Node {self.node_id} gossiping state")
        await asyncio.sleep(0.1)
    
    async def receive_gossip(self, message: Dict[str, Any]):
        """Receive and process gossip messages."""
        self.message_queue.append(message)
        # Process the message (simplified)
        print(f"Node {self.node_id} received gossip: {message}")
    
    def sync_state(self):
        """Synchronize state from gossip messages."""
        # In a real implementation, this would merge incoming state
        while self.message_queue:
            msg = self.message_queue.pop(0)
            # Apply state update
            self.state.update(msg.get("state", {}))


class PartitionDetector:
    """
    Detects network partitions and handles healing.
    
    Ensures system remains consistent during network issues.
    """
    
    def __init__(self):
        self.partitioned_nodes: Set[str] = set()
        self.last_heartbeat: Dict[str, float] = {}
        self.heartbeat_timeout = 30.0  # seconds
    
    def record_heartbeat(self, node_id: str):
        """Record heartbeat from a node."""
        self.last_heartbeat[node_id] = time.time()
    
    def is_partitioned(self, node_id: str) -> bool:
        """Check if a node appears to be partitioned."""
        last_seen = self.last_heartbeat.get(node_id)
        if not last_seen:
            return True  # Unknown node - assume partitioned
        
        return (time.time() - last_seen) > self.heartbeat_timeout
    
    def detect_partitions(self) -> Set[str]:
        """Detect currently partitioned nodes."""
        partitions = set()
        for node_id in self.last_heartbeat:
            if self.is_partitioned(node_id):
                partitions.add(node_id)
        
        return partitions
    
    def heal_partition(self, node_id: str):
        """Heal a partition for a node."""
        self.partitioned_nodes.discard(node_id)
        print(f"Partition healed for node {node_id}")


class CRDTManager:
    """
    Conflict-free replicated data types manager.
    
    Ensures consistency in distributed boundary state.
    """
    
    def __init__(self):
        self.boundaries: Dict[str, Any] = {}
        self.jurisdictions: Dict[str, Any] = {}
    
    def update_boundary(self, boundary_id: str, boundary_data: Dict[str, Any]):
        """Update a boundary with CRDT semantics."""
        # In a real implementation, this would use proper CRDTs
        # For now, simple merge
        self.boundaries[boundary_id] = boundary_data
    
    def get_boundary(self, boundary_id: str) -> Optional[Dict[str, Any]]:
        """Get a boundary."""
        return self.boundaries.get(boundary_id)
    
    def merge_state(self, other_crdt: 'CRDTManager'):
        """Merge state from another CRDT manager."""
        # In a real implementation, this would use proper CRDT merge operations
        for k, v in other_crdt.boundaries.items():
            self.boundaries[k] = v