"""
Data provenance and lineage tracking for JIB.
"""

from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
import hashlib
from datetime import datetime


@dataclass(frozen=True)
class ProvenanceNode:
    """Node in provenance graph representing data transformation."""
    
    id: str
    artifact_id: str
    operation: str  # "read", "write", "transform", "transmit"
    jurisdiction_id: str
    timestamp: int
    parent_nodes: List[str]  # IDs of input provenance nodes
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            object.__setattr__(self, 'metadata', {})


class ProvenanceGraph:
    """
    Directed acyclic graph tracking data lineage.
    
    Properties:
    - Acyclicity: No cycles in data flow
    - Completeness: All operations recorded
    - Cross-boundary visibility: Track all jurisdiction crossings
    - Taint propagation: Track sensitive data flow
    """
    
    def __init__(self):
        self.nodes: Dict[str, ProvenanceNode] = {}
        self.edges: Dict[str, List[str]] = {}  # parent -> children
    
    def add_node(self, node: ProvenanceNode):
        """Add provenance node to graph."""
        self.nodes[node.id] = node
        for parent_id in node.parent_nodes:
            if parent_id not in self.edges:
                self.edges[parent_id] = []
            self.edges[parent_id].append(node.id)
    
    def trace_lineage(self, node_id: str) -> List[ProvenanceNode]:
        """Trace full lineage back to source."""
        lineage = []
        visited = set()
        
        def dfs(current_id: str):
            if current_id in visited:
                return
            visited.add(current_id)
            
            if current_id in self.nodes:
                node = self.nodes[current_id]
                lineage.append(node)
                for parent_id in node.parent_nodes:
                    dfs(parent_id)
        
        dfs(node_id)
        return lineage
    
    def find_boundary_crossings(self, node_id: str) -> List[Tuple[str, str]]:
        """Find all jurisdiction boundary crossings in lineage."""
        lineage = self.trace_lineage(node_id)
        crossings = []
        
        for i in range(len(lineage) - 1):
            current_jid = lineage[i].jurisdiction_id
            next_jid = lineage[i + 1].jurisdiction_id
            if current_jid != next_jid:
                crossings.append((current_jid, next_jid))
        
        return crossings
    
    def check_taint_propagation(
        self,
        source_node_id: str,
        target_node_id: str,
        taint_label: str
    ) -> bool:
        """
        Check if taint from source propagates to target.
        
        In a real implementation, this would perform actual taint analysis.
        """
        # Simplified implementation - in practice would be more complex
        lineage = self.trace_lineage(target_node_id)
        
        # Check if source is in the lineage
        for node in lineage:
            if node.id == source_node_id:
                return True
        
        return False
    
    def get_jurisdiction_summary(self, node_id: str) -> Dict[str, int]:
        """Get summary of jurisdictions involved in lineage."""
        lineage = self.trace_lineage(node_id)
        jurisdiction_counts = {}
        
        for node in lineage:
            jurisdiction_counts[node.jurisdiction_id] = \
                jurisdiction_counts.get(node.jurisdiction_id, 0) + 1
        
        return jurisdiction_counts
    
    def validate_acyclicity(self) -> bool:
        """Validate that the graph is acyclic."""
        # Simple cycle detection using DFS
        visited = set()
        rec_stack = set()
        
        def dfs(node_id: str) -> bool:
            if node_id not in self.nodes:
                return True
            
            if node_id in rec_stack:
                return False  # Cycle detected
            
            if node_id in visited:
                return True  # Already processed
            
            visited.add(node_id)
            rec_stack.add(node_id)
            
            # Check all children
            for child_id in self.edges.get(node_id, []):
                if not dfs(child_id):
                    return False
            
            rec_stack.remove(node_id)
            return True
        
        # Check all nodes
        for node_id in self.nodes:
            if node_id not in visited:
                if not dfs(node_id):
                    return False
        
        return True


class DataFlowTracker:
    """
    Tracks data flows across jurisdictional boundaries.
    
    Provides audit-ready information about data movement.
    """
    
    def __init__(self):
        self.graph = ProvenanceGraph()
        self.flow_records: List[Dict[str, Any]] = []
    
    def record_data_flow(
        self,
        artifact_id: str,
        operation: str,
        source_jurisdiction: str,
        target_jurisdiction: str,
        timestamp: Optional[int] = None
    ):
        """Record a data flow event."""
        if timestamp is None:
            timestamp = int(datetime.now().timestamp())
        
        # Create provenance node for this operation
        node_id = hashlib.sha256(
            f"{artifact_id}:{operation}:{source_jurisdiction}:{target_jurisdiction}:{timestamp}".encode()
        ).hexdigest()
        
        node = ProvenanceNode(
            id=node_id,
            artifact_id=artifact_id,
            operation=operation,
            jurisdiction_id=source_jurisdiction,
            timestamp=timestamp,
            parent_nodes=[],  # No parents for initial flow
            metadata={
                "target_jurisdiction": target_jurisdiction,
                "flow_type": "cross_boundary" if source_jurisdiction != target_jurisdiction else "intra_boundary"
            }
        )
        
        self.graph.add_node(node)
        
        # Record the flow
        flow_record = {
            "node_id": node_id,
            "artifact_id": artifact_id,
            "operation": operation,
            "source_jurisdiction": source_jurisdiction,
            "target_jurisdiction": target_jurisdiction,
            "timestamp": timestamp,
            "cross_boundary": source_jurisdiction != target_jurisdiction
        }
        
        self.flow_records.append(flow_record)
    
    def get_cross_boundary_flows(self) -> List[Dict[str, Any]]:
        """Get all cross-boundary data flows."""
        return [record for record in self.flow_records if record["cross_boundary"]]
    
    def get_flow_summary(self) -> Dict[str, Any]:
        """Get summary of all recorded flows."""
        total_flows = len(self.flow_records)
        cross_boundary_flows = len(self.get_cross_boundary_flows())
        
        return {
            "total_flows": total_flows,
            "cross_boundary_flows": cross_boundary_flows,
            "intra_boundary_flows": total_flows - cross_boundary_flows
        }
    
    def audit_compliance(self, jurisdiction_id: str) -> List[Dict[str, Any]]:
        """
        Audit compliance for a specific jurisdiction.
        
        Returns list of flows that involve this jurisdiction.
        """
        relevant_flows = []
        
        for record in self.flow_records:
            if (record["source_jurisdiction"] == jurisdiction_id or
                record["target_jurisdiction"] == jurisdiction_id):
                relevant_flows.append(record)
        
        return relevant_flows


# Example usage
def example_provenance_usage():
    """Demonstrate provenance tracking."""
    
    tracker = DataFlowTracker()
    
    # Record some data flows
    tracker.record_data_flow("model-x", "read", "us-ca", "us-tx")
    tracker.record_data_flow("model-x", "transform", "us-tx", "us-ca")
    tracker.record_data_flow("model-y", "write", "us-ca", "us-ca")  # Intra-boundary
    
    # Get summary
    summary = tracker.get_flow_summary()
    print(f"Flow Summary: {summary}")
    
    # Get cross-boundary flows
    cross_boundary = tracker.get_cross_boundary_flows()
    print(f"Cross-boundary flows: {len(cross_boundary)}")
    
    # Audit compliance for us-ca
    audit_results = tracker.audit_compliance("us-ca")
    print(f"Audit results for us-ca: {len(audit_results)} flows")


if __name__ == "__main__":
    example_provenance_usage()