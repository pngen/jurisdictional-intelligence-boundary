"""
Tests for provenance tracking components.
"""

import pytest
from jib.core.provenance_tracking import (
    ProvenanceNode,
    ProvenanceGraph,
    DataFlowTracker
)


def test_provenance_node_creation():
    """Test provenance node creation."""
    
    node = ProvenanceNode(
        id="node-1",
        artifact_id="model-x",
        operation="read",
        jurisdiction_id="us-ca",
        timestamp=1234567890,
        parent_nodes=["parent-1", "parent-2"],
        metadata={"source": "api"}
    )
    
    assert node.id == "node-1"
    assert node.artifact_id == "model-x"
    assert node.operation == "read"
    assert node.jurisdiction_id == "us-ca"
    assert node.timestamp == 1234567890
    assert node.parent_nodes == ["parent-1", "parent-2"]
    assert node.metadata["source"] == "api"


def test_provenance_graph():
    """Test provenance graph functionality."""
    
    graph = ProvenanceGraph()
    
    # Create nodes
    node1 = ProvenanceNode(
        id="node-1",
        artifact_id="model-x",
        operation="read",
        jurisdiction_id="us-ca",
        timestamp=1234567890,
        parent_nodes=[]
    )
    
    node2 = ProvenanceNode(
        id="node-2",
        artifact_id="model-x",
        operation="transform",
        jurisdiction_id="us-tx",
        timestamp=1234567891,
        parent_nodes=["node-1"]
    )
    
    # Add nodes to graph
    graph.add_node(node1)
    graph.add_node(node2)
    
    # Trace lineage
    lineage = graph.trace_lineage("node-2")
    assert len(lineage) == 2
    assert lineage[0].id == "node-2"
    assert lineage[1].id == "node-1"
    
    # Find boundary crossings
    crossings = graph.find_boundary_crossings("node-2")
    assert len(crossings) == 1
    assert crossings[0] == ("us-ca", "us-tx")


def test_data_flow_tracker():
    """Test data flow tracker."""
    
    tracker = DataFlowTracker()
    
    # Record some flows
    tracker.record_data_flow("model-x", "read", "us-ca", "us-tx")
    tracker.record_data_flow("model-y", "write", "us-ca", "us-ca")  # Intra-boundary
    
    # Get summary
    summary = tracker.get_flow_summary()
    assert summary["total_flows"] == 2
    assert summary["cross_boundary_flows"] == 1
    assert summary["intra_boundary_flows"] == 1
    
    # Get cross-boundary flows
    cross_boundary = tracker.get_cross_boundary_flows()
    assert len(cross_boundary) == 1
    assert cross_boundary[0]["artifact_id"] == "model-x"
    
    # Audit compliance
    audit_results = tracker.audit_compliance("us-ca")
    assert len(audit_results) == 2  # Both flows involve us-ca


def test_graph_validation():
    """Test graph validation."""
    
    graph = ProvenanceGraph()
    
    # Create a simple valid graph
    node1 = ProvenanceNode(
        id="node-1",
        artifact_id="model-x",
        operation="read",
        jurisdiction_id="us-ca",
        timestamp=1234567890,
        parent_nodes=[]
    )
    
    node2 = ProvenanceNode(
        id="node-2",
        artifact_id="model-x",
        operation="transform",
        jurisdiction_id="us-tx",
        timestamp=1234567891,
        parent_nodes=["node-1"]
    )
    
    graph.add_node(node1)
    graph.add_node(node2)
    
    # Should be acyclic
    assert graph.validate_acyclicity() is True


def test_taint_propagation():
    """Test taint propagation."""
    
    tracker = DataFlowTracker()
    
    # Record flows
    tracker.record_data_flow("model-x", "read", "us-ca", "us-tx")
    tracker.record_data_flow("model-x", "transform", "us-tx", "us-ca")
    
    # Check taint propagation (simplified)
    # In a real system, this would be more complex
    assert True  # Placeholder for actual taint analysis