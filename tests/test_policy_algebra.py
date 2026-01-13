"""
Tests for policy algebra components.
"""

import pytest
from jib.core.policy_algebra import (
    AtomicBoundary,
    AndBoundary,
    OrBoundary,
    NotBoundary,
    PolicyNode,
    PolicyManager,
    PolicySimulator
)


def test_atomic_boundary():
    """Test atomic boundary evaluation."""
    
    # Test allowed boundary
    allowed = AtomicBoundary("boundary-1", True)
    assert allowed.evaluate({}) is True
    
    # Test denied boundary
    denied = AtomicBoundary("boundary-2", False)
    assert denied.evaluate({}) is False


def test_boundary_composition():
    """Test boundary composition operators."""
    
    # Create simple boundaries
    a = AtomicBoundary("a", True)
    b = AtomicBoundary("b", False)
    c = AtomicBoundary("c", True)
    
    # Test AND
    and_result = a & b
    assert and_result.evaluate({}) is False  # True AND False = False
    
    # Test OR
    or_result = a | b
    assert or_result.evaluate({}) is True   # True OR False = True
    
    # Test NOT
    not_result = ~a
    assert not_result.evaluate({}) is False  # NOT True = False


def test_complex_composition():
    """Test complex boundary composition."""
    
    # Create boundaries
    a = AtomicBoundary("a", True)
    b = AtomicBoundary("b", False)
    c = AtomicBoundary("c", True)
    
    # Complex expression: (A AND B) OR (NOT C)
    complex_expr = (a & b) | (~c)
    
    # Should be False OR False = False
    assert complex_expr.evaluate({}) is False


def test_policy_node():
    """Test policy node functionality."""
    
    # Create a simple policy node
    expr = AtomicBoundary("test-boundary", True)
    node = PolicyNode(
        id="policy-1",
        name="Test Policy",
        expression=expr
    )
    
    # Evaluate the policy
    result = node.evaluate({})
    assert result is True


def test_policy_manager():
    """Test policy manager functionality."""
    
    manager = PolicyManager()
    
    # Create policies
    boundary_a = AtomicBoundary("a", True)
    boundary_b = AtomicBoundary("b", False)
    
    policy_a = PolicyNode("policy-a", "Policy A", boundary_a)
    policy_b = PolicyNode("policy-b", "Policy B", boundary_b)
    
    # Add policies to manager
    manager.add_policy(policy_a)
    manager.add_policy(policy_b)
    
    # Evaluate policies
    result_a = manager.evaluate_policy("policy-a", {})
    result_b = manager.evaluate_policy("policy-b", {})
    
    assert result_a is True
    assert result_b is False


def test_policy_simulation():
    """Test policy simulator."""
    
    simulator = PolicySimulator()
    
    # Create a simple policy
    policy = AtomicBoundary("test", True)
    
    # Add test cases
    simulator.add_test_case({"artifact": "model-x"}, True)
    simulator.add_test_case({"artifact": "model-y"}, False)
    
    # Run simulation
    results = simulator.run_simulation(policy)
    
    assert len(results) == 2
    assert results[0]["expected"] is True
    assert results[1]["expected"] is False


def test_policy_conflict_detection():
    """Test policy conflict detection."""
    
    manager = PolicyManager()
    
    # Add some policies (simplified for testing)
    boundary_a = AtomicBoundary("a", True)
    policy_a = PolicyNode("policy-a", "Policy A", boundary_a)
    
    manager.add_policy(policy_a)
    
    # Find conflicts (should be empty in simple case)
    conflicts = manager.find_conflicts()
    assert len(conflicts) == 0