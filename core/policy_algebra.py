"""
Advanced boundary composition and policy algebra for JIB.
"""

from typing import Optional, List, Dict, Any, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass


class BoundaryExpression(ABC):
    """Abstract base for composable boundary expressions."""
    
    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate boundary expression in context."""
        pass
    
    def __and__(self, other: 'BoundaryExpression') -> 'BoundaryExpression':
        """Logical AND composition."""
        return AndBoundary(self, other)
    
    def __or__(self, other: 'BoundaryExpression') -> 'BoundaryExpression':
        """Logical OR composition."""
        return OrBoundary(self, other)
    
    def __invert__(self) -> 'BoundaryExpression':
        """Logical NOT."""
        return NotBoundary(self)


class AtomicBoundary(BoundaryExpression):
    """Primitive boundary rule."""
    
    def __init__(self, boundary_id: str, allowed: bool = True):
        self.boundary_id = boundary_id
        self.allowed = allowed
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        # In a real implementation, this would look up the actual boundary
        # For now, we'll simulate with a simple lookup
        return self.allowed


class AndBoundary(BoundaryExpression):
    """Conjunction of two boundaries."""
    
    def __init__(self, left: BoundaryExpression, right: BoundaryExpression):
        self.left = left
        self.right = right
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        return self.left.evaluate(context) and self.right.evaluate(context)


class OrBoundary(BoundaryExpression):
    """Disjunction of two boundaries."""
    
    def __init__(self, left: BoundaryExpression, right: BoundaryExpression):
        self.left = left
        self.right = right
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        return self.left.evaluate(context) or self.right.evaluate(context)


class NotBoundary(BoundaryExpression):
    """Negation of a boundary."""
    
    def __init__(self, expr: BoundaryExpression):
        self.expr = expr
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        return not self.expr.evaluate(context)


class PolicyNode:
    """
    Node in policy tree for hierarchical policy management.
    
    Supports inheritance and versioning.
    """
    
    def __init__(
        self,
        id: str,
        name: str,
        expression: BoundaryExpression,
        parent_id: Optional[str] = None,
        version: str = "1.0"
    ):
        self.id = id
        self.name = name
        self.expression = expression
        self.parent_id = parent_id
        self.version = version
        self.children: List[PolicyNode] = []
    
    def add_child(self, child: 'PolicyNode'):
        """Add a child policy node."""
        self.children.append(child)
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate this policy and all children."""
        result = self.expression.evaluate(context)
        
        # If this is an AND policy, all children must also be true
        if isinstance(self.expression, AndBoundary):
            for child in self.children:
                if not child.evaluate(context):
                    return False
        
        return result


class PolicyManager:
    """
    Manages hierarchical policies and policy composition.
    
    Supports versioning, inheritance, and conflict detection.
    """
    
    def __init__(self):
        self.policies: Dict[str, PolicyNode] = {}
        self.policy_tree: Dict[str, List[str]] = {}  # parent -> children
    
    def add_policy(self, policy: PolicyNode):
        """Add a policy to the manager."""
        self.policies[policy.id] = policy
        
        if policy.parent_id:
            if policy.parent_id not in self.policy_tree:
                self.policy_tree[policy.parent_id] = []
            self.policy_tree[policy.parent_id].append(policy.id)
    
    def evaluate_policy(self, policy_id: str, context: Dict[str, Any]) -> bool:
        """Evaluate a specific policy."""
        policy = self.policies.get(policy_id)
        if not policy:
            return False  # Policy not found
        
        return policy.evaluate(context)
    
    def get_policy_tree(self) -> Dict[str, List[str]]:
        """Get the policy hierarchy tree."""
        return self.policy_tree.copy()
    
    def find_conflicts(self) -> List[Dict[str, Any]]:
        """Find conflicting policies in the system."""
        conflicts = []
        
        # Simple conflict detection - check for overlapping boundaries
        # In a real implementation, this would be more sophisticated
        
        return conflicts
    
    def normalize_policy(self, policy_id: str) -> BoundaryExpression:
        """
        Normalize a policy to canonical form (CNF/DNF).
        
        Returns the normalized expression.
        """
        policy = self.policies.get(policy_id)
        if not policy:
            return AtomicBoundary("unknown", False)
        
        # In a real implementation, this would convert to normal form
        # For now, just return the original
        return policy.expression


class PolicySimulator:
    """
    Simulates policy evaluation for testing and validation.
    
    Provides tools for policy testing and debugging.
    """
    
    def __init__(self):
        self.test_cases: List[Dict[str, Any]] = []
    
    def add_test_case(self, context: Dict[str, Any], expected_result: bool):
        """Add a test case for policy evaluation."""
        self.test_cases.append({
            "context": context,
            "expected": expected_result
        })
    
    def run_simulation(self, policy: BoundaryExpression) -> List[Dict[str, Any]]:
        """Run simulation of policy evaluation."""
        results = []
        
        for i, test_case in enumerate(self.test_cases):
            context = test_case["context"]
            expected = test_case["expected"]
            
            try:
                actual = policy.evaluate(context)
                passed = actual == expected
                results.append({
                    "test_id": i,
                    "context": context,
                    "expected": expected,
                    "actual": actual,
                    "passed": passed
                })
            except Exception as e:
                results.append({
                    "test_id": i,
                    "context": context,
                    "error": str(e),
                    "passed": False
                })
        
        return results


# Example usage of policy algebra
def example_policy_usage():
    """Demonstrate usage of policy algebra."""
    
    # Create simple boundaries
    boundary_a = AtomicBoundary("boundary_a", True)
    boundary_b = AtomicBoundary("boundary_b", False)
    boundary_c = AtomicBoundary("boundary_c", True)
    
    # Compose policies
    policy1 = boundary_a & boundary_b  # A AND B
    policy2 = boundary_a | boundary_b  # A OR B
    policy3 = ~boundary_a              # NOT A
    
    # Complex composition
    complex_policy = (boundary_a & boundary_b) | (~boundary_c)
    
    # Test contexts
    context1 = {"artifact": "model-x", "jurisdiction": "us-ca"}
    context2 = {"artifact": "model-y", "jurisdiction": "us-tx"}
    
    print("Policy evaluation results:")
    print(f"policy1 (A AND B): {policy1.evaluate(context1)}")
    print(f"policy2 (A OR B): {policy2.evaluate(context1)}")
    print(f"policy3 (NOT A): {policy3.evaluate(context1)}")
    print(f"complex_policy: {complex_policy.evaluate(context1)}")


# Run example if this file is executed directly
if __name__ == "__main__":
    example_policy_usage()