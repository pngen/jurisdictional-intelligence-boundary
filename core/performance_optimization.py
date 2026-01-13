"""
Performance and scalability optimizations for JIB.
"""

from typing import Optional, Dict, Any, List
from collections import OrderedDict
import time


class LRUCache:
    """
    LRU Cache implementation for performance optimization.
    
    Used to cache frequently accessed boundaries and proofs.
    """
    
    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self.cache = OrderedDict()
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache."""
        if key not in self.cache:
            return None
        
        # Move to end (most recently used)
        self.cache.move_to_end(key)
        return self.cache[key]
    
    def put(self, key: str, value: Any):
        """Put item in cache."""
        if key in self.cache:
            # Update existing
            self.cache.move_to_end(key)
        elif len(self.cache) >= self.maxsize:
            # Remove least recently used
            self.cache.popitem(last=False)
        
        self.cache[key] = value
    
    def size(self) -> int:
        """Get current cache size."""
        return len(self.cache)


class OptimizedBoundaryEnforcer:
    """
    Performance-optimized enforcer with caching and indexing.
    
    Requirements:
    - O(1) boundary lookup via hash index
    - LRU cache for frequent checks
    - Batch verification for multiple artifacts
    - Lazy proof generation
    - Connection pooling for distributed consensus
    """
    
    def __init__(self):
        self.jurisdictions: Dict[str, Any] = {}
        self.execution_domains: Dict[str, Any] = {}
        self.bound_artifacts: Dict[str, List[Any]] = {}
        self.boundary_index: Dict[tuple, Any] = {}  # source, target -> boundary
        self.proof_cache: LRUCache = LRUCache(maxsize=10000)
        self.binding_cache: LRUCache = LRUCache(maxsize=5000)
        
    def register_jurisdiction(self, jurisdiction: Any):
        """Register a jurisdiction."""
        self.jurisdictions[jurisdiction.id] = jurisdiction
    
    def register_execution_domain(self, domain: Any):
        """Register an execution domain."""
        self.execution_domains[domain.id] = domain
    
    def bind_artifact_to_jurisdiction(
        self,
        artifact_id: str,
        jurisdiction_id: str,
        binding_type: str = "static",
        signature: Optional[str] = None
    ):
        """
        Bind an artifact to a jurisdiction.
        
        Optimized with caching and indexing.
        """
        # Check cache first
        cache_key = f"binding:{artifact_id}:{jurisdiction_id}"
        cached = self.binding_cache.get(cache_key)
        if cached:
            return cached
        
        # Create binding (simplified)
        binding = {
            "id": f"{artifact_id}:{jurisdiction_id}",
            "artifact_id": artifact_id,
            "jurisdiction_id": jurisdiction_id,
            "binding_type": binding_type,
            "signature": signature
        }
        
        # Cache result
        self.binding_cache.put(cache_key, binding)
        
        # Index for fast lookup
        if artifact_id not in self.bound_artifacts:
            self.bound_artifacts[artifact_id] = []
        self.bound_artifacts[artifact_id].append(binding)
        
        return binding
    
    def register_boundary(self, boundary: Any):
        """Register a boundary with O(1) index."""
        key = (boundary.source_jurisdiction_id, boundary.target_jurisdiction_id)
        self.boundary_index[key] = boundary
        # Also store in regular boundaries dict for completeness
        if not hasattr(self, 'boundaries'):
            self.boundaries = {}
        self.boundaries[boundary.id] = boundary
    
    def check_boundary(
        self,
        artifact_id: str,
        source_domain_id: str,
        target_domain_id: str
    ):
        """
        Check boundary with caching.
        
        Optimized for O(1) lookup via index.
        """
        # Create cache key
        cache_key = f"boundary:{artifact_id}:{source_domain_id}:{target_domain_id}"
        
        # Check proof cache first
        cached_proof = self.proof_cache.get(cache_key)
        if cached_proof:
            return cached_proof
        
        # Look up boundary in index
        index_key = (source_domain_id, target_domain_id)
        boundary = self.boundary_index.get(index_key)
        
        # Create and cache proof
        proof = {
            "id": f"proof:{cache_key}",
            "artifact_id": artifact_id,
            "source_domain_id": source_domain_id,
            "target_domain_id": target_domain_id,
            "jurisdiction_id": self.execution_domains.get(source_domain_id, {}).get("jurisdiction_id", ""),
            "allowed": boundary.allowed if boundary else False,
            "reason": boundary.reason if boundary else "No boundary defined",
            "timestamp": int(time.time()),
            "evidence": []
        }
        
        # Cache the proof
        self.proof_cache.put(cache_key, proof)
        
        return proof
    
    def batch_check_boundaries(
        self,
        checks: List[tuple]
    ) -> List[Any]:
        """
        Batch check multiple boundaries.
        
        Optimized for bulk operations.
        """
        results = []
        for artifact_id, source_domain_id, target_domain_id in checks:
            result = self.check_boundary(artifact_id, source_domain_id, target_domain_id)
            results.append(result)
        return results
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "proof_cache_size": self.proof_cache.size(),
            "binding_cache_size": self.binding_cache.size()
        }


class PerformanceMonitor:
    """
    Monitors performance of JIB operations.
    
    Provides metrics for optimization and debugging.
    """
    
    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
        self.operation_counts: Dict[str, int] = {}
    
    def record_operation(self, operation_name: str, duration: float):
        """Record an operation's duration."""
        if operation_name not in self.metrics:
            self.metrics[operation_name] = []
            self.operation_counts[operation_name] = 0
        
        self.metrics[operation_name].append(duration)
        self.operation_counts[operation_name] += 1
    
    def get_average_duration(self, operation_name: str) -> float:
        """Get average duration for an operation."""
        if operation_name not in self.metrics or not self.metrics[operation_name]:
            return 0.0
        
        return sum(self.metrics[operation_name]) / len(self.metrics[operation_name])
    
    def get_operation_count(self, operation_name: str) -> int:
        """Get count of operations performed."""
        return self.operation_counts.get(operation_name, 0)
    
    def reset_metrics(self):
        """Reset all metrics."""
        self.metrics.clear()
        self.operation_counts.clear()


# Example usage
def example_performance_optimization():
    """Demonstrate performance optimizations."""
    
    # Create optimized enforcer
    enforcer = OptimizedBoundaryEnforcer()
    
    # Register some test data
    jurisdiction = {"id": "us-ca", "name": "California"}
    domain = {"id": "prod-us-west", "jurisdiction_id": "us-ca"}
    
    enforcer.register_jurisdiction(jurisdiction)
    enforcer.register_execution_domain(domain)
    
    # Bind artifact
    binding = enforcer.bind_artifact_to_jurisdiction("model-x", "us-ca")
    print(f"Binding created: {binding}")
    
    # Check boundary multiple times (should use cache)
    start_time = time.time()
    for i in range(10):
        proof = enforcer.check_boundary("model-x", "prod-us-west", "dev-us-east")
    end_time = time.time()
    
    print(f"10 boundary checks took {end_time - start_time:.4f} seconds")
    print(f"Cache stats: {enforcer.get_cache_stats()}")


if __name__ == "__main__":
    example_performance_optimization()