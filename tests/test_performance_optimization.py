"""
Tests for performance optimization components.
"""

import pytest
from jib.core.performance_optimization import (
    LRUCache,
    OptimizedBoundaryEnforcer,
    PerformanceMonitor
)
import time


def test_lru_cache():
    """Test LRU cache functionality."""
    
    cache = LRUCache(maxsize=3)
    
    # Add items
    cache.put("key1", "value1")
    cache.put("key2", "value2")
    cache.put("key3", "value3")
    
    # Check retrieval
    assert cache.get("key1") == "value1"
    assert cache.get("key2") == "value2"
    assert cache.get("key3") == "value3"
    
    # Add one more - should evict oldest (key1)
    cache.put("key4", "value4")
    
    # key1 should be gone
    assert cache.get("key1") is None
    assert cache.get("key2") == "value2"
    assert cache.get("key3") == "value3"
    assert cache.get("key4") == "value4"
    
    # Check size
    assert cache.size() == 3


def test_optimized_enforcer():
    """Test optimized boundary enforcer."""
    
    enforcer = OptimizedBoundaryEnforcer()
    
    # Test binding caching
    binding1 = enforcer.bind_artifact_to_jurisdiction("model-x", "us-ca")
    binding2 = enforcer.bind_artifact_to_jurisdiction("model-x", "us-ca")
    
    # Should be same object due to caching
    assert binding1 is binding2
    
    # Test cache stats
    stats = enforcer.get_cache_stats()
    assert stats["binding_cache_size"] == 1
    assert stats["proof_cache_size"] == 0


def test_performance_monitor():
    """Test performance monitor."""
    
    monitor = PerformanceMonitor()
    
    # Record operations
    monitor.record_operation("check_boundary", 0.005)
    monitor.record_operation("check_boundary", 0.003)
    monitor.record_operation("bind_artifact", 0.01)
    
    # Check metrics
    avg_boundary = monitor.get_average_duration("check_boundary")
    assert abs(avg_boundary - 0.004) < 0.0001  # Should be around 0.004
    
    avg_bind = monitor.get_average_duration("bind_artifact")
    assert abs(avg_bind - 0.01) < 0.0001  # Should be around 0.01
    
    count_boundary = monitor.get_operation_count("check_boundary")
    assert count_boundary == 2


def test_batch_operations():
    """Test batch boundary checking."""
    
    enforcer = OptimizedBoundaryEnforcer()
    
    # Register some test data
    jurisdiction = {"id": "us-ca", "name": "California"}
    domain = {"id": "prod-us-west", "jurisdiction_id": "us-ca"}
    
    enforcer.register_jurisdiction(jurisdiction)
    enforcer.register_execution_domain(domain)
    
    # Create some checks
    checks = [
        ("model-x", "prod-us-west", "dev-us-east"),
        ("model-y", "prod-us-west", "dev-us-east"),
        ("model-z", "prod-us-west", "dev-us-east")
    ]
    
    # Batch check
    results = enforcer.batch_check_boundaries(checks)
    
    assert len(results) == 3
    for result in results:
        assert "artifact_id" in result
        assert "source_domain_id" in result
        assert "target_domain_id" in result


def test_cache_efficiency():
    """Test cache efficiency."""
    
    enforcer = OptimizedBoundaryEnforcer()
    
    # Add some bindings
    for i in range(10):
        enforcer.bind_artifact_to_jurisdiction(f"model-{i}", "us-ca")
    
    # Check cache stats
    stats = enforcer.get_cache_stats()
    assert stats["binding_cache_size"] <= 10  # Should not exceed number of bindings