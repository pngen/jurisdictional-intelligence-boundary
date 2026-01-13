"""
Tests for temporal boundary components.
"""

import pytest
from jib.core.temporal_boundary import (
    TemporalBoundary,
    State,
    TemporalBoundaryManager,
    GracePeriodManager
)
import time


def test_temporal_boundary_validity():
    """Test temporal boundary validity checks."""
    
    # Create a boundary with time constraints
    boundary = TemporalBoundary(
        id="temp-boundary",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Time-limited access",
        valid_from=int(time.time()) - 3600,  # 1 hour ago
        valid_until=int(time.time()) + 3600   # 1 hour from now
    )
    
    current_time = int(time.time())
    
    # Should be valid now
    assert boundary.is_valid_at(current_time) is True
    
    # Test before valid_from
    past_time = current_time - 7200  # 2 hours ago
    assert boundary.is_valid_at(past_time) is False
    
    # Test after valid_until
    future_time = current_time + 7200  # 2 hours from now
    assert boundary.is_valid_at(future_time) is False


def test_temporal_boundary_manager():
    """Test temporal boundary manager."""
    
    manager = TemporalBoundaryManager()
    
    # Create boundaries with different time constraints
    boundary1 = TemporalBoundary(
        id="boundary-1",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Valid now",
        valid_from=int(time.time()) - 3600,
        valid_until=int(time.time()) + 3600
    )
    
    boundary2 = TemporalBoundary(
        id="boundary-2",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-nv",
        allowed=False,
        reason="Expired",
        valid_from=int(time.time()) - 7200,
        valid_until=int(time.time()) - 3600  # Already expired
    )
    
    # Register boundaries
    manager.register_boundary(boundary1)
    manager.register_boundary(boundary2)
    
    # Check validity
    assert manager.check_validity("boundary-1") is True
    assert manager.check_validity("boundary-2") is False
    
    # Get valid boundaries
    valid = manager.get_valid_boundaries()
    assert len(valid) == 1
    assert valid[0].id == "boundary-1"
    
    # Get expired boundaries
    expired = manager.get_expired_boundaries()
    assert len(expired) == 1
    assert expired[0].id == "boundary-2"


def test_grace_period_manager():
    """Test grace period manager."""
    
    gpm = GracePeriodManager(default_grace_period=3600)  # 1 hour
    
    # Create a boundary with expiration
    boundary = TemporalBoundary(
        id="test-boundary",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Test",
        valid_until=int(time.time()) + 1800  # Expires in 30 minutes
    )
    
    current_time = int(time.time())
    
    # Should not be in grace period yet
    assert gpm.is_in_grace_period(boundary, current_time) is False
    
    # Test with time near expiration
    grace_time = boundary.valid_until - 1800  # 30 minutes before expiry
    assert gpm.is_in_grace_period(boundary, grace_time) is True
    
    # Get remaining time
    remaining = gpm.get_remaining_time(boundary, current_time)
    assert remaining > 0


def test_boundary_expiry():
    """Test boundary expiry handling."""
    
    manager = TemporalBoundaryManager()
    
    # Create an expired boundary
    expired_boundary = TemporalBoundary(
        id="expired-boundary",
        source_jurisdiction_id="us-ca",
        target_jurisdiction_id="us-tx",
        allowed=True,
        reason="Expired",
        valid_until=int(time.time()) - 3600  # Already expired
    )
    
    manager.register_boundary(expired_boundary)
    
    # Check if expired
    assert manager.check_validity("expired-boundary") is False
    
    # Get expired boundaries
    expired = manager.get_expired_boundaries()
    assert len(expired) == 1
    assert expired[0].id == "expired-boundary"