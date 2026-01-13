"""
Pytest configuration for JIB tests.
"""

import pytest
from hypothesis import settings, Verbosity

# Configure Hypothesis settings
settings.register_profile("ci", max_examples=100, verbosity=Verbosity.verbose)
settings.register_profile("dev", max_examples=10)
settings.register_profile("research", max_examples=1000, verbosity=Verbosity.verbose)

# Use dev profile by default
settings.load_profile("dev")


@pytest.fixture
def sample_jurisdiction():
    """Fixture: Sample jurisdiction for testing."""
    from jib.core.types import Jurisdiction, JurisdictionType
    return Jurisdiction(
        id="test-jid",
        name="Test Jurisdiction",
        type=JurisdictionType.SOVEREIGN
    )


@pytest.fixture
def sample_execution_domain(sample_jurisdiction):
    """Fixture: Sample execution domain for testing."""
    from jib.core.types import ExecutionDomain
    return ExecutionDomain(
        id="test-domain",
        name="Test Domain",
        jurisdiction_id=sample_jurisdiction.id
    )


@pytest.fixture
def sample_private_key():
    """Fixture: Sample Ed25519 private key for testing."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def research_enforcer():
    """Fixture: Research-grade enforcer for testing."""
    from jib.core.research_grade_enforcer import ResearchGradeBoundaryEnforcer
    return ResearchGradeBoundaryEnforcer("test-node", set())