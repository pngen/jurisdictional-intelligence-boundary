# Jurisdictional Intelligence Boundary (JIB)

A sovereign containment and boundary enforcement system for intelligence execution.

## One-sentence value proposition

JIB enforces jurisdictional, legal, and sovereign boundaries on intelligence execution, preventing unauthorized cross-domain activity without exception.

## Overview

JIB is a systems-level framework that defines where intelligence (models, agents, workflows) is allowed to exist, execute, and act. It operates below orchestration and above infrastructure, binding execution environments to territorial and legal reality through hard constraints rather than policy interpretation.

## Architecture diagram
<pre>
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│   Intelligence  │    │   Execution      │    │   Jurisdiction     │
│   Artifacts     │◄──►│   Domains        │◄──►│   Boundaries       │
│                 │    │                  │    │                    │
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│  Boundary       │    │  Enforcement     │    │   Resolution       │
│  Enforcer       │◄──►│  Engine          │◄──►│   Logic            │
│                 │    │                  │    │                    │
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│  Integration    │    │  Proof           │    │   Governance       │
│  Adapter        │◄──►│  Generator       │◄──►│   Layer            │
│                 │    │                  │    │                    │
└─────────────────┘    └──────────────────┘    └────────────────────┘
</pre>

## Core Components

1. **Types**: Formal definitions of jurisdiction, execution domain, boundary, claim, binding, and proof primitives.
2. **Boundary Enforcer**: Enforces jurisdictional boundaries at runtime.
3. **Boundary Resolver**: Resolves conflicts and overlaps in jurisdictional claims.
4. **Proof Generator**: Generates machine-verifiable audit trails.
5. **Integration Adapter**: Interfaces with execution systems and governance layers.

## Installation
```bash
pip install cryptography hypothesis pytest pytest-asyncio
```

## Quick Start
```python
from jib.core.research_grade_enforcer import ResearchGradeBoundaryEnforcer
from jib.core.types import Jurisdiction, ExecutionDomain, Boundary, JurisdictionType
from cryptography.hazmat.primitives.asymmetric import ed25519
import asyncio

# Create research-grade enforcer
enforcer = ResearchGradeBoundaryEnforcer("node-1", {"node-2", "node-3"})

# Define jurisdictions
us_ca = Jurisdiction(id="us-ca", name="California", type=JurisdictionType.SOVEREIGN)
us_tx = Jurisdiction(id="us-tx", name="Texas", type=JurisdictionType.SOVEREIGN)

enforcer.base_enforcer.register_jurisdiction(us_ca)
enforcer.base_enforcer.register_jurisdiction(us_tx)

# Define execution domains
prod_west = ExecutionDomain(id="prod-west", name="Production West", jurisdiction_id="us-ca")
prod_east = ExecutionDomain(id="prod-east", name="Production East", jurisdiction_id="us-tx")

enforcer.base_enforcer.register_execution_domain(prod_west)
enforcer.base_enforcer.register_execution_domain(prod_east)

# Create cryptographic binding
private_key = ed25519.Ed25519PrivateKey.generate()
binding = enforcer.bind_artifact_with_crypto(
    artifact_id="model-x",
    jurisdiction_id="us-ca",
    private_key=private_key,
    artifact_hash="abc123def456"
)

# Verify cryptographic integrity
assert binding.verify()  # Cryptographically verified

# Define boundary rule
boundary = Boundary(
    id="ca-to-tx",
    source_jurisdiction_id="us-ca",
    target_jurisdiction_id="us-tx",
    allowed=True,
    reason="Cross-region allowed"
)
enforcer.base_enforcer.boundaries["us-ca:us-tx"] = boundary

# Enforce boundary with all checks (async)
async def enforce():
    proof = await enforcer.enforce_boundary_with_all_checks(
        artifact_id="model-x",
        source_domain_id="prod-west",
        target_domain_id="prod-east"
    )
    print(f"Boundary check: {proof.allowed}")
    print(f"Reason: {proof.reason}")

asyncio.run(enforce())
```

## Running Tests
```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=jib.core --cov-report=html

# Run property-based tests only
pytest tests/test_property_based.py -v

# Run integration tests only
pytest tests/test_integration_full.py -v

# Run with more Hypothesis examples (thorough)
pytest --hypothesis-profile=research
```

## Design Principles
- **Hard Boundaries**: Jurisdictional constraints are absolute, not advisory.
- **Enforcement-Oriented**: JIB prevents execution, does not observe it.
- **Deterministic**: All behavior is predictable and consistent.
- **Auditability**: Every decision generates a verifiable proof.
- **Composability**: Integrates cleanly with existing systems.

## Requirements
1. **Core Data Structures**:
    - Jurisdiction
    - ExecutionDomain
    - Boundary
    - JurisdictionalClaim
    - JurisdictionalBinding
    - BoundaryProof

2. **Enforcement Model**:
    - Bind artifacts to jurisdictions at compile/deploy time
    - Prevent runtime boundary escalation
    - Fail closed on ambiguous or missing jurisdictional clarity

3. **Resolution Semantics**:
    - Conflicting claims fail closed
    - Overlapping jurisdictions resolved deterministically
    - Missing bindings denied by default

4. **Auditability**:
    - Machine-verifiable proofs for all decisions
    - Proofs reconstructable without runtime introspection
    - Full context included in audit trail

5. **Integration Points**:
    - Deterministic execution systems
    - Authority compilers
    - Zero-trust sandboxes
    - Cost attribution systems

## What JIB Is / What JIB Is Not

### What JIB Is
- A hard constraint system for jurisdictional boundaries
- An enforcement mechanism, not a policy interpreter
- A framework for sovereign containment of intelligence execution
- A deterministic, verifiable audit trail generator

### What JIB Is Not
- A legal reasoning engine or policy interpreter
- A data classification system
- A geopolitical judgment system
- An identity or access control system
- A replacement for compliance teams

## Versioning Contract (v1.0.0)
- **Major**: 1
- **Minor**: 0
- **Patch**: 0
- **Status**: Stable
- **API Stability**: Stable
- **Data Model Stability**: Stable
- **Security Model**: Hard-boundary enforcement

All guarantees are non-negotiable:
- No silent cross-jurisdiction execution
- No runtime jurisdiction mutation
- No trust-based boundary relaxation
- No implicit data or control flow across boundaries
