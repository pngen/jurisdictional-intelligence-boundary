"""
Robust error handling and recovery for JIB.
"""

import time
import traceback
from typing import Optional, Dict, Any
from dataclasses import dataclass


class JIBError(Exception):
    """Base exception for JIB errors."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.context = context or {}
        self.timestamp = int(time.time())
        self.stack_trace = traceback.format_exc()


class BoundaryEnforcementError(JIBError):
    """Enhanced error with recovery context."""
    
    def __init__(
        self, 
        message: str, 
        context: Dict[str, Any], 
        recovery_hint: Optional[str] = None
    ):
        super().__init__(message, context)
        self.recovery_hint = recovery_hint


class UnauthorizedJurisdictionAccess(BoundaryEnforcementError):
    """Raised when unauthorized access to jurisdiction is attempted."""
    pass


class BindingIntegrityViolation(BoundaryEnforcementError):
    """Raised when binding integrity is compromised."""
    pass


class TemporalConstraintViolation(BoundaryEnforcementError):
    """Raised when temporal constraints are violated."""
    pass


class ConsensusFailure(BoundaryEnforcementError):
    """Raised when distributed consensus fails."""
    pass


class InvariantViolation(BoundaryEnforcementError):
    """Raised when system invariants are violated."""
    pass


class BoundaryVerificationError(Exception):
    """Raised when boundary verification fails."""
    
    def __init__(self, message: str, binding_id: str, error_type: str):
        super().__init__(message)
        self.binding_id = binding_id
        self.error_type = error_type
        self.timestamp = int(time.time())


class JIBRecoveryContext:
    """
    Context for recovery operations.
    
    Provides information needed to recover from errors.
    """
    
    def __init__(self, error: JIBError):
        self.error = error
        self.recovery_actions = []
    
    def add_recovery_action(self, action: str, details: Dict[str, Any]):
        """Add a recovery action to the context."""
        self.recovery_actions.append({
            "action": action,
            "details": details,
            "timestamp": int(time.time())
        })
    
    def get_recovery_plan(self) -> Dict[str, Any]:
        """Get complete recovery plan."""
        return {
            "error_message": self.error.message,
            "context": self.error.context,
            "recovery_actions": self.recovery_actions
        }


# Example usage of error handling
def example_error_handling():
    """Demonstrate error handling patterns."""
    
    try:
        # Simulate an unauthorized access attempt
        raise UnauthorizedJurisdictionAccess(
            "Access denied to jurisdiction us-tx",
            {
                "artifact_id": "model-x",
                "user_id": "user-123",
                "requested_jurisdiction": "us-tx"
            },
            "Check jurisdiction bindings and user permissions"
        )
    except UnauthorizedJurisdictionAccess as e:
        print(f"Error: {e}")
        print(f"Context: {e.context}")
        print(f"Recovery hint: {e.recovery_hint}")
        
        # Create recovery context
        ctx = JIBRecoveryContext(e)
        ctx.add_recovery_action("check_bindings", {"artifact": "model-x"})
        ctx.add_recovery_action("verify_permissions", {"user": "user-123"})
        
        print(f"Recovery plan: {ctx.get_recovery_plan()}")


if __name__ == "__main__":
    example_error_handling()