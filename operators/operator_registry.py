"""
Security Mutation Operator Registry

Maps operators to CWEs and provides utility functions for
selecting applicable operators.
"""

from typing import Dict, List, Optional
from .security_operators import (
    SecurityMutationOperator,
    PSQLI,
    RVALID,
    INPUTVAL,
    RHTTPO,
    WEAKCRYPTO,
    HARDCODE,
    RMAUTH,
    PATHCONCAT,
    CMDINJECT,
    RENCRYPT,
    DESERIAL,
    SSRF,
    IDOR,
    XXE,
    SSTI,
    CORS_WEAK,
    CSRF_REMOVE,
    WEAKRANDOM,
)


# Global registry of all operators
OPERATORS: Dict[str, SecurityMutationOperator] = {
    "PSQLI": PSQLI(),
    "RVALID": RVALID(),
    "INPUTVAL": INPUTVAL(),
    "RHTTPO": RHTTPO(),
    "WEAKCRYPTO": WEAKCRYPTO(),
    "HARDCODE": HARDCODE(),
    "RMAUTH": RMAUTH(),
    "PATHCONCAT": PATHCONCAT(),
    "CMDINJECT": CMDINJECT(),
    "RENCRYPT": RENCRYPT(),
    "DESERIAL": DESERIAL(),
    "SSRF": SSRF(),
    "IDOR": IDOR(),
    "XXE": XXE(),
    "SSTI": SSTI(),
    "CORS_WEAK": CORS_WEAK(),
    "CSRF_REMOVE": CSRF_REMOVE(),
    "WEAKRANDOM": WEAKRANDOM(),
}


# CWE to Operator mappings
CWE_OPERATOR_MAP: Dict[str, List[str]] = {
    # Injection vulnerabilities
    "CWE-89": ["PSQLI", "RVALID"],  # SQL Injection
    "CWE-79": ["RVALID", "RHTTPO"],  # XSS
    "CWE-78": ["CMDINJECT", "RVALID"],  # OS Command Injection
    "CWE-77": ["CMDINJECT"],  # Command Injection
    "CWE-94": ["SSTI"],  # Improper Control of Code Generation
    "CWE-1336": ["SSTI"],  # Server-Side Template Injection

    # Path traversal
    "CWE-22": ["PATHCONCAT", "RVALID"],  # Path Traversal
    "CWE-73": ["PATHCONCAT"],  # External Control of File Name

    # Input validation
    "CWE-20": ["INPUTVAL", "RVALID"],  # Improper Input Validation

    # Authentication/Authorization
    "CWE-287": ["RMAUTH"],  # Improper Authentication
    "CWE-306": ["RMAUTH"],  # Missing Authentication
    "CWE-862": ["RMAUTH"],  # Missing Authorization
    "CWE-284": ["IDOR"],  # Improper Access Control
    "CWE-639": ["IDOR"],  # Authorization Bypass Through User-Controlled Key

    # Credentials
    "CWE-798": ["HARDCODE"],  # Hardcoded Credentials
    "CWE-259": ["HARDCODE"],  # Hardcoded Password

    # Cryptography
    "CWE-327": ["WEAKCRYPTO"],  # Broken or Risky Crypto
    "CWE-328": ["WEAKCRYPTO"],  # Reversible One-Way Hash

    # Weak Randomness
    "CWE-338": ["WEAKRANDOM"],  # Use of Cryptographically Weak PRNG
    "CWE-330": ["WEAKRANDOM"],  # Use of Insufficiently Random Values
    "CWE-331": ["WEAKRANDOM"],  # Insufficient Entropy

    # Network security
    "CWE-319": ["RENCRYPT"],  # Cleartext Transmission
    "CWE-311": ["RENCRYPT"],  # Missing Encryption
    "CWE-918": ["SSRF"],  # Server-Side Request Forgery

    # Session management
    "CWE-1004": ["RHTTPO"],  # Sensitive Cookie Without HttpOnly

    # Deserialization
    "CWE-502": ["DESERIAL"],  # Deserialization of Untrusted Data

    # XML Processing
    "CWE-611": ["XXE"],  # Improper Restriction of XML External Entity Reference

    # CORS/Origin
    "CWE-942": ["CORS_WEAK"],  # Permissive CORS Policy
    "CWE-346": ["CORS_WEAK"],  # Origin Validation Error

    # CSRF
    "CWE-352": ["CSRF_REMOVE"],  # Cross-Site Request Forgery
}


def get_operators_for_cwe(cwe: str) -> List[SecurityMutationOperator]:
    """
    Get all operators applicable to a specific CWE.

    Args:
        cwe: CWE identifier (e.g., "CWE-89")

    Returns:
        List of operator instances
    """
    operator_names = CWE_OPERATOR_MAP.get(cwe, [])
    return [OPERATORS[name] for name in operator_names if name in OPERATORS]


def get_applicable_operators(
    code: str,
    cwe: Optional[str] = None
) -> List[str]:
    """
    Get names of operators that can mutate the given code.

    Args:
        code: Source code to analyze
        cwe: Optional CWE to filter by

    Returns:
        List of applicable operator names
    """
    applicable = []

    if cwe:
        # Only check operators for this CWE
        candidates = CWE_OPERATOR_MAP.get(cwe, [])
        for name in candidates:
            if name in OPERATORS and OPERATORS[name].applies_to(code):
                applicable.append(name)
    else:
        # Check all operators
        for name, operator in OPERATORS.items():
            if operator.applies_to(code):
                applicable.append(name)

    return applicable


def get_all_operators() -> Dict[str, SecurityMutationOperator]:
    """Return all registered operators."""
    return OPERATORS.copy()


def get_operator(name: str) -> Optional[SecurityMutationOperator]:
    """Get a specific operator by name."""
    return OPERATORS.get(name)


def get_cwe_coverage() -> Dict[str, int]:
    """
    Get count of operators per CWE.

    Returns:
        Dict mapping CWE to number of operators
    """
    return {cwe: len(ops) for cwe, ops in CWE_OPERATOR_MAP.items()}


def get_operator_info() -> List[Dict]:
    """
    Get information about all operators.

    Returns:
        List of dicts with operator details
    """
    info = []
    for name, op in OPERATORS.items():
        info.append({
            "name": name,
            "description": op.description,
            "target_cwes": op.target_cwes,
        })
    return info
