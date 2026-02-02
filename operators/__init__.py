"""
SecMutBench Security Mutation Operators

This module provides security-specific mutation operators for evaluating
the effectiveness of security test suites.
"""

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
)

from .operator_registry import (
    OPERATORS,
    get_applicable_operators,
    get_operators_for_cwe,
)

__all__ = [
    'SecurityMutationOperator',
    'PSQLI',
    'RVALID',
    'INPUTVAL',
    'RHTTPO',
    'WEAKCRYPTO',
    'HARDCODE',
    'RMAUTH',
    'PATHCONCAT',
    'CMDINJECT',
    'RENCRYPT',
    'DESERIAL',
    'SSRF',
    'IDOR',
    'XXE',
    'SSTI',
    'CORS_WEAK',
    'CSRF_REMOVE',
    'OPERATORS',
    'get_applicable_operators',
    'get_operators_for_cwe',
]
