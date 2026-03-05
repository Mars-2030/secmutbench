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
    SUBDOMAIN_SPOOF,
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
    # New operators for expanded CWE coverage
    EVALINJECT,
    LOGINJECT,
    OPENREDIRECT,
    NOCERTVALID,
    FILEUPLOAD,
    INFOEXPOSE,
    WEAKKEY,
    LDAPINJECT,
    XMLBOMB,
    REGEXDOS,
    CREDEXPOSE,
    WEAKPASSREQ,
    MISSINGAUTH,
    HTTPRS,
)


# Global registry of all operators
OPERATORS: Dict[str, SecurityMutationOperator] = {
    "PSQLI": PSQLI(),
    "RVALID": RVALID(),
    "INPUTVAL": INPUTVAL(),
    "SUBDOMAIN_SPOOF": SUBDOMAIN_SPOOF(),
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
    # New operators for expanded CWE coverage
    "EVALINJECT": EVALINJECT(),
    "LOGINJECT": LOGINJECT(),
    "OPENREDIRECT": OPENREDIRECT(),
    "NOCERTVALID": NOCERTVALID(),
    "FILEUPLOAD": FILEUPLOAD(),
    "INFOEXPOSE": INFOEXPOSE(),
    "WEAKKEY": WEAKKEY(),
    "LDAPINJECT": LDAPINJECT(),
    "XMLBOMB": XMLBOMB(),
    "REGEXDOS": REGEXDOS(),
    "CREDEXPOSE": CREDEXPOSE(),
    "WEAKPASSREQ": WEAKPASSREQ(),
    "MISSINGAUTH": MISSINGAUTH(),
    "HTTPRS": HTTPRS(),
}


# CWE to Operator mappings
CWE_OPERATOR_MAP: Dict[str, List[str]] = {
    # Injection vulnerabilities
    "CWE-89": ["PSQLI", "RVALID"],  # SQL Injection
    "CWE-79": ["RVALID", "RHTTPO"],  # XSS
    "CWE-78": ["CMDINJECT", "RVALID"],  # OS Command Injection
    "CWE-77": ["CMDINJECT"],  # Command Injection
    "CWE-94": ["DESERIAL", "RVALID", "EVALINJECT"],  # Code Injection
    "CWE-95": ["EVALINJECT"],  # Eval Injection
    "CWE-1336": ["SSTI"],  # Server-Side Template Injection
    "CWE-90": ["LDAPINJECT"],  # LDAP Injection
    "CWE-643": ["LDAPINJECT"],  # XPath Injection (similar pattern)

    # Path traversal
    "CWE-22": ["PATHCONCAT", "RVALID"],  # Path Traversal
    "CWE-73": ["PATHCONCAT"],  # External Control of File Name

    # Input validation
    "CWE-20": ["INPUTVAL", "RVALID", "SUBDOMAIN_SPOOF"],  # Improper Input Validation
    "CWE-117": ["LOGINJECT"],  # Log Injection
    "CWE-113": ["HTTPRS"],  # HTTP Response Splitting

    # Authentication/Authorization
    "CWE-287": ["RMAUTH"],  # Improper Authentication
    "CWE-306": ["RMAUTH"],  # Missing Authentication
    "CWE-862": ["RMAUTH", "MISSINGAUTH"],  # Missing Authorization
    "CWE-863": ["MISSINGAUTH"],  # Incorrect Authorization
    "CWE-284": ["IDOR", "MISSINGAUTH"],  # Improper Access Control
    "CWE-639": ["IDOR"],  # Authorization Bypass Through User-Controlled Key

    # Credentials
    "CWE-798": ["HARDCODE"],  # Hardcoded Credentials
    "CWE-259": ["HARDCODE"],  # Hardcoded Password
    "CWE-521": ["WEAKPASSREQ"],  # Weak Password Requirements
    "CWE-522": ["CREDEXPOSE"],  # Insufficiently Protected Credentials

    # Cryptography
    "CWE-327": ["WEAKCRYPTO"],  # Broken or Risky Crypto
    "CWE-328": ["WEAKCRYPTO"],  # Reversible One-Way Hash
    "CWE-326": ["WEAKKEY"],  # Inadequate Encryption Strength
    "CWE-295": ["NOCERTVALID"],  # Improper Certificate Validation
    "CWE-297": ["NOCERTVALID"],  # Improper Validation of Certificate with Host Mismatch

    # Weak Randomness
    "CWE-338": ["WEAKRANDOM"],  # Use of Cryptographically Weak PRNG
    "CWE-330": ["WEAKRANDOM"],  # Use of Insufficiently Random Values
    "CWE-331": ["WEAKRANDOM"],  # Insufficient Entropy

    # Network security
    "CWE-319": ["RENCRYPT"],  # Cleartext Transmission
    "CWE-311": ["RENCRYPT"],  # Missing Encryption
    "CWE-918": ["SSRF", "SUBDOMAIN_SPOOF"],  # Server-Side Request Forgery
    "CWE-601": ["OPENREDIRECT"],  # URL Redirection to Untrusted Site

    # Session management
    "CWE-1004": ["RHTTPO"],  # Sensitive Cookie Without HttpOnly

    # Deserialization
    "CWE-502": ["DESERIAL"],  # Deserialization of Untrusted Data

    # XML Processing
    "CWE-611": ["XXE"],  # Improper Restriction of XML External Entity Reference
    "CWE-776": ["XMLBOMB"],  # Improper Restriction of Recursive Entity References

    # CORS/Origin
    "CWE-942": ["CORS_WEAK"],  # Permissive CORS Policy
    "CWE-346": ["CORS_WEAK"],  # Origin Validation Error

    # CSRF
    "CWE-352": ["CSRF_REMOVE"],  # Cross-Site Request Forgery

    # File Upload
    "CWE-434": ["FILEUPLOAD"],  # Unrestricted File Upload

    # Information Exposure
    "CWE-200": ["INFOEXPOSE"],  # Exposure of Sensitive Information
    "CWE-209": ["INFOEXPOSE"],  # Information Exposure Through Error Message
    "CWE-215": ["INFOEXPOSE"],  # Information Exposure Through Debug Information

    # Resource Exhaustion / DoS
    "CWE-400": ["REGEXDOS"],  # Uncontrolled Resource Consumption
    "CWE-1333": ["REGEXDOS"],  # Inefficient Regular Expression Complexity
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
