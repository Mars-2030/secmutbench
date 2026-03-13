"""
SecMutBench Security Mutation Operators

This module provides security-specific mutation operators for evaluating
the effectiveness of security test suites.
"""

from .security_operators import (
    SecurityMutationOperator,
    # Original 19 operators
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
    # New 14 operators (v2.5.0)
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

from .operator_registry import (
    OPERATORS,
    CWE_OPERATOR_MAP,
    get_applicable_operators,
    get_operators_for_cwe,
    get_all_operators,
    get_operator,
    get_cwe_coverage,
    get_operator_info,
)

__all__ = [
    # Base class
    'SecurityMutationOperator',
    # Original 19 operators
    'PSQLI',
    'RVALID',
    'INPUTVAL',
    'SUBDOMAIN_SPOOF',
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
    'WEAKRANDOM',
    # New 14 operators (v2.5.0)
    'EVALINJECT',
    'LOGINJECT',
    'OPENREDIRECT',
    'NOCERTVALID',
    'FILEUPLOAD',
    'INFOEXPOSE',
    'WEAKKEY',
    'LDAPINJECT',
    'XMLBOMB',
    'REGEXDOS',
    'CREDEXPOSE',
    'WEAKPASSREQ',
    'MISSINGAUTH',
    'HTTPRS',
    # Registry functions
    'OPERATORS',
    'CWE_OPERATOR_MAP',
    'get_applicable_operators',
    'get_operators_for_cwe',
    'get_all_operators',
    'get_operator',
    'get_cwe_coverage',
    'get_operator_info',
]
