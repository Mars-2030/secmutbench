#!/usr/bin/env python3
"""
Multi-Source Handlers for SecMutBench Dataset Generation

Implements step 3 of the research-driven workflow:
    3. FIND REAL EXAMPLES
       └── SecurityEval, CyberSecEval, OWASP, CVE, Snyk, GitHub, CodeQL

Sources:
- SecurityEval: HuggingFace dataset s2e-lab/SecurityEval
- CyberSecEval: HuggingFace dataset from Meta
- OWASP: Attack payloads from payloads.json + web scraping
- CodeQL: Query examples from GitHub codeql repository
"""

import json
import re
import os
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from abc import ABC, abstractmethod
import hashlib


@dataclass
class ExternalSample:
    """Represents a sample from an external source."""
    id: str
    cwe: str
    cwe_name: str
    source: str
    original_id: str
    prompt: str
    code: str  # The vulnerable/insecure code
    language: str = "python"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPayload:
    """Represents an attack payload for testing."""
    cwe: str
    category: str
    payload: str
    description: str = ""
    source: str = "OWASP"


# CWE ID normalization
def normalize_cwe(cwe_raw: str) -> str:
    """Normalize CWE format (CWE-089 -> CWE-89)."""
    match = re.match(r'CWE-0*(\d+)', cwe_raw)
    if match:
        return f"CWE-{match.group(1)}"
    return cwe_raw


# CWE to Name mapping
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-327": "Use of Broken or Risky Cryptographic Algorithm",
    "CWE-338": "Use of Cryptographically Weak PRNG",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted Upload of Dangerous File Type",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "XXE (XML External Entity)",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy",
    "CWE-1336": "Improper Neutralization of Template Expressions",
    "CWE-95": "Eval Injection",
    "CWE-113": "HTTP Response Splitting",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-1333": "Inefficient Regular Expression Complexity",
}


class BaseSourceHandler(ABC):
    """Abstract base class for source handlers."""

    @abstractmethod
    def load_samples(self) -> List[ExternalSample]:
        """Load all samples from this source."""
        pass

    @abstractmethod
    def extract_by_cwe(self, cwe_id: str) -> List[ExternalSample]:
        """Extract samples for a specific CWE."""
        pass


class SecurityEvalHandler(BaseSourceHandler):
    """
    Handler for SecurityEval dataset from HuggingFace.

    Dataset: s2e-lab/SecurityEval
    Contains: Python code samples with CWE labels
    """

    DATASET_NAME = "s2e-lab/SecurityEval"

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else Path("data/raw")
        self.cache_file = self.cache_dir / "securityeval_raw.json"
        self._samples: Optional[List[ExternalSample]] = None

    def _download_dataset(self) -> List[Dict]:
        """Download SecurityEval from HuggingFace."""
        try:
            from datasets import load_dataset
            print(f"Downloading SecurityEval dataset from {self.DATASET_NAME}...")
            dataset = load_dataset(self.DATASET_NAME)

            samples = []
            for item in dataset["train"]:
                samples.append({
                    "ID": item.get("ID", ""),
                    "Prompt": item.get("Prompt", ""),
                    "Insecure_code": item.get("Insecure_code", ""),
                })

            # Cache the download
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(samples, f, indent=2)

            print(f"Downloaded and cached {len(samples)} samples")
            return samples

        except ImportError:
            print("Please install datasets: pip install datasets")
            return []
        except Exception as e:
            print(f"Failed to download SecurityEval: {e}")
            return []

    def _load_cached(self) -> List[Dict]:
        """Load from cache if available."""
        if self.cache_file.exists():
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return []

    def load_samples(self) -> List[ExternalSample]:
        """Load all SecurityEval samples."""
        if self._samples is not None:
            return self._samples

        # Try cache first
        raw_samples = self._load_cached()
        if not raw_samples:
            raw_samples = self._download_dataset()

        self._samples = []
        for raw in raw_samples:
            sample_id = raw.get("ID", "")
            cwe = self._extract_cwe(sample_id)
            if cwe:
                self._samples.append(ExternalSample(
                    id=hashlib.md5(sample_id.encode()).hexdigest()[:12],
                    cwe=cwe,
                    cwe_name=CWE_NAMES.get(cwe, "Unknown"),
                    source="SecurityEval",
                    original_id=sample_id,
                    prompt=raw.get("Prompt", ""),
                    code=raw.get("Insecure_code", ""),
                    language="python",
                    metadata={"raw_id": sample_id},
                ))

        return self._samples

    def _extract_cwe(self, sample_id: str) -> str:
        """Extract CWE from SecurityEval sample ID."""
        # Format: CWE-089_codeql_1.py or CWE-078_autocomplete_1
        if sample_id.startswith("CWE"):
            parts = sample_id.split("_")
            if parts:
                return normalize_cwe(parts[0])
        return ""

    def extract_by_cwe(self, cwe_id: str) -> List[ExternalSample]:
        """Extract samples for a specific CWE."""
        cwe_normalized = normalize_cwe(cwe_id)
        all_samples = self.load_samples()
        return [s for s in all_samples if s.cwe == cwe_normalized]

    def get_available_cwes(self) -> List[str]:
        """Get list of CWEs available in this dataset."""
        all_samples = self.load_samples()
        return sorted(set(s.cwe for s in all_samples))


# =============================================================================
# Snippet Wrapping Helper (Phase 6 - CyberSecEval Fix)
# =============================================================================

def wrap_snippet_in_function(code: str, entry_point: str = "vulnerable_function") -> Tuple[str, str]:
    """
    Wrap a code snippet in a function for testing.

    CyberSecEval and some SecurityEval samples contain code snippets
    without function definitions. This wraps them in a testable function.

    Args:
        code: Code snippet (may or may not have function definition)
        entry_point: Name for the wrapper function if needed

    Returns:
        Tuple of (wrapped_code, actual_entry_point)
    """
    if not code or not code.strip():
        return code, entry_point

    # Check if it already has a function definition
    func_match = re.search(r'^def\s+(\w+)\s*\(', code, re.MULTILINE)
    if func_match:
        return code, func_match.group(1)

    # Check if it's a class
    if re.search(r'^class\s+\w+', code, re.MULTILINE):
        return code, entry_point

    # Detect imports at the top
    lines = code.split('\n')
    import_lines = []
    code_lines = []
    in_imports = True

    for line in lines:
        stripped = line.strip()
        if in_imports and (stripped.startswith('import ') or stripped.startswith('from ')):
            import_lines.append(line)
        elif in_imports and not stripped:
            import_lines.append(line)  # Keep blank lines in import section
        else:
            in_imports = False
            code_lines.append(line)

    # Detect what parameters the snippet needs
    # Look for free variables that appear to be user input
    tainted_vars = set()
    for var in ['user_input', 'input', 'data', 'payload', 'query', 'path', 'filename',
                'url', 'command', 'xml', 'content', 'text', 'message', 'username']:
        if re.search(rf'\b{var}\b', '\n'.join(code_lines)):
            tainted_vars.add(var)

    # Build parameter list
    if tainted_vars:
        params = ', '.join(sorted(tainted_vars))
    else:
        params = 'user_input'  # Default parameter

    # Indent the code body
    indented_body = '\n'.join('    ' + line if line.strip() else '' for line in code_lines)

    # Assemble wrapped function
    imports_str = '\n'.join(import_lines) + '\n\n' if import_lines else ''
    wrapped = f'''{imports_str}def {entry_point}({params}):
    """Wrapped code snippet for testing."""
{indented_body}
'''

    return wrapped.strip(), entry_point


def _is_python_snippet(code: str) -> bool:
    """
    Check if code is a Python snippet (with or without function definition).

    More permissive than _is_python_code to allow code snippets.
    """
    if not code or not code.strip():
        return False

    # Reject common non-Python patterns
    non_python_patterns = [
        'system("',  # Perl/shell
        '`',  # Backtick execution
        '$_',  # Perl variable
        '@_',  # Perl array
        'my $',  # Perl variable
        '#!/bin/bash',  # Bash shebang
        '#!/bin/sh',  # Shell shebang
        'getcwd()',  # Perl function
        'print "',  # Perl print without parentheses
    ]
    for pattern in non_python_patterns:
        if pattern in code:
            return False

    # Check for Python indicators
    python_patterns = [
        r'\bdef\s+\w+\s*\(',  # Function definition
        r'\bimport\s+\w+',  # Import statement
        r'\bfrom\s+\w+\s+import',  # From import
        r'\bif\s+.*:',  # If statement
        r'\bfor\s+\w+\s+in\s+',  # For loop
        r'\bwhile\s+.*:',  # While loop
        r'\breturn\s+',  # Return statement
        r'\bclass\s+\w+',  # Class definition
        r'print\s*\(',  # Python 3 print
        r'\bwith\s+\w+',  # With statement
    ]

    return any(re.search(p, code) for p in python_patterns)


def _has_undefined_context_variables(code: str) -> bool:
    """
    Check if code snippet has undefined context variables from original file.

    CyberSecEval samples are often extracted from larger files and reference
    variables that were defined elsewhere (config objects, file paths, etc.).
    These samples are not testable without the original context.

    Returns:
        True if code has problematic undefined variables, False otherwise.
    """
    # Common context variables that indicate extracted snippets
    context_var_patterns = [
        # Configuration objects
        r'\bconfig\.\w+',  # config.SETTING
        r'\bsettings\.\w+',  # settings.VALUE
        r'\bCONFIG\[',  # CONFIG['key']

        # File paths from original context
        r'\b(src_dir|dest_dir|work_dir|base_dir|root_dir|output_dir)\b',
        r'\b(test_dir|build_dir|data_dir|log_dir|tmp_dir)\b',

        # Command/script variables from original context
        r'\b(build_cmd|run_cmd|exec_cmd|shell_cmd)\b',
        r'\b(dep_dir|lib_dir|bin_dir)\b',

        # Revision/version control context
        r'\brev\b(?!\s*=)',  # rev used but not defined

        # Loop variables used outside loops
        r'\bcloud_function\b',
        r'\bfunction_names\b',

        # Database/connection context
        r'\b(db_conn|connection|cursor)\b(?!\s*=)',

        # Logger objects (usually defined at module level)
        r'\blogger\.\w+',  # logger.debug(), logger.info()

        # File handles used without assignment
        r'\bp\.readline',  # p.readline() where p is undefined
        r'\bf\.read',  # f.read() where f is undefined

        # LSF/job scheduler context
        r'\blsfJobID\b',
        r'\bjob\s*,\s*task\s*=',

        # Perl-style print without parentheses (indicates non-Python code)
        r'^print\s+["\'][^"\']+["\']\s*$',
    ]

    for pattern in context_var_patterns:
        if re.search(pattern, code):
            return True

    # Check for variables used before definition (simple heuristic)
    # Look for assignments vs usages
    lines = code.split('\n')
    defined_vars = set()

    for line in lines:
        # Skip comments and empty lines
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # Find variable definitions (simple assignment)
        assign_match = re.match(r'^(\w+)\s*=', stripped)
        if assign_match:
            defined_vars.add(assign_match.group(1))

    # Check for common problematic patterns: using config-like variables
    # that aren't defined in the snippet
    problematic_vars = ['config', 'settings', 'options', 'args', 'params']
    for var in problematic_vars:
        # Used but not defined
        if re.search(rf'\b{var}\b', code) and var not in defined_vars:
            # Check it's not a function parameter
            if not re.search(rf'def\s+\w+\s*\([^)]*\b{var}\b', code):
                return True

    return False


class CyberSecEvalHandler(BaseSourceHandler):
    """
    Handler for CyberSecEval dataset from Meta/HuggingFace.

    Dataset: walledai/CyberSecEval or facebook/CyberSecEval
    Contains: Security-focused code completion prompts

    Enhanced to handle code snippets without function definitions
    by wrapping them in testable functions.
    """

    DATASET_NAME = "walledai/CyberSecEval"

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else Path("data/raw")
        self.cache_file = self.cache_dir / "cyberseceval_raw.json"
        self._samples: Optional[List[ExternalSample]] = None

    def _download_dataset(self) -> List[Dict]:
        """Download CyberSecEval from HuggingFace."""
        try:
            from datasets import load_dataset
            print(f"Downloading CyberSecEval dataset...")

            # Try different configurations
            try:
                dataset = load_dataset(self.DATASET_NAME, "instruct", split="python")
            except Exception:
                try:
                    dataset = load_dataset(self.DATASET_NAME, split="test")
                except Exception:
                    dataset = load_dataset(self.DATASET_NAME)
                    if "train" in dataset:
                        dataset = dataset["train"]

            samples = []
            for item in dataset:
                samples.append(dict(item))

            # Cache the download
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(samples, f, indent=2)

            print(f"Downloaded and cached {len(samples)} samples")
            return samples

        except ImportError:
            print("Please install datasets: pip install datasets")
            return []
        except Exception as e:
            print(f"Failed to download CyberSecEval: {e}")
            return []

    def _load_cached(self) -> List[Dict]:
        """Load from cache if available."""
        if self.cache_file.exists():
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return []

    def _is_python_code(self, code: str) -> bool:
        """Check if code is Python (not Perl, shell, etc.)."""
        # Use the enhanced snippet detection
        return _is_python_snippet(code)

    def load_samples(self) -> List[ExternalSample]:
        """Load all CyberSecEval samples.

        Enhanced to handle code snippets without function definitions
        by wrapping them in testable functions.
        """
        if self._samples is not None:
            return self._samples

        raw_samples = self._load_cached()
        if not raw_samples:
            raw_samples = self._download_dataset()

        self._samples = []
        wrapped_count = 0

        for i, raw in enumerate(raw_samples):
            cwe = raw.get("cwe_identifier", "")
            if cwe:
                cwe = normalize_cwe(cwe)
                code = raw.get("origin_code", "") or raw.get("prompt", "")

                # Check if it's Python
                if not code or not self._is_python_code(code):
                    continue

                # Check if code needs wrapping (no function definition)
                original_code = code
                entry_point = f"cybersec_{i}"

                if 'def ' not in code:
                    # Wrap snippet in function
                    code, entry_point = wrap_snippet_in_function(code, entry_point)
                    wrapped_count += 1
                else:
                    # Extract entry point from existing function
                    func_match = re.search(r'def\s+(\w+)\s*\(', code)
                    if func_match:
                        entry_point = func_match.group(1)

                # Verify wrapped code compiles
                try:
                    compile(code, '<wrapped>', 'exec')
                except SyntaxError:
                    continue  # Skip invalid code

                # Filter out samples with undefined context variables
                if _has_undefined_context_variables(original_code):
                    continue  # Skip samples needing external context

                self._samples.append(ExternalSample(
                    id=hashlib.md5(f"cse_{i}_{cwe}".encode()).hexdigest()[:12],
                    cwe=cwe,
                    cwe_name=CWE_NAMES.get(cwe, raw.get("cwe_name", "Unknown")),
                    source="CyberSecEval",
                    original_id=raw.get("pattern_id", f"cse_{i}"),
                    prompt=raw.get("prompt", ""),
                    code=code,
                    language="python",
                    metadata={
                        **raw,
                        "entry_point": entry_point,
                        "was_wrapped": code != original_code,
                    },
                ))

        if wrapped_count > 0:
            print(f"  Wrapped {wrapped_count} code snippets in functions")

        return self._samples

    def extract_by_cwe(self, cwe_id: str) -> List[ExternalSample]:
        """Extract samples for a specific CWE."""
        cwe_normalized = normalize_cwe(cwe_id)
        all_samples = self.load_samples()
        return [s for s in all_samples if s.cwe == cwe_normalized]

    def get_available_cwes(self) -> List[str]:
        """Get list of CWEs available in this dataset."""
        all_samples = self.load_samples()
        return sorted(set(s.cwe for s in all_samples))


class OWASPPayloadHandler:
    """
    Handler for OWASP attack payloads.

    Loads payloads from:
    1. Local payloads.json file
    2. Extended payloads for additional CWEs
    """

    def __init__(self, payloads_file: Optional[str] = None):
        if payloads_file:
            self.payloads_file = Path(payloads_file)
        else:
            self.payloads_file = Path("data/attack_payloads/payloads.json")

        self._payloads: Optional[Dict] = None

    def _load_payloads(self) -> Dict:
        """Load payloads from file."""
        if self._payloads is not None:
            return self._payloads

        if self.payloads_file.exists():
            with open(self.payloads_file, 'r') as f:
                self._payloads = json.load(f)
        else:
            self._payloads = {}

        # Add extended payloads for additional CWEs
        self._extend_payloads()

        return self._payloads

    def _extend_payloads(self):
        """Add payloads for CWEs not in the base file."""
        extended = {
            "CWE-287": {
                "name": "Authentication Bypass",
                "payloads": {
                    "null_session": ["", None, "null"],
                    "admin_bypass": ["admin", "administrator", "root"],
                    "token_manipulation": ["invalid_token", "expired_token"],
                }
            },
            "CWE-306": {
                "name": "Missing Authentication",
                "payloads": {
                    "unauthenticated": ["no_auth", "anonymous"],
                    "header_bypass": ["X-Forwarded-For: 127.0.0.1"],
                }
            },
            "CWE-352": {
                "name": "CSRF",
                "payloads": {
                    "missing_token": ["", "invalid_csrf_token"],
                    "wrong_origin": ["https://evil.com", "null"],
                }
            },
            "CWE-611": {
                "name": "XXE",
                "payloads": {
                    "file_read": [
                        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/shadow">]><data>&file;</data>',
                    ],
                    "ssrf": [
                        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]><foo>&xxe;</foo>',
                    ],
                }
            },
            "CWE-918": {
                "name": "SSRF",
                "payloads": {
                    "internal": [
                        "http://127.0.0.1/admin",
                        "http://localhost:22",
                        "http://169.254.169.254/latest/meta-data/",
                    ],
                    "bypass": [
                        "http://127.1/",
                        "http://[::1]/",
                        "http://0x7f000001/",
                    ],
                }
            },
            "CWE-942": {
                "name": "Permissive CORS",
                "payloads": {
                    "origins": ["*", "null", "https://evil.com"],
                    "headers": ["Access-Control-Allow-Origin: *"],
                }
            },
            "CWE-338": {
                "name": "Weak PRNG",
                "payloads": {
                    "predictable_seeds": ["0", "1", "time.time()"],
                    "weak_functions": ["random.random()", "random.randint()"],
                }
            },
            "CWE-319": {
                "name": "Cleartext Transmission",
                "payloads": {
                    "protocols": ["http://", "ftp://", "telnet://"],
                    "verify_false": ["verify=False", "ssl=False"],
                }
            },
            "CWE-295": {
                "name": "Certificate Validation",
                "payloads": {
                    "bypass": ["verify=False", "ssl._create_unverified_context()"],
                }
            },
            "CWE-312": {
                "name": "Cleartext Storage",
                "payloads": {
                    "sensitive_data": ["password", "secret", "api_key", "token"],
                }
            },
            "CWE-639": {
                "name": "IDOR",
                "payloads": {
                    "id_manipulation": ["1", "2", "999", "../1", "admin"],
                }
            },
            "CWE-94": {
                "name": "Code Injection",
                "payloads": {
                    "eval": [
                        "__import__('os').system('id')",
                        "exec('import os; os.system(\"whoami\")')",
                    ],
                    "template": [
                        "{{7*7}}",
                        "${7*7}",
                        "#{7*7}",
                    ],
                }
            },
            "CWE-1336": {
                "name": "SSTI",
                "payloads": {
                    "jinja2": [
                        "{{config}}",
                        "{{''.__class__.__mro__[2].__subclasses__()}}",
                        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                    ],
                    "detection": [
                        "{{7*7}}",
                        "${7*7}",
                        "<%=7*7%>",
                    ],
                }
            },
            "CWE-284": {
                "name": "Access Control",
                "payloads": {
                    "role_bypass": ["admin", "root", "superuser"],
                    "path_bypass": ["../admin", "/admin"],
                }
            },
        }

        # Merge with existing payloads
        for cwe, data in extended.items():
            if cwe not in self._payloads:
                self._payloads[cwe] = data

    def get_payloads(self, cwe_id: str) -> List[AttackPayload]:
        """Get all attack payloads for a CWE."""
        payloads = self._load_payloads()
        cwe_normalized = normalize_cwe(cwe_id)

        result = []
        if cwe_normalized in payloads:
            cwe_data = payloads[cwe_normalized]
            cwe_name = cwe_data.get("name", "Unknown")

            for category, payload_list in cwe_data.get("payloads", {}).items():
                for payload in payload_list:
                    if payload:  # Skip None/empty
                        result.append(AttackPayload(
                            cwe=cwe_normalized,
                            category=category,
                            payload=str(payload),
                            description=f"{cwe_name} - {category}",
                            source="OWASP",
                        ))

        return result

    def get_payload_strings(self, cwe_id: str) -> List[str]:
        """Get just the payload strings for a CWE."""
        return [p.payload for p in self.get_payloads(cwe_id)]

    def get_available_cwes(self) -> List[str]:
        """Get list of CWEs with available payloads."""
        payloads = self._load_payloads()
        return sorted(payloads.keys())


class SecCodePLTHandler(BaseSourceHandler):
    """
    Handler for SecCodePLT dataset (Virtue-AI-HUB/SecCodePLT).

    Local parquet file: data/raw/insecure_coding-00000-of-00001.parquet
    Contains: 1,345 samples across 27 CWEs with both vulnerable and patched code.

    Phase 1: Only loads samples for CWEs that overlap with existing SecMutBench
    mutation operators (9 CWEs). Filters out samples requiring external dependencies.
    """

    PARQUET_FILENAME = "insecure_coding-00000-of-00001.parquet"

    # Expanded: all CWEs where we have mutation operators (49 total)
    SUPPORTED_CWES = {
        # Original
        "22", "78", "79", "94", "327", "352", "502", "611", "918",
        # Expanded coverage
        "20", "73", "77", "89", "90", "95", "113", "117",
        "200", "209", "215", "259", "284", "287", "295", "297", "306",
        "311", "319", "326", "328", "330", "331", "338", "346",
        "400", "434", "521", "522", "601", "639", "643",
        "776", "798", "862", "863", "942", "1004", "1333", "1336",
    }

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else Path("data/raw")
        self.parquet_path = self.cache_dir / self.PARQUET_FILENAME
        self._samples: Optional[List[ExternalSample]] = None

    def _parse_field(self, value):
        """Parse a field that may be a dict, string repr of dict, or JSON."""
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (json.JSONDecodeError, ValueError):
                try:
                    return eval(value)
                except Exception:
                    return {}
        return {}

    def _has_external_deps(self, install_requires) -> bool:
        """Check if sample requires external dependencies."""
        if install_requires is None:
            return False
        if isinstance(install_requires, str):
            try:
                install_requires = eval(install_requires)
            except Exception:
                return False
        # Handle numpy arrays and lists
        try:
            return len(install_requires) > 0
        except (TypeError, ValueError):
            return False

    def load_samples(self) -> List[ExternalSample]:
        """Load SecCodePLT samples from local parquet file."""
        if self._samples is not None:
            return self._samples

        if not self.parquet_path.exists():
            print(f"SecCodePLT parquet not found at {self.parquet_path}")
            self._samples = []
            return self._samples

        try:
            import pandas as pd
        except ImportError:
            print("Please install pandas: pip install pandas pyarrow")
            self._samples = []
            return self._samples

        df = pd.read_parquet(self.parquet_path)
        print(f"Loading SecCodePLT: {len(df)} total rows")

        self._samples = []
        skipped_cwe = 0
        skipped_deps = 0

        for _, row in df.iterrows():
            cwe_id = str(row.get("CWE_ID", ""))

            # Phase 1: skip unsupported CWEs
            if cwe_id not in self.SUPPORTED_CWES:
                skipped_cwe += 1
                continue

            # Skip samples with external dependencies
            if self._has_external_deps(row.get("install_requires")):
                skipped_deps += 1
                continue

            cwe = f"CWE-{cwe_id}"
            original_id = str(row.get("id", ""))

            # Parse nested fields
            ground_truth = self._parse_field(row.get("ground_truth", {}))
            task_desc = self._parse_field(row.get("task_description", {}))
            unittest_data = self._parse_field(row.get("unittest", {}))

            # Assemble full code from fragments
            code_before = ground_truth.get("code_before", "")
            code_after = ground_truth.get("code_after", "")
            vulnerable_code = ground_truth.get("vulnerable_code", "")
            patched_code = ground_truth.get("patched_code", "")

            if not vulnerable_code or not patched_code:
                continue

            # Assemble with proper newlines between fragments
            # Ensure each fragment ends cleanly before concatenation
            def safe_concat(*parts):
                """Concatenate code fragments with proper newline handling."""
                result = []
                for part in parts:
                    if not part:
                        continue
                    # Ensure fragment doesn't start/end with excess newlines
                    part = part.rstrip('\n')
                    if result and not result[-1].endswith('\n'):
                        result.append('\n')
                    result.append(part)
                return ''.join(result)

            # Setup code (imports, global variables the function depends on)
            # MUST be included before the function code
            setup_code = unittest_data.get("setup", "")

            # Include setup_code in assembled code (fixes NameError for BLOG_FORMAT, etc.)
            insecure_code = safe_concat(setup_code, code_before, vulnerable_code, code_after)
            secure_code = safe_concat(setup_code, code_before, patched_code, code_after)
            function_name = task_desc.get("function_name", "")
            description = task_desc.get("description", "")
            security_policy = task_desc.get("security_policy", "")

            # Build prompt from task description
            prompt = description if description else f"Implement {function_name}"

            self._samples.append(ExternalSample(
                id=hashlib.md5(f"seccodeplt_{original_id}".encode()).hexdigest()[:12],
                cwe=cwe,
                cwe_name=CWE_NAMES.get(cwe, "Unknown"),
                source="SecCodePLT",
                original_id=original_id,
                prompt=prompt,
                code=insecure_code,
                language="python",
                metadata={
                    "secure_code": secure_code,
                    "insecure_code": insecure_code,
                    "setup_code": setup_code,
                    "function_name": function_name,
                    "security_policy": security_policy,
                    "rule": str(row.get("rule", "")),
                    "use_rule": bool(row.get("use_rule", False)),
                },
            ))

        print(f"  Loaded {len(self._samples)} samples (skipped {skipped_cwe} unsupported CWEs, {skipped_deps} with external deps)")
        return self._samples

    def extract_by_cwe(self, cwe_id: str) -> List[ExternalSample]:
        """Extract samples for a specific CWE."""
        cwe_normalized = normalize_cwe(cwe_id)
        all_samples = self.load_samples()
        return [s for s in all_samples if s.cwe == cwe_normalized]

    def get_available_cwes(self) -> List[str]:
        """Get list of CWEs available in this dataset."""
        all_samples = self.load_samples()
        return sorted(set(s.cwe for s in all_samples))


class CWEvalHandler(BaseSourceHandler):
    """
    Handler for CWEval dataset (expert-verified task/test pairs).

    Local files: data/raw/CWE-eval/cwe_*_task.py and cwe_*_test.py
    Contains: 25 expert-verified pairs across 20 CWEs with unsafe variants.
    Each pair produces one sample per unsafe variant (~26 samples after filtering).
    """

    # CWEs without mutation operators — skip these
    SKIP_CWES = {"329", "377", "760", "943"}

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else Path("data/raw")
        self.cweval_dir = self.cache_dir / "CWE-eval"
        self._samples: Optional[List[ExternalSample]] = None

    def _parse_task_file(self, filepath: Path) -> Dict[str, Any]:
        """Parse a CWEval task file, extracting function name, imports, prompt, and secure code."""
        content = filepath.read_text()
        lines = content.split("\n")

        pair_id = filepath.stem.replace("_task", "")

        # Find function definition
        func_start_line = None
        func_name = None
        for i, line in enumerate(lines):
            match = re.match(r'^def\s+(\w+)\s*\(', line)
            if match:
                func_start_line = i
                func_name = match.group(1)
                break

        if func_start_line is None:
            raise ValueError(f"No function definition found in {filepath}")

        module_imports = "\n".join(lines[:func_start_line]).strip()

        # Find BEGIN SOLUTION marker
        solution_line = None
        for i, line in enumerate(lines):
            if "# BEGIN SOLUTION" in line:
                solution_line = i
                break

        if solution_line is None:
            raise ValueError(f"No # BEGIN SOLUTION marker in {filepath}")

        # Prompt = function signature + docstring
        prompt_lines = lines[func_start_line:solution_line]
        prompt = "\n".join(prompt_lines).rstrip()

        # Secure code = imports + full function
        func_lines = lines[func_start_line:]
        while func_lines and not func_lines[-1].strip():
            func_lines.pop()

        if module_imports:
            secure_code = module_imports + "\n\n\n" + "\n".join(func_lines)
        else:
            secure_code = "\n".join(func_lines)

        return {
            "pair_id": pair_id,
            "func_name": func_name,
            "module_imports": module_imports,
            "prompt": prompt,
            "secure_code": secure_code,
        }

    def _parse_test_file(self, filepath: Path) -> Dict[str, Any]:
        """Parse a CWEval test file, extracting CWE and unsafe function variants."""
        content = filepath.read_text()
        lines = content.split("\n")

        # Extract CWE from filename
        cwe_id = None
        fname_match = re.match(r'cwe_(\d+)', filepath.stem)
        if fname_match:
            cwe_id = f"CWE-{fname_match.group(1)}"

        # Fallback: extract from docstring
        if cwe_id is None:
            for line in lines[:10]:
                cwe_match = re.search(r'CWE-(\d+)', line)
                if cwe_match:
                    cwe_id = f"CWE-{cwe_match.group(1)}"
                    break

        # Parse AST to find unsafe functions
        import ast as ast_mod
        try:
            tree = ast_mod.parse(content)
        except SyntaxError as e:
            raise ValueError(f"Syntax error in {filepath}: {e}")

        unsafe_functions = []
        for node in ast_mod.iter_child_nodes(tree):
            if isinstance(node, ast_mod.FunctionDef) and "unsafe" in node.name:
                if node.name.startswith("test_"):
                    continue
                start = node.lineno - 1
                end = node.end_lineno
                func_source = "\n".join(lines[start:end])
                unsafe_functions.append({
                    "name": node.name,
                    "source": func_source,
                })

        return {
            "cwe_id": cwe_id,
            "unsafe_functions": unsafe_functions,
        }

    def load_samples(self) -> List[ExternalSample]:
        """Load all CWEval samples from local task/test file pairs."""
        if self._samples is not None:
            return self._samples

        self._samples = []

        if not self.cweval_dir.exists():
            print(f"CWEval directory not found at {self.cweval_dir}")
            return self._samples

        task_files = sorted(self.cweval_dir.glob("cwe_*_task.py"))
        if not task_files:
            print(f"No CWEval task files found in {self.cweval_dir}")
            return self._samples

        skipped_cwe = 0

        for task_path in task_files:
            pair_id = task_path.stem.replace("_task", "")
            test_path = task_path.parent / f"{pair_id}_test.py"

            if not test_path.exists():
                continue

            try:
                task_data = self._parse_task_file(task_path)
                test_data = self._parse_test_file(test_path)
            except (ValueError, SyntaxError):
                continue

            cwe_id = normalize_cwe(test_data["cwe_id"]) if test_data["cwe_id"] else None
            if not cwe_id:
                continue

            # Skip CWEs without mutation operators
            cwe_num = cwe_id.replace("CWE-", "")
            if cwe_num in self.SKIP_CWES:
                skipped_cwe += 1
                continue

            func_name = task_data["func_name"]

            # Create one sample per unsafe variant
            for variant_idx, uf in enumerate(test_data["unsafe_functions"]):
                unsafe_name = uf["name"]

                # Assemble insecure code: rename unsafe func to original name
                renamed_source = re.sub(
                    rf'def\s+{re.escape(unsafe_name)}\s*\(',
                    f'def {func_name}(',
                    uf["source"],
                )
                if task_data["module_imports"]:
                    insecure_code = task_data["module_imports"] + "\n\n\n" + renamed_source
                else:
                    insecure_code = renamed_source

                variant_suffix = unsafe_name.replace(func_name, "").strip("_") or "unsafe"
                sample_id_str = f"cweval_{pair_id}_{variant_suffix}_{variant_idx}"

                self._samples.append(ExternalSample(
                    id=hashlib.md5(sample_id_str.encode()).hexdigest()[:12],
                    cwe=cwe_id,
                    cwe_name=CWE_NAMES.get(cwe_id, "Unknown"),
                    source="CWEval",
                    original_id=pair_id,
                    prompt=task_data["prompt"],
                    code=insecure_code,
                    language="python",
                    metadata={
                        "secure_code": task_data["secure_code"],
                        "insecure_code": insecure_code,
                        "function_name": func_name,
                        "pair_id": pair_id,
                        "unsafe_variant": unsafe_name,
                    },
                ))

        print(f"  Loaded {len(self._samples)} CWEval samples (skipped {skipped_cwe} unsupported CWEs)")
        return self._samples

    def extract_by_cwe(self, cwe_id: str) -> List[ExternalSample]:
        """Extract samples for a specific CWE."""
        cwe_normalized = normalize_cwe(cwe_id)
        all_samples = self.load_samples()
        return [s for s in all_samples if s.cwe == cwe_normalized]

    def get_available_cwes(self) -> List[str]:
        """Get list of CWEs available in this dataset."""
        all_samples = self.load_samples()
        return sorted(set(s.cwe for s in all_samples))


class CodeQLHandler:
    """
    Handler for CodeQL query examples.

    Fetches security-related CodeQL queries that demonstrate
    vulnerability patterns for various CWEs.
    """

    CODEQL_BASE_URL = "https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security"

    # Map CWE to CodeQL query paths
    CWE_TO_CODEQL = {
        "CWE-89": "CWE-089/SqlInjection.ql",
        "CWE-78": "CWE-078/CommandInjection.ql",
        "CWE-22": "CWE-022/PathTraversal.ql",
        "CWE-79": "CWE-079/ReflectedXss.ql",
        "CWE-502": "CWE-502/UnsafeDeserialization.ql",
        "CWE-611": "CWE-611/Xxe.ql",
        "CWE-918": "CWE-918/ServerSideRequestForgery.ql",
        "CWE-1336": "CWE-094/CodeInjection.ql",  # SSTI often categorized under code injection
    }

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else Path("data/codeql_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_query_examples(self, cwe_id: str) -> List[str]:
        """
        Get CodeQL query examples for a CWE.

        Returns list of code patterns that the query detects.
        """
        cwe_normalized = normalize_cwe(cwe_id)

        if cwe_normalized not in self.CWE_TO_CODEQL:
            return []

        query_path = self.CWE_TO_CODEQL[cwe_normalized]
        cache_file = self.cache_dir / f"{cwe_normalized}.ql"

        # Try cache
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                content = f.read()
        else:
            # Fetch from GitHub
            try:
                import requests
                url = f"{self.CODEQL_BASE_URL}/{query_path}"
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                content = response.text

                # Cache it
                with open(cache_file, 'w') as f:
                    f.write(content)
            except Exception as e:
                print(f"Failed to fetch CodeQL query for {cwe_id}: {e}")
                return []

        # Extract code examples from query comments
        examples = self._extract_examples_from_query(content)
        return examples

    def _extract_examples_from_query(self, query_content: str) -> List[str]:
        """Extract code examples from CodeQL query comments."""
        examples = []

        # Look for example patterns in comments
        in_example = False
        current_example = []

        for line in query_content.split('\n'):
            # Start of example block
            if '```python' in line.lower() or '// bad' in line.lower():
                in_example = True
                continue

            # End of example block
            if in_example and ('```' in line or '// good' in line.lower()):
                if current_example:
                    examples.append('\n'.join(current_example))
                    current_example = []
                in_example = False
                continue

            # Collect example lines
            if in_example:
                # Remove comment prefix if present
                clean_line = re.sub(r'^//\s*', '', line)
                clean_line = re.sub(r'^\*\s*', '', clean_line)
                current_example.append(clean_line)

        return examples


class TemplateHandler:
    """
    Handler for existing SecMutBench templates.

    Loads pre-verified sample templates from generate_samples.py
    """

    def __init__(self, templates_module_path: Optional[str] = None):
        self.templates: Dict[str, List[Dict]] = {}
        self._load_templates()

    def _load_templates(self):
        """Load templates from the existing generate_samples module."""
        # Import templates from generate_samples.py
        import sys
        scripts_dir = Path(__file__).parent
        if str(scripts_dir) not in sys.path:
            sys.path.insert(0, str(scripts_dir))

        try:
            # Import the sample definitions
            from generate_samples import (
                CWE89_SAMPLES, CWE78_SAMPLES, CWE22_SAMPLES,
                CWE79_SAMPLES, CWE327_SAMPLES, CWE798_SAMPLES,
                CWE502_SAMPLES, CWE20_SAMPLES,
            )

            # Also try to import additional samples
            try:
                from generate_samples import (
                    CWE89_ADDITIONAL, CWE78_ADDITIONAL, CWE22_ADDITIONAL,
                    CWE79_ADDITIONAL, CWE327_ADDITIONAL, CWE798_ADDITIONAL,
                )
                self.templates = {
                    "CWE-89": CWE89_SAMPLES + CWE89_ADDITIONAL,
                    "CWE-78": CWE78_SAMPLES + CWE78_ADDITIONAL,
                    "CWE-22": CWE22_SAMPLES + CWE22_ADDITIONAL,
                    "CWE-79": CWE79_SAMPLES + CWE79_ADDITIONAL,
                    "CWE-327": CWE327_SAMPLES + CWE327_ADDITIONAL,
                    "CWE-798": CWE798_SAMPLES + CWE798_ADDITIONAL,
                    "CWE-502": CWE502_SAMPLES,
                    "CWE-20": CWE20_SAMPLES,
                }
            except ImportError:
                self.templates = {
                    "CWE-89": CWE89_SAMPLES,
                    "CWE-78": CWE78_SAMPLES,
                    "CWE-22": CWE22_SAMPLES,
                    "CWE-79": CWE79_SAMPLES,
                    "CWE-327": CWE327_SAMPLES,
                    "CWE-798": CWE798_SAMPLES,
                    "CWE-502": CWE502_SAMPLES,
                    "CWE-20": CWE20_SAMPLES,
                }

            print(f"Loaded templates for {len(self.templates)} CWEs")

        except ImportError as e:
            print(f"Could not load templates from generate_samples: {e}")
            self.templates = {}

    def get_templates(self, cwe_id: str) -> List[Dict]:
        """Get templates for a specific CWE."""
        cwe_normalized = normalize_cwe(cwe_id)
        return self.templates.get(cwe_normalized, [])

    def get_available_cwes(self) -> List[str]:
        """Get list of CWEs with templates."""
        return sorted(self.templates.keys())

    def get_template_count(self) -> Dict[str, int]:
        """Get count of templates per CWE."""
        return {cwe: len(templates) for cwe, templates in self.templates.items()}


class MultiSourceAggregator:
    """
    Aggregates samples from all sources.

    Provides unified interface for accessing samples from:
    - SecurityEval
    - CyberSecEval
    - OWASP Payloads
    - CodeQL Examples
    - Existing Templates
    """

    def __init__(self, cache_dir: str = "data/raw"):
        self.cache_dir = cache_dir

        # Initialize all handlers
        self.securityeval = SecurityEvalHandler(cache_dir)
        self.cyberseceval = CyberSecEvalHandler(cache_dir)
        self.owasp = OWASPPayloadHandler()
        self.codeql = CodeQLHandler()
        self.templates = TemplateHandler()

    def get_samples_for_cwe(self, cwe_id: str) -> Dict[str, Any]:
        """
        Get all available samples and resources for a CWE.

        Returns:
            Dict with samples from each source
        """
        cwe_normalized = normalize_cwe(cwe_id)

        return {
            "cwe": cwe_normalized,
            "cwe_name": CWE_NAMES.get(cwe_normalized, "Unknown"),
            "sources": {
                "securityeval": [s.to_dict() for s in self.securityeval.extract_by_cwe(cwe_normalized)],
                "cyberseceval": [s.to_dict() for s in self.cyberseceval.extract_by_cwe(cwe_normalized)],
                "templates": self.templates.get_templates(cwe_normalized),
            },
            "payloads": self.owasp.get_payload_strings(cwe_normalized),
            "codeql_examples": self.codeql.get_query_examples(cwe_normalized),
        }

    def get_all_external_samples(self, cwe_id: str) -> List[ExternalSample]:
        """Get all external samples (SecurityEval + CyberSecEval) for a CWE."""
        cwe_normalized = normalize_cwe(cwe_id)
        samples = []
        samples.extend(self.securityeval.extract_by_cwe(cwe_normalized))
        samples.extend(self.cyberseceval.extract_by_cwe(cwe_normalized))
        return samples

    def get_available_cwes(self) -> Dict[str, List[str]]:
        """Get available CWEs from each source."""
        return {
            "securityeval": self.securityeval.get_available_cwes(),
            "cyberseceval": self.cyberseceval.get_available_cwes(),
            "owasp": self.owasp.get_available_cwes(),
            "templates": self.templates.get_available_cwes(),
        }

    def get_coverage_summary(self) -> Dict[str, Any]:
        """Get summary of coverage across all sources."""
        se_cwes = set(self.securityeval.get_available_cwes())
        cse_cwes = set(self.cyberseceval.get_available_cwes())
        owasp_cwes = set(self.owasp.get_available_cwes())
        template_cwes = set(self.templates.get_available_cwes())

        all_cwes = se_cwes | cse_cwes | owasp_cwes | template_cwes

        coverage = []
        for cwe in sorted(all_cwes):
            coverage.append({
                "cwe": cwe,
                "name": CWE_NAMES.get(cwe, "Unknown"),
                "securityeval": len(self.securityeval.extract_by_cwe(cwe)),
                "cyberseceval": len(self.cyberseceval.extract_by_cwe(cwe)),
                "owasp_payloads": len(self.owasp.get_payloads(cwe)),
                "templates": len(self.templates.get_templates(cwe)),
            })

        return {
            "total_cwes": len(all_cwes),
            "coverage": coverage,
        }


def main():
    """Test the source handlers."""
    import argparse

    parser = argparse.ArgumentParser(description="Test source handlers")
    parser.add_argument("--cwe", default="CWE-89", help="CWE to test")
    parser.add_argument("--source", choices=["all", "securityeval", "cyberseceval", "owasp", "templates"],
                        default="all", help="Source to test")
    parser.add_argument("--summary", action="store_true", help="Show coverage summary")

    args = parser.parse_args()

    aggregator = MultiSourceAggregator()

    if args.summary:
        summary = aggregator.get_coverage_summary()
        print(f"\nCoverage Summary ({summary['total_cwes']} CWEs):")
        print("=" * 80)
        print(f"{'CWE':<10} {'Name':<35} {'SE':>4} {'CSE':>4} {'OWASP':>6} {'Templ':>6}")
        print("-" * 80)
        for item in summary['coverage']:
            print(f"{item['cwe']:<10} {item['name'][:35]:<35} "
                  f"{item['securityeval']:>4} {item['cyberseceval']:>4} "
                  f"{item['owasp_payloads']:>6} {item['templates']:>6}")
    else:
        print(f"\nFetching resources for {args.cwe}...")
        resources = aggregator.get_samples_for_cwe(args.cwe)

        print(f"\n{resources['cwe']}: {resources['cwe_name']}")
        print("=" * 60)

        print(f"\nSecurityEval samples: {len(resources['sources']['securityeval'])}")
        for s in resources['sources']['securityeval'][:2]:
            print(f"  - {s['original_id']}: {s['prompt'][:50]}...")

        print(f"\nCyberSecEval samples: {len(resources['sources']['cyberseceval'])}")
        for s in resources['sources']['cyberseceval'][:2]:
            print(f"  - {s['original_id']}: {s['prompt'][:50]}...")

        print(f"\nTemplates: {len(resources['sources']['templates'])}")
        for t in resources['sources']['templates'][:2]:
            print(f"  - {t.get('variant', 'unknown')}")

        print(f"\nOWASP Payloads: {len(resources['payloads'])}")
        for p in resources['payloads'][:5]:
            print(f"  - {p[:50]}...")

        print(f"\nCodeQL Examples: {len(resources['codeql_examples'])}")


if __name__ == "__main__":
    main()
