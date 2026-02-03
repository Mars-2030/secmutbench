# SecMutBench Documentation

**Date:** 2026-02-02
**Version:** 3.0
**Author:** SecMutBench Team

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [How SecMutBench Works](#how-secmutbench-works)
4. [Dataset Generation](#dataset-generation)
5. [CWE Coverage & Operators](#cwe-coverage--operators)
6. [Templates Deep Dive](#templates-deep-dive)
7. [Architecture & Package Structure](#architecture--package-structure)
8. [Mock Objects System](#mock-objects-system)
9. [Baseline Results](#baseline-results)
10. [File Structure](#file-structure)
11. [Changelog from V2.2](#changelog-from-v22)

---

## Overview

SecMutBench is a benchmark for evaluating how well Large Language Models (LLMs) can generate **security tests** that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

```
┌─────────────────────────────────────────────────────────────────┐
│                      SecMutBench Flow                           │
├─────────────────────────────────────────────────────────────────┤
│  Dataset → Prompt LLM → Generate Test → Mutation Testing → Score │
└─────────────────────────────────────────────────────────────────┘
```

### Key Features (V3.0)

- **Proper Python Package**: Install with `pip install -e .`
- **16 Core CWEs**: Consolidated from 74 to 16 high-quality CWEs with matching operators
- **279 Validated Samples**: All samples have mutation operators and 5+ samples per CWE
- **17 Mutation Operators**: Including new WEAKRANDOM operator for CWE-338
- **Quality Filtering**: Automatic filtering to ensure all samples can be mutation-tested
- **Auto-Calculated Baselines**: Reference test baselines computed live, not hardcoded
- **Improved Code Preprocessing**: Handles Python 2 syntax and indentation issues

### Dataset Summary (V3.0)

| Metric | Value |
|--------|-------|
| Total Samples | 279 |
| Unique CWEs | 16 |
| Mutation Operators | 17 |
| Difficulty Split | 25 easy, 178 medium, 76 hard |
| Sources | SecMutBench (70), CyberSecEval (170), SecurityEval (39) |

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/SecMutBench.git
cd SecMutBench

# Install as editable package
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"

# Install with LLM support
pip install -e ".[llm]"
```

### Generate Dataset

```bash
# Generate dataset (targets 500, filters to ~279 valid samples)
python scripts/dataset_builder.py --target 500

# Generate with full validation
python scripts/dataset_builder.py --target 500 --deep-validate

# Skip contamination prevention (faster)
python scripts/dataset_builder.py --target 500 --skip-contamination
```

### Run LLM Baseline Evaluation

```bash
# Run evaluation with Ollama model
python baselines/run_llm_baselines.py --provider ollama --model qwen2.5-coder:7b --samples 30

# Run with multiple models
python baselines/run_llm_baselines.py --provider ollama --model codestral:latest --samples 30
```

### Run Evaluation

```python
from evaluation.evaluate import load_benchmark, evaluate_generated_tests
from evaluation.mutation_engine import MutationEngine
from evaluation.test_runner import TestRunner

# Load dataset
dataset = load_benchmark("data/dataset.json")

# Evaluate a model's generated tests
results = evaluate_generated_tests(
    generated_tests="def test_sql_injection(): ...",
    sample=dataset["samples"][0]
)
```

### Verify Installation

```bash
# Test imports
python -c "from evaluation.mocks import MockDatabase; print('OK')"
python -c "from evaluation.mutation_engine import MutationEngine; print('OK')"
python -c "from evaluation.test_runner import TestRunner; print('OK')"
python -c "from operators.operator_registry import OPERATORS; print(f'{len(OPERATORS)} operators')"
```

---

## How SecMutBench Works

### Step 1: Dataset Preparation

The dataset (`data/dataset.json`) contains validated samples. Each sample has:

```json
{
  "id": "abc123",
  "cwe": "CWE-89",
  "cwe_name": "SQL Injection",
  "difficulty": "medium",
  "prompt": "Write a function to get user by ID",
  "entry_point": "get_user_by_id",
  "secure_code": "def get_user_by_id(id): ...",
  "insecure_code": "def get_user_by_id(id): ...",
  "security_tests": "def test_sql_injection(): ...",
  "functional_tests": "def test_basic(): ...",
  "mutation_operators": ["PSQLI", "RVALID"],
  "source": "SecMutBench"
}
```

---

### Step 2: Prompt the LLM

The model receives a prompt like:

```
You are a security testing expert. Generate pytest security tests
for the following code that may be vulnerable to CWE-89 (SQL Injection).

Code:
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))

Entry point: get_user

Generate comprehensive security tests that would detect if this
code were vulnerable to SQL injection.
```

---

### Step 3: LLM Generates Tests

The model (e.g., qwen2.5-coder:7b) generates:

```python
def test_sql_injection_prevention():
    """Test that SQL injection payloads are handled safely."""
    malicious_inputs = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1 UNION SELECT * FROM passwords"
    ]
    for payload in malicious_inputs:
        result = get_user(payload)
        assert "error" in str(result).lower() or result is None
```

---

### Step 4: Mutation Testing

This is the **core evaluation mechanism**.

#### 4a. Generate Mutants

The **MutationEngine** creates "mutants" - slightly modified versions of the secure code that introduce vulnerabilities:

```
Original (Secure):
    query = "SELECT * FROM users WHERE id = ?"
    db.execute(query, (user_id,))

Mutant 1 (Vulnerable - string concat):
    query = "SELECT * FROM users WHERE id = " + user_id
    db.execute(query)

Mutant 2 (Vulnerable - f-string):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    db.execute(query)

Mutant 3 (Vulnerable - no parameterization):
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    db.execute(query)
```

#### 4b. Run Tests Against Mutants

```
┌────────────────┐     ┌─────────────┐     ┌────────────┐
│ Generated Test │ --> │  Mutant 1   │ --> │   FAIL ✓   │  (killed)
│                │     │ (vulnerable)│     │            │
└────────────────┘     └─────────────┘     └────────────┘

┌────────────────┐     ┌─────────────┐     ┌────────────┐
│ Generated Test │ --> │  Mutant 2   │ --> │   PASS ✗   │  (survived)
│                │     │ (vulnerable)│     │            │
└────────────────┘     └─────────────┘     └────────────┘

┌────────────────┐     ┌─────────────┐     ┌────────────┐
│ Generated Test │ --> │  Mutant 3   │ --> │   FAIL ✓   │  (killed)
│                │     │ (vulnerable)│     │            │
└────────────────┘     └─────────────┘     └────────────┘
```

#### 4c. Calculate Mutation Score

```
Mutation Score = Killed Mutants / Total Mutants
               = 2 / 3
               = 66.7%
```

**Higher score = Better security tests**

---

### Step 5: Additional Checks

#### 5a. Vulnerability Detection Check

```
1. Run generated test on SECURE code   → Should PASS ✓
2. Run generated test on INSECURE code → Should FAIL ✓

If both conditions met → vuln_detected = True
```

#### 5b. Line Coverage

```
How much of the code did the tests execute?
Coverage = Lines Executed / Total Lines = 85%
```

---

### Step 6: Results Aggregation

All metrics combined:

```json
{
  "model": "qwen2.5-coder:7b",
  "sample_id": "abc123",
  "cwe": "CWE-89",
  "mutation_score": 0.67,
  "vuln_detected": true,
  "line_coverage": 0.85,
  "tests_count": 6
}
```

---

## Dataset Generation

### Overview

The dataset is built from **3 sources** using **3 consolidated modules**, with **quality filtering** to ensure all samples can be mutation-tested.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DATASET GENERATION PIPELINE (V3.0)               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐                                               │
│  │ source_ingestion │ ── Load from Templates, SecurityEval,        │
│  │       .py        │    CyberSecEval                               │
│  └────────┬─────────┘                                               │
│           │                                                         │
│           ▼                                                         │
│  ┌──────────────────┐                                               │
│  │ sample_generator │ ── Generate/transform samples, preprocess    │
│  │       .py        │    code (Python 2→3, dedent)                  │
│  └────────┬─────────┘                                               │
│           │                                                         │
│           ▼                                                         │
│  ┌──────────────────┐                                               │
│  │ dataset_builder  │ ── Orchestrate pipeline, validation,         │
│  │       .py        │    CWE filtering (operators + 5+ samples)    │
│  └────────┬─────────┘                                               │
│           │                                                         │
│           ▼                                                         │
│      dataset.json (279 samples, 16 CWEs)                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Command Line Options

```bash
python scripts/dataset_builder.py [OPTIONS]

Options:
  --target N            Target number of samples (default: 150)
  --output PATH         Output file path
  --splits-dir DIR      Directory for train/val/test splits
  --skip-contamination  Skip identifier renaming
  --skip-validation     Skip sample validation
  --deep-validate       Run comprehensive validation (Bandit + runtime)
  --validate-only       Only validate existing dataset
  --seed N              Random seed (default: 42)
```

### Pipeline Steps

1. **Generate samples from all sources** (366 raw samples)
2. **Select samples for balanced distribution**
3. **Apply contamination prevention** (identifier renaming)
4. **Validate samples** (syntax check, removes ~4 invalid)
5. **Filter to CWEs with operators and 5+ samples** (362 → 279)
6. **Fix remaining issues**
7. **Add quality metadata**
8. **Output final dataset**

### CWE Quality Filtering (V3.0 NEW)

The dataset builder now automatically filters samples to only include CWEs that:
1. Have a matching mutation operator in `CWE_OPERATOR_MAP`
2. Have at least 5 samples (configurable)

This ensures **all retained samples can be mutation-tested** and provides **statistically meaningful per-CWE results**.

```
Before filtering: 362 samples across 74 CWEs
After filtering:  279 samples across 16 CWEs
Removed: 57 CWEs (no operator or <5 samples)
```

---

## CWE Coverage & Operators

### Retained CWEs (V3.0)

| CWE | Name | Samples | Operator(s) |
|-----|------|---------|-------------|
| CWE-78 | Command Injection | 54 | CMDINJECT |
| CWE-94 | Code Injection (SSTI) | 30 | SSTI |
| CWE-89 | SQL Injection | 28 | PSQLI, RVALID |
| CWE-502 | Deserialization | 25 | DESERIAL |
| CWE-798 | Hardcoded Credentials | 24 | HARDCODE |
| CWE-328 | Weak Hash | 20 | WEAKCRYPTO |
| CWE-22 | Path Traversal | 15 | PATHCONCAT |
| CWE-79 | Cross-Site Scripting | 15 | RVALID, RHTTPO |
| CWE-338 | Weak PRNG | 14 | WEAKRANDOM |
| CWE-611 | XXE | 13 | XXE |
| CWE-20 | Input Validation | 8 | INPUTVAL, RVALID |
| CWE-918 | SSRF | 8 | SSRF |
| CWE-306 | Missing Authentication | 7 | RMAUTH |
| CWE-287 | Improper Authentication | 6 | RMAUTH |
| CWE-327 | Broken Crypto | 6 | WEAKCRYPTO |
| CWE-352 | CSRF | 6 | CSRF_REMOVE |

**Total: 279 samples across 16 CWEs**

### Mutation Operators (17 Total)

| Operator | Description | Target CWEs |
|----------|-------------|-------------|
| PSQLI | Parameterized SQL to string concat | CWE-89 |
| RVALID | Remove input validation | CWE-89, CWE-79, CWE-78, CWE-22, CWE-20 |
| INPUTVAL | Weaken input validation | CWE-20 |
| RHTTPO | Remove HttpOnly cookie flag | CWE-79, CWE-1004 |
| WEAKCRYPTO | Strong crypto to weak crypto | CWE-327, CWE-328 |
| HARDCODE | Environment vars to hardcoded | CWE-798, CWE-259 |
| RMAUTH | Remove authentication checks | CWE-287, CWE-306, CWE-862 |
| PATHCONCAT | Safe path to concat | CWE-22, CWE-73 |
| CMDINJECT | Array args to shell string | CWE-78, CWE-77 |
| RENCRYPT | Remove encryption | CWE-319, CWE-311 |
| DESERIAL | Safe deserialize to unsafe | CWE-502 |
| SSRF | Add SSRF vulnerability | CWE-918 |
| IDOR | Remove authorization checks | CWE-284, CWE-639 |
| XXE | Safe XML to vulnerable | CWE-611 |
| SSTI | Safe template to vulnerable | CWE-94, CWE-1336 |
| CORS_WEAK | Strict CORS to permissive | CWE-942, CWE-346 |
| CSRF_REMOVE | Remove CSRF protection | CWE-352 |
| **WEAKRANDOM** | Secure random to weak PRNG | **CWE-338, CWE-330, CWE-331** |

### WEAKRANDOM Operator (V3.0 NEW)

Transforms cryptographically secure random functions to weak PRNG:

```python
# Before (Secure)
token = secrets.token_bytes(32)
hex_token = secrets.token_hex(16)
api_key = secrets.token_urlsafe(32)

# After (Vulnerable - mutant)
token = random.randbytes(32)
hex_token = '%032x' % random.getrandbits(128)
api_key = base64.urlsafe_b64encode(random.randbytes(32)).rstrip(b'=').decode()
```

---

## Templates Deep Dive

Templates are the **core building blocks** for generating original SecMutBench samples. V3.0 adds **44 new templates** for high-priority CWEs.

### Template Structure

```python
{
    "prompt": "Task description for the LLM",
    "entry_point": "function_name",
    "insecure": "Vulnerable code implementation",
    "secure": "Fixed/safe code implementation",
    "difficulty": "easy|medium|hard"
}
```

### Template Counts by CWE (V3.0)

| CWE | V2.2 Templates | V3.0 Templates | Added |
|-----|----------------|----------------|-------|
| CWE-79 (XSS) | 4 | 13 | +9 |
| CWE-22 (Path Traversal) | 3 | 11 | +8 |
| CWE-287 (Authentication) | 1 | 6 | +5 |
| CWE-306 (Missing Auth) | 0 | 6 | +6 |
| CWE-352 (CSRF) | 1 | 6 | +5 |
| CWE-611 (XXE) | 1 | 7 | +6 |
| CWE-918 (SSRF) | 1 | 6 | +5 |
| **Total** | **~27** | **~71** | **+44** |

### Example Templates

#### CWE-79: XSS (13 templates)

```python
# Template: render_profile_card
# INSECURE
def render_profile_card(username, bio):
    return f"<div class='profile'><h3>{username}</h3><p>{bio}</p></div>"

# SECURE
import html
def render_profile_card(username, bio):
    return f"<div class='profile'><h3>{html.escape(username)}</h3><p>{html.escape(bio)}</p></div>"
```

#### CWE-306: Missing Authentication (6 templates)

```python
# Template: get_admin_dashboard
# INSECURE
def get_admin_dashboard():
    return {"users": db.count_users(), "revenue": db.get_total_revenue()}

# SECURE
def get_admin_dashboard(request):
    if not request.user or not request.user.is_admin:
        raise PermissionError("Admin access required")
    return {"users": db.count_users(), "revenue": db.get_total_revenue()}
```

#### CWE-338: Weak PRNG (via WEAKRANDOM operator)

```python
# SECURE (original)
import secrets
def generate_api_key():
    return secrets.token_urlsafe(32)

# INSECURE (mutant generated by WEAKRANDOM)
import random
import base64
def generate_api_key():
    return base64.urlsafe_b64encode(random.randbytes(32)).rstrip(b'=').decode()
```

---

## Architecture & Package Structure

### Package Installation (V3.0)

SecMutBench uses `pyproject.toml` for proper Python packaging:

```toml
[project]
name = "secmutbench"
version = "3.0.0"
requires-python = ">=3.9"

[project.optional-dependencies]
dev = ["pytest>=7.0.0", "bandit>=1.7.0"]
llm = ["openai>=1.0.0", "anthropic>=0.18.0", "ollama>=0.1.0"]
```

### Import Patterns

```python
# Evaluation modules (primary API)
from evaluation.evaluate import load_benchmark, evaluate_generated_tests
from evaluation.mutation_engine import MutationEngine
from evaluation.test_runner import TestRunner, run_tests

# Mock objects (for testing)
from evaluation.mocks import (
    MockDatabase,      # CWE-89: SQL injection
    MockFileSystem,    # CWE-22: Path traversal
    MockHTTPClient,    # CWE-918: SSRF
    MockXMLParser,     # CWE-611: XXE
    MockAuthenticator, # CWE-287: Authentication
    MockSubprocess,    # CWE-78: Command injection
    MockEnvironment,   # CWE-798: Hardcoded credentials
)

# Operators
from operators.operator_registry import (
    OPERATORS,           # All operator instances
    CWE_OPERATOR_MAP,    # CWE → operator mapping
    get_operators_for_cwe,
    get_applicable_operators,
)

# Dataset generation
from scripts.dataset_builder import DatasetBuilder
from scripts.sample_generator import SampleGenerator, preprocess_code
from scripts.source_ingestion import SourceManager
```

---

## Mock Objects System

### Overview

Mock objects simulate external dependencies for safe test execution. All mocks are consolidated in `evaluation/mocks/`.

### Mock Classes

| Mock Class | CWE | Purpose |
|------------|-----|---------|
| `MockDatabase` | CWE-89 | SQL database mock - tracks parameterization |
| `MockFileSystem` | CWE-22 | Filesystem mock - detects path traversal |
| `MockHTTPClient` | CWE-918 | HTTP client mock - detects SSRF attempts |
| `MockXMLParser` | CWE-611 | XML parser mock - detects XXE attacks |
| `MockAuthenticator` | CWE-287/306 | Auth mock - validates authentication |
| `MockSubprocess` | CWE-78 | Subprocess mock - detects command injection |
| `MockEnvironment` | CWE-798 | Environment mock - validates credential handling |

### SafeOS with MockEnvironment (V3.0 FIX)

The `SafeOS` class now properly uses `MockEnvironment` instead of real `os.environ`:

```python
class SafeOS:
    """Wrapper around os module that blocks command execution and uses mock environ."""
    _blocked = {'system', 'popen', 'spawn', ...}
    _real_os = __import__('os')

    def __init__(self, mock_environ=None):
        self._mock_environ = mock_environ

    def __getattr__(self, name):
        if name in self._blocked:
            raise PermissionError(f"os.{name}() blocked in sandbox")
        if name == 'environ' and self._mock_environ is not None:
            return self._mock_environ  # Use mock, not real environ!
        return getattr(self._real_os, name)
```

This fixes CWE-798 (hardcoded credentials) tests which depend on `KeyError` being raised for missing environment variables.

### SAFE_MODULES Whitelist (V3.0)

```python
SAFE_MODULES = {
    're', 'json', 'html', 'base64', 'urllib', 'urllib.parse', 'hmac',
    'secrets', 'ast', 'math', 'string', 'collections', 'itertools',
    'functools', 'operator', 'copy', 'types', 'datetime', 'time', 'random',
    'hashlib', 'typing', 'dataclasses', 'enum', 'abc',
    # Added in V3.0
    'shlex', 'pathlib', 'xml', 'xml.etree', 'xml.etree.ElementTree',
    'defusedxml', 'inspect'
}
```

---

## Baseline Results

### Reference Test Baseline (Auto-Calculated)

The reference test baseline is now computed live, not hardcoded:

| Metric | Value |
|--------|-------|
| Samples | 279 |
| Avg Mutation Score | 31.1% |
| Overall Mutation Score | 67.1% |
| Avg Vuln Detection | 6.8% |
| Avg Line Coverage | 19.8% |
| Total Mutants | 216 |
| Mutants Killed | 145 |

### LLM Baseline Comparison

| Metric | qwen2.5-coder:7b | codestral:latest |
|--------|------------------|------------------|
| Samples Evaluated | 30 | 30 |
| Avg Mutation Score | 20.0% | 20.0% |
| **Avg Vuln Detection** | **16.7%** | 3.3% |
| **Avg Line Coverage** | **38.5%** | 13.8% |
| Evaluation Time | 782s | 1300s |

**Key Finding**: qwen2.5-coder:7b significantly outperforms codestral:latest on vulnerability detection (5x better) and line coverage (2.8x better) despite same mutation scores.

---

## File Structure

```
SecMutBench/
│
├── pyproject.toml                 # Package configuration
├── README.md                      # Project documentation
├── DATASET_CARD.md                # HuggingFace dataset card
│
├── data/                          # === DATASET FILES ===
│   ├── dataset.json               # Main dataset (279 validated samples)
│   ├── samples.json               # HuggingFace-compatible format
│   │
│   ├── splits/                    # Difficulty-based splits
│   │   ├── easy.json              # 25 samples
│   │   ├── medium.json            # 178 samples
│   │   └── hard.json              # 76 samples
│   │
│   └── raw/                       # Original source data
│       ├── securityeval_raw.json
│       └── cyberseceval_raw.json
│
├── evaluation/                    # === CORE EVALUATION ENGINE ===
│   ├── __init__.py
│   ├── evaluate.py                # Main evaluation orchestrator
│   ├── mutation_engine.py         # Mutation testing engine
│   ├── test_runner.py             # Test execution framework (SafeOS fix)
│   ├── sample_validator.py        # Sample validation logic
│   ├── llm_judge.py               # LLM-as-judge evaluation
│   │
│   └── mocks/                     # === CONSOLIDATED MOCKS ===
│       ├── __init__.py            # Exports all mocks
│       ├── mock_database.py       # CWE-89: SQL injection
│       ├── mock_filesystem.py     # CWE-22: Path traversal
│       ├── mock_http.py           # CWE-918: SSRF
│       ├── mock_xml.py            # CWE-611: XXE
│       ├── mock_auth.py           # CWE-287: Authentication
│       ├── mock_subprocess.py     # CWE-78: Command injection
│       └── mock_environment.py    # CWE-798: Hardcoded credentials
│
├── operators/                     # === MUTATION OPERATORS ===
│   ├── __init__.py
│   ├── operator_registry.py       # Operator registration + CWE mapping
│   └── security_operators.py      # 17 security mutation operators
│
├── scripts/                       # === DATASET GENERATION ===
│   ├── dataset_builder.py         # Main orchestrator (CWE filtering)
│   ├── sample_generator.py        # Sample generation (preprocess_code)
│   ├── source_ingestion.py        # Source loading (71 templates)
│   ├── validate.py                # Dataset validation
│   └── contamination_prevention.py # Prevent data leakage
│
├── baselines/                     # === BASELINE EVALUATION ===
│   ├── run_llm_baselines.py       # LLM baseline runner
│   └── results/                   # Baseline results JSON files
│
└── docs/                          # === DOCUMENTATION ===
    ├── SECMUTBENCH_DOCUMENTATION_V3_2026-02-02.md  # This file
    └── SECMUTBENCH_DOCUMENTATION_V2_2026-02-01.md  # Previous version
```

---

## Changelog from V2.2

### V3.0 Changes (2026-02-02)

#### CWE Consolidation (Major)
- **Reduced from 74 CWEs to 16**: Only CWEs with mutation operators AND 5+ samples retained
- **Quality filtering**: Dataset builder now automatically filters unusable CWEs
- **Statistically meaningful**: All CWEs now have sufficient samples for per-CWE analysis
- **Paper-ready**: "362 collected, 279 retained after quality filtering"

#### New WEAKRANDOM Operator
- **Added operator for CWE-338** (Use of Cryptographically Weak PRNG)
- Transforms: `secrets.token_*` → `random.*`
- Transforms: `os.urandom()` → `random.randbytes()`
- Transforms: `SystemRandom()` → `Random()`
- Also covers CWE-330 and CWE-331

#### 44 New Templates
- CWE-79 (XSS): +9 templates (total 13)
- CWE-22 (Path Traversal): +8 templates (total 11)
- CWE-287 (Authentication): +5 templates (total 6)
- CWE-306 (Missing Auth): +6 templates (new)
- CWE-352 (CSRF): +5 templates (total 6)
- CWE-611 (XXE): +6 templates (total 7)
- CWE-918 (SSRF): +5 templates (total 6)

#### SafeOS Fix
- **Fixed MockEnvironment integration**: SafeOS now uses MockEnvironment instead of real `os.environ`
- **CWE-798 tests now work correctly**: KeyError raised for missing env vars
- **Reference test vuln detection improved**: From ~41% to 100%

#### Code Preprocessing
- **Added `preprocess_code()` function**: Handles external code issues
- Python 2 → Python 3 conversion (print statements, except syntax)
- Dedenting code with leading whitespace
- Wrapping still-indented code in function wrapper
- **Sample yield improved**: 193 → 318 samples before CWE filtering

#### Auto-Calculated Baselines
- **Reference baselines computed live**: No more hardcoded values
- **LLM baselines include reference comparison**: Automatic computation in `run_llm_baselines.py`

#### Operator Fixes
- **SSRF operator**: Fixed regex patterns to handle indentation
- **CMDINJECT operator**: Fixed to preserve f-string variable interpolation

#### Extended SAFE_MODULES
- Added: `shlex`, `pathlib`, `xml`, `xml.etree`, `xml.etree.ElementTree`, `defusedxml`, `inspect`
- Required for CWE-78, CWE-22, CWE-611 tests

---

## References

- [MITRE CWE](https://cwe.mitre.org/) - Common Weakness Enumeration
- [SecurityEval](https://huggingface.co/datasets/s2e-lab/SecurityEval) - HuggingFace Dataset
- [CyberSecEval](https://github.com/meta-llama/PurpleLlama) - Meta's PurpleLlama
- Gebru et al. (2021) - "Datasheets for Datasets"
