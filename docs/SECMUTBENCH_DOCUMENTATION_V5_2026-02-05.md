# SecMutBench Documentation

**Date:** 2026-02-05
**Version:** 5.0
**Author:** SecMutBench Team

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [How SecMutBench Works](#how-secmutbench-works)
4. [Architecture & Code Structure](#architecture--code-structure)
5. [Dataset Generation Pipeline](#dataset-generation-pipeline)
6. [Data Sources](#data-sources)
7. [Mutation Operators](#mutation-operators)
8. [Evaluation Engine](#evaluation-engine)
9. [Metrics](#metrics)
10. [CWEval Validation System](#cweval-validation-system)
11. [LLM Baseline Evaluation](#llm-baseline-evaluation)
12. [Static Analysis Baseline](#static-analysis-baseline)
13. [File Reference](#file-reference)
14. [Version History](#version-history)

---

## Overview

SecMutBench is a benchmark for evaluating how well Large Language Models (LLMs) generate **security tests** that detect vulnerabilities in code. Unlike benchmarks that assess secure code generation, SecMutBench focuses on **security test generation quality** evaluated through **mutation testing**.

The core idea: given secure code and a CWE category, an LLM generates security tests. Those tests are then evaluated by running them against **mutants** -- versions of the secure code with injected vulnerabilities. A test that detects the injected vulnerability (kills the mutant) demonstrates genuine security awareness. A test that only catches crashes does not.

### Current Dataset (V5.0)

| Metric | Value |
|--------|-------|
| Total Samples | 307 |
| Unique CWEs | 14 |
| Mutation Operators | 19 |
| Pre-generated Mutants | 774 |
| Difficulty Split | 24 easy / 208 medium / 75 hard |
| Sources | SecCodePLT (168), SecMutBench (61), CyberSecEval (59), SecurityEval (19) |

### Validation Dataset

| Metric | Value |
|--------|-------|
| Source | CWEval (expert-verified) |
| Total Samples | 32 |
| Unique CWEs | 20 (7 overlapping with main dataset) |
| Pre-generated Mutants | 55 |

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd SecMutBench

# Install as editable package
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"

# Install with LLM support
pip install -e ".[llm]"
```

### Build the Main Dataset

```bash
# Build dataset (targets 300 samples, filters to ~307 after quality checks)
python scripts/dataset_builder.py --target 300

# Validate existing dataset without rebuilding
python scripts/dataset_builder.py --validate-only

# Skip contamination prevention (faster)
python scripts/dataset_builder.py --target 300 --skip-contamination
```

### Build the CWEval Validation Dataset

```bash
# Parse CWEval pairs and generate data/validation.json
python scripts/build_validation_dataset.py

# Filter to a specific CWE
python scripts/build_validation_dataset.py --cwe CWE-78 --verbose
```

### Run CWEval Validation

```bash
# Run all three validation checks
python evaluation/validate_with_cweval.py

# Run individual checks
python evaluation/validate_with_cweval.py --checks mutation
python evaluation/validate_with_cweval.py --checks detection
python evaluation/validate_with_cweval.py --checks coverage

# Filter to a CWE with verbose output
python evaluation/validate_with_cweval.py --cwe CWE-78 --verbose
```

### Run LLM Baseline Evaluation

```bash
# Run with Ollama model
python baselines/run_llm_baselines.py --provider ollama --model qwen2.5-coder:7b --samples 30

# Run with --skip-invalid to filter bad samples
python baselines/run_llm_baselines.py --provider ollama --model codestral:latest --skip-invalid
```

### Run Static Analysis Baseline

```bash
# Run Bandit on full dataset
python baselines/run_static_analysis.py --tool bandit

# Run on subset with verbose output
python baselines/run_static_analysis.py --tool bandit --max-samples 100 --verbose

# Generate LaTeX table for paper
python baselines/run_static_analysis.py --tool bandit --latex

# Compare with mutation testing results
python baselines/run_static_analysis.py --tool bandit --compare-mutation results/model_results.json
```

### Evaluate Programmatically

```python
from evaluation.evaluate import load_benchmark, evaluate_generated_tests
from evaluation.mutation_engine import MutationEngine
from evaluation.test_runner import TestRunner

# Load dataset
dataset = load_benchmark("data/dataset.json")

# Evaluate a model's generated tests against a sample
results = evaluate_generated_tests(
    generated_tests="def test_sql_injection(): ...",
    sample=dataset[0]
)
```

### Verify Installation

```bash
python -c "from evaluation.mocks import MockDatabase; print('Mocks: OK')"
python -c "from evaluation.mutation_engine import MutationEngine; print('Engine: OK')"
python -c "from evaluation.test_runner import TestRunner; print('Runner: OK')"
python -c "from operators.operator_registry import OPERATORS; print(f'Operators: {len(OPERATORS)}')"
```

---

## How SecMutBench Works

### End-to-End Flow

```
                        SecMutBench Evaluation Flow

  ┌──────────┐    ┌───────────┐    ┌──────────────┐    ┌───────────────┐
  │  Dataset  │ -> │ Prompt    │ -> │ LLM Generates│ -> │ Mutation      │
  │  Sample   │    │ the LLM   │    │ Security Test│    │ Testing       │
  └──────────┘    └───────────┘    └──────────────┘    └───────┬───────┘
                                                               │
                                                               ▼
                                                       ┌───────────────┐
                                                       │ Metrics:      │
                                                       │ - SMS         │
                                                       │ - Vuln Det.   │
                                                       │ - Sec. Prec.  │
                                                       └───────────────┘
```

### Step 1: Dataset Sample

Each sample provides:
- **Secure code**: A correct, vulnerability-free implementation
- **Insecure code**: The same function with a known vulnerability
- **CWE**: The vulnerability category (e.g., CWE-89 SQL Injection)
- **Pre-generated mutants**: Secure code with injected vulnerabilities
- **Reference tests**: Baseline security and functional tests

### Step 2: Prompt the LLM

The model receives the secure code, CWE category, and entry point name. It must generate pytest-compatible security tests that would detect if the code were vulnerable.

```
You are a security testing expert. Generate pytest security tests
for the following code that may be vulnerable to CWE-89 (SQL Injection).

Code:
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))

Entry point: get_user
```

### Step 3: Mutation Testing

The core evaluation mechanism. Pre-generated mutants are versions of the secure code with injected vulnerabilities:

```
Original (Secure):                          Mutant (Vulnerable):
  query = "SELECT * FROM users              query = "SELECT * FROM users
           WHERE id = ?"                             WHERE id = " + user_id
  db.execute(query, (user_id,))             db.execute(query)
```

Each mutant is tested:
1. Run tests on **secure code** -- tests should **pass**
2. Run tests on **mutant code** -- tests should **fail** (kill the mutant)

### Step 4: Operator-Aware Kill Classification

When a test kills a mutant, the kill is classified using **operator-aware heuristics** (V5.0):

| Kill Type | Meaning | Counts Toward SMS? |
|-----------|---------|-------------------|
| **Semantic** | Test assertion detects vulnerability using operator-specific terms | Yes |
| **Assertion Incidental** | Assertion fails but not with operator-relevant security terms | No |
| **Crash** | Code crashes (ImportError, TypeError, etc.) | No |

**V5.0 Improvement**: Kill classification now uses operator-specific security patterns instead of a flat list. For example, "path" only triggers semantic classification for `PATHCONCAT` mutants, not for `PSQLI` mutants. This prevents false inflation of SMS scores.

### Step 5: Scoring

```
Mutation Score (MS)          = All kills / Total mutants
Security Mutation Score (SMS) = Semantic kills / Total mutants
Crash Score                  = Crash kills / Total mutants
Vuln Detection (VD)          = Tests pass on secure AND fail on insecure (binary)
Security Precision (SP)      = VD count / Secure passes count
```

**Higher SMS = Better security tests.** MS alone is misleading because crash kills inflate the score.

### VD Metric Clarification

**Important:** SecMutBench uses **secure-vs-insecure VD** (also called "ground truth validation"):

```
VD = 1 if (tests pass on secure code AND tests fail on insecure code) else 0
```

This is a **binary per-sample metric** that validates the test can distinguish the original secure implementation from the original insecure implementation provided in the dataset.

This is **different from mutant-based VD** sometimes used in mutation testing literature:

```
VD_mutant = vulnerability-injecting mutants killed / total mutants
```

In SecMutBench, since ALL mutants inject vulnerabilities (that's the benchmark's purpose), mutant-based VD would be equivalent to Mutation Score (MS). We therefore report:

| Metric | Definition | Use |
|--------|------------|-----|
| **MS** | All kills / mutants | Overall kill rate (includes crashes) |
| **SMS** | Semantic kills / mutants | Security-aware test quality (excludes crashes) |
| **VD** | Pass-secure ∧ Fail-insecure | Ground truth sanity check |

**What we report:** The `avg_vuln_detection` in results is the proportion of samples where VD=1 (i.e., the test correctly distinguishes secure from insecure code). This is a sanity check, not a mutation-based metric.

---

## Architecture & Code Structure

### Package Layout

```
SecMutBench/
├── pyproject.toml                    # Package config (pip install -e .)
│
├── data/                             # Datasets
│   ├── dataset.json                  # Main dataset (307 samples, 774 mutants)
│   ├── validation.json               # CWEval validation dataset (32 samples)
│   ├── splits/                       # Difficulty-based splits
│   │   ├── easy.json                 #   24 samples
│   │   ├── medium.json               #   208 samples
│   │   └── hard.json                 #   75 samples
│   └── raw/                          # Source data files
│       ├── CWE-eval/                 #   25 CWEval task/test pairs (48 files)
│       ├── insecure_coding-*.parquet #   SecCodePLT (1,345 rows)
│       ├── securityeval_raw.json     #   SecurityEval
│       └── cyberseceval_raw.json     #   CyberSecEval
│
├── evaluation/                       # Core evaluation engine
│   ├── evaluate.py                   # Orchestrator: evaluate_generated_tests()
│   ├── mutation_engine.py            # MutationEngine: generate_mutants()
│   ├── test_runner.py                # TestRunner: subprocess+pytest isolation
│   ├── conftest_template.py          # CONFTEST_TEMPLATE: mock injection
│   ├── metrics.py                    # All metric calculations
│   ├── validate_with_cweval.py       # CWEval validation (3 checks)
│   ├── attack_vectors.py             # CWE attack patterns (13 CWEs)
│   ├── mocks/                        # Mock objects for safe test execution
│   │   ├── __init__.py               #   Exports all mocks
│   │   ├── mock_database.py          #   MockDatabase (CWE-89)
│   │   ├── mock_filesystem.py        #   MockFileSystem (CWE-22)
│   │   ├── mock_http.py              #   MockHTTPClient (CWE-918)
│   │   ├── mock_subprocess.py        #   MockSubprocess (CWE-78)
│   │   ├── mock_deserializer.py      #   MockPickle, MockYAML (CWE-502)
│   │   └── ...                       #   MockCrypto, MockAuth, MockEnvironment
│   └── attack_vectors.py             # Attack payload definitions
│
├── operators/                        # Mutation operators
│   ├── __init__.py                   # Exports OPERATORS, get_applicable_operators
│   ├── operator_registry.py          # OPERATORS dict, CWE_OPERATOR_MAP
│   └── security_operators.py         # 19 operator classes
│
├── scripts/                          # Dataset generation
│   ├── dataset_builder.py            # DatasetBuilder: orchestrates full pipeline
│   ├── sample_generator.py           # SampleGenerator: transforms raw -> Sample
│   ├── source_ingestion.py           # SourceManager: loads all data sources
│   ├── source_handlers.py            # Handler classes per source
│   ├── build_validation_dataset.py   # Builds data/validation.json from CWEval
│   └── contamination_prevention.py   # Identifier renaming for decontamination
│
├── baselines/                        # Baseline evaluations
│   ├── run_llm_baselines.py          # Multi-model LLM evaluation runner
│   ├── run_static_analysis.py        # Bandit/Semgrep baseline (V5.0)
│   └── results/                      # Saved baseline results
│
├── results/                          # Validation outputs
│   ├── cweval_validation.json        # CWEval validation report
│   └── static_analysis_baseline.json # Static analysis results
│
└── docs/                             # Documentation
```

### Key Import Patterns

```python
# Evaluation (primary API)
from evaluation.evaluate import load_benchmark, evaluate_generated_tests, classify_kill
from evaluation.mutation_engine import MutationEngine, Mutant, MutationResult
from evaluation.test_runner import TestRunner, TestSuiteResult, TestResult
from evaluation.metrics import calculate_kill_breakdown, calculate_security_precision

# Operators
from operators.operator_registry import OPERATORS, CWE_OPERATOR_MAP

# Mock objects (for understanding test environment)
from evaluation.mocks import MockDatabase, MockSubprocess, MockHTTPClient

# Dataset generation
from scripts.source_ingestion import SourceManager, CWE_REGISTRY
from scripts.sample_generator import SampleGenerator, Sample
```

---

## Dataset Generation Pipeline

The main dataset is built by `scripts/dataset_builder.py` which orchestrates a multi-step pipeline.

### Pipeline Diagram

```
  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
  │  Source Ingestion │     │ Sample Generator  │     │  Dataset Builder │
  │                  │     │                  │     │                  │
  │  Templates (71)  │     │  from_template() │     │  _select_samples │
  │  SecurityEval    │ --> │  from_external() │ --> │  _fix_samples    │
  │  CyberSecEval    │     │  from_sec_code_  │     │  _final_valid.   │
  │  SecCodePLT      │     │    plt()         │     │  _pregen_mutants │
  └──────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                             │
                                                     data/dataset.json
                                                     data/splits/*.json
```

### Pipeline Steps (9 steps)

| Step | Action | Example Output |
|------|--------|---------------|
| 1 | Generate samples from all sources | ~500 raw samples |
| 2 | Select for balanced CWE distribution | ~300 selected |
| 3 | Apply contamination prevention | Identifier renaming |
| 4 | Validate samples (syntax check) | Removes ~4 invalid |
| 5 | Filter to CWEs with operators + 5 samples | 307 across 14 CWEs |
| 6 | Fix issues (add assertions, regen tests) | Applied fixes |
| 7 | Final validation (operators fire, no tautologies) | Drop non-functional |
| 7.5 | Pre-generate mutants (up to 10 per sample) | 774 mutants |
| 8 | Add quality metadata | Quality levels assigned |

### Sample Schema

Each sample in `data/dataset.json`:

```json
{
  "id": "d07ded395aff",
  "cwe": "CWE-89",
  "cwe_name": "SQL Injection",
  "difficulty": "easy",
  "prompt": "Write a function to get user by ID from database",
  "entry_point": "get_user_by_id",
  "insecure_code": "def get_user_by_id(user_id): ...",
  "secure_code": "def get_user_by_id(user_id): ...",
  "functional_tests": "def test_basic(): ...",
  "security_tests": "def test_sql_injection(): ...",
  "mutation_operators": ["PSQLI"],
  "source": "SecMutBench",
  "original_id": "CWE-89_get_user_by_id",
  "quality": {
    "quality_level": "curated",
    "validation_passed": true,
    "confidence": 0.95,
    "...": "..."
  },
  "mutants": [
    {
      "id": "fd1834de",
      "operator": "PSQLI",
      "description": "Replaced parameterized query with f-string",
      "mutated_code": "def get_user_by_id(user_id): ..."
    }
  ]
}
```

### CLI Options

```bash
python scripts/dataset_builder.py [OPTIONS]

  --target N              Target number of samples (default: 150)
  --output PATH           Output file path (default: data/dataset.json)
  --splits-dir DIR        Splits directory (default: data/splits)
  --skip-contamination    Skip identifier renaming
  --skip-validation       Skip sample validation
  --deep-validate         Run comprehensive validation (Bandit + runtime)
  --validate-only         Only validate existing dataset
  --seed N                Random seed (default: 42)
```

---

## Data Sources

SecMutBench consolidates samples from four external sources plus internal templates.

### Source Summary

| Source | Type | Samples in Dataset | Description |
|--------|------|-------------------|-------------|
| **SecCodePLT** | Parquet file | 168 | Virtue-AI-HUB/SecCodePLT from HuggingFace. 1,345 total rows, filtered to 9 overlapping CWEs, external-dep samples excluded. Ground-truth secure/insecure pairs. |
| **SecMutBench** | Templates | 61 | 71 hand-crafted templates across 16 CWE categories in `source_ingestion.py`. Each template has secure/insecure code pairs. |
| **CyberSecEval** | HuggingFace | 59 | Meta's PurpleLlama CyberSecEval dataset. Autocomplete-style samples with insecure completions. |
| **SecurityEval** | HuggingFace | 19 | s2e-lab/SecurityEval dataset. Prompt-based security coding challenges. |
| **CWEval** | Local files | 0 (validation only) | 25 expert-verified task/test pairs used as validation oracle, not in main dataset. |

### Source Handlers

Each source has a dedicated handler class in `scripts/source_handlers.py`:

| Handler Class | Source | Key Method |
|---------------|--------|-----------|
| `SecurityEvalHandler` | SecurityEval | `load_samples()`, `extract_by_cwe()` |
| `CyberSecEvalHandler` | CyberSecEval | `load_samples()`, `extract_by_cwe()` |
| `SecCodePLTHandler` | SecCodePLT | `load_samples()`, `extract_by_cwe()` |
| `OWASPPayloadHandler` | OWASP | `get_payloads()`, `get_payload_strings()` |

All handlers inherit from `BaseSourceHandler` and return `ExternalSample` dataclass instances.

### SecCodePLT Integration Details

SecCodePLT provides both `vulnerable_code` and `patched_code` via a `ground_truth` field, avoiding the need for LLM-based secure code generation. Phase 1 integrates 9 overlapping CWEs where mutation operators already exist:

```
Supported CWEs: 22, 78, 79, 94, 327, 352, 502, 611, 918
Loaded: 412 samples (880 unsupported CWEs, 53 external deps filtered)
After pipeline: 168 samples in final dataset
```

### CWE Registry

The single source of truth for CWE-to-operator mappings lives in `scripts/source_ingestion.py`:

```python
CWE_REGISTRY = {
    "CWE-89":  {"name": "SQL Injection",       "operators": ["PSQLI", "RVALID"],    "tier": 1},
    "CWE-79":  {"name": "XSS",                 "operators": ["RVALID", "RHTTPO"],   "tier": 1},
    "CWE-78":  {"name": "Command Injection",    "operators": ["CMDINJECT", "RVALID"],"tier": 1},
    "CWE-22":  {"name": "Path Traversal",       "operators": ["PATHCONCAT", "RVALID"],"tier": 1},
    "CWE-20":  {"name": "Input Validation",     "operators": ["INPUTVAL", "RVALID", "SUBDOMAIN_SPOOF"], "tier": 1},
    "CWE-502": {"name": "Deserialization",      "operators": ["DESERIAL"],           "tier": 2},
    "CWE-327": {"name": "Weak Cryptography",    "operators": ["WEAKCRYPTO"],         "tier": 2},
    "CWE-918": {"name": "SSRF",                 "operators": ["SSRF", "SUBDOMAIN_SPOOF"], "tier": 3},
    # ... 24 total CWE entries
}
```

---

## Mutation Operators

### Overview

Mutation operators transform secure code into vulnerable code by injecting realistic vulnerability patterns. Each operator targets specific CWE categories.

### Operator Registry (19 Operators)

| Operator | Description | Target CWEs | Samples |
|----------|-------------|-------------|---------|
| **PSQLI** | Parameterized SQL to string concat | CWE-89 | 5 |
| **RVALID** | Remove input validation | CWE-20, 79, 89, 22, 78 | 65 |
| **INPUTVAL** | Weaken input validation checks | CWE-20 | 8 |
| **SUBDOMAIN_SPOOF** | Remove domain/subdomain validation (V5.0) | CWE-20, CWE-918 | -- |
| **RHTTPO** | Remove HttpOnly cookie flag | CWE-79 | -- |
| **WEAKCRYPTO** | Strong crypto to weak (SHA256->MD5) | CWE-327, 328 | 35 |
| **HARDCODE** | Environment vars to hardcoded secrets | CWE-798 | 20 |
| **RMAUTH** | Remove authentication/authorization checks | CWE-287, 306, 862 | 8 |
| **PATHCONCAT** | Safe path resolution to string concat | CWE-22, 73 | 68 |
| **CMDINJECT** | Array args to shell=True string | CWE-78, 77 | 32 |
| **RENCRYPT** | Remove encryption/TLS checks | CWE-319, 311 | 5 |
| **DESERIAL** | safe_load to load, json to pickle, YAML gadget patterns | CWE-502, 94 | 53 |
| **SSRF** | Add SSRF vulnerability | CWE-918 | 7 |
| **IDOR** | Remove authorization/ownership checks | CWE-639, 284 | -- |
| **XXE** | defusedxml to xml.etree | CWE-611 | 13 |
| **SSTI** | Safe template rendering to eval | CWE-94, 1336 | -- |
| **CORS_WEAK** | Strict CORS to permissive wildcard | CWE-942 | -- |
| **CSRF_REMOVE** | Remove CSRF token validation | CWE-352 | 7 |
| **WEAKRANDOM** | secrets.token_* to random.* | CWE-338 | -- |

### New in V5.0: SUBDOMAIN_SPOOF Operator

Removes subdomain/domain validation checks, enabling URL spoofing attacks:

```python
# Input (secure):
if not url.endswith('.example.com'):
    raise ValueError("Invalid domain")
return requests.get(url)

# Output (mutant - vulnerable):
return requests.get(url)  # No domain validation
```

Difficulty levels:
- **Easy**: Remove `endswith('.domain.com')` or `allowed_domains` checks
- **Medium**: Remove `netloc` or `hostname` validation
- **Hard**: Replace `validate_domain()` with `True`, remove compound validation

### Extended in V5.0: DESERIAL Operator

Now handles YAML gadget patterns:

```python
# Additional mutations:
- SafeLoader → Loader/UnsafeLoader/FullLoader
- Remove Loader restriction from yaml.load()
- Remove !!python tag validation
```

### How Operators Work

Each operator implements:

```python
class SecurityMutationOperator(ABC):
    def applies_to(self, code: str) -> bool:
        """Check if this operator can mutate the given code."""

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        """Return list of (mutated_code, description) pairs."""
```

### Example: PSQLI Operator

```python
# Input (secure):
query = "SELECT * FROM users WHERE id = ?"
db.execute(query, (user_id,))

# Output (mutant - vulnerable):
query = f"SELECT * FROM users WHERE id = {user_id}"
db.execute(query)
```

### Example: CMDINJECT Operator

```python
# Input (secure):
subprocess.run(["ping", "-c", "1", hostname], capture_output=True)

# Output (mutant - vulnerable):
subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
```

### Pre-generated Mutants

Mutants are pre-generated during dataset build (Step 7.5) and stored in each sample's `mutants` array. This ensures:
- **Deterministic evaluation**: Same mutants across all evaluation runs
- **Reproducibility**: No variation from operator application order
- **Efficiency**: No mutation generation needed at evaluation time

At evaluation time, `evaluate_generated_tests()` loads pre-generated mutants when available, with fallback to runtime generation for backward compatibility.

---

## Evaluation Engine

### Test Runner (subprocess + pytest)

Tests are executed in isolated subprocesses, not via `exec()`. Each `run_tests()` call:

1. Creates a temp directory
2. Writes `target_module.py` (the code under test)
3. Writes `test_generated.py` with `from target_module import *` preamble
4. Writes `conftest.py` from `CONFTEST_TEMPLATE` (mock injection + safety layer)
5. Runs `subprocess.run([python, -m, pytest, ...])` with `PYTHONPATH` set
6. Parses structured JSON results from `ResultCollector` plugin

### Mock Injection via Conftest

The `CONFTEST_TEMPLATE` in `evaluation/conftest_template.py` handles:

**Builtins injection** -- Mock objects are injected into Python's `builtins` namespace, making them available via name resolution (local -> enclosing -> global -> **builtin**) without explicit imports:

```python
builtins.db = MockDatabase()           # CWE-89
builtins.subprocess = MockSubprocess() # CWE-78
builtins.requests = MockHTTPClient()   # CWE-918
builtins.hashlib = MockCrypto()        # CWE-327
builtins.pickle = MockPickle()         # CWE-502
builtins.yaml = MockYAML()             # CWE-502
builtins.os = SafeOS(real_os)          # Blocked: system, popen, exec*
```

**sys.modules patching** -- `import subprocess` returns the mock, not the real module:

```python
sys.modules["subprocess"] = _mock_subprocess
sys.modules["requests"] = _mock_http
sys.modules["hashlib"] = _mock_crypto
sys.modules["pickle"] = _mock_pickle
sys.modules["yaml"] = _mock_yaml
sys.modules["os"] = _safe_os
```

**Standard library not blocked** -- Real imports work for: `re`, `json`, `html`, `base64`, `urllib`, `hmac`, `secrets`, `ast`, `math`, `string`, `collections`, `itertools`, `functools`, `typing`, `dataclasses`, `pathlib`.

### SafeOS Wrapper

Blocks dangerous operations while allowing safe `os.path` usage:

```python
class SafeOS:
    _blocked = {"system", "popen", "execl", "execve", "fork", ...}

    def __getattr__(self, name):
        if name in self._blocked:
            raise PermissionError(f"os.{name}() blocked in sandbox")
        if name == "environ":
            return self._mock_environ  # MockEnvironment, not real environ
        return getattr(self._real_os, name)
```

### Operator-Aware Kill Classification (V5.0)

`classify_kill()` in `evaluate.py` now accepts an operator parameter for context-aware classification:

```python
def classify_kill(error: str, operator: str = None) -> str:
    """
    Classify kill type using operator-specific security patterns.

    Args:
        error: The error message from the failing test
        operator: The mutation operator (e.g., "PSQLI", "PATHCONCAT")
    """
```

**Operator-Specific Patterns:**

| Operator | Security Keywords |
|----------|------------------|
| PSQLI | parameterized, prepared, sql, inject, last_params |
| CMDINJECT | shell, command, subprocess, shlex, last_shell |
| PATHCONCAT | traversal, ../, path, base_dir, realpath, startswith |
| WEAKCRYPTO | md5, sha1, weak.*algorithm, bcrypt, salt, iteration |
| DESERIAL | pickle, deserial, yaml, safe_load, SafeLoader |
| SUBDOMAIN_SPOOF | subdomain, domain, host, url, endswith, validate.*url |

**Classification Logic:**

| Classification | Criteria | Example |
|---------------|----------|---------|
| **semantic** | Error contains operator-specific security terms | `AssertionError: SQL query not parameterized` (PSQLI) |
| **assertion_incidental** | AssertionError without operator-relevant terms | `AssertionError: expected 5 got 3` |
| **crash** | Non-assertion error | `TypeError: unsupported operand` |

---

## Metrics

All metric calculations live in `evaluation/metrics.py`.

### Primary Metrics

| Metric | Formula | Purpose |
|--------|---------|---------|
| **Mutation Score (MS)** | killed / total | Overall test effectiveness (includes crashes) |
| **Security Mutation Score (SMS)** | semantic_kills / total | Genuine security test quality |
| **Crash Score** | crash_kills / total | Crash-driven inflation indicator |
| **Vuln Detection (VD)** | passes_secure ∧ fails_insecure | Ground truth sanity check (binary, per-sample)¹ |
| **Security Precision (SP)** | vuln_detected / secure_passes | Precision of passing tests |

¹ **VD is NOT mutant-based.** It checks whether the test distinguishes the original secure/insecure code pair—a sanity check that the test is functional. Mutant-based detection is captured by MS and SMS. See "VD Metric Clarification" in Section 3.

### Aggregation Functions

```python
calculate_mutation_score(killed, total, equivalent)  # Per-sample MS
calculate_kill_breakdown(sample_results)              # SMS, crash, incidental
calculate_security_precision(sample_results)          # SP metric
aggregate_by_cwe(sample_results)                      # Per-CWE breakdown
aggregate_by_difficulty(sample_results)               # Per-difficulty breakdown
aggregate_by_operator(sample_results)                 # Per-operator breakdown
```

### Low-n Confidence Flags

`aggregate_by_cwe()` adds `"low_confidence": True` when a CWE has fewer than 5 samples. The report output appends `[!low-n]` to flagged CWEs. This prevents over-interpreting per-CWE results from small sample sizes.

---

## CWEval Validation System

### Purpose

CWEval provides 25 expert-verified Python task/test pairs across 20 CWEs. These are used as a **validation oracle** to assess SecMutBench's pipeline quality -- they are NOT part of the main dataset.

The validation system consists of two scripts:

1. **`scripts/build_validation_dataset.py`** -- Parses CWEval pairs into `data/validation.json`
2. **`evaluation/validate_with_cweval.py`** -- Runs three validation checks

### CWEval Data Format

Each CWEval pair consists of:

**Task file** (`cwe_XXX_Y_task.py`):
- Single function with docstring
- `# BEGIN SOLUTION` marker
- Secure implementation after the marker

**Test file** (`cwe_XXX_Y_test.py`):
- CWE docstring and CodeQL URL
- One or more `_unsafe` function variants (known vulnerabilities)
- `pytest_params_functionality` -- correct behavior test cases
- `pytest_params_security` -- attack vectors the secure version blocks
- Three test functions: secure (all params), unsafe functionality, unsafe security

### Three Validation Checks

#### Check 1: Mutation Operator Sanity

For each overlapping validation sample:
1. Compute diff: secure_code -> each mutant (our mutation operators)
2. Compute diff: secure_code -> insecure_code (CWEval's known vulnerability)
3. Compare using CWE-specific vulnerability fingerprints and `difflib.SequenceMatcher`
4. Report whether at least one mutant introduces the same vulnerability class

**Fingerprints** (expanded in V5.0):

| CWE | Patterns |
|-----|----------|
| CWE-78 | `shell=True`, `os.system`, `subprocess.call.*shell`, `Popen.*shell` |
| CWE-22 | `../`, string concat paths, f-string paths |
| CWE-89 | f-string SELECT, .format() SQL, string + WHERE |
| CWE-502 | `yaml.load`, `pickle.loads`, `UnsafeLoader`, `FullLoader`, `eval()` |
| CWE-611 | `resolve_entities=True`, `XMLParser()`, `xml.etree` |
| CWE-798 | `password = "..."`, `secret = "..."`, hardcoded values |
| CWE-338 | `random.random`, `random.randint`, non-SystemRandom |

#### Check 2: Vulnerability Detection Ground Truth

**Phase A** (CWEval expert tests as baseline):
1. Run expert tests against secure code -> expect ALL PASS
2. Run expert tests against insecure code -> expect security tests FAIL
3. If both hold, ground truth is established

**Phase B** (SecMutBench pipeline comparison):
1. Find main dataset samples matching same CWE
2. Run their security tests against CWEval's secure/insecure code (with mock environment)
3. Report whether SecMutBench tests detect the same vulnerability

#### Check 3: Attack Vector Coverage

For each overlapping CWE:
1. Extract attack categories from CWEval test source
2. Extract attack categories from SecMutBench security tests
3. Compute Jaccard overlap

**Attack Categories** (expanded in V5.0):

| CWE | Categories |
|-----|-----------|
| CWE-78 | command_chaining, pipe, subshell, backtick, shell_check |
| CWE-22 | parent_traversal, encoded_traversal, absolute_path, null_byte, base_dir_check |
| CWE-89 | tautology, union_injection, stacked_queries, comment_truncation, time_based, parameterization |
| CWE-502 | yaml_gadget, pickle_gadget, safe_check, object_instantiation |
| CWE-918 | internal_ip, cloud_metadata, domain_spoofing, url_scheme, dns_rebinding, allowlist |
| CWE-611 | external_entity, dtd_processing, safe_parser |

---

## LLM Baseline Evaluation

### How It Works

`baselines/run_llm_baselines.py` evaluates LLM-generated security tests:

1. Load dataset samples
2. For each sample, prompt the LLM with secure code + CWE
3. Extract generated test code from LLM response
4. Run tests against secure code, insecure code, and mutants
5. Classify kills and compute all metrics
6. Aggregate results and save

### ModelResult Fields

```python
@dataclass
class ModelResult:
    model_name: str
    total_samples: int
    avg_mutation_score: float
    avg_vuln_detection: float
    avg_line_coverage: float
    avg_security_mutation_score: Optional[float]   # SMS
    avg_incidental_score: Optional[float]
    avg_crash_score: Optional[float]
    avg_security_precision: Optional[float]         # SP
    avg_security_relevance: Optional[float] = None  # Judge only
    avg_test_quality: Optional[float] = None        # Judge only
    avg_composite_score: Optional[float] = None     # Judge only
```

### CLI Options

```bash
python baselines/run_llm_baselines.py [OPTIONS]

  --provider PROVIDER     LLM provider (ollama, openai, anthropic)
  --model MODEL           Model name
  --samples N             Number of samples to evaluate
  --dataset PATH          Dataset path (default: data/dataset.json)
  --skip-invalid          Filter out samples with validation_passed=False
  --use-judge             Enable LLM-as-judge evaluation
  --output-dir DIR        Output directory for results
```

---

## Static Analysis Baseline

**New in V5.0**: `baselines/run_static_analysis.py` provides comparison with traditional static analysis tools.

### Purpose

Static analysis baselines answer the reviewer question: "Why not just use Bandit?" The comparison shows:

1. Where static analysis excels (pattern-based vulnerabilities)
2. Where static analysis fails (logic flaws, missing controls)
3. The unique value of mutation testing

### CWE Classification

CWEs are classified by analyzability:

**Static-Analyzable (7 CWEs)** - Bandit has detection rules:
- CWE-78: Command Injection (shell=True pattern)
- CWE-89: SQL Injection (string formatting in queries)
- CWE-94: Code Injection (eval/exec usage)
- CWE-327: Weak Crypto (MD5/SHA1 usage)
- CWE-502: Deserialization (pickle/yaml.load)
- CWE-611: XXE (xml parsing without defused)
- CWE-798: Hardcoded Credentials

**Dynamic-Only (7 CWEs)** - Require semantic analysis:
- CWE-20: Input Validation (logic flaw)
- CWE-22: Path Traversal (open() is normal usage)
- CWE-79: XSS (missing escaping in custom functions)
- CWE-287: Auth Bypass (logic flaw)
- CWE-306: Missing Auth (absence of code)
- CWE-352: CSRF (missing token validation)
- CWE-918: SSRF (URL validation logic)

### Baseline Results (Full Dataset)

| Category | Samples | Detection Rate |
|----------|---------|---------------|
| **Overall** | 307 | 32.9% |
| Static-Analyzable CWEs | 140 | 70.7% |
| Dynamic-Only CWEs | 167 | 1.2% |

**Per-CWE Detection (Static-Analyzable):**

| CWE | Detection Rate |
|-----|---------------|
| CWE-78 (Command Injection) | 100% |
| CWE-89 (SQL Injection) | 100% |
| CWE-94 (Code Injection) | 93.3% |
| CWE-502 (Deserialization) | 97.3% |
| CWE-611 (XXE) | 60.0% |
| CWE-327 (Weak Crypto) | 11.4% |
| CWE-798 (Hardcoded Creds) | 0% |

**Per-CWE Detection (Dynamic-Only):**

| CWE | Detection Rate | Why Bandit Misses |
|-----|---------------|-------------------|
| CWE-79 (XSS) | 0% | Custom render functions |
| CWE-22 (Path Traversal) | 3.2% | open() is normal usage |
| CWE-352 (CSRF) | 0% | Missing token = no pattern |
| CWE-918 (SSRF) | 0% | URL validation is logic |
| CWE-306 (Missing Auth) | 0% | Absence of code |
| CWE-287 (Auth Bypass) | 0% | Logic flaw |
| CWE-20 (Input Validation) | 0% | No syntax for "missing validation" |

### CLI Options

```bash
python baselines/run_static_analysis.py [OPTIONS]

  --dataset PATH          Dataset path (default: data/dataset.json)
  --tool TOOL             bandit, semgrep, or both
  --semgrep-rules RULES   Semgrep ruleset (default: p/python)
  --max-samples N         Maximum samples to analyze
  --cwe CWE               Filter to specific CWE
  --output PATH           Output JSON path
  --compare-mutation PATH Compare with mutation testing results
  --latex                 Generate LaTeX table for paper
  --verbose               Print progress
```

### Paper Narrative

> *"Static analysis tools like Bandit achieve 70.7% detection on pattern-based vulnerabilities (e.g., `shell=True`, string SQL concatenation) but only 1.2% on logic-flaw vulnerabilities. Since 54% of our dataset consists of logic-flaw CWEs, mutation testing provides essential coverage that static analysis cannot."*

---

## File Reference

### Core Files

| File | Purpose | Key Exports |
|------|---------|-------------|
| `evaluation/evaluate.py` | Main evaluation orchestrator | `load_benchmark()`, `evaluate_generated_tests()`, `classify_kill()`, `OPERATOR_SECURITY_PATTERNS` |
| `evaluation/mutation_engine.py` | Mutant generation | `MutationEngine`, `Mutant`, `MutationResult`, `generate_mutants()` |
| `evaluation/test_runner.py` | Subprocess+pytest test execution | `TestRunner`, `TestSuiteResult`, `TestResult`, `run_tests()` |
| `evaluation/conftest_template.py` | Conftest template for mock injection | `CONFTEST_TEMPLATE` |
| `evaluation/metrics.py` | All metric calculations | `calculate_kill_breakdown()`, `calculate_security_precision()`, `aggregate_by_cwe()` |
| `evaluation/validate_with_cweval.py` | CWEval validation checks | `CWEvalTestRunner`, `check_mutation_sanity()`, `check_vulnerability_detection()`, `check_attack_coverage()` |
| `evaluation/attack_vectors.py` | CWE attack patterns | `CWE_ATTACK_VECTORS`, `check_attack_coverage()` |

### Dataset Generation Files

| File | Purpose | Key Exports |
|------|---------|-------------|
| `scripts/dataset_builder.py` | Build pipeline orchestrator | `DatasetBuilder` |
| `scripts/sample_generator.py` | Raw -> Sample transformation | `SampleGenerator`, `Sample`, `generate_id()`, `validate_operators()` |
| `scripts/source_ingestion.py` | Source loading + CWE registry | `SourceManager`, `CWE_REGISTRY`, `SAMPLE_TEMPLATES` |
| `scripts/source_handlers.py` | Per-source handler classes | `SecurityEvalHandler`, `CyberSecEvalHandler`, `SecCodePLTHandler`, `ExternalSample` |
| `scripts/build_validation_dataset.py` | CWEval -> validation.json | `build_validation_dataset()`, `parse_task_file()`, `parse_test_file()` |

### Baseline Files

| File | Purpose | Key Exports |
|------|---------|-------------|
| `baselines/run_llm_baselines.py` | LLM test generation evaluation | `ModelResult`, `evaluate_model()` |
| `baselines/run_static_analysis.py` | Static analysis baseline (V5.0) | `BanditRunner`, `SemgrepRunner`, `run_static_analysis_baseline()`, `generate_latex_table()` |

### Operator Files

| File | Purpose | Key Exports |
|------|---------|-------------|
| `operators/operator_registry.py` | Operator registry + CWE mapping | `OPERATORS`, `CWE_OPERATOR_MAP`, `get_applicable_operators()` |
| `operators/security_operators.py` | 19 operator implementations | `PSQLI`, `RVALID`, `CMDINJECT`, `PATHCONCAT`, `WEAKCRYPTO`, `DESERIAL`, `SUBDOMAIN_SPOOF`, ... |

### Data Files

| File | Contents |
|------|----------|
| `data/dataset.json` | Main dataset: 307 samples, 774 mutants, 14 CWEs |
| `data/validation.json` | CWEval validation: 32 samples, 55 mutants, 20 CWEs |
| `data/splits/easy.json` | 24 easy-difficulty samples |
| `data/splits/medium.json` | 208 medium-difficulty samples |
| `data/splits/hard.json` | 75 hard-difficulty samples |
| `results/cweval_validation.json` | Full CWEval validation report |
| `results/static_analysis_baseline.json` | Bandit/Semgrep baseline results |

---

## Version History

### V5.0 (2026-02-05) -- Current

**Operator-aware kill classification, SUBDOMAIN_SPOOF operator, static analysis baseline**

Evaluation improvements:
- **Operator-aware kill classification**: `classify_kill()` now uses operator-specific security patterns instead of a flat list. Prevents false inflation of SMS (e.g., "path" no longer triggers semantic for SQL injection mutants).
- Added `OPERATOR_SECURITY_PATTERNS` dict with 19 operator-specific keyword sets
- Updated callsite to pass `operator=mutant.operator` to `classify_kill()`

New operator:
- **SUBDOMAIN_SPOOF**: Removes domain/subdomain validation checks (CWE-20, CWE-918)
  - Easy: Remove `endswith('.domain.com')`, `allowed_domains` checks
  - Medium: Remove `netloc`, `hostname` validation
  - Hard: Replace `validate_domain()` with `True`, remove compound validation

Extended operators:
- **DESERIAL**: Added YAML gadget patterns (`!!python`, `!!python/object`), SafeLoader → Loader/UnsafeLoader/FullLoader replacements

Static analysis baseline:
- New script: `baselines/run_static_analysis.py`
- Bandit integration with CWE mapping (40+ Bandit test IDs mapped)
- Semgrep support (optional)
- Fair comparison: CWEs classified as "static-analyzable" vs "dynamic-only"
- Results: 70.7% detection on pattern-based CWEs, 1.2% on logic-flaw CWEs
- LaTeX table generation for paper

Attack vectors expanded:
- `evaluation/attack_vectors.py`: Added CWE-918 (SSRF), CWE-611 (XXE) categories
- CWE-89: Added time_based, error_based injection patterns
- CWE-502: Added YAML tag injection, object instantiation patterns
- CWE-918: Added dns_rebinding, cloud_metadata, url_scheme patterns

Validation improvements:
- `validate_with_cweval.py`: Expanded ATTACK_CATEGORIES with 11 CWEs
- Extended VULN_FINGERPRINTS with CWE-611, CWE-287, CWE-798, CWE-338

### V4.0 (2026-02-04)

**SecCodePLT integration + CWEval validation system**

Dataset changes:
- Integrated SecCodePLT dataset (168 samples from 9 overlapping CWEs)
- Dataset grew from ~85 samples to 307 samples
- 4 data sources: SecCodePLT (168), SecMutBench (61), CyberSecEval (59), SecurityEval (19)
- 774 pre-generated mutants across 307 samples
- 14 CWEs in final dataset

New files:
- `scripts/build_validation_dataset.py` -- CWEval parser + validation dataset builder
- `evaluation/validate_with_cweval.py` -- 3 validation checks against CWEval expert tests
- `data/validation.json` -- 32 CWEval samples across 20 CWEs

SecCodePLT handler:
- `SecCodePLTHandler` in `scripts/source_handlers.py`
- `from_sec_code_plt()` in `scripts/sample_generator.py`
- Phase 1: 9 overlapping CWEs only (22, 78, 79, 94, 327, 352, 502, 611, 918)
- External dependency filtering (lxml, defusedxml, etc.)
- Direct use of ground-truth secure/insecure code pairs

CWEval validation results (preliminary):
- Mutation operator sanity: 50% vulnerability class match (6/12)
- Vulnerability detection ground truth: 92% established (12/13)
- Attack vector coverage: 47.6% average Jaccard

### V2.2.0 (2026-02-03)

**Subprocess + pytest test runner, pre-generated mutants**

- Replaced exec-based sandbox with subprocess isolation + real pytest
- Created `evaluation/conftest_template.py` with builtins injection + SafeOS + ResultCollector
- Pre-generated mutants stored in dataset JSON for deterministic evaluation
- Crash kills dropped from ~46% to ~23%
- Standard library imports no longer blocked

### V2.1.0 (2026-02-03)

**Metric decomposition, tautological test fix, new metrics**

Critical fixes:
- Wired Security Mutation Score into evaluation output
- Fixed tautological functional tests (`assert result is not None or result is None`)
- Changed judge metric defaults from 0.0 to None

New metrics:
- Security Mutation Score (SMS) -- semantic kills only
- Crash Score -- crash kill fraction
- Security Precision -- vuln detected / secure passes
- Low-n confidence flags for per-CWE analysis

Infrastructure:
- `--skip-invalid` flag for filtering bad samples
- Mutant generation non-determinism fix

### V3.0 (2026-02-02)

**Package restructure, CWE consolidation, new operators**

- Proper Python package with `pyproject.toml`
- Consolidated 74 CWEs to 16 with operator+sample filters
- Added WEAKRANDOM operator for CWE-338
- 44 new templates across 7 CWE categories
- SafeOS + MockEnvironment integration fix
- Code preprocessing for Python 2 compatibility

---

## References

- [MITRE CWE](https://cwe.mitre.org/) -- Common Weakness Enumeration
- [SecurityEval](https://huggingface.co/datasets/s2e-lab/SecurityEval) -- HuggingFace Dataset
- [CyberSecEval](https://github.com/meta-llama/PurpleLlama) -- Meta's PurpleLlama
- [SecCodePLT](https://huggingface.co/datasets/Virtue-AI-HUB/SecCodePLT) -- HuggingFace Dataset
- [CWEval](https://github.com/co1lin/CWEval) -- Expert-verified security evaluation pairs
- [Bandit](https://bandit.readthedocs.io/) -- Python Security Linter
- [Semgrep](https://semgrep.dev/) -- Static Analysis Tool
