# SecMutBench Documentation

**Date:** 2026-02-01
**Version:** 2.2
**Author:** SecMutBench Team

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [How SecMutBench Works](#how-secmutbench-works)
4. [Dataset Generation](#dataset-generation)
5. [Templates Deep Dive](#templates-deep-dive)
6. [Architecture & Package Structure](#architecture--package-structure)
7. [Mock Objects System](#mock-objects-system)
8. [File Structure](#file-structure)
9. [Changelog from V2.1](#changelog-from-v21)

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

### Key Features (V2.2)

- **Proper Python Package**: Install with `pip install -e .`
- **Consolidated Mock System**: All mocks in `evaluation/mocks/`
- **Modular Scripts**: 3 core modules replace 6 legacy scripts
- **Deep Validation**: Optional Bandit analysis and runtime testing
- **16 CWE Types**: Comprehensive vulnerability coverage

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
# Generate 10 samples (quick test)
python scripts/dataset_builder.py --target 10

# Generate with full validation
python scripts/dataset_builder.py --target 10 --deep-validate

# Skip contamination prevention (faster)
python scripts/dataset_builder.py --target 10 --skip-contamination
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

#### 5c. Attack Vector Coverage

```
Check if tests cover known attack patterns:
✓ Tautology attacks ("' OR '1'='1")
✓ Union-based injection
✗ Time-based injection (missing)
✗ Error-based injection (missing)

Attack Coverage = 2/4 = 50%
```

---

### Step 6: LLM Judge Evaluation

An LLM judge (e.g., gpt-5) reviews the generated tests:

```
┌─────────────────────────────────────────────────────────┐
│                    LLM Judge Scores                     │
├─────────────────────────────────────────────────────────┤
│ Security Relevance: 0.88                                │
│   "Tests target correct vulnerability pattern"          │
│                                                         │
│ Test Quality: 0.35                                      │
│   "Tests are brittle, implementation-specific"          │
│                                                         │
│ Composite Score: 0.23                                   │
└─────────────────────────────────────────────────────────┘
```

---

### Step 7: Results Aggregation

All metrics combined:

```json
{
  "model": "qwen2.5-coder:7b",
  "sample_id": "abc123",
  "cwe": "CWE-89",
  "mutation_score": 0.67,
  "vuln_detected": true,
  "line_coverage": 0.85,
  "attack_coverage": 0.50,
  "judge_scores": {
    "security_relevance": 0.88,
    "test_quality": 0.35,
    "composite": 0.23
  }
}
```

---

### Visual Summary

```
                    SecMutBench Pipeline

    ┌──────────────────────────────────────────────────┐
    │                   DATASET                        │
    │  149 samples (secure code, insecure code, CWE)   │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │                 PROMPT LLM                       │
    │  "Generate security tests for this CWE-89 code" │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │              LLM GENERATES TESTS                 │
    │  def test_sql_injection(): assert ...           │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │             MUTATION TESTING                     │
    │  Create mutants → Run tests → Count kills       │
    │  Score = killed / total = 67%                   │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │              LLM JUDGE REVIEW                    │
    │  Security: 88% | Quality: 35% | Composite: 23%  │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │               FINAL RESULTS                      │
    │  Model X scored 45% avg mutation score          │
    │  Best on CWE-89, worst on CWE-79                │
    └──────────────────────────────────────────────────┘
```

---

## Dataset Generation

### Overview

The dataset is built from **3 sources** using **3 consolidated modules**.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DATASET GENERATION PIPELINE (V2.2)               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐                                               │
│  │ source_ingestion │ ── Load from Templates, SecurityEval,        │
│  │       .py        │    CyberSecEval                               │
│  └────────┬─────────┘                                               │
│           │                                                         │
│           ▼                                                         │
│  ┌──────────────────┐                                               │
│  │ sample_generator │ ── Generate/transform samples, apply         │
│  │       .py        │    secure code fixes, create tests           │
│  └────────┬─────────┘                                               │
│           │                                                         │
│           ▼                                                         │
│  ┌──────────────────┐                                               │
│  │ dataset_builder  │ ── Orchestrate pipeline, validation,         │
│  │       .py        │    contamination prevention                  │
│  └────────┬─────────┘                                               │
│           │                                                         │
│           ▼                                                         │
│      dataset.json                                                   │
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

---

### Step 1: Define CWE Types & Weights

```python
DEFAULT_CWE_WEIGHTS = {
    "CWE-89": 15,   # SQL Injection - most samples
    "CWE-79": 15,   # XSS
    "CWE-78": 12,   # Command Injection
    "CWE-22": 12,   # Path Traversal
    "CWE-20": 10,   # Input Validation
    "CWE-287": 8,   # Authentication
    "CWE-798": 8,   # Hardcoded Credentials
    "CWE-502": 8,   # Deserialization
    ...
}
```

---

### Step 2: Source Ingestion

The `source_ingestion.py` module handles loading from all sources:

```python
from scripts.source_ingestion import SourceManager

manager = SourceManager()

# Load from all sources
templates = manager.load_templates()           # SecMutBench originals
security_eval = manager.load_security_eval()   # HuggingFace
cyber_sec = manager.load_cybersec_eval()       # Meta PurpleLlama
```

---

### Step 3: Sample Generation & Transformation

The `sample_generator.py` module handles:

```python
from scripts.sample_generator import SampleGenerator

generator = SampleGenerator()

# Generate from template
sample = generator.from_template(template, cwe="CWE-89")

# Transform external sample
sample = generator.transform_external(raw_sample, source="SecurityEval")

# Generate secure version from insecure code
secure_code = generator.generate_secure_version(insecure_code, cwe="CWE-89")

# Generate security tests
tests = generator.generate_security_test(entry_point, cwe="CWE-89")
```

---

### Step 4: Contamination Prevention

Identifiers are renamed to prevent training data leakage:

```python
# Before
def get_user_by_id(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))

# After (same rename_map applied to BOTH secure and insecure)
def fetch_record_by_key(record_key):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (record_key,))
```

**Important**: V2.2 fixes a bug where secure and insecure code could get different renames.

---

### Step 5: Validation

```python
# Basic validation (fast)
sample.validate()  # Syntax check, required fields

# Deep validation (comprehensive)
from scripts.validate import SampleValidator
validator = SampleValidator()
result = validator.validate_comprehensive(sample)
# Includes: Bandit analysis, runtime testing, mutation verification
```

---

### Dataset Generation Visual Summary

```
                     DATASET GENERATION FLOW (V2.2)

    ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
    │   TEMPLATES      │   │   SECURITYEVAL   │   │   CYBERSECEVAL   │
    │   (Original)     │   │   (HuggingFace)  │   │   (Meta)         │
    │   ~80 samples    │   │   ~40 samples    │   │   ~29 samples    │
    └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
             │                      │                      │
             │         source_ingestion.py                 │
             └──────────────────────┼──────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    sample_generator.py                          │
    │  • Generate secure/insecure pairs                               │
    │  • Create CWE-specific security tests                           │
    │  • Assign mutation operators                                    │
    │  • Generate unique IDs                                          │
    └─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    dataset_builder.py                           │
    │  • Apply contamination prevention                               │
    │  • Validate samples (basic or deep)                             │
    │  • Balance CWE distribution                                     │
    │  • Create difficulty splits                                     │
    └─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    OUTPUT FILES                                 │
    │  • data/dataset.json (validated samples)                        │
    │  • data/splits/easy.json                                        │
    │  • data/splits/medium.json                                      │
    │  • data/splits/hard.json                                        │
    └─────────────────────────────────────────────────────────────────┘
```

---

## Templates Deep Dive

Templates are the **core building blocks** for generating original SecMutBench samples. Each template defines a **vulnerable pattern** and its **secure fix**.

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

---

### CWE-89: SQL Injection (5 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `get_user_by_id` | f-string in query | Parameterized `?` |
| 2 | `search_users` | f-string LIKE | Parameterized LIKE |
| 3 | `authenticate_user` | String concat login | Parameterized auth |
| 4 | `update_user_email` | f-string UPDATE | Parameterized UPDATE |
| 5 | `delete_user` | f-string DELETE | Parameterized DELETE |

**Example - Template 1:**
```python
# INSECURE (vulnerable)
def get_user_by_id(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Direct injection
    return db.execute(query)

# SECURE (fixed)
def get_user_by_id(user_id):
    query = "SELECT * FROM users WHERE id = ?"  # Placeholder
    return db.execute(query, (user_id,))        # Parameterized
```

---

### CWE-79: Cross-Site Scripting (4 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `render_greeting` | Unescaped name in HTML | `html.escape()` |
| 2 | `display_comment` | Unescaped comment | `html.escape()` |
| 3 | `create_link` | Unvalidated URL | URL validation + escape |
| 4 | `render_search_results` | Unescaped query + results | Escape all outputs |

---

### CWE-78: Command Injection (3 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `ping_host` | `shell=True` with f-string | Array args, no shell |
| 2 | `list_directory` | `os.popen()` with user input | `os.listdir()` |
| 3 | `get_file_info` | `shell=True` in subprocess | Array args |

---

### CWE-22: Path Traversal (2 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `read_upload` | Direct path concat | `abspath` + prefix check |
| 2 | `serve_static` | Direct path concat | `abspath` + prefix check |

---

### Template Summary

| CWE | Count | Difficulty Mix |
|-----|-------|----------------|
| CWE-89 (SQL Injection) | 5 + 1 hard | 4 easy, 1 medium, 1 hard |
| CWE-79 (XSS) | 4 | 2 easy, 2 medium |
| CWE-78 (Command Injection) | 3 + 1 hard | 1 easy, 2 medium, 1 hard |
| CWE-22 (Path Traversal) | 2 + 1 hard | 1 easy, 1 medium, 1 hard |
| CWE-798 (Hardcoded Creds) | 2 | 2 easy |
| CWE-502 (Deserialization) | 2 | 1 easy, 1 medium |
| CWE-287 (Auth) | 1 + 1 hard | 1 medium, 1 hard |
| CWE-327 (Weak Crypto) | 1 | 1 medium |
| CWE-352 (CSRF) | 1 | 1 medium |
| CWE-20 (Input Validation) | 1 | 1 easy |

**Total: ~25 base templates** expanded to ~80 SecMutBench original samples.

---

## Architecture & Package Structure

### Package Installation (V2.2)

SecMutBench now uses `pyproject.toml` for proper Python packaging:

```toml
[project]
name = "secmutbench"
version = "2.0.0"
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
from evaluation.llm_judge import create_evaluator

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

# Dataset generation
from scripts.dataset_builder import DatasetBuilder
from scripts.sample_generator import SampleGenerator
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

### Usage Example

```python
from evaluation.mocks import MockDatabase

# Create mock
db = MockDatabase()

# Execute query
db.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Check if parameterized (security test)
assert db.last_params is not None, "Query not parameterized!"

# Check for injection patterns
assert not db.injection_detected, "SQL injection detected!"
```

### MockDatabase Contract

```python
class MockDatabase:
    # Tracks last query and parameters
    last_query: str
    last_params: tuple | None

    # Detection flags
    injection_detected: bool
    vulnerable_pattern_used: bool

    # Methods
    def execute(query, params=None) -> list
    def fetchone() -> dict | None
    def fetchall() -> list
    def reset() -> None
```

---

## File Structure

```
SecMutBench/
│
├── pyproject.toml                 # Package configuration (NEW in V2.2)
├── README.md                      # Project documentation
├── DATASET_CARD.md                # HuggingFace dataset card
├── requirements.txt               # Legacy dependencies
│
├── data/                          # === DATASET FILES ===
│   ├── dataset.json               # Main dataset (validated samples)
│   ├── samples.json               # HuggingFace-compatible format
│   ├── contamination_audit.json   # N-gram overlap analysis
│   │
│   ├── splits/                    # Difficulty-based splits
│   │   ├── easy.json
│   │   ├── medium.json
│   │   └── hard.json
│   │
│   └── raw/                       # Original source data
│       ├── securityeval_raw.json
│       └── cyberseceval_raw.json
│
├── evaluation/                    # === CORE EVALUATION ENGINE ===
│   ├── __init__.py
│   ├── evaluate.py                # Main evaluation orchestrator
│   ├── mutation_engine.py         # Mutation testing engine
│   ├── test_runner.py             # Test execution framework
│   ├── sample_validator.py        # Sample validation logic
│   ├── llm_judge.py               # LLM-as-judge evaluation
│   ├── attack_vectors.py          # Attack coverage checking
│   ├── prompts.py                 # Prompt templates
│   │
│   └── mocks/                     # === CONSOLIDATED MOCKS (V2.2) ===
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
│   ├── operator_registry.py       # Operator registration
│   └── security_operators.py      # 10 security mutation operators
│
├── scripts/                       # === DATASET GENERATION (V2.2) ===
│   ├── dataset_builder.py         # Main orchestrator (NEW)
│   ├── sample_generator.py        # Sample generation/transformation (NEW)
│   ├── source_ingestion.py        # Source loading (NEW)
│   ├── validate.py                # Dataset validation
│   ├── contamination_prevention.py # Prevent data leakage
│   │
│   └── archive/                   # Legacy scripts (deprecated)
│       ├── rebuild_dataset.py
│       ├── generate_samples.py
│       ├── download_sources.py
│       └── ...
│
├── agentic_pipeline/             # === MULTI-AGENT SYSTEM ===
│   ├── run_agents.py              # Agent runner
│   ├── agents/
│   │   ├── orchestrator.py        # Main coordinator
│   │   └── sub_agents/
│   │       ├── model_runner.py    # Run LLM evaluations
│   │       ├── judge_runner.py    # Run LLM judges
│   │       ├── stat_agent.py      # Statistical analysis
│   │       ├── chart_agent.py     # Generate visualizations
│   │       └── report_agent.py    # Generate reports
│   │
│   └── outputs/                   # Agent outputs
│       └── experiments/           # Timestamped experiment results
│
├── baselines/                     # Baseline implementations
├── results/                       # Historical evaluation results
│
└── docs/                          # === DOCUMENTATION ===
    ├── SECMUTBENCH_DOCUMENTATION_V2_2026-02-01.md  # This file
    ├── mock_contracts.md          # Mock object specifications
    └── cwe_research/              # CWE-specific research
```

---

## Changelog from V2.1

### V2.2 Changes (2026-02-01)

#### Package Structure
- **Added `pyproject.toml`**: Proper Python packaging with `pip install -e .`
- **Fixed import inconsistency**: Standardized try/except fallback pattern
- **Consolidated mocks**: All 8 mock classes now in `evaluation/mocks/`

#### Scripts Consolidation
- **NEW `dataset_builder.py`**: Main orchestrator replacing 6 legacy scripts
- **NEW `sample_generator.py`**: Unified sample generation/transformation
- **NEW `source_ingestion.py`**: Unified source loading
- **Archived legacy scripts**: Moved to `scripts/archive/`

#### Bug Fixes
- **Fixed contamination rename bug**: Secure and insecure code now get same identifier renames
- **Fixed test generation duplication**: Single source of truth for CWE-specific tests
- **Added `--deep-validate` flag**: Optional comprehensive validation with Bandit

#### Mock System
- Extracted `MockDatabase` (228 lines) from test_runner.py
- Extracted `MockFileSystem`, `MockHTTPClient`, `MockXMLParser`, `MockAuthenticator`
- All mocks now properly exported from `evaluation.mocks`

#### Documentation
- Updated file structure documentation
- Added Quick Start section
- Added Mock Objects System documentation
- Added Architecture section

---

## References

- [MITRE CWE](https://cwe.mitre.org/) - Common Weakness Enumeration
- [SecurityEval](https://huggingface.co/datasets/s2e-lab/SecurityEval) - HuggingFace Dataset
- [CyberSecEval](https://github.com/meta-llama/PurpleLlama) - Meta's PurpleLlama
- Gebru et al. (2021) - "Datasheets for Datasets"
