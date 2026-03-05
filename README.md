# SecMutBench

A benchmark for evaluating LLM-generated security tests using mutation testing.

**Version:** 2.5.0

## Overview

SecMutBench evaluates whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

## Key Features

- **Security-Focused**: Samples mapped to Common Weakness Enumeration (CWE) vulnerability types
- **Mutation Testing Evaluation**: Test quality measured by ability to kill security-relevant mutants
- **32 Security Mutation Operators**: Custom operators that inject realistic vulnerability patterns with multiple variants
- **Mock-State Observability**: Layer 1.5 classification detecting tests that access security-relevant mock attributes
- **Pre-generated Mutants**: Deterministic mutant sets stored in dataset for reproducible evaluation
- **Multi-Modal Evaluation**: Combines mutation testing with LLM-as-judge metrics
- **CWE-Strict Operator Mapping**: Operators only fire on samples matching their target CWEs (no cross-contamination)

## Statistics

| Metric | Value |
|--------|-------|
| Total Samples | 304 |
| Viable CWE Types | 24 |
| Languages | Python |
| Core Mutation Operators | 18 |
| Extended Operators | 14 |
| Total Operators | 32 |
| CWE Mappings | 49 |

### CWE Distribution

| CWE | Name | Samples |
|-----|------|---------|
| CWE-22 | Path Traversal | 60 |
| CWE-79 | Cross-Site Scripting (XSS) | 54 |
| CWE-78 | OS Command Injection | 39 |
| CWE-502 | Insecure Deserialization | 32 |
| CWE-327 | Weak Cryptography | 29 |
| CWE-352 | Cross-Site Request Forgery | 29 |
| CWE-918 | SSRF | 22 |
| CWE-94 | Code Injection | 10 |
| CWE-611 | XXE Injection | 7 |
| CWE-306 | Missing Authentication | 6 |
| CWE-89 | SQL Injection | 5 |
| CWE-287 | Improper Authentication | 4 |
| CWE-798 | Hardcoded Credentials | 3 |
| CWE-20 | Improper Input Validation | 2 |
| CWE-319 | Cleartext Transmission | 2 |

### Difficulty Distribution

| Difficulty | Samples |
|------------|---------|
| Easy | 25 |
| Medium | 205 |
| Hard | 74 |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/SecMutBench.git
cd SecMutBench

# Install dependencies (requires Python 3.8+)
pip install -r requirements.txt
```

### Check Version

```bash
python -m evaluation.evaluate --version
# SecMutBench v2.5.0
# Benchmark: v2.5
# Python: 3.11.5
# Dependencies: ...
```

### Basic Usage

```python
from evaluation import load_benchmark, evaluate_generated_tests, __version__

print(f"SecMutBench v{__version__}")

# Load benchmark
benchmark = load_benchmark()

# Evaluate generated tests for a sample
sample = benchmark[0]
generated_tests = """
def test_sql_injection():
    result = get_user_by_id("1 OR 1=1")
    assert "injection" in str(db.last_query).lower() or len(result) <= 1
"""

results = evaluate_generated_tests(sample, generated_tests)
print(f"Mutation Score: {results['metrics']['mutation_score']:.2%}")
print(f"Security MS: {results['metrics'].get('security_mutation_score', 0):.2%}")
print(f"Vulnerability Detected: {results['metrics']['vuln_detected']}")
```

### Run Evaluation

```bash
# Evaluate reference tests
python -m evaluation.evaluate --model reference

# Filter by difficulty or CWE
python -m evaluation.evaluate --difficulty easy
python -m evaluation.evaluate --cwe CWE-89

# Run with LLM baselines
python baselines/run_llm_baselines.py --provider ollama --model qwen2.5-coder:7b --max-samples 30

# Run static analysis baseline
python baselines/run_static_analysis.py --tool bandit
```

## Security Mutation Operators

### Core Operators (18)

| Operator | Description | Target CWEs | Variants |
|----------|-------------|-------------|----------|
| PSQLI | Parameterized SQL to string concatenation | CWE-89 | 4 (f-string, .format, %, +) |
| RVALID | Remove input validation/sanitization | CWE-20, CWE-79 | 1 |
| CMDINJECT | Enable shell command injection | CWE-78 | 9 (shell=True, os.system, os.popen, etc.) |
| PATHCONCAT | Unsafe path concatenation | CWE-22 | 1 |
| RMAUTH | Remove authentication checks | CWE-287, CWE-306 | 1 |
| HARDCODE | Inject hardcoded credentials | CWE-798 | 5 (admin123, password, 123456, etc.) |
| WEAKCRYPTO | Use weak cryptographic algorithms (MD5/SHA1) | CWE-327 | 1 |
| WEAKRAND | Use weak random (random instead of secrets) | CWE-338 | 1 |
| RHTTPO | Remove HttpOnly cookie flag | CWE-1004 | 1 |
| RENCRYPT | Remove encryption/TLS | CWE-319 | 1 |
| DESERIAL | Unsafe deserialization (pickle.loads) | CWE-502 | 1 |
| YAMLLOAD | Unsafe YAML load | CWE-502 | 1 |
| XXENABLE | Enable external XML entities | CWE-611 | 1 |
| SSRFOPEN | Remove SSRF URL validation | CWE-918 | 1 |
| EVALINJECT | Enable eval/exec injection | CWE-94, CWE-95 | 1 |
| JWTVERIFY | Disable JWT signature verification | CWE-287 | 1 |
| BCRYPTCOST | Reduce bcrypt cost factor | CWE-327 | 1 |
| ENVLEAK | Expose environment secrets | CWE-798 | 1 |

### Extended Operators (14 new in v2.5.0)

| Operator | Description | Target CWEs | Has Source Material |
|----------|-------------|-------------|---------------------|
| OPENREDIRECT | Remove redirect URL validation | CWE-601 | ✓ |
| NOCERTVALID | Disable SSL certificate verification | CWE-295 | ✓ |
| INFOEXPOSE | Expose sensitive data in errors | CWE-209 | ✓ |
| REGEXDOS | Introduce ReDoS-vulnerable patterns | CWE-400, CWE-1333 | ✓ |
| MISSINGAUTH | Remove authorization checks | CWE-862 | ✓ |
| INSUFFLOG | Remove security logging | CWE-778 | ✗ |
| NULLCHECK | Remove null pointer checks | CWE-476 | ✗ |
| MEMLEAK | Remove resource cleanup | CWE-401 | ✗ |
| INTOVERFLOW | Remove integer overflow checks | CWE-190 | ✗ |
| RACECOND | Remove synchronization | CWE-362 | ✗ |
| PRIVESC | Weaken permission checks | CWE-269 | ✗ |
| SESSIONFIX | Disable session regeneration | CWE-384 | ✗ |
| XMLINJECT | Remove XML special char escaping | CWE-91 | ✗ |

## Project Structure

```
SecMutBench/
├── data/
│   ├── dataset.json           # Main benchmark (304 samples, 737 mutants)
│   └── splits/
│       ├── easy.json          # 25 samples
│       ├── medium.json        # 205 samples
│       └── hard.json          # 74 samples
├── operators/
│   ├── security_operators.py  # 32 mutation operator implementations
│   └── operator_registry.py   # Operator-to-CWE mappings (49 CWEs)
├── evaluation/
│   ├── evaluate.py            # Main evaluation orchestrator
│   ├── mutation_engine.py     # Mutant generation
│   ├── test_runner.py         # Subprocess + pytest test execution
│   ├── conftest_template.py   # Mock injection templates
│   ├── metrics.py             # Score calculation
│   ├── prompts.py             # Prompt templates (including ablation)
│   ├── llm_judge.py           # LLM-as-judge evaluation
│   ├── version.py             # Version tracking for reproducibility
│   └── mocks/                 # 15 mock objects for safe test execution
│       ├── mock_database.py   # SQL injection testing
│       ├── mock_subprocess.py # Command injection testing
│       ├── mock_filesystem.py # Path traversal testing
│       └── ...
├── baselines/
│   ├── run_llm_baselines.py   # LLM baseline evaluation
│   └── run_static_analysis.py # Bandit/Semgrep baselines
├── scripts/
│   ├── dataset_builder.py     # Main dataset orchestrator
│   ├── sample_generator.py    # Sample generation from templates
│   ├── source_ingestion.py    # Multi-source data loading
│   ├── compute_mutant_validity.py    # Mutant validity analysis
│   ├── compute_test_validity.py      # Test validity aggregation
│   ├── evaluate_no_mocks.py          # Mock vs no-mock comparison
│   ├── evaluate_reference_tests.py   # Reference test baseline
│   ├── run_semgrep_baseline.py       # Semgrep static analysis
│   └── sample_kills_for_audit.py     # Manual audit sampling
├── requirements.txt
└── README.md
```

## Kill Classification

SecMutBench classifies mutant kills into categories to distinguish genuine security awareness from accidental detection:

| Category | Description | Layer |
|----------|-------------|-------|
| **Semantic** | AssertionError with security-relevant assertions | Layer 1 (keywords) or Layer 1.5 (mock observability) |
| **Incidental** | AssertionError without security terms | Layer 1 |
| **Crash** | ImportError, TypeError, SyntaxError, etc. | Layer 0 |

### Mock-State Observability (Layer 1.5)

Tests that access security-relevant mock attributes are classified as semantic kills, even without explicit security keywords:

```python
# This test accesses db.last_params - a security-relevant attribute
def test_sql_injection():
    get_user("admin' OR '1'='1")
    assert "?" in db.last_query  # Checks for parameterized query
```

**Tracked Security Attributes by Mock:**

| Mock | Security Attributes |
|------|---------------------|
| `db` | `last_query`, `last_params`, `query_count` |
| `subprocess` | `last_shell`, `last_command`, `injection_detected`, `dangerous_command_detected` |
| `fs` | `last_path`, `base_dir` |
| `crypto` | `last_algorithm`, `weak_algorithm_used`, `strong_algorithm_used`, `algorithms_used` |
| `http` | `last_url`, `ssrf_attempted`, `last_method` |
| `xml` | `last_xml`, `external_entities_resolved`, `dtd_processed` |
| `pickle` | `last_data`, `unsafe_load_called`, `load_count` |
| `yaml` | `last_data`, `unsafe_load_called`, `safe_loader_used`, `load_count` |
| `auth` | `last_username`, `last_password`, `last_token`, `auth_attempts`, `failed_attempts` |
| `env` | `last_key`, `sensitive_accessed`, `access_log` |
| `eval` | `last_code`, `unsafe_eval_called`, `unsafe_exec_called`, `injection_detected` |

## Evaluation Metrics

### Multi-Modal Evaluation

SecMutBench supports multi-modal evaluation combining execution-based and LLM-as-judge metrics:

| Metric | Method | Weight |
|--------|--------|--------|
| Mutation Score | Execution | 50% |
| Security Relevance | Claude Sonnet Judge | 20% |
| Test Quality | Claude Sonnet Judge | 15% |
| Coverage | Execution | 15% |

```bash
# Run multi-modal evaluation with Claude (default)
export ANTHROPIC_API_KEY=your-key
python evaluation/evaluate.py --multimodal

# Or specify a different Claude model
python evaluation/evaluate.py --multimodal --judge-model claude-sonnet-4-5-20250929

# Or use OpenAI GPT-4 instead
export OPENAI_API_KEY=your-key
python evaluation/evaluate.py --multimodal --judge-provider openai --judge-model gpt-4
```

### Primary Metrics

- **Mutation Score**: Killed Mutants / Total Mutants
- **Vulnerability Detection Rate**: Samples where security tests pass on secure code and fail on insecure code
- **Security Relevance**: LLM-judged assessment of test security focus
- **Test Quality**: LLM-judged assessment of test structure and best practices

### Secondary Metrics

- Line Coverage
- Branch Coverage

## Docker Usage

```bash
# Build image
docker build -t secmutbench .

# Run evaluation
docker run secmutbench --model reference

# Run with specific filters
docker run secmutbench --difficulty easy --cwe CWE-89
```

## Dataset Building

Build or rebuild the dataset with configurable options:

```bash
# Build dataset with default settings (300 samples, min 5 per CWE)
python scripts/dataset_builder.py --target 300

# Build with lower CWE threshold to include rare vulnerability types
python scripts/dataset_builder.py --target 300 --min-samples 2

# Validate existing dataset without rebuilding
python scripts/dataset_builder.py --validate-only

# Skip contamination prevention (faster, for testing)
python scripts/dataset_builder.py --target 300 --skip-contamination
```

## Analysis Scripts

Scripts for analyzing evaluation results and dataset quality:

```bash
# Analyze mutant validity (compilability/executability)
python scripts/compute_mutant_validity.py
python scripts/compute_mutant_validity.py --test-execution  # Also test execution

# Analyze test validity from evaluation results
python scripts/compute_test_validity.py --results results/evaluation.json

# Sample kills for manual audit
python scripts/sample_kills_for_audit.py results/evaluation.json --samples-per-category 30
python scripts/sample_kills_for_audit.py results/evaluation.json --format csv --output audit.csv
```

## Contamination Prevention

SecMutBench employs four contamination mitigation strategies:

1. **Perturbation Pipeline**: All samples adapted from public datasets undergo systematic modification:
   - Function/variable renaming
   - Control flow restructuring
   - Comment removal/modification

2. **Novel Samples**: 30%+ of samples are originally authored

3. **Temporal Filtering**: CVE-based samples use vulnerabilities disclosed after January 2024

4. **Contamination Audit**: N-gram overlap analysis with known training corpora

```bash
# Run contamination prevention pipeline
python scripts/contamination_prevention.py --input data/samples.json --output data/decontaminated
```

## Machine-Readable Metadata

SecMutBench provides Croissant-compliant metadata for automated discovery:

- `croissant.json`: Schema.org dataset description
- `datasheet.md`: Following Gebru et al. (2021) template
- `DATASET_CARD.md`: HuggingFace dataset card

## Extending the Benchmark

### Adding New Samples

1. Add sample to `data/samples.json` following the schema
2. Include: id, cwe, secure_code, insecure_code, functional_tests, security_tests
3. Run validation: `python scripts/validate.py`

### Adding New Mutation Operators

1. Create operator class in `operators/security_operators.py`
2. Register in `operators/operator_registry.py`
3. Map to relevant CWEs

## Citation

```bibtex
@inproceedings{secmutbench2025,
  title={SecMutBench: A Benchmark for Evaluating LLM Security Test Generation via Mutation Testing},
  author={...},
  booktitle={...},
  year={2025}
}
```

## License

MIT License
