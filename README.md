# SecMutBench

A benchmark for evaluating LLM-generated security tests using mutation testing.

**Version:** 2.8.0

## Overview

SecMutBench evaluates whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

## Key Features

- **Security-Focused**: Samples mapped to Common Weakness Enumeration (CWE) vulnerability types
- **Mutation Testing Evaluation**: Test quality measured by ability to kill security-relevant mutants
- **25 Active Security Mutation Operators**: Custom operators that inject realistic vulnerability patterns with multiple variants
- **LLM Variation Pipeline**: Semantic-preserving code transformations to expand dataset while maintaining vulnerability patterns
- **Mock-State Observability**: Layer 1.5 classification detecting tests that access security-relevant mock attributes
- **Pre-generated Mutants**: 1,869 deterministic mutants stored in dataset (avg 5.5/sample) for reproducible evaluation
- **Multi-Modal Evaluation**: Combines mutation testing with LLM-as-judge metrics
- **CWE-Strict Operator Mapping**: Operators only fire on samples matching their target CWEs (no cross-contamination)
- **Multi-Source**: Samples from SecMutBench, CWEval, SecurityEval, and LLM-generated variations

## Statistics

| Metric | Value |
|--------|-------|
| Total Samples | 339 |
| CWE Types | 30 |
| Languages | Python |
| Active Mutation Operators | 25 |
| Pre-generated Mutants | 1,869 |
| Avg Mutants/Sample | 5.5 |
| Compilability | 100% |

### CWE Distribution

| CWE | Name | Samples |
|-----|------|---------|
| CWE-319 | Cleartext Transmission | 18 |
| CWE-89 | SQL Injection | 16 |
| CWE-306 | Missing Authentication | 16 |
| CWE-22 | Path Traversal | 15 |
| CWE-918 | SSRF | 15 |
| CWE-94 | Code Injection | 15 |
| CWE-400 | Resource Exhaustion (ReDoS) | 15 |
| CWE-352 | Cross-Site Request Forgery | 14 |
| CWE-295 | Improper Certificate Validation | 14 |
| CWE-79 | Cross-Site Scripting (XSS) | 13 |
| CWE-798 | Hardcoded Credentials | 13 |
| CWE-611 | XXE Injection | 13 |
| CWE-327 | Weak Cryptography | 12 |
| CWE-732 | Incorrect Permission Assignment | 12 |
| CWE-117 | Log Injection | 12 |
| CWE-74 | Injection | 11 |
| CWE-328 | Weak Hash | 11 |
| CWE-338 | Weak PRNG | 11 |
| CWE-601 | Open Redirect | 11 |
| CWE-502 | Insecure Deserialization | 10 |
| CWE-862 | Missing Authorization | 10 |
| CWE-326 | Inadequate Key Size | 10 |
| CWE-20 | Improper Input Validation | 9 |
| CWE-95 | Eval Injection | 8 |
| CWE-643 | XPath Injection | 8 |
| CWE-209 | Info Exposure in Error | 7 |
| CWE-434 | Unrestricted File Upload | 5 |
| CWE-639 | Insecure Direct Object Reference | 5 |
| CWE-863 | Incorrect Authorization | 5 |
| CWE-915 | Mass Assignment | 5 |

### Difficulty Distribution

| Difficulty | Samples |
|------------|---------|
| Easy | 136 |
| Medium | 101 |
| Hard | 102 |

### Source Distribution

| Source | Samples |
|--------|---------|
| SecMutBench (original) | 75 |
| CWEval | 3 |
| SecurityEval | 3 |
| LLM_Variation | 258 |

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
# SecMutBench v2.8.0
# Benchmark: v2.8.0
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
# Step 1: Build dataset (required first)
./build_db.sh 500

# Step 2: Run evaluation
./run_evaluation.sh --models "qwen2.5-coder:7b" --samples 30

# With ablation study (all prompt variants)
./run_evaluation.sh --models "qwen2.5-coder:7b qwen2.5-coder:14b-instruct" --ablation --samples 10

# With LLM-as-Judge (OpenAI)
./run_evaluation.sh --models "qwen2.5-coder:7b" --judge openai --samples 30

# With batch judge for 50% cost savings
./run_evaluation.sh --models "qwen2.5-coder:7b" --judge openai --batch-judge --samples 100

# With static analysis
./run_evaluation.sh --models "qwen2.5-coder:7b" --static-analysis --samples 30

# Full evaluation with all options
./run_evaluation.sh \
    --models "qwen2.5-coder:7b qwen2.5-coder:14b-instruct deepseek-coder-v2:latest" \
    --ablation \
    --judge openai \
    --batch-judge \
    --static-analysis \
    --shuffle \
    --samples 10

# Direct script usage
python baselines/run_llm_baselines.py --provider ollama --model qwen2.5-coder:7b --max-samples 30
python baselines/run_static_analysis.py --tool bandit
```

## Security Mutation Operators

### Active Operators (25)

| Operator | Description | Target CWEs |
|----------|-------------|-------------|
| PSQLI | Parameterized SQL to string concatenation | CWE-89 |
| RVALID | Remove input validation/sanitization | CWE-20, CWE-79 |
| INPUTVAL | Remove input validation checks | CWE-20 |
| PATHCONCAT | Unsafe path concatenation | CWE-22 |
| RMAUTH | Remove authentication checks | CWE-287, CWE-306 |
| HARDCODE | Inject hardcoded credentials | CWE-798 |
| WEAKCRYPTO | Use weak cryptographic algorithms (MD5/SHA1) | CWE-327 |
| WEAKKEY | Use inadequate key sizes | CWE-326 |
| WEAKRANDOM | Use weak PRNG (random instead of secrets) | CWE-338 |
| RENCRYPT | Remove encryption/TLS | CWE-319 |
| DESERIAL | Unsafe deserialization (pickle.loads) | CWE-502 |
| XXE | Enable external XML entities | CWE-611 |
| SSRF | Remove SSRF URL validation | CWE-918 |
| EVALINJECT | Enable eval/exec injection | CWE-94, CWE-95 |
| OPENREDIRECT | Remove redirect URL validation | CWE-601 |
| NOCERTVALID | Disable SSL certificate verification | CWE-295 |
| INFOEXPOSE | Expose sensitive data in errors | CWE-209 |
| REGEXDOS | Introduce ReDoS-vulnerable patterns | CWE-400 |
| MISSINGAUTH | Remove authorization checks | CWE-862 |
| LOGINJECT | Enable log injection | CWE-117 |
| LDAPINJECT | Enable LDAP injection | CWE-74 |
| FILEUPLOAD | Remove file upload validation | CWE-434 |
| IDOR | Remove object-level authorization | CWE-639 |
| CSRF_REMOVE | Remove CSRF token validation | CWE-352 |
| WEAKPERM | Set overly permissive file permissions | CWE-732 |

## Project Structure

```
SecMutBench/
├── data/
│   ├── dataset2.json          # Main benchmark (339 samples, 1,869 mutants)
│   ├── dataset.json           # Original benchmark (117 samples, 289 mutants)
│   └── splits/
│       ├── easy.json          # 136 samples
│       ├── medium.json        # 101 samples
│       └── hard.json          # 102 samples
├── operators/
│   ├── security_operators.py  # 25 active mutation operator implementations
│   └── operator_registry.py   # Operator-to-CWE mappings
├── evaluation/
│   ├── evaluate.py            # Main evaluation orchestrator
│   ├── mutation_engine.py     # Mutant generation
│   ├── test_runner.py         # Subprocess + pytest test execution
│   ├── conftest_template.py   # Mock injection templates
│   ├── metrics.py             # Score calculation
│   ├── prompts.py             # Prompt templates (including ablation)
│   ├── llm_judge.py           # LLM-as-judge evaluation
│   ├── version.py             # Version tracking for reproducibility
│   └── mocks/                 # 12 mock objects for safe test execution
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
│   ├── source_handlers.py     # Source-specific handlers (CWEval, SecurityEval, etc.)
│   ├── generate_variations.py # LLM variation generation pipeline
│   ├── validate_dataset_quality.py   # Dataset quality validation
│   ├── compute_mutant_validity.py    # Mutant validity analysis
│   ├── compute_test_validity.py      # Test validity aggregation
│   ├── evaluate_reference_tests.py   # Reference test baseline
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
