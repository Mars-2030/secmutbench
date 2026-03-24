# SecMutBench

> **Submitted to [ACM AIWare 2026 — Benchmark and Dataset Track](https://2026.aiwareconf.org/track/aiware-2026-benchmark---dataset-track)**
>
> *Paper under review. Author names withheld for double-blind review.*

A benchmark for evaluating LLM-generated security tests using mutation testing.

**Version:** 2.8.0

## Overview

SecMutBench evaluates whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

Given secure source code and a CWE category, an LLM generates security tests. These tests are then evaluated by running them against mutants — code variants with injected vulnerabilities. Tests that detect (kill) mutants demonstrate genuine security awareness.

## Key Features

- **Security-Focused**: 339 samples mapped to 30 Common Weakness Enumeration (CWE) vulnerability types
- **Mutation Testing Evaluation**: Test quality measured by ability to kill security-relevant mutants
- **25 Security Mutation Operators**: Custom operators that inject realistic vulnerability patterns with multiple variants
- **Pre-generated Mutants**: 1,869 deterministic mutants (avg 5.5/sample) for reproducible evaluation
- **Kill Classification**: Three-layer classification (semantic, incidental, crash) with mock-state observability
- **Multi-Modal Evaluation**: Combines mutation testing with LLM-as-judge metrics
- **CWE-Strict Operator Mapping**: Operators only fire on samples matching their target CWEs (no cross-contamination)
- **Multi-Source Dataset**: Samples from SecMutBench originals, CWEval, SecurityEval, and LLM-generated semantic variations

## Statistics

| Metric | Value |
|--------|-------|
| Total Samples | 339 |
| CWE Types | 30 |
| Language | Python |
| Mutation Operators | 25 |
| Pre-generated Mutants | 1,869 |
| Avg Mutants/Sample | 5.5 |
| Compilability | 100% |
| Difficulty Levels | Easy (136) / Medium (101) / Hard (102) |

### CWE Coverage

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

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Mars-2030/secmutbench.git
cd secmutbench

# Requires Python 3.11 (MutPy incompatible with 3.12+)
pip install -r requirements.txt
```

### Basic Usage

```python
from evaluation import load_benchmark, evaluate_generated_tests

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
print(f"Vulnerability Detected: {results['metrics']['vuln_detected']}")
```

### Run Evaluation

```bash
# Evaluate with a local LLM via Ollama
./run_evaluation.sh --models "qwen2.5-coder:7b" --samples 30

# With ablation study (all prompt variants)
./run_evaluation.sh --models "qwen2.5-coder:7b qwen2.5-coder:14b-instruct" --ablation --samples 10

# With LLM-as-Judge
./run_evaluation.sh --models "qwen2.5-coder:7b" --judge openai --samples 30

# With static analysis baselines
./run_evaluation.sh --models "qwen2.5-coder:7b" --static-analysis --samples 30

# Direct script usage
python baselines/run_llm_baselines.py --provider ollama --model qwen2.5-coder:7b --max-samples 30
python baselines/run_static_analysis.py --tool bandit
```

## Security Mutation Operators

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

## Kill Classification

SecMutBench classifies mutant kills to distinguish genuine security awareness from accidental detection:

| Category | Description | Layer |
|----------|-------------|-------|
| **Semantic** | AssertionError with security-relevant assertions | Layer 1 (keywords) or Layer 1.5 (mock observability) |
| **Incidental** | AssertionError without security terms | Layer 1 |
| **Crash** | ImportError, TypeError, SyntaxError, etc. | Layer 0 |

### Mock-State Observability (Layer 1.5)

Tests that access security-relevant mock attributes are classified as semantic kills:

```python
# Accesses db.last_params — a security-relevant mock attribute
def test_sql_injection():
    get_user("admin' OR '1'='1")
    assert "?" in db.last_query  # Checks for parameterized query
```

## Evaluation Metrics

### Primary Metrics

- **Mutation Score**: Killed Mutants / Total Mutants
- **Vulnerability Detection Rate**: Samples where security tests pass on secure code and fail on insecure code
- **Security Relevance**: LLM-judged assessment of test security focus

### Multi-Modal Evaluation

| Metric | Method | Weight |
|--------|--------|--------|
| Mutation Score | Execution | 50% |
| Security Relevance | LLM Judge | 20% |
| Test Quality | LLM Judge | 15% |
| Coverage | Execution | 15% |

## Project Structure

```
SecMutBench/
├── data/
│   ├── dataset2.json          # Main benchmark (339 samples, 1,869 mutants)
│   └── splits/                # Easy / Medium / Hard splits
├── operators/
│   ├── security_operators.py  # 25 mutation operator implementations
│   └── operator_registry.py   # Operator-to-CWE mappings
├── evaluation/
│   ├── evaluate.py            # Main evaluation orchestrator
│   ├── mutation_engine.py     # Mutant generation
│   ├── test_runner.py         # Subprocess + pytest execution
│   ├── metrics.py             # Score calculation
│   ├── prompts.py             # Prompt templates (including ablation variants)
│   ├── llm_judge.py           # LLM-as-judge evaluation
│   └── mocks/                 # Mock objects for safe test execution
├── baselines/
│   ├── run_llm_baselines.py   # LLM baseline evaluation
│   └── run_static_analysis.py # Bandit/Semgrep baselines
├── scripts/
│   ├── dataset_builder.py     # Dataset construction pipeline
│   ├── sample_generator.py    # Sample generation from templates
│   ├── generate_variations.py # LLM variation generation
│   └── validate_dataset_quality.py  # Quality validation
├── requirements.txt
└── README.md
```

## Contamination Prevention

SecMutBench employs four contamination mitigation strategies:

1. **Perturbation Pipeline**: Samples from public datasets undergo systematic modification (renaming, restructuring, comment changes)
2. **Novel Samples**: 30%+ of samples are originally authored
3. **Temporal Filtering**: CVE-based samples use vulnerabilities disclosed after January 2024
4. **Contamination Audit**: N-gram overlap analysis with known training corpora

## Dataset Building

```bash
# Build dataset (requires Python 3.11)
python scripts/dataset_builder.py --target 300

# Validate existing dataset
python scripts/dataset_builder.py --validate-only
```

## Docker Usage

```bash
docker build -t secmutbench .
docker run secmutbench --model reference
docker run secmutbench --difficulty easy --cwe CWE-89
```

## Citation

```bibtex
@inproceedings{secmutbench2026,
  title={SecMutBench: A Benchmark for Evaluating LLM Security Test Generation via Mutation Testing},
  booktitle={Proceedings of the ACM International Conference on AI-Powered Software (AIWare)},
  year={2026}
}
```

## License

MIT License
