# SecMutBench

A benchmark for evaluating LLM-generated security tests using mutation testing.

## Overview

SecMutBench evaluates whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

## Key Features

- **Security-Focused**: Samples mapped to Common Weakness Enumeration (CWE) vulnerability types
- **Mutation Testing Evaluation**: Test quality measured by ability to kill security-relevant mutants
- **10 Security Mutation Operators**: Custom operators that inject realistic vulnerability patterns

## Statistics

| Metric | Value |
|--------|-------|
| Total Samples | 155 |
| CWE Types | 22 |
| Languages | Python |
| Mutation Operators | 10 |

### Data Sources

| Source | Samples | Description |
|--------|---------|-------------|
| SecMutBench | 50 | Original samples created for this benchmark |
| SecurityEval | 59 | From s2e-lab/SecurityEval on HuggingFace |
| CyberSecEval | 46 | Python samples from Meta's PurpleLlama |

### CWE Distribution (Top 10)

| CWE | Name | Samples |
|-----|------|---------|
| CWE-78 | OS Command Injection | 30 |
| CWE-89 | SQL Injection | 15 |
| CWE-22 | Path Traversal | 12 |
| CWE-20 | Improper Input Validation | 12 |
| CWE-79 | Cross-Site Scripting (XSS) | 11 |
| CWE-798 | Hardcoded Credentials | 11 |
| CWE-502 | Insecure Deserialization | 10 |
| CWE-327 | Weak Cryptography | 7 |
| CWE-611 | XXE Injection | 6 |
| CWE-94 | Code Injection | 5 |

### Difficulty Distribution

| Difficulty | Samples |
|------------|---------|
| Easy | 73 |
| Medium | 69 |
| Hard | 13 |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/SecMutBench.git
cd SecMutBench

# Install dependencies
pip install -r requirements.txt

# Generate difficulty splits
python scripts/generate_splits.py
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
    assert result is None or len(result) <= 1
"""

results = evaluate_generated_tests(sample, generated_tests)
print(f"Mutation Score: {results['metrics']['mutation_score']:.2%}")
print(f"Vulnerability Detected: {results['metrics']['vuln_detected']}")
```

### Evaluate Reference Tests

```bash
python evaluation/evaluate.py --model reference
```

### Filter by Difficulty or CWE

```bash
# Easy samples only
python evaluation/evaluate.py --difficulty easy

# SQL Injection samples only
python evaluation/evaluate.py --cwe CWE-89
```

## Security Mutation Operators

| Operator | Description | Target CWEs |
|----------|-------------|-------------|
| PSQLI | Parameterized SQL to string injection | CWE-89 |
| RVALID | Remove input validation/sanitization | CWE-20, CWE-79 |
| CMDINJECT | Enable shell command injection | CWE-78 |
| PATHCONCAT | Unsafe path concatenation | CWE-22 |
| RMAUTH | Remove authentication checks | CWE-287 |
| HARDCODE | Inject hardcoded credentials | CWE-798 |
| WEAKCRYPTO | Use weak cryptographic algorithms | CWE-327 |
| RHTTPO | Remove HttpOnly cookie flag | CWE-1004 |
| RENCRYPT | Remove encryption/TLS | CWE-319 |
| DESERIAL | Unsafe deserialization | CWE-502 |

## Project Structure

```
SecMutBench/
├── data/
│   ├── samples.json           # Main benchmark (155 samples)
│   ├── metadata.json          # CWE descriptions, statistics
│   ├── raw_securityeval.json  # Raw SecurityEval data
│   ├── raw_cyberseceval.json  # Raw CyberSecEval data
│   └── splits/
│       ├── easy.json          # 73 samples
│       ├── medium.json        # 69 samples
│       └── hard.json          # 13 samples
├── operators/
│   ├── security_operators.py  # Mutation operator implementations
│   └── operator_registry.py   # Operator-to-CWE mappings
├── evaluation/
│   ├── evaluate.py            # Main evaluation script
│   ├── mutation_engine.py     # Mutant generation
│   ├── test_runner.py         # Test execution
│   └── metrics.py             # Score calculation
├── scripts/
│   ├── download_sources.py    # Download seed datasets
│   ├── transform_datasets.py  # Transform SecurityEval/CyberSecEval
│   ├── validate.py            # Validate samples
│   └── generate_splits.py     # Generate difficulty splits
├── Dockerfile
├── requirements.txt
└── README.md
```

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
