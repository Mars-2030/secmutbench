---
language:
- en
license: mit
task_categories:
- text-generation
- text2text-generation
tags:
- security
- mutation-testing
- vulnerability-detection
- code-generation
- security-testing
- benchmark
- python
- cwe
pretty_name: SecMutBench
size_categories:
- n<1K
configs:
- config_name: default
  data_files:
  - split: all
    path: data/dataset.json
  - split: easy
    path: data/splits/easy.json
  - split: medium
    path: data/splits/medium.json
  - split: hard
    path: data/splits/hard.json
dataset_info:
  features:
  - name: id
    dtype: string
  - name: cwe
    dtype: string
  - name: cwe_name
    dtype: string
  - name: difficulty
    dtype: string
  - name: secure_code
    dtype: string
  - name: insecure_code
    dtype: string
  - name: security_tests
    dtype: string
  - name: functional_tests
    dtype: string
  - name: entry_point
    dtype: string
  - name: source
    dtype: string
  splits:
  - name: all
    num_examples: 180
  - name: easy
    num_examples: 37
  - name: medium
    num_examples: 98
  - name: hard
    num_examples: 45
---

# SecMutBench

A benchmark for evaluating LLM-generated security tests using mutation testing.

## Dataset Description

SecMutBench evaluates whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

### Key Features

- **Security-Focused**: Samples mapped to 78 Common Weakness Enumeration (CWE) vulnerability types
- **Mutation Testing Evaluation**: Test quality measured by ability to kill security-relevant mutants
- **10 Security Mutation Operators**: Custom operators that inject realistic vulnerability patterns
- **Contamination Prevention**: Perturbation pipeline applied to public dataset samples

## Dataset Statistics

| Metric | Value |
|--------|-------|
| Total Samples | 180 |
| CWE Types | 78 |
| Languages | Python |
| Mutation Operators | 10 |

### By Difficulty

| Difficulty | Samples |
|------------|---------|
| Easy | 37 |
| Medium | 98 |
| Hard | 45 |

### By Source

| Source | Samples | Description |
|--------|---------|-------------|
| SecMutBench | 26 | Original samples (novel) |
| SecurityEval | 118 | Adapted from s2e-lab/SecurityEval |
| CyberSecEval | 36 | Adapted from Meta's PurpleLlama |

### Top CWE Types

| CWE | Name | Samples |
|-----|------|---------|
| CWE-89 | SQL Injection | 15 |
| CWE-78 | OS Command Injection | 12 |
| CWE-798 | Hardcoded Credentials | 8 |
| CWE-502 | Insecure Deserialization | 8 |
| CWE-79 | Cross-Site Scripting (XSS) | 7 |
| CWE-20 | Improper Input Validation | 7 |
| CWE-22 | Path Traversal | 6 |
| CWE-327 | Weak Cryptography | 5 |
| CWE-601 | CWE-601 | 5 |
| CWE-611 | XXE Injection | 5 |

## Dataset Structure

Each sample contains:

```python
{
    "id": "sql_injection_001",
    "cwe": "CWE-89",
    "cwe_name": "SQL Injection",
    "difficulty": "easy",
    "secure_code": "def get_user(user_id):\n    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n    ...",
    "insecure_code": "def get_user(user_id):\n    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n    ...",
    "security_tests": "def test_sql_injection():\n    result = get_user(\"1 OR 1=1\")\n    assert ...",
    "functional_tests": "def test_get_user():\n    result = get_user(1)\n    assert result is not None",
    "entry_point": "get_user",
    "source": "SecMutBench"
}
```

## Usage

### Loading the Dataset

```python
from datasets import load_dataset

# Load full dataset
dataset = load_dataset("secmutbench/SecMutBench")

# Load specific split
easy = load_dataset("secmutbench/SecMutBench", split="easy")
```

### Local Usage

```python
import json

# Load dataset
with open("data/dataset.json") as f:
    data = json.load(f)

samples = data["samples"]
print(f"Total samples: {len(samples)}")
```

## Evaluation Metrics

### Primary Metrics

- **Mutation Score**: Killed Mutants / Total Mutants
- **Vulnerability Detection Rate**: Tests pass on secure code AND fail on insecure code

### Secondary Metrics

- Line Coverage
- Branch Coverage

### LLM-as-Judge Metrics

- Security Relevance (GPT-4/Claude evaluated)
- Test Quality (GPT-4/Claude evaluated)

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

## Contamination Prevention

SecMutBench employs contamination mitigation strategies:

1. **Perturbation Pipeline**: Adapted samples undergo systematic modification
2. **Novel Samples**: 26 samples are originally authored (14%)
3. **Temporal Filtering**: CVE-based samples use recent vulnerabilities
4. **Contamination Audit**: N-gram overlap analysis available

## Citation

```bibtex
@inproceedings{secmutbench2025,
  title={SecMutBench: A Benchmark for Evaluating LLM Security Test Generation via Mutation Testing},
  author={SecMutBench Team},
  booktitle={Proceedings},
  year={2025}
}
```

## License

MIT License

## Links

- [GitHub Repository](https://github.com/secmutbench/SecMutBench)
- [Documentation](https://github.com/secmutbench/SecMutBench#readme)
- [Croissant Metadata](https://github.com/secmutbench/SecMutBench/blob/main/croissant.json)
