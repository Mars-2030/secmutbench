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
    path: data/dataset2.json
  - split: easy
    path: data/splits/easy.json
  - split: medium
    path: data/splits/medium.json
  - split: hard
    path: data/splits/hard.json
- config_name: original
  data_files:
  - split: all
    path: data/dataset.json
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
  - name: source_type
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
  - name: mutation_operators
    sequence: string
  - name: mutants
    sequence:
      struct:
      - name: id
        dtype: string
      - name: operator
        dtype: string
      - name: description
        dtype: string
      - name: mutated_code
        dtype: string
      - name: mutant_category
        dtype: string
  - name: source
    dtype: string
  splits:
  - name: all
    num_examples: 339
  - name: easy
    num_examples: 136
  - name: medium
    num_examples: 101
  - name: hard
    num_examples: 102
---

# SecMutBench

A benchmark for evaluating LLM-generated security tests using mutation testing.

**Version:** 2.8.0

## Dataset Description

SecMutBench evaluates whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

### Key Features

- **Security-Focused**: Samples mapped to 30 Common Weakness Enumeration (CWE) vulnerability types
- **Mutation Testing Evaluation**: Test quality measured by ability to kill 1,869 pre-generated security-relevant mutants
- **25 Security Mutation Operators**: Custom operators that inject realistic vulnerability patterns
- **Multi-Source**: Samples from SecMutBench, CWEval, SecurityEval, and LLM-generated variations
- **Contamination Prevention**: Perturbation pipeline and LLM variations reduce training data overlap

## Dataset Statistics

| Metric | Value |
|--------|-------|
| Total Samples | 339 |
| CWE Types | 30 |
| Languages | Python |
| Mutation Operators | 25 |
| Pre-generated Mutants | 1,869 |
| Avg Mutants/Sample | 5.5 |
| Compilability | 100% |

### By Difficulty

| Difficulty | Samples |
|------------|---------|
| Easy | 136 |
| Medium | 101 |
| Hard | 102 |

### By Source

| Source | Samples | Description |
|--------|---------|-------------|
| SecMutBench | 75 | Original samples (novel) |
| CWEval | 3 | Adapted from CWEval benchmark |
| SecurityEval | 3 | Adapted from s2e-lab/SecurityEval |
| LLM_Variation | 258 | LLM-generated semantic-preserving variations |

### Top CWE Types

| CWE | Name | Samples |
|-----|------|---------|
| CWE-319 | Cleartext Transmission | 18 |
| CWE-89 | SQL Injection | 16 |
| CWE-306 | Missing Authentication | 16 |
| CWE-22 | Path Traversal | 15 |
| CWE-918 | SSRF | 15 |
| CWE-94 | Code Injection | 15 |
| CWE-400 | Resource Exhaustion (ReDoS) | 15 |
| CWE-352 | CSRF | 14 |
| CWE-295 | Certificate Validation | 14 |
| CWE-79 | Cross-Site Scripting (XSS) | 13 |
| CWE-798 | Hardcoded Credentials | 13 |
| CWE-611 | XXE Injection | 13 |
| CWE-327 | Weak Cryptography | 12 |
| CWE-732 | Incorrect Permissions | 12 |
| CWE-117 | Log Injection | 12 |

### Mutant Categories

| Category | Count | Percentage |
|----------|-------|------------|
| CWE-specific | 1,252 | 67% |
| Generic | 617 | 33% |

## Dataset Structure

Each sample contains:

```python
{
    "id": "sql_injection_001",
    "cwe": "CWE-89",
    "cwe_name": "SQL Injection",
    "difficulty": "easy",
    "source_type": "SecMutBench",
    "secure_code": "def get_user(user_id):\n    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n    ...",
    "insecure_code": "def get_user(user_id):\n    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n    ...",
    "security_tests": "def test_sql_injection():\n    result = get_user(\"1 OR 1=1\")\n    assert ...",
    "functional_tests": "def test_get_user():\n    result = get_user(1)\n    assert result is not None",
    "entry_point": "get_user",
    "mutation_operators": ["PSQLI", "RVALID"],
    "mutants": [
        {
            "id": "fd1834de",
            "operator": "PSQLI",
            "description": "Replace parameterized query with f-string interpolation",
            "mutated_code": "...",
            "mutant_category": "cwe_specific"
        }
    ],
    "source": "SecMutBench"
}
```

## Usage

### Loading the Dataset

```python
from datasets import load_dataset

# Load full dataset (v2.8.0)
dataset = load_dataset("Mars203020/secmutbench")

# Load specific split
easy = load_dataset("Mars203020/secmutbench", split="easy")

# Load original dataset (v2.6.2)
original = load_dataset("Mars203020/secmutbench", "original")
```

### Local Usage

```python
import json

# Load dataset
with open("data/dataset2.json") as f:
    data = json.load(f)

samples = data["samples"]
print(f"Total samples: {len(samples)}")
print(f"Total mutants: {sum(len(s['mutants']) for s in samples)}")
```

## Evaluation Metrics

### Primary Metrics

- **Mutation Score**: Killed Mutants / Total Mutants
- **Effective Mutation Score**: MS corrected for secure-pass rate
- **Vulnerability Detection Rate**: Tests pass on secure code AND fail on insecure code
- **Security Mutation Score**: Kills via security-relevant assertions only

### LLM-as-Judge Metrics

- **Security Relevance**: Does the test target the specific CWE with realistic attack vectors?
- **Test Quality**: Assertion quality, edge cases, best practices, mock usage

## Security Mutation Operators

| Operator | Description | Target CWEs |
|----------|-------------|-------------|
| PSQLI | Parameterized SQL to string injection | CWE-89 |
| RVALID | Remove input validation/sanitization | CWE-20, CWE-79 |
| PATHCONCAT | Unsafe path concatenation | CWE-22 |
| RMAUTH | Remove authentication checks | CWE-287, CWE-306 |
| HARDCODE | Inject hardcoded credentials | CWE-798 |
| WEAKCRYPTO | Use weak cryptographic algorithms | CWE-327 |
| WEAKRANDOM | Use weak PRNG | CWE-338 |
| RENCRYPT | Remove encryption/TLS | CWE-319 |
| DESERIAL | Unsafe deserialization | CWE-502 |
| XXE | Enable external XML entities | CWE-611 |
| SSRF | Remove SSRF URL validation | CWE-918 |
| EVALINJECT | Enable eval/exec injection | CWE-94, CWE-95 |
| OPENREDIRECT | Remove redirect validation | CWE-601 |
| NOCERTVALID | Disable SSL cert verification | CWE-295 |
| WEAKPERM | Set overly permissive permissions | CWE-732 |
| ... and 10 more | | |

## Contamination Prevention

SecMutBench employs contamination mitigation strategies:

1. **LLM Variation Pipeline**: 258 samples generated via semantic-preserving code transformations
2. **Novel Samples**: 75 originally authored samples (22%)
3. **Multi-Source**: Samples drawn from 4 independent sources
4. **Structural Deduplication**: Max 2 samples per structural pattern
5. **Contamination Audit**: N-gram overlap analysis available

## Submission

Submitted to [ACM AIWare 2026 — Benchmark and Dataset Track](https://2026.aiwareconf.org/track/aiware-2026-benchmark---dataset-track). Paper under review. Author names withheld for double-blind review.

## License

MIT License

## Links

- [GitHub Repository](https://github.com/Mars-2030/secmutbench)
- [HuggingFace Dataset](https://huggingface.co/datasets/Mars203020/secmutbench)
- [Croissant Metadata](https://github.com/Mars-2030/secmutbench/blob/main/croissant.json)
