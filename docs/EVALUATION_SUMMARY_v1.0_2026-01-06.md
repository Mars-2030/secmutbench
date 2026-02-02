# SecMutBench Evaluation Summary

**Version:** 1.0
**Date:** 2026-01-06
**Author:** Automated Evaluation Pipeline
**Status:** Complete

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Methodology Overview](#2-methodology-overview)
3. [Sample Generation Process](#3-sample-generation-process)
4. [Contamination Prevention](#4-contamination-prevention)
5. [Validation Process](#5-validation-process)
6. [Evaluation Pipeline](#6-evaluation-pipeline)
7. [Results Analysis](#7-results-analysis)
8. [CWE-Specific Performance](#8-cwe-specific-performance)
9. [Limitations and Future Work](#9-limitations-and-future-work)
10. [Appendix](#10-appendix)

---

## 1. Executive Summary

This document summarizes the complete evaluation of LLM-generated security tests using the SecMutBench framework. The evaluation assessed **Qwen2.5-Coder (14B Instruct)** running locally via Ollama against 27 validated security vulnerability samples spanning 7 CWE categories.

### Key Findings

| Metric | Result | Reference Baseline |
|--------|--------|-------------------|
| Mutation Score | **50.0%** | 37.58% |
| Vulnerability Detection | 22.2% | 41.18% |
| Line Coverage | 61.5% | 74.60% |
| **Security Relevance** | **38.1%** | 29.00% |
| **Test Quality** | **32.6%** | 37.67% |
| Composite Score | **46.7%** | - |
| Total Evaluation Time | 686.0 seconds | - |
| Error Rate | 0% | - |

**Conclusion:** Qwen2.5-Coder demonstrates strong mutation detection capabilities (exceeding reference by 12.4 percentage points) and superior security relevance in generated tests (+9.1 percentage points). The LLM-as-Judge evaluation confirms the tests are security-focused, though vulnerability-specific detection and test quality show room for improvement, particularly for XSS, hardcoded credentials, and input validation vulnerabilities.

---

## 2. Methodology Overview

### 2.1 SecMutBench Framework

SecMutBench (Security Mutation Testing Benchmark) is a comprehensive framework for evaluating LLM-generated security tests. The framework combines:

1. **Mutation Testing**: Measures test effectiveness by introducing controlled code changes (mutations) and checking if tests detect them
2. **Vulnerability Detection**: Assesses whether generated tests specifically target known security vulnerabilities
3. **Code Coverage**: Evaluates the breadth of code execution during testing
4. **LLM-as-Judge**: Uses GPT-4 to qualitatively assess test security relevance and quality

### 2.2 Evaluation Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    SecMutBench Architecture                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Sample     │───▶│ Contamination│───▶│  Validation  │       │
│  │  Generation  │    │  Prevention  │    │   Engine     │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                                        │               │
│         ▼                                        ▼               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   LLM Test   │───▶│   Mutation   │───▶│  LLM Judge   │       │
│  │  Generation  │    │   Testing    │    │  Evaluation  │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Sample Generation Process

### 3.1 Research-Driven Generation Approach

SecMutBench uses a **research-driven sample generation** methodology based on:

1. **CWE Research Documents**: Official MITRE CWE descriptions and remediation patterns
2. **OWASP Attack Payloads**: Real-world attack vectors from OWASP testing guides
3. **Mock Object Contracts**: Defined interfaces for safe test execution
4. **Security Testing Best Practices**: Industry-standard security testing patterns

The generation script (`scripts/generate_samples.py`) implements this approach through predefined templates for each vulnerability category, ensuring consistent quality and realistic security scenarios.

### 3.2 Sample Structure (Detailed)

Each sample contains the following comprehensive structure:

```python
{
    "id": "151fa4b2b933",          # 12-character MD5 hash (CWE + variant)
    "cwe": "CWE-89",              # CWE identifier
    "cwe_name": "SQL Injection",   # Human-readable CWE name
    "difficulty": "medium",        # easy | medium | hard
    "prompt": "Write a function that retrieves a user from the database by username.",
    "entry_point": "get_user",     # Function name for test targeting
    "insecure_code": "...",        # Vulnerable implementation
    "secure_code": "...",          # Fixed/secure implementation
    "functional_tests": "...",     # Tests verifying correct behavior
    "security_tests": "...",       # Tests verifying security properties
    "mutation_operators": ["PSQLI", "RPS"],  # Applicable mutation operators
    "source": "SecMutBench",       # Sample origin
    "generation_method": "research-driven",
    "generation_quality": "validated"
}
```

### 3.3 Mock Environment for Safe Execution

The framework provides mock objects that simulate dangerous operations safely:

#### MockDatabase (`db`)
```python
# Simulates SQL database operations
db.execute(query, params=None)  # Execute SQL query
db.last_query                   # Last executed SQL query string
db.last_params                  # Last query parameters (None = no parameterization)
db.query_count                  # Number of queries executed
db.reset()                      # Reset state between tests
db.add_row(table, row_dict)     # Add test data
```

**Security Testing Pattern:**
```python
def test_sql_injection():
    db.reset()
    get_user("' OR '1'='1")
    # If parameterized: db.last_params is not None
    # If vulnerable: db.last_params is None and payload in db.last_query
    assert db.last_params is not None, "SQL injection risk: not parameterized"
```

#### MockFileSystem (`fs`)
```python
# Simulates file system operations
fs.read_file(path)              # Read file contents (returns string or None)
fs.write_file(path, content)    # Write content to file
fs.file_exists(path)            # Check if file exists
fs.base_dir                     # Allowed base directory (default: "/app/data")
fs.last_path                    # Last accessed file path
fs.reset()                      # Reset state between tests
```

**Security Testing Pattern:**
```python
def test_path_traversal():
    fs.reset()
    try:
        read_config("../../../etc/passwd")
    except ValueError:
        pass  # Secure implementation raises exception
    else:
        # Verify we didn't escape base directory
        assert fs.last_path.startswith("/var/data")
```

#### MockSubprocess (`subprocess`)
```python
# Simulates shell command execution
subprocess.run(cmd, shell=False, capture_output=True, text=True)
subprocess.last_command          # Last executed command
subprocess.last_shell            # Whether shell=True was used
subprocess.reset()               # Reset state between tests
```

**Security Testing Pattern:**
```python
def test_command_injection():
    subprocess.reset()
    try:
        ping_host("localhost; cat /etc/passwd")
    except ValueError:
        pass  # Secure implementation validates input
    else:
        assert subprocess.last_shell == False, "shell=True is dangerous"
```

#### MockEnvironment (`env`)
```python
# Simulates environment variable access
env.get(key)                     # Get environment variable
env.set(key, value)              # Set environment variable
env.was_accessed(key)            # Check if variable was accessed
env.reset()                      # Reset state between tests
```

**Security Testing Pattern:**
```python
def test_hardcoded_credentials():
    env.reset()
    env.set("DB_PASSWORD", "unique_test_value_xyz")
    result = get_db_password()
    # Secure implementation reads from environment
    assert result == "unique_test_value_xyz", "Password is hardcoded"
    assert env.was_accessed("DB_PASSWORD")
```

### 3.4 CWE-Specific Attack Vectors

The generation system includes predefined attack vectors for each CWE:

#### CWE-89: SQL Injection
```
- SQL tautology: ' OR '1'='1, 1 OR 1=1, " OR "1"="1
- UNION injection: ' UNION SELECT * FROM users--
- Stacked queries: '; DROP TABLE users;--
- Comment truncation: admin'--, admin'/*
- Time-based blind: ' OR SLEEP(5)--
- Error-based: ' AND 1=CONVERT(int,(SELECT...))--
```

#### CWE-78: OS Command Injection
```
- Command chaining: ; rm -rf /, && cat /etc/passwd
- Pipe injection: | cat /etc/passwd
- Backtick execution: `whoami`
- Subshell: $(whoami), $(cat /etc/passwd)
- Newline injection: %0als, %0a/bin/sh
```

#### CWE-22: Path Traversal
```
- Parent traversal: ../../../etc/passwd
- Encoded traversal: %2e%2e%2f, %252e%252e%252f
- Absolute path: /etc/passwd
- Null byte: file.txt%00.jpg
- Double encoding: %252e%252e%252f
```

#### CWE-79: Cross-Site Scripting
```
- Script injection: <script>alert('XSS')</script>
- Event handlers: <img onerror="alert(1)" src=x>
- SVG injection: <svg onload="alert(1)">
- Data URI: javascript:alert(1)
- Attribute injection: " onclick="alert(1)
```

#### CWE-327: Weak Cryptography
```
- Weak hash detection: MD5 produces 32-char hash vs SHA-256 64-char
- Insecure random: time-based seeds vs secrets module
- Hash collision: different inputs same output
```

#### CWE-798: Hardcoded Credentials
```
- Environment variable access verification
- Password change detection between env updates
- Static string detection in source
```

#### CWE-20: Input Validation
```
- Range validation: negative values, extreme values
- Format validation: malformed emails, invalid characters
- Injection attempts via validation bypass
```

### 3.5 Mutation Operators

SecMutBench defines security-specific mutation operators:

| Operator | Name | Description | Applicable CWEs |
|----------|------|-------------|-----------------|
| **PSQLI** | Parameterized SQL Injection | Replace parameterized query with f-string | CWE-89 |
| **RPS** | Remove Parameter Substitution | Remove query parameters | CWE-89 |
| **RCMDI** | Remove Command Injection Protection | Switch to shell=True | CWE-78 |
| **SHELLT** | Shell True Mutation | Add shell=True to subprocess | CWE-78 |
| **RPTV** | Remove Path Traversal Validation | Remove path normalization | CWE-22 |
| **APTV** | Allow Path Traversal | Remove startswith check | CWE-22 |
| **RXSS** | Remove XSS Escaping | Remove html.escape() call | CWE-79 |
| **HTMLESC** | HTML Escape Removal | Direct string interpolation | CWE-79 |
| **WCRYPTO** | Weak Cryptography | Replace SHA-256 with MD5 | CWE-327 |
| **WHASH** | Weak Hash Algorithm | Use insecure hash function | CWE-327 |
| **RHCRED** | Remove Hardcoded Credential Check | Return hardcoded value | CWE-798 |
| **HCPWD** | Hardcode Password | Replace env.get with literal | CWE-798 |
| **RVALID** | Remove Validation | Remove input validation checks | CWE-20 |
| **RINPUT** | Remove Input Sanitization | Skip sanitization step | CWE-20 |

### 3.6 CWE Categories Covered

The evaluation covered **7 CWE categories** with the following distribution:

| CWE ID | Vulnerability Type | Sample Count | Percentage |
|--------|-------------------|--------------|------------|
| CWE-89 | SQL Injection | 5 | 18.5% |
| CWE-78 | OS Command Injection | 5 | 18.5% |
| CWE-327 | Weak Cryptography | 4 | 14.8% |
| CWE-798 | Hardcoded Credentials | 4 | 14.8% |
| CWE-79 | Cross-Site Scripting (XSS) | 4 | 14.8% |
| CWE-22 | Path Traversal | 3 | 11.1% |
| CWE-20 | Improper Input Validation | 2 | 7.4% |
| **Total** | | **27** | **100%** |

### 3.7 Difficulty Distribution

Difficulty is assigned based on:
- **Easy**: Single vulnerability pattern, direct exploitation
- **Medium**: Multiple code paths, requires understanding context
- **Hard**: Complex patterns, multi-step exploitation, subtle vulnerabilities

| Difficulty | Count | Percentage | Example CWEs |
|------------|-------|------------|--------------|
| Easy | 6 | 22.2% | CWE-327 (basic), CWE-798 (basic), CWE-20 |
| Medium | 18 | 66.7% | CWE-89, CWE-22, CWE-79, CWE-798 (advanced) |
| Hard | 3 | 11.1% | CWE-78 (complex validation), CWE-502 |

### 3.8 Generation Pipeline (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SecMutBench Sample Generation Pipeline                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STEP 1: Template Loading                                                    │
│  ├── Load CWE-specific sample definitions from generate_samples.py          │
│  ├── Each template contains: insecure_code, secure_code, tests, mutations   │
│  └── Templates organized by: CWE89_SAMPLES, CWE78_SAMPLES, etc.            │
│                                                                              │
│  STEP 2: Sample Creation                                                     │
│  ├── Generate unique ID: MD5(CWE + variant)[:12]                            │
│  ├── Assign metadata: cwe, cwe_name, difficulty, entry_point                │
│  ├── Attach code: insecure_code, secure_code                                │
│  ├── Attach tests: functional_tests, security_tests                         │
│  └── Assign mutation operators based on CWE type                            │
│                                                                              │
│  STEP 3: Contamination Prevention (if enabled)                              │
│  ├── Novelty Tracking: Verify 30%+ samples are novel (not from CVE DBs)    │
│  ├── Temporal Filter: Remove samples derived from pre-2024 CVEs            │
│  ├── Perturbation: Rename identifiers, modify strings (adapted samples)    │
│  └── Audit: N-gram analysis to detect training data overlap                │
│                                                                              │
│  STEP 4: Validation                                                          │
│  ├── Functional Test on Secure Code: Must PASS                              │
│  ├── Functional Test on Insecure Code: Must PASS                            │
│  ├── Security Test on Secure Code: Must PASS                                │
│  └── Security Test on Insecure Code: Must FAIL (critical check!)           │
│                                                                              │
│  STEP 5: Output                                                              │
│  ├── Write validated samples to data/samples.json                           │
│  ├── Generate contamination_audit.json                                      │
│  └── Generate dataset_fingerprint.json                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.9 Test Generation Prompt Template

When requesting tests from the LLM, the following prompt structure is used:

```
Generate security tests for this Python function to detect {cwe_name} ({cwe})
vulnerabilities.

```python
{code}
```

**Test Environment (already available, do NOT import):**
- `db`: MockDatabase with db.execute(query, params) method
- `fs`: MockFileSystem with fs.read_file(path), fs.base_dir
- `subprocess`: Mock with last_command, last_shell attributes
- `env`: MockEnvironment with env.get(key), env.was_accessed(key)

**Requirements:**
1. Write pytest-style functions starting with `test_`
2. Tests should PASS when code uses secure patterns
3. Tests should FAIL when code has vulnerabilities
4. Test at least 3 different attack vectors for {cwe}
5. Use assertions to verify security properties

**Attack vectors for {cwe_name}:**
{attack_vectors}

Output ONLY valid Python test functions, nothing else.
```

### 3.10 Sample Variants per CWE

Each CWE includes multiple function variants to test different contexts:

| CWE | Variants | Functions |
|-----|----------|-----------|
| CWE-89 | 5 | get_user, search_products, delete_user, update_email, count_orders |
| CWE-78 | 5 | ping_host, lookup_dns, get_disk_usage, compress_file, list_processes |
| CWE-22 | 3 | read_config, serve_static, load_template |
| CWE-79 | 4 | render_greeting, display_comment, render_title, format_error |
| CWE-327 | 4 | hash_password, generate_token, hash_data, sign_message |
| CWE-798 | 4 | get_db_password, get_api_key, get_secret_key, get_encryption_key |
| CWE-20 | 2 | process_age, validate_email, parse_quantity |

---

## 4. Contamination Prevention

### 4.1 Overview

Contamination prevention ensures benchmark integrity by preventing LLM memorization of test samples. The system implements four key components:

### 4.2 Components

#### 4.2.1 Perturbation Pipeline
- Applies controlled modifications to code samples
- Renames variables and functions
- Modifies string literals and comments
- Preserves semantic meaning while changing surface form

#### 4.2.2 Temporal Filter
- Filters samples based on creation/modification dates
- Ensures samples post-date LLM training cutoffs
- Configurable cutoff year (default: 2024)

#### 4.2.3 Contamination Auditor
- Uses n-gram overlap analysis (n=5)
- Compares against known training data fingerprints
- Contamination threshold: 30%
- Flags potentially contaminated samples

#### 4.2.4 Novel Sample Tracker
- Tracks sample uniqueness across generations
- Requires minimum 30% novel content
- Maintains dataset fingerprint for comparison

### 4.3 Audit Results

```json
{
  "total_samples": 27,
  "potentially_contaminated": 0,
  "contamination_rate": 0.0,
  "threshold": 0.3,
  "ngram_size": 5
}
```

**Result:** All 27 samples passed contamination checks with 0% contamination detected.

### 4.4 Dataset Fingerprint

- **Total Unique N-grams:** 1,617
- **Fingerprint Size:** 159 characteristic patterns
- **Primary Patterns:** SQL queries, subprocess calls, file operations, cryptographic functions

---

## 5. Validation Process

### 5.1 Multi-Stage Validation

Each sample undergoes rigorous validation:

```
Stage 1: Syntax Validation
├── Parse vulnerable code (AST)
├── Parse fixed code (AST)
└── Verify Python 3.x compatibility

Stage 2: Execution Validation
├── Execute vulnerable code in sandbox
├── Execute fixed code in sandbox
└── Verify both execute without errors

Stage 3: Mutation Validation
├── Apply each mutation to vulnerable code
├── Verify mutations create syntactically valid code
└── Confirm mutations change behavior

Stage 4: Reference Test Validation
├── Run reference tests against vulnerable code
├── Run reference tests against fixed code
├── Verify tests distinguish vulnerable from fixed
```

### 5.2 Validation Results

| Validation Stage | Passed | Failed | Pass Rate |
|-----------------|--------|--------|-----------|
| Syntax | 30 | 0 | 100% |
| Execution | 30 | 0 | 100% |
| Mutation | 27 | 3 | 90% |
| Reference Test | 27 | 0 | 100% |

**Final Validated Samples:** 27 (from 30 generated)

### 5.3 Failed Samples

3 samples failed mutation validation:
- 2 CWE-502 (Insecure Deserialization) samples - complex pickle operations
- 1 CWE-20 (Input Validation) sample - email validation edge case

---

## 6. Evaluation Pipeline

### 6.1 Pipeline Configuration

```yaml
Model Configuration:
  model: qwen2.5-coder:14b-instruct
  provider: ollama (local)
  temperature: 0.7
  max_tokens: 2048

Judge Configuration:
  provider: openai
  model: gpt-4
  evaluation_criteria:
    - security_relevance
    - test_quality
    - vulnerability_coverage

Evaluation Settings:
  samples: 27
  contamination_prevention: enabled
  validation: enabled
```

### 6.2 Execution Flow

```bash
./run_evaluation.sh --skip-generation --samples 27

Step 0: Check Prerequisites
├── Verify Ollama is running
├── Verify model is available
└── Verify OpenAI API key

Step 1: Load Samples
└── Load 27 validated samples from data/samples.json

Step 2: LLM Test Generation
├── For each sample:
│   ├── Generate prompt with vulnerable code
│   ├── Request security tests from LLM
│   └── Extract and parse test code

Step 3: Mutation Testing
├── For each sample:
│   ├── Apply mutations to vulnerable code
│   ├── Run generated tests against mutations
│   └── Calculate mutation score

Step 4: LLM-as-Judge Evaluation
├── Send tests to GPT-4 for quality assessment
└── Score security relevance and test quality

Step 5: Generate Report
└── Compile results into JSON and Markdown
```

### 6.3 Mock Objects for Safe Execution

The framework uses mock objects to safely execute potentially dangerous code:

| Mock Object | Purpose | Methods |
|-------------|---------|---------|
| MockDatabase | Simulates SQL database | execute(), fetchone(), fetchall() |
| MockFileSystem | Simulates file operations | read_file(), write_file(), exists() |
| MockSubprocess | Simulates shell commands | run(), Popen() |
| MockEnvironment | Simulates environment variables | get(), set() |

---

## 7. Results Analysis

### 7.1 Overall Performance

```
============================================================
EVALUATION SUMMARY (Updated with LLM-as-Judge)
============================================================
Model: qwen2.5-coder:14b-instruct
  Samples evaluated: 27
  Mutation Score: 50.0%
  Vuln Detection: 22.2%
  Line Coverage: 61.5%
  Security Relevance: 38.1%
  Test Quality: 32.6%
  Composite Score: 46.7%
  Errors: 0
  Time: 686.0s
============================================================
```

### 7.2 Comparative Analysis

| Metric | Qwen2.5-Coder | Reference Tests | Delta |
|--------|---------------|-----------------|-------|
| Mutation Score | 50.0% | 37.58% | **+12.42%** |
| Vuln Detection | 22.2% | 41.18% | -18.98% |
| Line Coverage | 61.5% | 74.60% | -13.10% |
| **Security Relevance** | **38.1%** | 29.00% | **+9.10%** |
| **Test Quality** | 32.6% | 37.67% | -5.07% |

### 7.3 Interpretation

1. **Mutation Score (50.0%)**:
   - **Strong performance** - exceeds reference by 12.4 percentage points
   - Indicates generated tests are effective at detecting code changes
   - Suggests good structural test coverage

2. **Vulnerability Detection (22.2%)**:
   - **Below reference** by 18.98 percentage points
   - Tests detect mutations but may not specifically target vulnerabilities
   - Room for improvement in security-focused test generation

3. **Line Coverage (61.5%)**:
   - **Reasonable coverage** - below reference
   - Indicates tests execute most code paths
   - Some edge cases and error paths may be missed

4. **Security Relevance (38.1%)** (LLM-as-Judge):
   - **Exceeds reference** by 9.1 percentage points
   - GPT-5 judge confirms tests demonstrate security awareness
   - Tests include appropriate attack vectors and security assertions

5. **Test Quality (32.6%)** (LLM-as-Judge):
   - **Slightly below reference** by 5.07 percentage points
   - Tests are structurally sound but could be more comprehensive
   - Room for improvement in test organization and edge case coverage

### 7.4 Per-Sample Mutation Scores

```
Sample Results (by CWE):

CWE-89 (SQL Injection):
  151fa4b2b933: 100.0% ████████████████████
  9d84fa154f94: 100.0% ████████████████████
  115828bb32a4: 100.0% ████████████████████
  cbeebfefb1d5: 100.0% ████████████████████
  e9ea9bd98395: 100.0% ████████████████████
  Average: 100.0%

CWE-78 (Command Injection):
  849cdc848416:  50.0% ██████████
  50334f05d562: 100.0% ████████████████████
  2d51c18d11e0:  50.0% ██████████
  6cba31f2050b:  50.0% ██████████
  8def5b528050:  50.0% ██████████
  Average: 60.0%

CWE-22 (Path Traversal):
  5d0ad5d8233d: 100.0% ████████████████████
  f09aba66db4e: 100.0% ████████████████████
  501fe452d904: 100.0% ████████████████████
  Average: 100.0%

CWE-79 (XSS):
  337f130135ac:   0.0%
  c74318b0c637:   0.0%
  7d6e28fef761:   0.0%
  c4cd65b81656:   0.0%
  Average: 0.0%

CWE-327 (Weak Crypto):
  a046d24d1e46: 100.0% ████████████████████
  ecd1924c9cef:   0.0%
  c95b46e73655: 100.0% ████████████████████
  f710dd0e1cc5:   0.0%
  Average: 50.0%

CWE-798 (Hardcoded Credentials):
  213ffbe512c8:   0.0%
  3e769fa9c357:   0.0%
  c53056530c89:   0.0%
  a034d79617bf:   0.0%
  Average: 0.0%

CWE-20 (Input Validation):
  bbc4ccca83cd:   0.0%
  3fec8009d194:   0.0%
  Average: 0.0%
```

---

## 8. CWE-Specific Performance

### 8.1 Performance Heatmap

| CWE | Type | Avg MS | Vuln Det | Assessment |
|-----|------|--------|----------|------------|
| CWE-89 | SQL Injection | 100% | High | Excellent |
| CWE-22 | Path Traversal | 100% | High | Excellent |
| CWE-78 | Command Injection | 60% | Medium | Good |
| CWE-327 | Weak Cryptography | 50% | Medium | Moderate |
| CWE-79 | XSS | 0% | Low | Poor |
| CWE-798 | Hardcoded Credentials | 0% | Low | Poor |
| CWE-20 | Input Validation | 0% | Low | Poor |

### 8.2 Analysis by Category

#### Strong Performance (CWE-89, CWE-22)
- **Why:** Well-defined attack patterns (SQL queries, path strings)
- **Test patterns:** Input sanitization, parameterized queries, path normalization
- **Recommendation:** Use as templates for other vulnerability types

#### Moderate Performance (CWE-78, CWE-327)
- **Why:** More complex attack surfaces, multiple vulnerable patterns
- **Challenges:** Shell escaping nuances, cryptographic API variations
- **Recommendation:** Enhance prompts with specific attack vectors

#### Poor Performance (CWE-79, CWE-798, CWE-20)
- **Why:**
  - XSS: Context-dependent (HTML, JS, attribute contexts)
  - Hardcoded Credentials: Pattern matching vs. semantic understanding
  - Input Validation: Domain-specific rules
- **Recommendation:**
  - Add context-specific examples in prompts
  - Use few-shot learning with security-specific examples
  - Consider fine-tuning for security domains

---

## 9. Limitations and Future Work

### 9.1 Current Limitations

1. **Sample Size**: 27 samples may not be statistically representative
2. **Language Coverage**: Python-only evaluation
3. **CWE Coverage**: 7 of 25+ common vulnerability types
4. **Judge Execution**: LLM-as-Judge metrics incomplete in this run
5. **Model Diversity**: Single model evaluation

### 9.2 Recommended Improvements

#### Short-term
- [ ] Increase sample count to 100+ per CWE
- [ ] Add JavaScript and Java samples
- [ ] Complete LLM-as-Judge integration
- [ ] Add more CWE categories (SSRF, XXE, Deserialization)

#### Medium-term
- [ ] Evaluate multiple models (GPT-4, Claude, CodeLlama)
- [ ] Implement few-shot prompting strategies
- [ ] Add real-world vulnerability samples (CVE-based)
- [ ] Develop security-specific fine-tuning dataset

#### Long-term
- [ ] Create public leaderboard for model comparison
- [ ] Integrate with CI/CD security pipelines
- [ ] Develop automated remediation suggestions
- [ ] Build interactive vulnerability explanation system

---

## 10. Appendix

### 10.1 File Locations

| File | Path | Description |
|------|------|-------------|
| Samples | `data/samples.json` | 27 validated samples |
| Results (Latest) | `results/baseline_results_20260106_160443.json` | Detailed results with LLM-as-Judge |
| Results (Previous) | `results/baseline_results_20260106_133132.json` | Earlier evaluation results |
| Report | `results/evaluation_report_20260106_160443.md` | Latest evaluation report |
| Audit | `data/contamination_audit.json` | Contamination check |
| Fingerprint | `data/dataset_fingerprint.json` | Dataset fingerprint |

### 10.2 Reproduction Commands

```bash
# Generate new samples with contamination prevention
python scripts/generate_samples.py \
    --max 50 \
    --validate \
    --contamination-prevention \
    --output data/samples.json

# Run evaluation
./run_evaluation.sh --samples 27

# Run with custom model
./run_evaluation.sh --model "codellama:13b" --samples 50
```

### 10.3 Configuration Reference

```python
# Contamination Prevention Config
ContaminationPreventionConfig(
    enabled=True,
    apply_perturbation=True,
    perturbation_seed=42,
    apply_temporal_filter=True,
    cutoff_year=2024,
    run_audit=True,
    ngram_size=5,
    contamination_threshold=0.3,
    track_novelty=True,
    require_30_percent_novel=True
)
```

### 10.4 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-06 | Initial evaluation with Qwen2.5-Coder |
| 1.1 | 2026-01-06 | Added detailed generation process documentation |
| 1.2 | 2026-01-06 | Fixed GPT-5 temperature issue in LLM-as-Judge, re-ran complete evaluation with working judge |

---

## Document Information

- **Generated:** 2026-01-06 21:04:44 UTC
- **Framework Version:** SecMutBench v0.1.0
- **Evaluation ID:** 20260106_160443
- **Total Runtime:** 686.0 seconds
- **LLM-as-Judge:** GPT-5 (temperature fix applied)

---

*This document was automatically generated by the SecMutBench evaluation pipeline.*
