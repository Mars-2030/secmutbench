# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecMutBench is a benchmark for evaluating how well LLMs generate security tests that detect vulnerabilities. Given secure code and a CWE category, an LLM generates security tests evaluated via mutation testing—tests that detect injected vulnerabilities (kill mutants) demonstrate genuine security awareness.

- **Language**: Python 3.11 (required - MutPy incompatible with 3.12+)
- **Dataset**: 304 samples, 15 CWEs, 18 mutation operators, 737 pre-generated mutants
- **Version**: 2.4.0

## Environment Setup

```bash
# Requires Python 3.11
conda activate sectest  # or: python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# For LLM evaluation, create .env with API keys:
# ANTHROPIC_API_KEY=...
# OPENAI_API_KEY=...
```

## Common Commands

### Run Evaluation
```bash
# Complete pipeline (requires Ollama running)
./run_evaluation.sh --samples 30 --models "qwen2.5-coder:14b-instruct"

# Test mode (1 sample, quick validation)
./run_evaluation.sh --test

# Filter by difficulty or CWE
python evaluation/evaluate.py --difficulty easy
python evaluation/evaluate.py --cwe CWE-89

# Evaluate reference tests only (no LLM)
python evaluation/evaluate.py --model reference
```

### Run LLM Baselines
```bash
# Ollama (local) - uses stratified sampling for CWE diversity
python baselines/run_llm_baselines.py --provider ollama --model qwen2.5-coder:7b --max-samples 30

# OpenAI with LLM-as-Judge
python baselines/run_llm_baselines.py --provider openai --max-samples 10 --use-judge

# Shuffle samples for random ordering
python baselines/run_llm_baselines.py --provider ollama --model qwen2.5-coder:7b --shuffle --seed 42
```

### Run Static Analysis Baselines
```bash
python baselines/run_static_analysis.py --tool bandit --max-samples 100
python baselines/run_static_analysis.py --tool semgrep --semgrep-rules p/security-audit
python baselines/run_static_analysis.py --tool both
```

### Build/Validate Dataset
```bash
python scripts/dataset_builder.py --target 300
python scripts/dataset_builder.py --validate-only
```

### Testing
```bash
pytest tests/
black --check .
```

## Architecture

### Core Data Flow

```
Benchmark Sample → Generate/Load Mutants → Run Tests (subprocess+pytest)
    → Classify Kills (semantic/incidental/crash) → Calculate Metrics → Report
```

### Key Modules

**evaluation/** - Core evaluation engine:
- `evaluate.py`: Main orchestrator with `OPERATOR_SECURITY_PATTERNS` for kill classification
- `test_runner.py`: Subprocess+pytest execution with mock injection
- `mutation_engine.py`: Mutant generation using operators
- `metrics.py`: Mutation score, security precision, aggregations
- `llm_judge.py`: Multi-modal evaluation (Anthropic/OpenAI/Google)
- `prompts.py`: Unified prompt templates and `MOCK_ENVIRONMENT_DOCS` for test generation
- `attack_vectors.py`: `CWE_ATTACK_VECTORS` - predefined attack patterns per CWE for coverage checking
- `conftest_template.py`: Template for injecting mocks into test subprocesses
- `mocks/`: SafeOS wrapper and mock objects (database, subprocess, filesystem, crypto, etc.)

**operators/** - 19 security mutation operators:
- `security_operators.py`: Operator base class and implementations
- `operator_registry.py`: CWE-to-operator mappings (`CWE_OPERATOR_MAP`)

Key operators: PSQLI (SQL injection), CMDINJECT (command injection), PATHCONCAT (path traversal), WEAKCRYPTO (weak crypto), DESERIAL (unsafe deserialization), XXE, SSRF, SSTI, IDOR, CORS_WEAK, CSRF_REMOVE, WEAKRANDOM

**baselines/** - Evaluation baselines:
- `run_llm_baselines.py`: Standalone LLM evaluation with stratified sampling
- `run_static_analysis.py`: Bandit/Semgrep comparison

**scripts/** - Data pipeline:
- `dataset_builder.py`: Main orchestrator for building dataset
- `sample_generator.py`: Generate samples from templates
- `source_ingestion.py` / `source_handlers.py`: External source processing

**data/** - Dataset:
- `dataset.json`: Main dataset with pre-generated mutants
- `splits/`: easy.json, medium.json, hard.json

### Test Execution Model

Each `run_tests()` spawns an isolated subprocess with:
1. Temp directory: `target_module.py`, `test_generated.py`, `conftest.py`
2. Mock injection via `conftest_template.py` patching `builtins` and `sys.modules`
3. SafeOS wrapper blocks dangerous operations (`os.system`, `os.exec*`, subprocess calls)
4. 5-second timeout per test suite

### Mock Objects for Security Testing

Tests use mocks that track security-relevant behavior (defined in `prompts.py`):
- `db.last_params`: None if SQL injection (string interpolation used)
- `subprocess.injection_detected`: True if shell injection patterns found
- `hashlib.weak_algorithm_used`: True if MD5/SHA1 used
- `pickle.unsafe_load_called`: True if unsafe deserialization
- `requests.ssrf_attempted`: True if internal URL accessed

### Kill Classification

Tests kill mutants through three mechanisms:
- **Semantic**: AssertionError containing security-related terms (genuine security awareness)
- **Incidental**: AssertionError without security terms (accidental detection)
- **Crash**: ImportError, TypeError, NameError, etc. (code structure issues)

Classification uses `OPERATOR_SECURITY_PATTERNS` in evaluate.py to match operator-specific keywords.

### Dataset Sample Structure

```json
{
  "id": "...",
  "cwe": "CWE-89",
  "cwe_name": "SQL Injection",
  "difficulty": "easy|medium|hard",
  "entry_point": "function_name",
  "secure_code": "...",
  "insecure_code": "...",
  "functional_tests": "...",
  "security_tests": "...",
  "mutation_operators": ["PSQLI", "RVALID"],
  "mutants": [{"id": "...", "operator": "...", "mutated_code": "..."}]
}
```

## Extending

### Adding a New Mutation Operator

1. Create operator class in `operators/security_operators.py` extending `SecurityMutationOperator`
2. Implement `applies_to(code)` and `mutate(code)` methods
3. Register in `operators/operator_registry.py` OPERATORS dict
4. Map to CWEs in `CWE_OPERATOR_MAP`
5. Add security patterns to `OPERATOR_SECURITY_PATTERNS` in `evaluation/evaluate.py`
6. Add attack vectors to `CWE_ATTACK_VECTORS` in `evaluation/attack_vectors.py`
