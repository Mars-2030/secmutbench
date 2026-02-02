# SecMutBench Fixes Summary - 2026-01-08

## Problem Statement

The SecMutBench evaluation pipeline was showing:
- **0% Mutation Score** - No mutants were being generated
- **0% Vulnerability Detection** - Tests weren't detecting vulnerabilities
- **Biased CWE Coverage** - First N samples were always the same CWE

## Root Causes Identified

### 1. RVALID Regex Bug
- **Location**: `operators/security_operators.py:234`
- **Problem**: Pattern `(\w+)\s*=\s*escape\s*\(` didn't match `html.escape()`
- **Impact**: Operators couldn't create mutants from module-prefixed function calls

### 2. Generic Placeholder Code
- **Location**: `scripts/generate_dataset.py`
- **Problem**: Synthetic variants generated code like `result = user_input` instead of real patterns
- **Impact**: Even working operators couldn't find patterns to mutate

### 3. No Shuffle in Dataset/Evaluation
- **Location**: `scripts/generate_dataset.py`, `baselines/run_llm_baselines.py`
- **Problem**: Samples generated sequentially by CWE, never randomized
- **Impact**: `--samples 20` always evaluated only CWE-79 samples

### 4. Missing Assertion Guidance in Prompts
- **Location**: `evaluation/prompts.py`
- **Problem**: LLMs generated tests with wrong assertion logic
- **Impact**: Tests failed on secure code instead of passing

## Fixes Applied

### Fix 1: RVALID Regex Pattern
```python
# OLD (broken):
pattern = rf'(\w+)\s*=\s*{re.escape(func)}\s*\(([^)]+)\)'

# NEW (fixed):
pattern = rf'(\w+)\s*=\s*(?:\w+\.)*{re.escape(func)}\s*\(([^)]+)\)'
#                       ^^^^^^^^^^^ handles html.escape, bleach.clean, etc.
```

### Fix 2: Code Generation Patterns
Updated `_generate_synthetic_variant()` in `generate_dataset.py` to produce CWE-specific code:
- CWE-89 (SQLi): Parameterized queries with `db.execute(query, params)`
- CWE-79 (XSS): HTML escaping with `html.escape()`
- CWE-78 (Command Injection): `subprocess.run()` with `shell=False`
- CWE-22 (Path Traversal): Path validation with `os.path.abspath()`

### Fix 3: Shuffle Functionality
Added to both dataset generation and evaluation:
```python
# In generate_dataset.py
import random
random.shuffle(all_samples)

# In run_llm_baselines.py
parser.add_argument("--shuffle", action="store_true")
parser.add_argument("--seed", type=int, default=42)
```

### Fix 4: Prompt Assertion Guidance
Added to `evaluation/prompts.py`:
```
**CRITICAL: Assertion Logic for Security Tests**

| Vulnerability | CORRECT Assertion | WRONG Assertion |
|---------------|-------------------|-----------------|
| XSS (CWE-79)  | assert "<script>" NOT in result | assert "<script>" in result |
| SQLi (CWE-89) | assert db.last_params is not None | assert payload in db.last_query |
```

## Files Modified

| File | Changes |
|------|---------|
| `operators/security_operators.py` | Fixed RVALID regex (line 234) |
| `evaluation/prompts.py` | Added assertion guidance (lines 132-173) |
| `scripts/generate_dataset.py` | Added shuffle + fixed code generation |
| `baselines/run_llm_baselines.py` | Added --shuffle and --seed flags |
| `run_evaluation.sh` | Added shuffle/seed CLI support |
| `scripts/generate_benchmark.py` | NEW - Unified generator combining best of both approaches |
| `data/dataset.json` | Regenerated with fixes (37 samples) |

## Verification Results

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Mutation Score | 0.0% | 80.0% | +80% |
| Mutants Generated | 0 | Multiple | Working |
| CWE Diversity | 1 CWE | Shuffled | Working |

## What's Next

### Immediate Actions
1. **Run full evaluation**: `./run_evaluation.sh --samples 37 --shuffle --seed 42`
2. **Test with multiple models**: Add more Ollama models to compare
3. **Enable LLM-as-Judge**: Run with `--judge openai` or `--judge anthropic`

### Future Improvements
1. **Expand dataset**: Use `scripts/generate_benchmark.py` to generate more samples
2. **Add more operators**: Implement operators for missing CWEs
3. **Improve prompts**: Iterate on assertion guidance based on LLM outputs
4. **Benchmark more models**: Test GPT-5, Claude Sonnet 4.5, DeepSeek-Coder

### Command Reference
```bash
# Quick test (5 samples, no judge)
python3 baselines/run_llm_baselines.py --models "qwen2.5-coder:14b-instruct" \
    --max-samples 5 --shuffle --seed 42

# Full evaluation with judge
./run_evaluation.sh --samples 20 --shuffle --seed 42 --judge openai

# Generate new dataset
python3 scripts/generate_dataset.py --output data/dataset.json --samples 100
```

---
*Generated: 2026-01-08*
