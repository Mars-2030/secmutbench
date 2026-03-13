# SecMutBench → NeurIPS 2026: Concrete Improvement Plan

## Executive Verdict

**Current state: Not submittable.** The core idea (SMS metric revealing crash-inflated mutation scores) is genuinely strong and differentiated. But the dataset is undersized, monolingual, and under-baselined for the 2026 Datasets & Benchmarks track. Below are the specific changes needed, ordered by impact, with exact file-level guidance.

---

## 1. CRITICAL: Scale Dataset to 500+ Samples, 20+ CWEs

**Why it's blocking:** 307 samples and 14 CWEs is below the 2026 bar. CWEval covers 20 CWEs; CyberGym has 1,507 samples. Reviewers will flag insufficient scale immediately.

**What to change:**

### 1a. Ingest more SecCodePLT data (currently 168/1,345 used)

In `source_handlers.py`, `SecCodePLTHandler` filters rows but only 168 survive. The main bottleneck is the CWE filter in `source_ingestion.py` `CWE_REGISTRY` — it only maps 22 CWEs. Expanding the registry and relaxing filters can yield 300+ additional samples.

**File: `source_ingestion.py`** — Add these CWEs to `CWE_REGISTRY`:
```
CWE-77   (Command Injection - general)     → operators: ["CMDINJECT"]
CWE-90   (LDAP Injection)                  → operators: ["RVALID", "INPUTVAL"]
CWE-113  (HTTP Response Splitting)         → operators: ["RVALID"]
CWE-134  (Format String Vulnerability)     → operators: ["RVALID"]
CWE-190  (Integer Overflow)                → operators: ["INPUTVAL"]
CWE-250  (Execution with Unnecessary Priv) → operators: ["RMAUTH"]
CWE-269  (Improper Privilege Management)   → operators: ["RMAUTH"]
CWE-276  (Incorrect Default Permissions)   → operators: ["RMAUTH"]
CWE-400  (Uncontrolled Resource Consump.)  → operators: ["INPUTVAL"]
CWE-601  (Open Redirect)                   → operators: ["RVALID", "INPUTVAL"]
CWE-732  (Incorrect Permission Assignment) → operators: ["RMAUTH"]
CWE-776  (XML Entity Expansion)            → operators: ["XXE"]
CWE-943  (Improper Neutralization of SQL)  → operators: ["PSQLI"]
```
This gets you from 22 → 35 CWEs and unlocks hundreds more SecCodePLT rows.

**File: `source_handlers.py`** — In `SecCodePLTHandler.process()`, the current logic at line ~180 drops samples where `normalize_cwe()` returns unknown CWEs. After expanding the registry, re-run the builder.

**File: `sample_generator.py`** — Add more templates in `SAMPLE_TEMPLATES` for the new CWEs. Each template needs: prompt, entry_point, insecure code, secure code, difficulty. Target at least 3 templates per new CWE.

### 1b. Add JavaScript/TypeScript support (high priority)

This is the single biggest differentiator you can add. No existing security mutation benchmark covers JS.

**New files needed:**
- `mocks/js/` — Mirror of Python mocks for Node.js (mock-database.js, mock-subprocess.js, etc.)
- `evaluation/js_test_runner.py` — Subprocess wrapper that runs `npx jest` instead of `pytest`
- `operators/js_security_operators.py` — JS-specific mutation operators

**Key JS mutation operators to implement:**
- `PSQLI_JS`: Convert parameterized queries to template literals (`${user_id}`)
- `CMDINJECT_JS`: `child_process.execFile` → `child_process.exec` with shell
- `PATHCONCAT_JS`: `path.join(base, user)` → `base + '/' + user`
- `DESERIAL_JS`: `JSON.parse()` → `eval()` for deserialization
- `WEAKCRYPTO_JS`: `crypto.createHash('sha256')` → `crypto.createHash('md5')`
- `PROTOTYPE_POLLUTION`: JS-specific — remove `hasOwnProperty` checks

**File: `evaluation/test_runner.py`** — Add a `JestTestRunner` class alongside `TestRunner`:
```python
class JestTestRunner:
    def run_tests(self, test_code: str, target_code: str, language: str = "javascript"):
        # Write .test.js and target.js to temp dir
        # Run: npx jest --json --outputFile=results.json
        # Parse Jest JSON output into TestSuiteResult
```

**File: `evaluation/conftest_template.py`** — Add `JS_CONFTEST_TEMPLATE` that sets up mock requires via Jest's `moduleNameMapper`.

### 1c. Add C/C++ support (medium priority, high reviewer impact)

Even a small C subset (50 samples) covering CWE-119 (buffer overflow), CWE-120 (classic buffer overflow), CWE-122 (heap overflow), CWE-125 (out-of-bounds read), CWE-416 (use after free) would dramatically strengthen the paper. Memory safety CWEs are the #1 real-world vulnerability class and no LLM security test benchmark covers them.

**Approach:** Use a lightweight C test harness (compile with gcc + AddressSanitizer, check for ASAN errors as kill signal).

---

## 2. CRITICAL: Run 10+ Model Baselines

**Why it's blocking:** Your current baselines in `run_llm_baselines.py` are `qwen2.5-coder:7b`, `qwen3-coder`, `gpt-5-mini`, `gemini-3-flash`. NeurIPS 2026 reviewers expect comprehensive model coverage.

**File: `run_llm_baselines.py`** — Update `API_MODELS` to include:

```python
API_MODELS = [
    # Frontier closed-source
    {"name": "claude-opus-4-5-20251101", "provider": "anthropic"},
    {"name": "claude-sonnet-4-5-20250929", "provider": "anthropic"},
    {"name": "gpt-5", "provider": "openai"},
    {"name": "gpt-5-mini-2025-08-07", "provider": "openai"},
    {"name": "o3-2025-04-16", "provider": "openai"},         # reasoning model
    {"name": "gemini-2.5-pro", "provider": "google"},

    # Open-weight
    {"name": "deepseek-coder-v3", "provider": "ollama"},
    {"name": "deepseek-r1:70b", "provider": "ollama"},       # reasoning
    {"name": "qwen3-coder:32b", "provider": "ollama"},
    {"name": "llama-4-maverick:70b", "provider": "ollama"},
    {"name": "codestral-25.01", "provider": "ollama"},

    # Coding-specialized
    {"name": "starcoder2-15b", "provider": "ollama"},
]
```

**Budget estimate:** ~$200-400 in API costs for full evaluation across 500 samples.

**Key analysis to include in paper:**
1. SMS vs MS gap per model family (the headline finding)
2. Reasoning models (o3, DeepSeek-R1) vs standard models — do they achieve higher SMS?
3. Open vs closed model comparison
4. Model size scaling curves (7b → 14b → 32b → 70b on same architecture)

---

## 3. HIGH IMPACT: Strengthen Kill Classification

**Why it matters:** The SMS metric is your core contribution, but the current classification in `evaluate.py` `classify_kill()` (lines 90-140) is a keyword heuristic. Reviewers will question its reliability.

**Current weakness:** `SECURITY_INDICATORS` is a flat list of ~50 keywords. "query" and "path" will match non-security assertions. "hash" matches any hash table reference.

**Improvements:**

### 3a. Two-tier classification with LLM verification

**File: `evaluate.py`** — After keyword classification, add an LLM-verification step for borderline cases:

```python
def classify_kill_verified(error: str, mutant_operator: str, cwe: str) -> str:
    """Two-tier kill classification with LLM verification for ambiguous cases."""
    # Tier 1: High-confidence heuristic
    keyword_result = classify_kill(error)

    if keyword_result == "semantic":
        # Verify: does the assertion actually reference the security property?
        # Use operator context to disambiguate
        if is_high_confidence_security(error, mutant_operator, cwe):
            return "semantic"
        else:
            # Ambiguous — defer to LLM judge
            return llm_classify_kill(error, mutant_operator, cwe)

    return keyword_result
```

### 3b. Operator-aware keyword matching

**File: `evaluate.py`** — Replace flat `SECURITY_INDICATORS` with operator-specific patterns:

```python
OPERATOR_SECURITY_PATTERNS = {
    "PSQLI": ["parameterized", "placeholder", "sql", "inject", "query.*param"],
    "CMDINJECT": ["shell", "command", "inject", "subprocess", "exec"],
    "PATHCONCAT": ["traversal", "path", "\.\.\/", "base_dir", "normalize"],
    "WEAKCRYPTO": ["md5", "sha1", "weak.*algo", "hash.*algorithm", "bcrypt"],
    "DESERIAL": ["pickle", "yaml.*safe", "deserial", "literal_eval"],
    "HARDCODE": ["hardcod", "environment", "credential", "password.*literal"],
    # ... etc for all 18 operators
}
```

This eliminates false positives where "path" in a PSQLI context is non-security.

### 3c. Report inter-rater reliability

Run both heuristic and LLM classification on 200+ kills, compute Cohen's kappa. Report this in the paper. Target κ > 0.75.

---

## 4. HIGH IMPACT: Add Agent Evaluation

**Why it matters:** Agent benchmarks are dominating NeurIPS 2026. Adding agent scaffolding evaluation turns SecMutBench from "another LLM benchmark" into "agent-era security testing benchmark."

**New file: `baselines/run_agent_baselines.py`**

```python
AGENT_CONFIGS = [
    {
        "name": "swe-agent",
        "command": "python -m swe_agent.run --model {model} --task {task_file}",
        "setup": "pip install swe-agent",
    },
    {
        "name": "openhands",
        "command": "python -m openhands.core.main --task {task_file}",
        "setup": "pip install openhands",
    },
    {
        "name": "aider",
        "command": "aider --model {model} --message '{prompt}'",
        "setup": "pip install aider-chat",
    },
]
```

**Task formulation:** Create a SWE-bench-style task description per sample:
```
Given the Python module in `target_module.py`, write pytest security tests
that detect if the function `{entry_point}` is vulnerable to {cwe_name}.
The tests should pass on secure implementations and fail on vulnerable ones.
Save tests to `test_security.py`.
```

**Key research question:** Do agents with repo-context access generate higher-SMS tests than bare LLM prompting? This is a novel finding regardless of the answer.

---

## 5. IMPORTANT: Improve CWEval Validation Metrics

**Why it matters:** 50% operator sanity and 47.6% attack coverage will draw reviewer criticism. These need to be above 70% and 60% respectively.

**File: `validate_with_cweval.py`**

### 5a. Fix operator sanity (target >70%)

The main issue is missing operators for certain CWE patterns. From the Check 1 logs, failures cluster around:
- CWE-20 (input validation): No subdomain spoofing operator → add `SUBDOMAIN_SPOOF` to `security_operators.py`
- CWE-502 (deserialization): Missing YAML gadget patterns → extend `DESERIAL` operator
- CWE-78 (command injection): Pipe injection not covered → extend `CMDINJECT` patterns

**File: `security_operators.py`** — Add these operator extensions:

```python
class SUBDOMAIN_SPOOF(SecurityMutationOperator):
    """Remove subdomain validation for CWE-20."""
    # Removes checks like: if not url.endswith('.example.com')
    # Mutates to: always accept URL

class PIPE_INJECT(SecurityMutationOperator):
    """Replace safe subprocess calls with pipe-vulnerable versions for CWE-78."""
    # Adds stdin=PIPE or uses Popen with communicate()
```

### 5b. Improve attack coverage (target >60%)

**File: `attack_vectors.py`** — The `CWE_ATTACK_VECTORS` dict is missing categories that CWEval tests for. Add:
- Time-based SQL injection (CWE-89)
- Double URL encoding (CWE-22)
- Null byte injection (CWE-22)
- YAML tag injection (CWE-502)
- DNS rebinding (CWE-918)

---

## 6. IMPORTANT: Harden Contamination Prevention

**Why it matters:** NeurIPS 2026 will scrutinize data contamination heavily. Your `contamination_prevention.py` has the right architecture but needs concrete audit results.

**File: `contamination_prevention.py`**

### 6a. Run n-gram overlap analysis against actual corpora

The `ContaminationAudit` class exists but you need to actually run it and report results. Compute:
- 8-gram overlap with The Stack (code training data)
- 10-gram overlap with SecurityEval and CyberSecEval originals
- Report per-sample contamination scores

### 6b. Add temporal contamination check

For SecCodePLT-sourced samples, record the original publication date. Any sample from before the model's training cutoff should be flagged and perturbation-treated.

### 6c. Report contamination metrics in paper

Create a contamination analysis table:
```
Source          | Samples | Avg 8-gram overlap | Perturbed | Novel
SecMutBench     |   61    |     0.00           |    No     |  Yes
SecCodePLT      |  168    |     0.XX           |    Yes    |  No
CyberSecEval    |   59    |     0.XX           |    Yes    |  No
SecurityEval    |   19    |     0.XX           |    Yes    |  No
```

---

## 7. IMPORTANT: Refine the Paper Narrative

### 7a. Lead with the "LLMs can't test for security" finding

The headline result — models achieve 80-94% raw mutation score but only 10-21% SMS — is striking. Frame the paper around this gap:

**Title suggestion:** "SecMutBench: LLMs Write Tests That Crash Mutants, Not Tests That Detect Vulnerabilities"

**Abstract structure:**
1. LLMs are increasingly used for security test generation
2. Standard mutation testing suggests they're effective (80-94% kill rates)
3. We introduce Security Mutation Score (SMS) — distinguishing genuine security detection from crash-driven kills
4. SMS reveals models achieve only 10-21% genuine security testing effectiveness
5. This finding holds across 12+ models, 3 languages, 500+ samples

### 7b. Position SMS as an ML contribution, not SE tooling

Frame kill classification as a learned evaluation function, not just a keyword heuristic. The LLM-judge verification step (Section 3a above) makes this an ML methodology contribution.

### 7c. Include capability scaling analysis

Plot SMS vs model size, SMS vs reasoning capability. If reasoning models (o3, R1) achieve meaningfully higher SMS, that's a finding about what security understanding requires. If they don't, that's an even stronger finding — security test generation may require fundamentally different capabilities.

---

## 8. MEDIUM: Mock System Improvements

**File: `mocks/mock_database.py`** — The SQL injection detection in `execute()` uses hardcoded patterns (line ~130). Add:
- Second-order injection patterns
- Blind SQL injection (boolean-based and time-based)
- UNION-based injection with column count detection

**File: `mocks/mock_subprocess.py`** — The `INJECTION_PATTERNS` list (line ~65) is good but missing:
- Environment variable injection (`$VAR` in commands)
- Argument injection (`--flag` injection)

**File: `mocks/mock_http.py`** — Add:
- DNS rebinding detection (internal IP after redirect)
- URL scheme confusion (gopher://, dict://)

---

## 9. MEDIUM: Prompt Engineering Improvements

**File: `prompts.py`** — The current `TEST_GENERATION_PROMPT` is detailed but could be improved:

### 9a. Add few-shot examples

Include 2 exemplar test functions in the prompt showing the expected format. This consistently improves LLM test generation quality across models.

### 9b. Test prompt variants as an ablation

Run baselines with 3 prompt variants:
1. Current prompt (baseline)
2. Prompt with mock documentation included
3. Prompt with vulnerability description from MITRE

Report SMS per prompt variant. This shows prompt sensitivity and strengthens the benchmark's evaluation methodology.

---

## 10. LOW: Code Quality for Open-Source Release

### 10a. Version management
**File: `version.py`** — Update to v2.0.0 for the NeurIPS submission version. Add `__dataset_version__ = "v2.0"` to track dataset evolution.

### 10b. Consolidate import paths
Multiple files have fragile `sys.path.insert()` hacks (dataset_builder.py lines 38-55, sample_generator.py lines 37-43). Create a proper `pyproject.toml` with package structure.

### 10c. Add comprehensive README with reproduction instructions
- One-command dataset build: `python scripts/dataset_builder.py --target 500`
- One-command evaluation: `python evaluation/evaluate.py --model claude-sonnet-4-5-20250929 --multimodal`
- Docker image for exact reproducibility

---

## Timeline Estimate (NeurIPS 2026 deadline: ~May 2026)

| Phase | Duration | Items |
|-------|----------|-------|
| Month 1 | 4 weeks | Dataset expansion (500+ samples, 20+ CWEs), JS support scaffolding |
| Month 2 | 4 weeks | JS test runner + mocks, C/C++ subset (50 samples), new operators |
| Month 3 | 3 weeks | Run all 12+ model baselines, agent evaluation, CWEval validation |
| Month 4 | 3 weeks | Kill classification hardening, contamination audit, analysis |
| Month 5 | 2 weeks | Paper writing, ablation studies, figures |
| Buffer  | 1 week  | Revisions, edge case fixes |

**Total: ~4 months of focused work.**

---

## Priority Summary

| Priority | Item | Effort | Impact on Acceptance |
|----------|------|--------|---------------------|
| 🔴 P0 | Scale to 500+ samples, 20+ CWEs | High | Fatal if missing |
| 🔴 P0 | Run 10+ model baselines | Medium | Fatal if missing |
| 🟠 P1 | Add JavaScript language support | High | Strong differentiator |
| 🟠 P1 | Agent evaluation (SWE-agent, Aider) | Medium | Aligns with 2026 trends |
| 🟡 P2 | Harden kill classification (operator-aware + LLM) | Medium | Strengthens core metric |
| 🟡 P2 | Improve CWEval validation to >70%/>60% | Medium | Addresses reviewer concern |
| 🟡 P2 | Contamination audit with real n-gram analysis | Low | Expected for 2026 |
| 🟢 P3 | Add C/C++ subset (50 samples) | Medium | High reviewer impact |
| 🟢 P3 | Paper narrative + scaling analysis | Low | Improves framing |
| 🟢 P3 | Prompt ablation study | Low | Strengthens methodology |
