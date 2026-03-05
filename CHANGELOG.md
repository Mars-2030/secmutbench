# SecMutBench Changelog

## [2.5.0] - 2026-03-04

### Summary
Major expansion of mutation operators with multiple variants per mutation location. Added 14 new security operators for broader CWE coverage. Fixed critical operator-CWE cross-contamination bug in dataset builder. Reality check confirms 24 viable CWEs with both operator support and source material.

---

### Major Features

#### U. Expanded Operator Variants
- **Files:** `operators/security_operators.py`
- **Problem:** Operators generated only 1 mutant per mutation location, limiting mutation testing granularity.
- **Fix:** Expanded core operators to generate multiple realistic variants:
  - **PSQLI**: 4 variants per SQL injection location (f-string, .format(), % formatting, + concatenation)
  - **CMDINJECT**: 9 variants covering shell=True, os.system, os.popen, subprocess patterns
  - **HARDCODE**: Multiple weak password variants ("admin123", "password", "123456", "secret", "test")
- **Impact:** Increased mutant diversity without inflating sample count

#### V. 14 New Security Mutation Operators
- **Files:** `operators/security_operators.py`, `operators/operator_registry.py`
- **Problem:** Limited CWE coverage (14 types) compared to other benchmarks (SecurityEval: 75, CWEval: 31).
- **Fix:** Added new operators:
  | Operator | Description | Target CWEs |
  |----------|-------------|-------------|
  | EVALINJECT | ast.literal_eval → eval | CWE-95 |
  | OPENREDIRECT | Remove redirect URL validation | CWE-601 |
  | NOCERTVALID | Disable SSL certificate verification | CWE-295 |
  | INFOEXPOSE | Expose sensitive data in errors | CWE-209 |
  | REGEXDOS | Introduce ReDoS-vulnerable patterns | CWE-400, CWE-1333 |
  | MISSINGAUTH | Remove authorization checks | CWE-862 |
  | INSUFFLOG | Remove security logging | CWE-778 |
  | NULLCHECK | Remove null pointer checks | CWE-476 |
  | MEMLEAK | Remove resource cleanup | CWE-401 |
  | INTOVERFLOW | Remove integer overflow checks | CWE-190 |
  | RACECOND | Remove synchronization | CWE-362 |
  | PRIVESC | Weaken permission checks | CWE-269 |
  | SESSIONFIX | Disable session regeneration | CWE-384 |
  | XMLINJECT | Remove XML special char escaping | CWE-91 |
- **CWE Mappings:** Expanded `CWE_OPERATOR_MAP` from 30 to 49 CWE entries

#### W. Operator-CWE Cross-Contamination Fix
- **Files:** `scripts/dataset_builder.py`
- **Problem:** Two dangerous patterns allowed unrelated operators to fire on samples:
  1. Validation fallback tried ALL operators when assigned operators didn't fire
  2. Pre-generation blindly cross-applied RVALID/INPUTVAL/HARDCODE to all samples
- **Fix:**
  - Validation fallback now ONLY tries operators mapped to the sample's CWE
  - Pre-generation uses strict CWE-to-operator mapping, no blind cross-apply
- **Example prevented:** WEAKCRYPTO operator firing on CWE-89 (SQL injection) samples

---

### Reality Check: Viable CWE Coverage

Analysis of source material availability shows:

| Category | Count |
|----------|-------|
| **Viable CWEs** (operator + ≥5 source samples) | 24 |
| CWEs with operators but no source material | 25 |
| Useful new operators (have source samples) | 6 of 14 |

**Useful new operators:** EVALINJECT, OPENREDIRECT, NOCERTVALID, INFOEXPOSE, REGEXDOS, MISSINGAUTH

**Operators without source material:** NULLCHECK, MEMLEAK, INTOVERFLOW, RACECOND, PRIVESC, SESSIONFIX, XMLINJECT, INSUFFLOG

---

### Files Modified

| File | Change |
|------|--------|
| `operators/security_operators.py` | Added 14 new operator classes, expanded PSQLI/CMDINJECT/HARDCODE variants |
| `operators/operator_registry.py` | Added 14 new imports, expanded CWE_OPERATOR_MAP (30→49 entries) |
| `scripts/dataset_builder.py` | Fixed cross-contamination in _final_validation and _pregenerate_mutants |
| `scripts/source_handlers.py` | Expanded SUPPORTED_CWES for SecCodePLT handler |

---

## [2.4.0] - 2026-03-04

### Summary
Expanded CWE coverage from 14 to 15 types. Fixed several bugs including field name mismatches in audit script, classify_kill generic fallback gap, OPERATOR_MOCK_MAPPING missing attributes, and prompt inconsistency between CLI and baselines.

---

### Major Features

#### O. Expanded CWE Coverage
- **Files:** `scripts/source_ingestion.py`, `scripts/dataset_builder.py`
- **Problem:** Dataset covered only 14 CWEs; several important vulnerability types were missing.
- **Fix:** Added 29 new templates covering 12 additional CWE patterns:
  - CWE-319 (Cleartext Transmission): 2 samples
  - CWE-352 (Cross-Site Request Forgery): 29 samples
  - Plus expanded coverage for existing CWEs
- **Sources:** Templates derived from SecurityEval, CyberSecEval, and original SecMutBench patterns

#### P. Configurable Min-Samples Threshold
- **Files:** `scripts/dataset_builder.py`
- **Problem:** Fixed threshold of 5 samples per CWE filtered out legitimate but rare vulnerability patterns.
- **Fix:** Added `--min-samples` CLI argument to control the minimum samples per CWE threshold:
  ```bash
  python scripts/dataset_builder.py --target 300 --min-samples 2
  ```
- **Default:** 5 (unchanged from previous behavior)

---

### Bug Fixes

#### Q. sample_kills_for_audit.py Field Name Mismatches
- **Files:** `scripts/sample_kills_for_audit.py`
- **Problem:** Audit script used wrong field names: `mutant_results` (should be `mutant_details`), `mutant_code` (should be `mutated_code`), `classification` (should be `kill_type`), `mutant_id` (should be `id`). Also, `secure_code` and `test_code` weren't stored per-sample in evaluation results.
- **Fix:** Updated `extract_kills_from_results()` to:
  - Handle both old and new field names for backwards compatibility
  - Added `load_benchmark_samples()` to join against benchmark for `secure_code`/`test_code`
  - Added `--benchmark` CLI argument for explicit benchmark path

#### R. classify_kill Generic Fallback Gap
- **Files:** `evaluation/evaluate.py`
- **Problem:** When operator was known but no operator-specific keyword matched, the function returned `assertion_incidental` without checking generic security patterns. This missed cases where error matched generic terms (e.g., "inject") not in operator-specific list.
- **Fix:** Always check `GENERIC_SECURITY_PATTERNS` as fallback even when operator is known.

#### S. OPERATOR_MOCK_MAPPING Missing Attributes
- **Files:** `evaluation/evaluate.py`
- **Problem:** Mapping was missing several attributes that mocks actually track:
  - CMDINJECT: missing `dangerous_command_detected`
  - WEAKCRYPTO: missing `strong_algorithm_used`, `algorithms_used`
  - DESERIAL: missing `load_count`
  - XXE: missing `dtd_processed`
  - RMAUTH: missing `auth_attempts`, `failed_attempts`
  - SSRF: missing `last_method`
  - SSTI/eval: missing `unsafe_exec_called`
- **Fix:** Updated all operator mappings to match their mock `SECURITY_ATTRS`. Added `EVALINJECT` operator mapping.

#### T. Prompt Inconsistency Between CLI and Baselines
- **Files:** `evaluation/evaluate.py`
- **Problem:** `evaluate.py` CLI used `DEFAULT_PROMPT_TEMPLATE` (simple prompt) while `run_llm_baselines.py` used `format_test_generation_prompt()` (includes mock docs, attack vectors). This inconsistency could confound ablation studies.
- **Fix:**
  - Imported `format_test_generation_prompt` into evaluate.py
  - Updated `evaluate_model()` to use unified prompts by default (`use_unified_prompts=True`)
  - Marked `DEFAULT_PROMPT_TEMPLATE` as legacy/deprecated
  - CLI now uses `format_test_generation_prompt()` for consistency

---

### Dataset Statistics Update

| Metric | v2.3.0 | v2.4.0 |
|--------|--------|--------|
| Total Samples | 307 | 304 |
| CWE Types | 14 | 15 |
| Pre-generated Mutants | 774 | 737 |
| Mutation Operators | 18 | 18 |

**New CWEs Added:**
- CWE-319 (Cleartext Transmission of Sensitive Information)
- CWE-352 (Cross-Site Request Forgery)

---

## [2.3.0] - 2026-03-04

### Summary
Added Mock-State Observability classification (Layer 1.5) for more accurate kill classification, integrated version tracking across all outputs, and added multiple new analysis scripts for mutant validity, test validity, ablation studies, and manual auditing.

---

### Major Features

#### K. Mock-State Observability Classification (Layer 1.5)
- **Files:** `evaluation/mocks/*.py` (11 files), `evaluation/conftest_template.py`, `evaluation/evaluate.py`
- **Problem:** Kill classification relied solely on keyword matching in error messages. Tests that accessed security-relevant mock attributes (e.g., `db.last_params`, `subprocess.last_shell`) without explicit security keywords were misclassified as "incidental" rather than "semantic".
- **Fix:** Added `__getattribute__` override to 11 mock classes to track access to security-relevant attributes:
  - `MockDatabase`: `last_query`, `last_params`, `query_count`
  - `MockSubprocess`: `last_shell`, `last_command`, `injection_detected`, `dangerous_command_detected`
  - `MockFileSystem`: `last_path`, `base_dir`
  - `MockCrypto`: `last_algorithm`, `weak_algorithm_used`, `strong_algorithm_used`
  - `MockHTTPClient`: `last_url`, `ssrf_attempted`, `last_method`
  - `MockXMLParser`: `last_xml`, `external_entities_resolved`, `dtd_processed`
  - `MockAuthenticator`: `last_username`, `last_password`, `last_token`, `auth_attempts`
  - `MockEnvironment`: `last_key`, `sensitive_accessed`, `access_log`
  - `MockPickle`/`MockYAML`: `last_data`, `unsafe_load_called`
  - `MockEval`: `last_code`, `unsafe_eval_called`, `injection_detected`
- **Classification:** Added `OPERATOR_MOCK_MAPPING` in `evaluate.py` mapping operators to relevant mocks/attributes. `classify_kill()` now checks Layer 1.5 (mock observability) before Layer 1 (keywords).
- **Tracking:** `conftest_template.py` resets tracking per-test via `pytest_runtest_setup` hook and collects access in `pytest_runtest_makereport`. Results include `mock_security_access` field.

#### L. Version Tracking Integration
- **Files:** `evaluation/version.py`, `evaluation/__init__.py`, `evaluation/evaluate.py`, `baselines/run_llm_baselines.py`, `baselines/run_static_analysis.py`
- **Problem:** Result files had no version metadata, making reproducibility difficult.
- **Fix:**
  - Created `version.py` with version tracking: `__version__`, `__benchmark_version__`, `__schema_version__`
  - Exported version functions from `evaluation/__init__.py`
  - Added `--version` flag to `evaluate.py` CLI
  - All result JSON files now include `version_info` with SecMutBench version, benchmark version, timestamp, Python version, and dependency versions

#### M. Prompt Ablation Templates
- **Files:** `evaluation/prompts.py`
- **Problem:** No way to run controlled ablation studies varying prompt detail level.
- **Fix:** Added two ablation templates:
  - `PROMPT_NO_HINT`: Generic "write tests" prompt without security context
  - `PROMPT_CWE_ID_ONLY`: Minimal prompt with just CWE ID, no attack vectors
  - Helper functions: `format_prompt_no_hint()`, `format_prompt_cwe_id_only()`

#### N. No-Mock Evaluation Mode
- **Files:** `evaluation/test_runner.py`, `evaluation/conftest_template.py`, `scripts/evaluate_no_mocks.py`
- **Problem:** No way to compare mock-based vs real execution for validation.
- **Fix:**
  - Added `use_mocks` parameter to `TestRunner.__init__()` and `run_tests()`
  - Added `CONFTEST_TEMPLATE_NO_MOCKS` (minimal conftest without mock injection)
  - Created `scripts/evaluate_no_mocks.py` for side-by-side comparison

---

### New Scripts

| Script | Purpose |
|--------|---------|
| `scripts/compute_mutant_validity.py` | Analyze compilability and executability of all mutants per operator/CWE |
| `scripts/compute_test_validity.py` | Aggregate test validity rates from evaluation results |
| `scripts/evaluate_no_mocks.py` | Compare evaluation with/without mock injection |
| `scripts/evaluate_reference_tests.py` | Evaluate human-written reference tests as upper bound |
| `scripts/run_semgrep_baseline.py` | Run Semgrep static analysis baseline per CWE |
| `scripts/sample_kills_for_audit.py` | Sample N kills per category for manual review (CSV/Markdown) |

---

### Files Modified

| File | Change |
|------|--------|
| `evaluation/mocks/mock_database.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/mocks/mock_subprocess.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/mocks/mock_filesystem.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/mocks/mock_crypto.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/mocks/mock_http.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/mocks/mock_xml.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/mocks/mock_auth.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/mocks/mock_environment.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/mocks/mock_deserializer.py` | Added `SECURITY_ATTRS` to MockPickle and MockYAML |
| `evaluation/mocks/mock_eval.py` | Added `SECURITY_ATTRS`, `__getattribute__`, `reset_security_tracking()` |
| `evaluation/conftest_template.py` | Added `_all_mocks`, `_reset_all_security_tracking()`, `_collect_mock_security_access()`, `CONFTEST_TEMPLATE_NO_MOCKS` |
| `evaluation/test_runner.py` | Added `mock_security_access` to TestResult, `use_mocks` parameter |
| `evaluation/evaluate.py` | Added `OPERATOR_MOCK_MAPPING`, updated `classify_kill()`, added version imports, `--version` flag |
| `evaluation/prompts.py` | Added `PROMPT_NO_HINT`, `PROMPT_CWE_ID_ONLY`, helper functions |
| `evaluation/version.py` | Created version tracking module, fixed Python 3.8 type hint compatibility |
| `evaluation/__init__.py` | Exported version functions |
| `baselines/run_llm_baselines.py` | Added version import, `version_info` in output |
| `baselines/run_static_analysis.py` | Added version import, `version_info` in output |

---

## [2.2.0] - 2026-02-03

### Summary
Replaced the exec-based sandbox test runner with subprocess isolation + real pytest. Pre-generated mutants are now stored in the dataset for deterministic evaluation. Crash kills dropped from ~46% to ~23% of total kills by eliminating sandbox-caused ImportError/AttributeError artifacts.

---

### Architectural Changes

#### H. Subprocess + pytest test runner
- **Files:** `evaluation/test_runner.py` (major rewrite), `evaluation/conftest_template.py` (new)
- **Problem:** The test runner used `exec(test_code, sandbox_globals)` with a custom `__import__` function that blocked all imports not in a `SAFE_MODULES` whitelist. This caused ~60% of mutant kills to be "crash" type -- `ImportError` from blocked legitimate imports, `TypeError`/`AttributeError` from mock objects not matching real module APIs, and `MockPytest` not behaving like real pytest. These crash kills inflated mutation scores without reflecting genuine security test quality.
- **Fix:** Each `run_tests()` call now spawns an isolated subprocess running real pytest:
  1. Writes `target_module.py`, `test_generated.py` (with `from target_module import *` preamble), and `conftest.py` to a temp directory
  2. Runs `subprocess.run([python, -m, pytest, ...])` with `PYTHONPATH` set to the project root
  3. Parses structured JSON results from a `ResultCollector` pytest plugin
  4. Falls back to parsing pytest stderr when collection errors occur (e.g., syntax errors in mutated target code)
- **Removed:** `RaisesContext`, `MockPytest`, `SafeOS`, `SAFE_MODULES`, `create_safe_import()`, `create_test_globals()`, `_run_single_test_with_coverage()`, `_run_single_test()` (~300 lines of sandbox code)
- **Kept unchanged:** `TestResult`, `TestSuiteResult` dataclasses, `check_mutant_killed()`, module-level `run_tests()` and `check_vulnerability_detection()` convenience functions -- all callers work without modification

#### I. Conftest.py safety layer with builtins injection
- **Files:** `evaluation/conftest_template.py` (new)
- **Problem:** The old sandbox injected mock objects as globals in the `exec()` namespace. Moving to file-based pytest execution required a new mechanism for mock availability.
- **Fix:** A `CONFTEST_TEMPLATE` string constant contains the conftest.py written to each temp directory. It:
  - Injects all 30+ mock objects into Python `builtins` (e.g., `builtins.db = MockDatabase()`), making them available via Python's name resolution chain (local -> enclosing -> global -> builtin) without any import changes to existing test code
  - Patches `sys.modules` for dangerous modules (`subprocess`, `os`, `pickle`, `yaml`, `hashlib`, `requests`, `jwt`, `bcrypt`, `flask`, `mysql`) so `import subprocess` returns the mock
  - Includes `SafeOS` wrapper blocking `os.system`, `os.popen`, `os.exec*`, `os.fork`
  - Includes `ResultCollector` pytest plugin that hooks `pytest_runtest_makereport` and writes per-test results to `results.json`
- **Standard library no longer blocked:** `re`, `json`, `html`, `base64`, `urllib`, `hmac`, `secrets`, `ast`, `math`, `string`, `collections`, `itertools`, `functools`, `typing`, `dataclasses`, `pathlib` now use real imports instead of being gated by `SAFE_MODULES`

#### J. Pre-generated mutants in dataset
- **Files:** `scripts/dataset_builder.py`, `evaluation/evaluate.py`, `data/dataset.json`, `data/splits/*.json`
- **Problem:** Mutants were generated at evaluation time by `MutationEngine.generate_mutants()`. This caused non-determinism (Change E partially fixed the crash case, but operator application order could still vary) and made results harder to reproduce across runs.
- **Fix:** Added `_pregenerate_mutants()` method to `DatasetBuilder` (Step 7.5 in build pipeline). For each sample, generates up to 10 mutants and stores them as a `mutants` array in the dataset JSON:
  ```json
  "mutants": [{"id": "fd1834de", "operator": "PSQLI", "description": "...", "mutated_code": "..."}]
  ```
  Modified `evaluate_generated_tests()` in `evaluate.py` to load pre-generated mutants from `sample["mutants"]` when available, with fallback to runtime generation for backward compatibility with older datasets. Modified `save()` and `save_splits()` to include the `mutants` field in output.

---

### Verified Output (Reference Tests, 81 samples after --skip-invalid)

| Metric | v2.1.0 (exec sandbox) | v2.2.0 (subprocess+pytest) |
|--------|----------------------|---------------------------|
| Mutation Score | 60.52% | 55.94% |
| Crash Score | 45.91% | 22.98% |
| Security Mutation Score | 12.58% | 12.42% |
| Vuln Detection | 25.32% | 25.93% |
| Security Precision | 37.74% | 35.59% |
| Crash kills | ~74 | 37 |
| Semantic kills | ~20 | 20 |
| Pre-generated mutants | N/A | 167 across 85 samples |
| Tautological tests | 0 | 0 |

---

### Files Modified

| File | Change |
|------|--------|
| `evaluation/test_runner.py` | Major rewrite: replaced exec-based sandbox with subprocess+pytest (~300 lines removed, ~150 lines added) |
| `evaluation/conftest_template.py` | New file: CONFTEST_TEMPLATE with builtins injection, sys.modules patches, SafeOS, ResultCollector plugin |
| `evaluation/evaluate.py` | Load pre-generated mutants from sample["mutants"] with fallback |
| `scripts/dataset_builder.py` | Added _pregenerate_mutants() method, mutants field in save/save_splits |
| `data/dataset.json` | Regenerated (85 samples, 167 mutants, 0 tautological tests) |
| `data/splits/easy.json` | Regenerated (23 samples) |
| `data/splits/medium.json` | Regenerated (42 samples) |
| `data/splits/hard.json` | Regenerated (20 samples) |

### Dependencies Added
- `pytest` (required for subprocess test execution)

---

## [2.1.0] - 2026-02-03

### Summary
Addressed critical and moderate issues identified during baseline evaluation analysis across 4 models (qwen2.5-coder:7b, qwen3-coder, gpt-5-mini, gemini-3-flash-preview). Changes improve metric reliability, fix misleading defaults, and add new decomposed scoring to separate genuine security test quality from crash-driven inflation.

---

### Critical Fixes

#### A. Security Mutation Score wired into evaluation output
- **Files:** `evaluation/evaluate.py`, `evaluation/metrics.py`, `baselines/run_llm_baselines.py`
- **Problem:** `calculate_kill_breakdown()` existed in `metrics.py:377-453` computing `security_mutation_score`, `crash_score`, and `incidental_score` but was never called in the evaluation output path. Mutation scores were reported as a single inflated number (80-94%) without distinguishing crash kills (~60%) from genuine security-aware kills (~10-21%).
- **Fix:** Imported and wired `calculate_kill_breakdown()` into `evaluate_model()`, `evaluate_reference_tests()`, and `evaluate_multimodal()` in `evaluate.py`. Added `avg_security_mutation_score`, `avg_incidental_score`, `avg_crash_score` fields to `ModelResult` dataclass. Added "Kill Breakdown" section to `format_metrics_report()`. Added "Sec MS" column to `print_results_table()`.

#### B. Tautological functional tests replaced
- **Files:** `scripts/sample_generator.py`, `data/dataset.json`, `data/splits/*.json`
- **Problem:** All 141 functional tests contained `assert result is not None or result is None` -- a logical tautology that is always True. These tests could never fail, meaning any mutant that crashed during execution was counted as "killed" regardless of test quality. This inflated mutation scores by ~60% across all models.
- **Fix:** Removed the tautological assertion from both branches (zero-param and parameterized) in `generate_functional_test()` at lines 550 and 559. The functional test now simply verifies the function executes without unhandled exceptions. Dataset regenerated with 0 tautological tests.

#### C. Judge metrics default changed from 0.0 to None
- **Files:** `baselines/run_llm_baselines.py`
- **Problem:** `ModelResult` defaulted `avg_security_relevance`, `avg_test_quality`, and `avg_composite_score` to `0.0`. These fields were only populated when `--use-judge` was passed. All 4 baseline runs reported `0.0` for these metrics, which is misleading -- it implies a measurement was taken and scored zero, when in reality no measurement occurred.
- **Fix:** Changed defaults to `Optional[float] = None`. Updated `print_results_table()` to display "N/A" for None values. Updated `save_results()` reference baseline fallback to use `None`. JSON output now serializes these as `null` when the judge was not used.

---

### Moderate Fixes

#### D. --skip-invalid flag for filtering bad samples
- **Files:** `baselines/run_llm_baselines.py`, `evaluation/evaluate.py`
- **Problem:** 15 CyberSecEval samples had `quality.validation_passed = False` with `func_XXX` entry points that don't exist in the secure code. These samples produce unreliable evaluation results.
- **Fix:** Added `--skip-invalid` CLI argument to both scripts. When set, filters out samples where `quality.validation_passed == False`. When not set, prints a warning with the count of invalid samples. Verified: 4 invalid samples detected and skippable in the regenerated dataset.

#### E. Mutant generation non-determinism fix
- **Files:** `evaluation/evaluate.py`
- **Problem:** Sample `44315e723003` (CWE-20) produced 1 mutant for qwen2.5 and gpt-5-mini but 0 mutants (with `mutants_total=None`) for qwen3. The `None` value indicated the mutation generation threw an uncaught exception, leaving `mutants_total` and `mutants_killed` unset.
- **Fix:** Added explicit defaults (`mutants_total=0`, `mutants_killed=0`) before the mutation try block. Added the same assignments in the except block so these fields are always present with integer values, never `None`.

#### F. Security Precision metric added
- **Files:** `evaluation/metrics.py`, `evaluation/evaluate.py`
- **Problem:** No metric existed to answer: "Of the tests that pass on secure code, what fraction also catches the vulnerability?" The existing Vuln Detection metric conflated test robustness with security awareness (the Qwen3 paradox: higher SMS but lower VD).
- **Fix:** Added `calculate_security_precision()` function to `metrics.py`. Formula: `security_precision = vuln_detected_count / secure_passes_count`. Wired into all three evaluation functions in `evaluate.py`. Added `avg_security_precision` to `ModelResult`.

#### G. Low-n confidence flags for per-CWE analysis
- **Files:** `evaluation/metrics.py`
- **Problem:** Per-CWE metrics were reported without sample-size context. CWE-20 (n=2), CWE-287 (n=4), CWE-798 (n=4) can swing from 0% to 100% based on a single sample, making per-CWE claims unreliable.
- **Fix:** `aggregate_by_cwe()` now adds `"low_confidence": True` when sample count < 5. `format_metrics_report()` appends `[!low-n]` marker to flagged CWEs in the report output.

---

### Verified Output (Reference Tests, 79 samples after --skip-invalid)

| Metric | Value |
|--------|-------|
| Mutation Score | 60.52% |
| Security Mutation Score | 12.58% |
| Crash Score | 45.91% |
| Vuln Detection | 25.32% |
| Security Precision | 37.74% |
| CWEs flagged low-n | 6 of 14 |
| Tautological tests | 0 |

---

### Files Modified

| File | Lines Changed |
|------|--------------|
| `evaluation/evaluate.py` | Imports, evaluate_model, evaluate_reference_tests, evaluate_multimodal, main (--skip-invalid), mutant error handling |
| `evaluation/metrics.py` | calculate_security_precision (new), aggregate_by_cwe (low_confidence), format_metrics_report (kill breakdown + low-n) |
| `baselines/run_llm_baselines.py` | ModelResult fields, print_results_table, save_results, main (--skip-invalid), evaluate_model (populate new fields) |
| `scripts/sample_generator.py` | generate_functional_test (removed tautological assertion) |
| `data/dataset.json` | Regenerated (83 samples, 0 tautological tests) |
| `data/splits/easy.json` | Regenerated (23 samples) |
| `data/splits/medium.json` | Regenerated (39 samples) |
| `data/splits/hard.json` | Regenerated (21 samples) |
