# SecMutBench Changelog

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
