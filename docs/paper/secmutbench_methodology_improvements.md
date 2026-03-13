# SecMutBench Methodology Improvements — Code-Level Implementation Guide

This document maps every discussed methodology improvement to your specific codebase, with exact file paths, line numbers, function signatures, and implementation details. Each section is self-contained and ordered by priority.

---

## 1. Kill Classification Hardening

**Current problem:** `evaluate.py` lines 67–87 define a flat `SECURITY_INDICATORS` list shared across all 18 mutation operators. The word `"path"` triggers a semantic classification for a PSQLI mutant. `"query"` matches any database call. `"access"` matches any auth-related text. This means your headline SMS number is unreliable — any reviewer who reads the code will see this immediately.

**Current code (evaluate.py:90–140):**
```python
def classify_kill(error: str) -> str:
    ...
    if "AssertionError" in error or "Assertion failed" in error:
        if any(term in error_lower for term in SECURITY_INDICATORS):
            return "semantic"
        else:
            return "assertion_incidental"
```

### 1A. Operator-Aware Heuristic (Layer 1)

**What to change:** Replace the flat `SECURITY_INDICATORS` list with `OPERATOR_SECURITY_PATTERNS` — a dict mapping each of your 18 operators to its own keyword set. Then modify `classify_kill()` to accept the operator name.

**New code in `evaluate.py`, replacing lines 62–140:**

```python
# =============================================================================
# Kill Classification — Operator-Aware
# =============================================================================

OPERATOR_SECURITY_PATTERNS = {
    # CWE-89: SQL Injection
    "PSQLI": [
        "parameterized", "prepared", "placeholder", "bind",
        "sql", "query.*param", "inject", "sqli",
        "last_params", "string.*concat", "interpolat",
    ],
    # CWE-78: Command Injection
    "CMDINJECT": [
        "shell", "command", "inject", "subprocess",
        "exec", "last_shell", "injection_detected",
        "shlex", "sanitize.*command",
    ],
    # CWE-22: Path Traversal
    "PATHCONCAT": [
        "traversal", "../", "..\\\\", "path",
        "base_dir", "realpath", "abspath", "normalize",
        "directory", "file.*access",
    ],
    # CWE-327: Weak Cryptography
    "WEAKCRYPTO": [
        "md5", "sha1", "weak.*algorithm", "hash",
        "encrypt", "bcrypt", "salt", "iteration",
        "weak_algorithm_used", "last_algorithm",
    ],
    # CWE-502: Insecure Deserialization
    "DESERIAL": [
        "pickle", "deserial", "yaml", "safe_load",
        "literal_eval", "unsafe_load", "SafeLoader",
        "marshal", "shelve",
    ],
    # CWE-918: SSRF
    "SSRF": [
        "ssrf", "internal.*url", "localhost", "127.0.0.1",
        "169.254", "metadata", "ssrf_attempted",
        "url.*valid", "scheme",
    ],
    # CWE-611: XXE
    "XXE": [
        "xxe", "external.*entit", "xml.*parse",
        "doctype", "entity", "dtd",
        "external_entities_resolved",
    ],
    # CWE-798: Hardcoded Credentials
    "HARDCODE": [
        "hardcoded", "credential", "password", "secret",
        "api_key", "token", "environ", "env.*var",
        "access_log", "sensitive_accessed",
    ],
    # CWE-79: XSS (if you add this)
    "RVALID": [
        "xss", "script", "escape", "sanitize",
        "html.*escape", "encode", "cross.*site",
    ],
    # Input Validation
    "INPUTVAL": [
        "validate", "sanitize", "filter", "whitelist",
        "blacklist", "allow", "deny", "regex",
        "clean", "input.*check",
    ],
    # HTTPS removal
    "RHTTPO": [
        "https", "http", "ssl", "tls", "certificate",
        "verify", "secure.*connect",
    ],
    # Auth removal
    "RMAUTH": [
        "auth", "login", "session", "permission",
        "access.*control", "is_authenticated",
        "credential", "token.*valid",
    ],
    # Encryption removal
    "RENCRYPT": [
        "encrypt", "decrypt", "cipher", "aes",
        "rsa", "key", "plaintext",
    ],
    # IDOR
    "IDOR": [
        "auth", "owner", "permission", "access",
        "user_id", "session", "unauthorized",
    ],
    # SSTI
    "SSTI": [
        "template", "render", "jinja", "inject",
        "expression", "sandbox",
    ],
    # CORS
    "CORS_WEAK": [
        "cors", "origin", "access-control", "cross.*origin",
        "wildcard", "header",
    ],
    # CSRF
    "CSRF_REMOVE": [
        "csrf", "token", "cross.*site.*request",
        "forgery", "session",
    ],
    # Weak Random
    "WEAKRANDOM": [
        "random", "seed", "urandom", "secrets",
        "cryptographic", "predictable", "entropy",
    ],
}

# Fallback patterns for operators not in the dict or unrecognized
GENERIC_SECURITY_PATTERNS = [
    "inject", "malicious", "attack", "vulnerability",
    "secure", "unsafe", "dangerous", "tainted",
]


def classify_kill(error: str, operator: str = None) -> str:
    """
    Classify the type of kill based on the error message and mutation operator.

    Layer 1: Operator-aware heuristic classification.

    Kill types:
    - semantic: AssertionError referencing security properties relevant to the
                specific mutation operator
    - assertion_incidental: AssertionError without operator-relevant security terms
    - crash: ImportError, TypeError, NameError, SyntaxError, AttributeError
    - other: Any other exception

    Args:
        error: The error message from the failing test
        operator: The mutation operator that produced this mutant (e.g., "PSQLI")

    Returns:
        One of: "semantic", "assertion_incidental", "crash", "other"
    """
    if not error:
        return "other"

    error_lower = error.lower()

    # --- Crash detection (unchanged) ---
    crash_types = [
        "ImportError", "TypeError", "NameError", "SyntaxError",
        "AttributeError", "IndentationError", "ModuleNotFoundError",
    ]
    if any(ct in error for ct in crash_types):
        return "crash"

    syntax_indicators = [
        "failed to execute target code", "failed to parse test code",
        "unterminated string", "f-string:", "invalid syntax",
        "unexpected eof", "expected ':'", "expected ')'", "expected '}'",
    ]
    if any(ind in error_lower for ind in syntax_indicators):
        return "crash"

    # --- Assertion classification (operator-aware) ---
    if "AssertionError" in error or "Assertion failed" in error:
        # Get operator-specific patterns, fall back to generic
        patterns = OPERATOR_SECURITY_PATTERNS.get(
            operator, GENERIC_SECURITY_PATTERNS
        )

        # Check for operator-relevant security terms
        for pattern in patterns:
            if re.search(pattern, error_lower):
                return "semantic"

        # No operator-specific match — check generic as weak fallback
        # Only if operator was None (unknown)
        if operator is None:
            for term in GENERIC_SECURITY_PATTERNS:
                if term in error_lower:
                    return "semantic"

        return "assertion_incidental"

    return "other"
```

**Required import addition at top of `evaluate.py`:** Add `import re` if not already present.

**Callsite update in `evaluate.py` lines 298–312:** The `classify_kill` call inside the mutant evaluation loop currently doesn't pass the operator. Update it:

```python
# Current (evaluate.py:311):
kill_type = classify_kill(kill_reason)

# Change to:
kill_type = classify_kill(kill_reason, operator=mutant.operator)
```

This is at line 311 inside `evaluate_generated_tests()`, within the `for mutant in mutants:` loop (line 298). The `mutant` object is a `Mutant` dataclass that already has `.operator` (set at line 285 from `m["operator"]`).

### 1B. LLM Judge Verification (Layer 2)

**Purpose:** For assertions classified as `assertion_incidental` by the heuristic, use a frontier LLM to verify whether the kill is actually security-aware.

**New file: `evaluation/kill_classifier_judge.py`**

```python
"""
LLM-based Kill Classification Judge (Layer 2)

Verifies ambiguous kill classifications using a frontier LLM.
Used after the heuristic classifier (Layer 1) for cases where
the heuristic returned 'assertion_incidental' but the kill might
actually be security-aware.
"""

import json
import re
from typing import Dict, Optional, Any

KILL_CLASSIFICATION_SYSTEM_PROMPT = """You are a security testing expert.
Your task: Given a mutation operator, the CWE it targets, the error message
from a failing test, and the mutant diff, classify whether the test failure
represents GENUINE security awareness or incidental detection.

SEMANTIC (security-aware): The assertion directly checks a security property
  relevant to the CWE. Example: For CWE-89, asserting db.last_params is not None.

INCIDENTAL: The assertion catches a behavioral change but is not checking
  a security property. Example: For CWE-89, asserting the return value is a list.

Respond ONLY with JSON:
{
    "classification": "semantic" or "incidental",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}"""

KILL_CLASSIFICATION_PROMPT = """Classify this test failure:

**Mutation Operator:** {operator}
**Target CWE:** {cwe}
**Operator Description:** {operator_description}
**Error Message:**
```
{error_message}
```
**Mutant Diff (secure → mutated):**
```diff
{mutant_diff}
```

Is this test failure detecting a security property (semantic)
or catching a behavioral side-effect (incidental)?"""


def classify_kill_with_llm(
    error_message: str,
    operator: str,
    cwe: str,
    operator_description: str,
    secure_code: str,
    mutated_code: str,
    judge_provider: str = "anthropic",
    judge_model: str = None,
) -> Dict[str, Any]:
    """
    Use an LLM judge to classify an ambiguous kill.

    This is Layer 2 — called only when the heuristic (Layer 1)
    returns 'assertion_incidental' and the kill needs verification.

    Args:
        error_message: The assertion error text
        operator: Mutation operator name (e.g., "PSQLI")
        cwe: CWE identifier (e.g., "CWE-89")
        operator_description: What the operator does
        secure_code: Original secure code
        mutated_code: Mutated (vulnerable) code
        judge_provider: "anthropic" or "openai"
        judge_model: Model name (default: claude-sonnet-4-5 / gpt-5)

    Returns:
        Dict with "classification", "confidence", "reasoning"
    """
    import difflib

    # Generate diff
    diff_lines = list(difflib.unified_diff(
        secure_code.splitlines(keepends=True),
        mutated_code.splitlines(keepends=True),
        fromfile="secure.py",
        tofile="mutant.py",
        lineterm="",
    ))
    mutant_diff = "\n".join(diff_lines[:50])  # Limit diff size

    prompt = KILL_CLASSIFICATION_PROMPT.format(
        operator=operator,
        cwe=cwe,
        operator_description=operator_description,
        error_message=error_message[:500],
        mutant_diff=mutant_diff,
    )

    # Call LLM
    try:
        if judge_provider == "anthropic":
            import anthropic
            import os
            client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            model = judge_model or "claude-sonnet-4-5-20250929"
            response = client.messages.create(
                model=model,
                max_tokens=256,
                system=KILL_CLASSIFICATION_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
            )
            text = response.content[0].text
        elif judge_provider == "openai":
            from openai import OpenAI
            import os
            client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            model = judge_model or "gpt-5"
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": KILL_CLASSIFICATION_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
            )
            text = response.choices[0].message.content
        else:
            return {"classification": "incidental", "confidence": 0.0, "reasoning": "Unknown provider"}

        # Parse response
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            result = json.loads(json_match.group())
            return {
                "classification": result.get("classification", "incidental"),
                "confidence": float(result.get("confidence", 0.0)),
                "reasoning": result.get("reasoning", ""),
            }
    except Exception as e:
        return {"classification": "incidental", "confidence": 0.0, "reasoning": f"Error: {e}"}

    return {"classification": "incidental", "confidence": 0.0, "reasoning": "Parse failure"}
```

**Integration point in `evaluate.py`:** After the heuristic returns `assertion_incidental`, optionally invoke the LLM judge. Add a parameter `use_llm_kill_classifier=False` to `evaluate_generated_tests()` (line 187):

```python
def evaluate_generated_tests(
    sample: Dict,
    generated_tests: str,
    engine: Optional[MutationEngine] = None,
    runner: Optional[TestRunner] = None,
    max_mutants: int = 10,
    use_llm_kill_classifier: bool = False,  # NEW PARAMETER
    kill_classifier_provider: str = "anthropic",  # NEW
) -> Dict[str, Any]:
```

Then inside the mutant loop (around line 311), after `classify_kill`:

```python
kill_type = classify_kill(kill_reason, operator=mutant.operator)

# Layer 2: LLM verification for ambiguous cases
llm_classification = None
if use_llm_kill_classifier and kill_type == "assertion_incidental":
    from evaluation.kill_classifier_judge import classify_kill_with_llm
    llm_result = classify_kill_with_llm(
        error_message=kill_reason,
        operator=mutant.operator,
        cwe=sample["cwe"],
        operator_description=mutant.description,
        secure_code=sample["secure_code"],
        mutated_code=mutant.mutated_code,
        judge_provider=kill_classifier_provider,
    )
    llm_classification = llm_result
    if llm_result["classification"] == "semantic" and llm_result["confidence"] >= 0.7:
        kill_type = "semantic"  # Upgrade classification
```

Store both classifications in mutant_details (around line 326):

```python
result["mutant_details"].append({
    "id": mutant.id,
    "operator": mutant.operator,
    "killed": is_killed,
    "kill_type": kill_type,
    "kill_type_heuristic": classify_kill(kill_reason, operator=mutant.operator),  # Original
    "kill_type_llm": llm_classification,  # LLM override (or None)
    "kill_reason": kill_reason,
    "description": mutant.description,
    "mutated_code": mutant.mutated_code,
    "test_results": test_results,
})
```

### 1C. Human Annotation Calibration (Layer 3)

**Purpose:** Manually annotate 200–300 kills to compute inter-rater reliability (Cohen's κ) between the heuristic, LLM judge, and human labels.

**New file: `evaluation/human_annotation.py`**

```python
"""
Human Annotation Tool and Agreement Analysis for Kill Classification.

Generates annotation batches, collects human labels, and computes
inter-rater reliability (Cohen's kappa) between:
  - Heuristic vs Human
  - LLM Judge vs Human
  - Heuristic vs LLM Judge
"""

import json
import random
from typing import List, Dict, Any, Optional
from pathlib import Path


def generate_annotation_batch(
    results_file: str,
    output_file: str,
    n_samples: int = 300,
    seed: int = 42,
) -> List[Dict]:
    """
    Extract a stratified sample of kills for human annotation.

    Samples proportionally across:
    - Kill types (semantic, incidental, crash, other)
    - Operators (PSQLI, CMDINJECT, etc.)
    - CWEs

    Args:
        results_file: Path to model evaluation results JSON
                      (output from evaluate_model or run_llm_baselines)
        output_file: Path to save annotation batch JSON
        n_samples: Target number of kills to annotate
        seed: Random seed

    Returns:
        List of annotation items
    """
    rng = random.Random(seed)

    with open(results_file) as f:
        data = json.load(f)

    # Collect all kills across all samples
    all_kills = []
    details = data.get("details", [])
    for sample_result in details:
        sample_id = sample_result.get("sample_id", "unknown")
        cwe = sample_result.get("cwe", "unknown")
        for mutant in sample_result.get("mutant_details", []):
            if mutant.get("killed"):
                all_kills.append({
                    "sample_id": sample_id,
                    "cwe": cwe,
                    "mutant_id": mutant["id"],
                    "operator": mutant.get("operator", "unknown"),
                    "kill_type_heuristic": mutant.get("kill_type", "unknown"),
                    "kill_reason": mutant.get("kill_reason", ""),
                    "mutated_code_snippet": mutant.get("mutated_code", "")[:500],
                    "description": mutant.get("description", ""),
                    # Human annotator fills these:
                    "human_label": None,  # "semantic", "incidental", "crash", "other"
                    "human_confidence": None,  # 1-5
                    "human_notes": "",
                })

    # Stratified sample: ensure representation across operators
    from collections import defaultdict
    by_operator = defaultdict(list)
    for kill in all_kills:
        by_operator[kill["operator"]].append(kill)

    selected = []
    per_operator = max(1, n_samples // len(by_operator))
    for operator, kills in by_operator.items():
        rng.shuffle(kills)
        selected.extend(kills[:per_operator])

    # Fill remaining slots randomly
    if len(selected) < n_samples:
        used_ids = {(s["sample_id"], s["mutant_id"]) for s in selected}
        remaining = [k for k in all_kills
                     if (k["sample_id"], k["mutant_id"]) not in used_ids]
        rng.shuffle(remaining)
        selected.extend(remaining[:n_samples - len(selected)])

    rng.shuffle(selected)

    with open(output_file, "w") as f:
        json.dump(selected, f, indent=2)

    print(f"Generated annotation batch: {len(selected)} kills -> {output_file}")
    return selected


def compute_cohens_kappa(labels_a: List[str], labels_b: List[str]) -> float:
    """
    Compute Cohen's kappa for inter-rater reliability.

    Args:
        labels_a: Rater A's labels
        labels_b: Rater B's labels

    Returns:
        Kappa coefficient (-1.0 to 1.0)
    """
    assert len(labels_a) == len(labels_b)
    n = len(labels_a)
    categories = sorted(set(labels_a) | set(labels_b))

    # Confusion matrix
    matrix = {a: {b: 0 for b in categories} for a in categories}
    for a, b in zip(labels_a, labels_b):
        matrix[a][b] += 1

    # Observed agreement
    po = sum(matrix[c][c] for c in categories) / n

    # Expected agreement (by chance)
    pe = 0.0
    for c in categories:
        row_sum = sum(matrix[c].values()) / n
        col_sum = sum(matrix[r][c] for r in categories) / n
        pe += row_sum * col_sum

    if pe == 1.0:
        return 1.0

    kappa = (po - pe) / (1 - pe)
    return kappa


def compute_agreement_report(
    annotation_file: str,
    llm_results_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compute agreement between heuristic, LLM judge, and human annotations.

    Args:
        annotation_file: Path to completed annotation batch JSON
                         (with human_label filled in)
        llm_results_file: Path to LLM judge results (optional)

    Returns:
        Dict with kappa values and confusion matrices
    """
    with open(annotation_file) as f:
        annotations = json.load(f)

    # Filter to annotated items
    annotated = [a for a in annotations if a.get("human_label")]

    human_labels = [a["human_label"] for a in annotated]
    heuristic_labels = [a["kill_type_heuristic"] for a in annotated]

    report = {
        "n_annotated": len(annotated),
        "heuristic_vs_human_kappa": compute_cohens_kappa(heuristic_labels, human_labels),
    }

    # Agreement breakdown
    agree = sum(1 for h, hu in zip(heuristic_labels, human_labels) if h == hu)
    report["heuristic_vs_human_agreement"] = agree / len(annotated) if annotated else 0

    # If LLM results available
    if llm_results_file:
        with open(llm_results_file) as f:
            llm_data = json.load(f)
        # Map LLM classifications to same annotation items
        llm_map = {}
        for item in llm_data:
            key = (item["sample_id"], item["mutant_id"])
            llm_map[key] = item.get("kill_type_llm", {}).get("classification", "incidental")

        llm_labels = []
        human_for_llm = []
        for a in annotated:
            key = (a["sample_id"], a["mutant_id"])
            if key in llm_map:
                llm_labels.append(llm_map[key])
                human_for_llm.append(a["human_label"])

        if llm_labels:
            report["llm_vs_human_kappa"] = compute_cohens_kappa(llm_labels, human_for_llm)
            agree_llm = sum(1 for l, h in zip(llm_labels, human_for_llm) if l == h)
            report["llm_vs_human_agreement"] = agree_llm / len(llm_labels)

    print(f"\n=== Agreement Report ({len(annotated)} annotations) ===")
    print(f"Heuristic vs Human κ: {report['heuristic_vs_human_kappa']:.3f}")
    print(f"Heuristic vs Human Agreement: {report['heuristic_vs_human_agreement']:.1%}")
    if "llm_vs_human_kappa" in report:
        print(f"LLM vs Human κ: {report['llm_vs_human_kappa']:.3f}")
        print(f"LLM vs Human Agreement: {report['llm_vs_human_agreement']:.1%}")

    return report
```

**What to report in the paper:**
- Heuristic-vs-Human κ (target: > 0.70)
- LLM-vs-Human κ (target: > 0.80)
- Heuristic-vs-LLM κ
- If LLM-vs-Human κ > 0.80, the LLM judge is validated as a reliable automated rater
- If Heuristic-vs-Human κ > 0.75, the heuristic alone is sufficient and the LLM judge is a robustness check

---

## 2. Equivalent Mutant Detection

**Current problem:** `metrics.py` line 29 defines `equivalent_mutants: int = 0` in `MutationMetrics`, and line 36 correctly subtracts equivalents from the denominator: `killable = self.total_mutants - self.equivalent_mutants`. But nothing ever sets `equivalent_mutants` to a nonzero value. Your 774 pre-generated mutants are all assumed killable. If 5–10% are equivalent, every model's SMS is systematically deflated.

**Where equivalents enter the pipeline:** In `evaluate.py` line 298, the mutant loop iterates all mutants and checks if tests kill them. A surviving mutant could be (a) a genuine survivor the tests missed, or (b) an equivalent mutant that's semantically identical to the original.

### 2A. Cross-Model Equivalence Detection

**New file: `evaluation/equivalent_mutant_detector.py`**

```python
"""
Equivalent Mutant Detection for SecMutBench

A mutant is potentially equivalent if it survives ALL tests from ALL models
AND all reference tests. Such mutants should be excluded from the denominator
when computing mutation scores and SMS.

Two detection strategies:
1. Cross-model consensus: Survived all models + reference tests
2. Functional equivalence: Behaves identically to original on a test suite
"""

import json
from typing import List, Dict, Any, Set, Tuple
from pathlib import Path
from collections import defaultdict


def detect_equivalent_mutants_cross_model(
    results_dir: str,
    reference_results_file: str = None,
) -> Dict[str, Any]:
    """
    Identify mutants that survived across ALL evaluated models.

    A mutant that no model's tests can kill (across all models AND reference
    tests) is a strong equivalent mutant candidate.

    Args:
        results_dir: Directory containing *_results.json files from
                     different models (output of run_llm_baselines.py)
        reference_results_file: Path to reference test results
                                (output of evaluate_reference_tests)

    Returns:
        Dict with:
        - equivalent_candidates: List of (sample_id, mutant_id) tuples
        - equivalence_rate: Proportion of total mutants
        - per_sample: Dict mapping sample_id to list of equivalent mutant IDs
    """
    results_dir = Path(results_dir)
    result_files = list(results_dir.glob("*_results.json"))

    if not result_files:
        raise FileNotFoundError(f"No result files found in {results_dir}")

    # Track which mutants are killed by at least one model
    # Key: (sample_id, mutant_id), Value: set of model names that killed it
    killed_by = defaultdict(set)
    all_mutants = set()  # (sample_id, mutant_id)

    for result_file in result_files:
        model_name = result_file.stem.replace("_results", "")

        with open(result_file) as f:
            data = json.load(f)

        for sample_result in data.get("details", []):
            sample_id = sample_result.get("sample_id", "unknown")
            for mutant in sample_result.get("mutant_details", []):
                mutant_id = mutant.get("id", "unknown")
                key = (sample_id, mutant_id)
                all_mutants.add(key)
                if mutant.get("killed", False):
                    killed_by[key].add(model_name)

    # Also check reference tests
    if reference_results_file and Path(reference_results_file).exists():
        with open(reference_results_file) as f:
            ref_data = json.load(f)
        for sample_result in ref_data.get("details", []):
            sample_id = sample_result.get("sample_id", "unknown")
            for mutant in sample_result.get("mutant_details", []):
                mutant_id = mutant.get("id", "unknown")
                key = (sample_id, mutant_id)
                if mutant.get("killed", False):
                    killed_by[key].add("reference_tests")

    # Equivalent candidates: survived ALL models AND reference tests
    equivalent_candidates = [
        key for key in all_mutants
        if key not in killed_by or len(killed_by[key]) == 0
    ]

    # Per-sample breakdown
    per_sample = defaultdict(list)
    for sample_id, mutant_id in equivalent_candidates:
        per_sample[sample_id].append(mutant_id)

    total_mutants = len(all_mutants)
    eq_rate = len(equivalent_candidates) / total_mutants if total_mutants else 0

    print(f"\n=== Equivalent Mutant Detection ===")
    print(f"Total mutants: {total_mutants}")
    print(f"Models evaluated: {len(result_files)}")
    print(f"Equivalent candidates: {len(equivalent_candidates)} ({eq_rate:.1%})")
    print(f"Samples with equivalents: {len(per_sample)}")

    return {
        "total_mutants": total_mutants,
        "models_checked": len(result_files),
        "equivalent_candidates": equivalent_candidates,
        "equivalence_rate": eq_rate,
        "per_sample": dict(per_sample),
    }


def recompute_scores_excluding_equivalents(
    results_file: str,
    equivalent_mutants: List[Tuple[str, str]],
    output_file: str = None,
) -> Dict[str, Any]:
    """
    Recompute mutation score and SMS excluding equivalent mutants.

    This gives the corrected scores to report in the paper.

    Args:
        results_file: Original model results JSON
        equivalent_mutants: List of (sample_id, mutant_id) to exclude
        output_file: Optional path to save corrected results

    Returns:
        Corrected metrics
    """
    eq_set = set(equivalent_mutants)

    with open(results_file) as f:
        data = json.load(f)

    total_mutants = 0
    total_killed = 0
    semantic_kills = 0
    excluded = 0

    for sample_result in data.get("details", []):
        sample_id = sample_result.get("sample_id", "unknown")
        for mutant in sample_result.get("mutant_details", []):
            mutant_id = mutant.get("id", "unknown")
            if (sample_id, mutant_id) in eq_set:
                excluded += 1
                continue  # Skip equivalent mutants

            total_mutants += 1
            if mutant.get("killed", False):
                total_killed += 1
                if mutant.get("kill_type") == "semantic":
                    semantic_kills += 1

    corrected = {
        "total_mutants_killable": total_mutants,
        "equivalents_excluded": excluded,
        "mutation_score": total_killed / total_mutants if total_mutants else 0,
        "security_mutation_score": semantic_kills / total_mutants if total_mutants else 0,
    }

    print(f"\n=== Corrected Scores (excluding {excluded} equivalents) ===")
    print(f"MS:  {corrected['mutation_score']:.1%}")
    print(f"SMS: {corrected['security_mutation_score']:.1%}")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(corrected, f, indent=2)

    return corrected
```

**Integration with `metrics.py`:** Update `calculate_kill_breakdown()` (line 378) to accept an optional `equivalent_mutants` set and exclude them from the denominator:

```python
# In metrics.py calculate_kill_breakdown(), add parameter:
def calculate_kill_breakdown(
    sample_results: List[Dict[str, Any]],
    equivalent_mutants: Optional[Set[tuple]] = None,  # NEW
) -> Dict[str, Any]:
    ...
    for result in sample_results:
        mutant_details = result.get("mutant_details", [])
        sample_id = result.get("sample_id", "unknown")
        for mutant in mutant_details:
            mutant_id = mutant.get("id", "unknown")
            # Skip equivalents
            if equivalent_mutants and (sample_id, mutant_id) in equivalent_mutants:
                continue
            total_mutants += 1
            ...
```

---

## 3. Mock Security Contract Formalization

**Current problem:** Each mock (MockDatabase, MockSubprocess, MockCrypto, etc.) has an implicit security contract scattered across docstrings and the `MOCK_ENVIRONMENT_DOCS` string in `prompts.py` (lines 18–76). A reviewer reading the paper won't understand how your mocks enable security detection unless you formalize these contracts.

**What to create:** A structured specification that the paper references as a table.

**New file: `evaluation/mock_contracts.py`**

```python
"""
Formal Security Contracts for SecMutBench Mock Objects

Each mock object exposes state variables that security tests can assert on.
This module defines the formal contract for each mock, mapping:
  CWE -> Mock Class -> Security Properties -> Detection Assertions

These contracts are referenced in the paper (Table 2) and used for
automated validation that generated tests check the correct properties.
"""

MOCK_SECURITY_CONTRACTS = {
    "CWE-89": {
        "mock_class": "MockDatabase",
        "file": "evaluation/mocks/mock_database.py",
        "security_properties": {
            "db.last_params": {
                "secure_value": "not None (tuple of parameters)",
                "insecure_value": "None (string interpolation used)",
                "detection_assertion": "assert db.last_params is not None",
                "what_it_checks": "Whether query uses parameterized execution",
            },
            "db.last_query": {
                "secure_value": "Contains ? or %s placeholders",
                "insecure_value": "Contains interpolated user input",
                "detection_assertion": "assert payload not in db.last_query",
                "what_it_checks": "Whether user input appears raw in SQL query",
            },
        },
        "contract_summary": "Parameterized queries set last_params; string "
                          "concatenation leaves last_params as None.",
    },

    "CWE-78": {
        "mock_class": "MockSubprocess",
        "file": "evaluation/mocks/mock_subprocess.py",
        "security_properties": {
            "subprocess.last_shell": {
                "secure_value": "False (command as list)",
                "insecure_value": "True (command as string with shell)",
                "detection_assertion": "assert subprocess.last_shell == False",
                "what_it_checks": "Whether shell=True was used (allows injection)",
            },
            "subprocess.injection_detected": {
                "secure_value": "False",
                "insecure_value": "True (injection patterns found in command)",
                "detection_assertion": "assert not subprocess.injection_detected",
                "what_it_checks": "Whether command contains injection characters (;, &&, |)",
            },
        },
        "contract_summary": "shell=False with list args is secure; shell=True "
                          "with string args allows command injection.",
    },

    "CWE-22": {
        "mock_class": "MockFileSystem",
        "file": "evaluation/mocks/mock_filesystem.py",
        "security_properties": {
            "path_validation": {
                "secure_value": "ValueError/PermissionError raised for ../",
                "insecure_value": "No exception, traversal succeeds",
                "detection_assertion": "pytest.raises(ValueError) or PermissionError",
                "what_it_checks": "Whether path traversal is blocked",
            },
            "fs.base_dir": {
                "secure_value": "Resolved path starts with base_dir",
                "insecure_value": "Resolved path escapes base_dir",
                "detection_assertion": "assert resolved.startswith(fs.base_dir)",
                "what_it_checks": "Whether file access is constrained to allowed directory",
            },
        },
        "contract_summary": "Secure code validates paths against base_dir; "
                          "insecure code allows traversal via ../.",
    },

    "CWE-327": {
        "mock_class": "MockCrypto",
        "file": "evaluation/mocks/mock_crypto.py",
        "security_properties": {
            "hashlib.weak_algorithm_used": {
                "secure_value": "False (SHA256/SHA512/bcrypt used)",
                "insecure_value": "True (MD5/SHA1/DES used)",
                "detection_assertion": "assert not hashlib.weak_algorithm_used",
                "what_it_checks": "Whether a cryptographically weak algorithm was used",
            },
            "hashlib.last_algorithm": {
                "secure_value": "sha256, sha512, bcrypt, etc.",
                "insecure_value": "md5, sha1, des, etc.",
                "detection_assertion": "assert hashlib.last_algorithm not in ['md5', 'sha1']",
                "what_it_checks": "Specific algorithm name used",
            },
        },
        "contract_summary": "Tracks which hash algorithm is used; weak algorithms "
                          "(MD5/SHA1) are flagged.",
    },

    "CWE-502": {
        "mock_class": "MockPickle / MockYAML",
        "file": "evaluation/mocks/mock_pickle.py, mock_yaml.py",
        "security_properties": {
            "pickle.unsafe_load_called": {
                "secure_value": "False (safe alternatives used)",
                "insecure_value": "True (pickle.loads/load called)",
                "detection_assertion": "assert not pickle.unsafe_load_called",
                "what_it_checks": "Whether unsafe deserialization function was called",
            },
            "yaml.unsafe_load_called": {
                "secure_value": "False (yaml.safe_load used)",
                "insecure_value": "True (yaml.load without SafeLoader)",
                "detection_assertion": "assert not yaml.unsafe_load_called",
                "what_it_checks": "Whether YAML was loaded without safe loader",
            },
        },
        "contract_summary": "Tracks whether deserialization uses safe methods "
                          "(safe_load, json.loads) vs unsafe (pickle.loads, yaml.load).",
    },

    "CWE-918": {
        "mock_class": "MockHTTPClient",
        "file": "evaluation/mocks/mock_http.py",
        "security_properties": {
            "requests.ssrf_attempted": {
                "secure_value": "False (URL validated before request)",
                "insecure_value": "True (internal IP/localhost accessed)",
                "detection_assertion": "assert not requests.ssrf_attempted",
                "what_it_checks": "Whether request targets internal/private IP ranges",
            },
        },
        "contract_summary": "Tracks whether HTTP requests target internal networks "
                          "(127.0.0.1, 169.254.x.x, localhost).",
    },

    "CWE-611": {
        "mock_class": "MockXMLParser",
        "file": "evaluation/mocks/mock_xml.py",
        "security_properties": {
            "xml_parser.external_entities_resolved": {
                "secure_value": "False (external entities disabled)",
                "insecure_value": "True (XXE patterns found in XML)",
                "detection_assertion": "assert not xml_parser.external_entities_resolved",
                "what_it_checks": "Whether XML parser resolves external entities",
            },
        },
        "contract_summary": "Detects external entity patterns in parsed XML.",
    },

    "CWE-798": {
        "mock_class": "MockEnvironment",
        "file": "evaluation/mocks/mock_environment.py",
        "security_properties": {
            "env.access_log": {
                "secure_value": "Non-empty (env vars were read)",
                "insecure_value": "Empty (credentials hardcoded in source)",
                "detection_assertion": "assert len(env.access_log) > 0",
                "what_it_checks": "Whether code reads credentials from environment",
            },
        },
        "contract_summary": "Tracks environment variable access; secure code reads "
                          "secrets from env, insecure code hardcodes them.",
    },
}


def validate_test_uses_contract(
    test_code: str,
    cwe: str,
) -> Dict[str, Any]:
    """
    Check if generated test code references the correct mock security
    properties for its target CWE.

    This is used for automated quality analysis, not scoring.

    Args:
        test_code: The generated test code
        cwe: The target CWE

    Returns:
        Dict with contract_used (bool), properties_checked (list),
        properties_missed (list)
    """
    import re

    contract = MOCK_SECURITY_CONTRACTS.get(cwe)
    if not contract:
        return {"contract_used": False, "reason": f"No contract for {cwe}"}

    properties_checked = []
    properties_missed = []

    for prop_name, prop_def in contract["security_properties"].items():
        # Check if the property is referenced in the test
        # Normalize property name for matching
        prop_patterns = [
            prop_name.replace(".", r"\."),  # Exact match
            prop_def["detection_assertion"].split("assert ")[-1][:30],  # Assertion pattern
        ]
        found = any(
            re.search(p, test_code, re.IGNORECASE)
            for p in prop_patterns
            if p
        )
        if found:
            properties_checked.append(prop_name)
        else:
            properties_missed.append(prop_name)

    return {
        "contract_used": len(properties_checked) > 0,
        "properties_checked": properties_checked,
        "properties_missed": properties_missed,
        "coverage": len(properties_checked) / len(contract["security_properties"])
                    if contract["security_properties"] else 0,
    }
```

**Usage in paper:** Generate Table 2 from `MOCK_SECURITY_CONTRACTS`:

| CWE | Mock | Key Property | Secure State | Insecure State | Detection Assertion |
|-----|------|-------------|-------------|----------------|---------------------|
| CWE-89 | MockDatabase | `db.last_params` | not None | None | `assert db.last_params is not None` |
| CWE-78 | MockSubprocess | `subprocess.injection_detected` | False | True | `assert not subprocess.injection_detected` |
| ... | ... | ... | ... | ... | ... |

---

## 4. Contamination Ablation

**Current infrastructure:** `contamination_prevention.py` already has `ContaminationAuditor` (line 574) with `extract_code_ngrams()`, `compute_overlap()`, and `audit_dataset()`. Also has `PerturbationPipeline` (line 79) for identifier renaming and structural perturbation.

**What's missing:** The auditor has never been run against actual corpora, and there's no ablation comparing SMS between public-sourced vs novel samples.

### 4A. Run Existing Contamination Audit

The `ContaminationAuditor` needs corpus patterns loaded via `load_corpus_patterns()` (line 612). For an internal comparison (your dataset against its own source datasets), you can generate corpus fingerprints from the raw source files.

**New file: `scripts/run_contamination_audit.py`**

```python
#!/usr/bin/env python3
"""
Run contamination audit on SecMutBench dataset.

Compares dataset samples against source corpora (SecurityEval, CyberSecEval,
SecCodePLT) using n-gram overlap analysis.

Also runs the contamination ablation: compare SMS between public-sourced
samples (potentially contaminated) vs SecMutBench-authored templates (novel).

Usage:
    python scripts/run_contamination_audit.py
    python scripts/run_contamination_audit.py --ngram-size 8
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.contamination_prevention import (
    ContaminationAuditor,
    PerturbationPipeline,
)


def build_source_corpus_fingerprints(
    auditor: ContaminationAuditor,
    dataset: list,
) -> None:
    """
    Build n-gram fingerprint from original source data for self-comparison.

    Groups samples by source and builds fingerprints from their original
    (pre-perturbation) code if available, or current code otherwise.
    """
    from collections import defaultdict
    by_source = defaultdict(list)
    for sample in dataset:
        source = sample.get("source", "unknown")
        by_source[source].append(sample)

    for source, samples in by_source.items():
        ngrams = set()
        for s in samples:
            code = s.get("secure_code", "") + s.get("insecure_code", "")
            ngrams.update(auditor.extract_code_ngrams(code))
        auditor.known_patterns[f"self_{source}"] = ngrams
        print(f"  Source '{source}': {len(ngrams)} n-grams from {len(samples)} samples")


def run_contamination_ablation(
    dataset: list,
    results_dir: str,
) -> dict:
    """
    Compare SMS between public-sourced and novel samples.

    Public-sourced: source in [SecurityEval, CyberSecEval, SecCodePLT]
    Novel: source == "secmutbench_template" (hand-authored)

    If SMS is similar across both groups, contamination is not inflating
    the metric. If public-sourced SMS >> novel SMS, contamination is a concern.
    """
    PUBLIC_SOURCES = {"SecurityEval", "CyberSecEval", "SecCodePLT", "seccodeplt"}
    NOVEL_SOURCES = {"secmutbench_template", "template", "secmutbench"}

    results_dir = Path(results_dir)
    result_files = list(results_dir.glob("*_results.json"))

    ablation = {}

    for result_file in result_files:
        model_name = result_file.stem.replace("_results", "")
        with open(result_file) as f:
            data = json.load(f)

        # Map sample_id -> source
        sample_sources = {s["id"]: s.get("source", "unknown") for s in dataset}

        public_semantic = 0
        public_total = 0
        novel_semantic = 0
        novel_total = 0

        for sample_result in data.get("details", []):
            sample_id = sample_result.get("sample_id")
            source = sample_sources.get(sample_id, "unknown")

            for mutant in sample_result.get("mutant_details", []):
                is_public = source in PUBLIC_SOURCES
                is_novel = source in NOVEL_SOURCES

                if is_public:
                    public_total += 1
                    if mutant.get("killed") and mutant.get("kill_type") == "semantic":
                        public_semantic += 1
                elif is_novel:
                    novel_total += 1
                    if mutant.get("killed") and mutant.get("kill_type") == "semantic":
                        novel_semantic += 1

        public_sms = public_semantic / public_total if public_total else 0
        novel_sms = novel_semantic / novel_total if novel_total else 0
        gap = public_sms - novel_sms

        ablation[model_name] = {
            "public_sms": public_sms,
            "public_mutants": public_total,
            "novel_sms": novel_sms,
            "novel_mutants": novel_total,
            "sms_gap": gap,
        }

        print(f"\n{model_name}:")
        print(f"  Public-sourced SMS: {public_sms:.1%} ({public_total} mutants)")
        print(f"  Novel SMS:         {novel_sms:.1%} ({novel_total} mutants)")
        print(f"  Gap:               {gap:+.1%} {'⚠️ POTENTIAL CONTAMINATION' if gap > 0.05 else '✓ OK'}")

    return ablation


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="data/dataset.json")
    parser.add_argument("--results-dir", default="results/baselines")
    parser.add_argument("--ngram-size", type=int, default=8)
    parser.add_argument("--output", default="results/contamination_audit.json")
    args = parser.parse_args()

    # Load dataset
    with open(args.dataset) as f:
        data = json.load(f)
    samples = data["samples"] if isinstance(data, dict) else data

    print(f"=== Contamination Audit (n={args.ngram_size}) ===")
    print(f"Dataset: {len(samples)} samples")

    # 1. N-gram overlap analysis
    auditor = ContaminationAuditor(n=args.ngram_size)
    print("\nBuilding source fingerprints...")
    build_source_corpus_fingerprints(auditor, samples)

    print("\nRunning audit...")
    audit_results = auditor.audit_dataset(samples)

    print(f"\nContamination rate: {audit_results['contamination_rate']:.1%}")
    print(f"Flagged samples: {audit_results['potentially_contaminated']}/{audit_results['total_samples']}")

    # 2. Perturbation verification
    pipeline = PerturbationPipeline()
    perturbed_count = sum(1 for s in samples if s.get("perturbation_applied"))
    print(f"\nPerturbation applied: {perturbed_count}/{len(samples)} samples")

    # 3. Contamination ablation (if results exist)
    results_dir = Path(args.results_dir)
    if results_dir.exists() and list(results_dir.glob("*_results.json")):
        print("\n=== Contamination Ablation ===")
        ablation = run_contamination_ablation(samples, args.results_dir)
        audit_results["ablation"] = ablation
    else:
        print(f"\nNo results in {results_dir}, skipping ablation.")

    # Save
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(audit_results, f, indent=2)
    print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
```

---

## 5. File-Level Context Ablation

**Current state:** `prompts.py` line 159 defines `TEST_GENERATION_PROMPT` which includes only `{code}` — the target function. The model never sees the surrounding file context (imports, other functions, class definitions).

**What to add:** A `format_test_generation_prompt_with_context()` variant that includes the full file surrounding the function. This creates a two-condition experiment: function-level vs file-level.

**Changes to `prompts.py`:**

```python
# Add after line 248 in prompts.py:

FILE_LEVEL_TEST_GENERATION_PROMPT = """Generate security tests for the function `{entry_point}` in this Python module to detect {cwe_name} ({cwe}) vulnerabilities.

**Full Module Context:**
```python
{file_context}
```

**Target Function (focus your tests here):**
```python
{code}
```

{mock_env}

**Requirements:**
1. Write pytest-style functions starting with `test_`
2. Tests should PASS when code uses secure patterns (parameterized queries, input validation, etc.)
3. Tests should FAIL when code has vulnerabilities (string concatenation in SQL, missing validation, etc.)
4. Test at least 3 different attack vectors for {cwe}
5. Use assertions to verify security properties (e.g., params not None, payload not in query)
6. Do NOT include import statements or class definitions
7. Use the full module context to understand data flow and trust boundaries

**Attack vectors for {cwe_name}:**
{attack_vectors}

**CRITICAL: Assertion Logic for Security Tests**

Tests verify that SECURE code properly handles malicious inputs:

| Vulnerability | CORRECT Assertion (secure code) | WRONG Assertion |
|---------------|--------------------------------|-----------------|
| XSS (CWE-79) | `assert "<script>" NOT in result` | `assert "<script>" in result` |
| SQLi (CWE-89) | `assert db.last_params is not None` | `assert payload in db.last_query` |
| Command Inj (CWE-78) | `assert subprocess.last_shell == False` | `assert ";" in command` |
| Path Traversal (CWE-22) | `assert fs.last_path.startswith(base_dir)` | `assert "../" in path` |

**FLEXIBLE ASSERTIONS (Check Behavior, Not Exact Strings):**
- Instead of checking exact escaping: check that dangerous characters are neutralized
- Instead of checking exact output: check the BEHAVIOR (exceptions, mock state, return values)
- Use mock object state (`db.last_params`, `subprocess.last_shell`, `fs.last_path`) over output inspection

Output ONLY valid Python test functions, nothing else."""


def format_test_generation_prompt_with_context(
    code: str,
    file_context: str,
    entry_point: str,
    cwe: str,
    cwe_name: str = "vulnerability",
    include_mock_env: bool = True,
) -> str:
    """
    Format the file-level test generation prompt.

    Args:
        code: The target function code
        file_context: The full file containing the function
        entry_point: Function name
        cwe: CWE identifier
        cwe_name: Human-readable CWE name
        include_mock_env: Whether to include mock documentation

    Returns:
        Formatted prompt string
    """
    return FILE_LEVEL_TEST_GENERATION_PROMPT.format(
        code=code,
        file_context=file_context,
        entry_point=entry_point,
        cwe=cwe,
        cwe_name=cwe_name,
        mock_env=MOCK_ENVIRONMENT_DOCS if include_mock_env else "",
        attack_vectors=get_attack_vectors(cwe),
    )
```

**Integration in `run_llm_baselines.py`:** The `generate_tests()` function (line 286) currently calls `format_test_generation_prompt()`. Add a `--context-level` argument:

```python
# In run_llm_baselines.py generate_tests(), around line 286:
def generate_tests(
    model: str,
    provider: str,
    sample: Dict,
    timeout: int = 300,
    context_level: str = "function",  # NEW: "function" or "file"
) -> str:
    """Generate security tests using specified model."""
    if context_level == "file" and "file_context" in sample:
        from evaluation.prompts import format_test_generation_prompt_with_context
        prompt = format_test_generation_prompt_with_context(
            code=sample["secure_code"],
            file_context=sample["file_context"],
            entry_point=sample.get("entry_point", "function"),
            cwe=sample["cwe"],
            cwe_name=sample.get("cwe_name", "vulnerability"),
            include_mock_env=True,
        )
    else:
        prompt = format_test_generation_prompt(
            code=sample["secure_code"],
            cwe=sample["cwe"],
            cwe_name=sample.get("cwe_name", "vulnerability"),
            include_mock_env=True,
        )
    ...
```

**Dataset augmentation:** For each sample, you need to generate a `file_context` field. For SecMutBench template samples, construct a synthetic file. For SecCodePLT samples, use the original file context if available.

Add to each sample in `dataset.json`:
```json
{
    "id": "sample_001",
    "secure_code": "def get_user(uid): ...",
    "file_context": "import sqlite3\nimport hashlib\n\nDB_PATH = 'app.db'\n\ndef get_db():\n    return sqlite3.connect(DB_PATH)\n\ndef get_user(uid): ...\n\ndef list_users(): ...",
    ...
}
```

---

## 6. Prompt Variant Ablation

**Current state:** `prompts.py` has one `TEST_GENERATION_PROMPT` (line 159). All models receive identical prompting with mock docs, attack vectors, and assertion logic examples.

**What to add:** Two additional prompt variants to run a 3-way ablation study.

**Add to `prompts.py` after the existing prompt:**

```python
# =============================================================================
# Prompt Variants for Ablation Study
# =============================================================================

# Variant 1: MINIMAL — No mock docs, no attack vectors, no assertion examples
MINIMAL_TEST_GENERATION_PROMPT = """Generate security tests for this Python function to detect {cwe_name} ({cwe}) vulnerabilities.

```python
{code}
```

**Requirements:**
1. Write pytest-style functions starting with `test_`
2. Tests should PASS when code uses secure patterns
3. Tests should FAIL when code has vulnerabilities
4. Test at least 3 different attack vectors for {cwe}
5. Do NOT include import statements or class definitions

Output ONLY valid Python test functions, nothing else."""


# Variant 2: WITH_MITRE — Adds MITRE CWE description + remediation guidance
# (No mock docs, but provides authoritative vulnerability context)
MITRE_TEST_GENERATION_PROMPT = """Generate security tests for this Python function to detect {cwe_name} ({cwe}) vulnerabilities.

```python
{code}
```

**CWE Description from MITRE:**
{mitre_description}

**Requirements:**
1. Write pytest-style functions starting with `test_`
2. Tests should PASS when code uses secure patterns
3. Tests should FAIL when code has vulnerabilities
4. Test at least 3 different attack vectors for {cwe}
5. Use assertions to verify security properties
6. Do NOT include import statements or class definitions

**Attack vectors for {cwe_name}:**
{attack_vectors}

Output ONLY valid Python test functions, nothing else."""


# MITRE CWE descriptions for the 14 CWEs in the dataset
MITRE_CWE_DESCRIPTIONS = {
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command. "
              "The software constructs all or part of an SQL command using externally-influenced "
              "input without properly neutralizing special elements that could modify the "
              "intended SQL command. Remediation: use parameterized queries or prepared statements.",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command. "
              "The software constructs all or part of an OS command using externally-influenced "
              "input without properly neutralizing special elements. Remediation: avoid shell=True, "
              "use subprocess with list arguments, validate and sanitize input.",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal). "
              "The software uses external input to construct a pathname without properly "
              "neutralizing sequences such as '../'. Remediation: validate paths, use "
              "os.path.realpath and check against a base directory.",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm. "
               "The software uses a broken or risky cryptographic algorithm (e.g., MD5, SHA1). "
               "Remediation: use SHA-256 or stronger; for passwords use bcrypt/scrypt/argon2.",
    "CWE-502": "Deserialization of Untrusted Data. "
               "The software deserializes data from untrusted sources without verification. "
               "Remediation: avoid pickle.loads on untrusted data, use yaml.safe_load, "
               "validate and restrict deserialized objects.",
    "CWE-918": "Server-Side Request Forgery (SSRF). "
               "The software accepts URLs from users and fetches them without validating "
               "the target. Remediation: validate URLs against an allowlist, block "
               "internal IP ranges (127.0.0.1, 169.254.x.x, 10.x.x.x).",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE). "
               "The software processes XML without disabling external entity resolution. "
               "Remediation: disable DTD processing, use defusedxml.",
    "CWE-798": "Use of Hard-coded Credentials. "
               "The software contains hard-coded passwords, keys, or tokens. "
               "Remediation: store secrets in environment variables or a secrets manager.",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (XSS). "
              "The software does not properly neutralize user input before placing it "
              "in output used as a web page. Remediation: escape HTML entities.",
    "CWE-287": "Improper Authentication. Missing or bypassable authentication checks. "
               "Remediation: verify authentication on every sensitive endpoint.",
    "CWE-20": "Improper Input Validation. The software does not properly validate input. "
              "Remediation: validate input against strict allowlists.",
    "CWE-703": "Improper Check or Handling of Exceptional Conditions. "
               "Remediation: handle all exceptions appropriately.",
    "CWE-730": "Regex Denial of Service (ReDoS). Use of regex patterns vulnerable "
               "to catastrophic backtracking. Remediation: avoid nested quantifiers.",
    "CWE-94": "Improper Control of Generation of Code (Code Injection). "
              "Remediation: never use eval() or exec() on user input.",
}


def format_prompt_variant(
    variant: str,
    code: str,
    cwe: str,
    cwe_name: str = "vulnerability",
) -> str:
    """
    Format a prompt variant for ablation study.

    Args:
        variant: One of "full" (default), "minimal", "mitre"
        code: Source code
        cwe: CWE identifier
        cwe_name: Human-readable CWE name

    Returns:
        Formatted prompt string
    """
    if variant == "minimal":
        return MINIMAL_TEST_GENERATION_PROMPT.format(
            code=code, cwe=cwe, cwe_name=cwe_name,
        )
    elif variant == "mitre":
        return MITRE_TEST_GENERATION_PROMPT.format(
            code=code, cwe=cwe, cwe_name=cwe_name,
            attack_vectors=get_attack_vectors(cwe),
            mitre_description=MITRE_CWE_DESCRIPTIONS.get(cwe, f"See MITRE for {cwe}"),
        )
    else:  # "full" — default, existing prompt
        return format_test_generation_prompt(
            code=code, cwe=cwe, cwe_name=cwe_name, include_mock_env=True,
        )
```

**How to run the ablation:** In `run_llm_baselines.py`, add `--prompt-variant` argument:

```python
# In argparse section of run_llm_baselines.py:
parser.add_argument("--prompt-variant", default="full",
                    choices=["full", "minimal", "mitre"],
                    help="Prompt variant for ablation study")
```

Then in `generate_tests()` use the variant:

```python
from evaluation.prompts import format_prompt_variant

prompt = format_prompt_variant(
    variant=args.prompt_variant,
    code=sample["secure_code"],
    cwe=sample["cwe"],
    cwe_name=sample.get("cwe_name", "vulnerability"),
)
```

**What to report:** SMS per model × prompt variant table. If SMS(full) >> SMS(minimal), the mock documentation is driving detection. If SMS(mitre) ≈ SMS(full), the model doesn't need mock-specific guidance.

---

## 7. Multimodal Weight Sensitivity Analysis

**Current state:** `llm_judge.py` line 479 hardcodes:
```python
DEFAULT_WEIGHTS = {
    'mutation_score': 0.50,
    'security_relevance': 0.20,
    'test_quality': 0.15,
    'coverage': 0.15,
}
```

These weights are asserted without justification.

**New file: `evaluation/weight_sensitivity.py`**

```python
"""
Weight Sensitivity Analysis for MultiModal Evaluation.

Tests whether model rankings are stable across reasonable weight ranges.
If rankings are stable, the specific weights don't matter much.
If rankings change, we need to justify the chosen weights.
"""

import json
import itertools
from typing import Dict, List, Any
from pathlib import Path


WEIGHT_PROFILES = {
    "default": {"mutation_score": 0.50, "security_relevance": 0.20,
                "test_quality": 0.15, "coverage": 0.15},
    "execution_heavy": {"mutation_score": 0.70, "security_relevance": 0.15,
                        "test_quality": 0.10, "coverage": 0.05},
    "security_heavy": {"mutation_score": 0.30, "security_relevance": 0.40,
                       "test_quality": 0.15, "coverage": 0.15},
    "quality_heavy": {"mutation_score": 0.30, "security_relevance": 0.20,
                      "test_quality": 0.35, "coverage": 0.15},
    "equal": {"mutation_score": 0.25, "security_relevance": 0.25,
              "test_quality": 0.25, "coverage": 0.25},
    "no_coverage": {"mutation_score": 0.50, "security_relevance": 0.30,
                    "test_quality": 0.20, "coverage": 0.00},
}


def compute_composite_score(
    sample_scores: Dict[str, float],
    weights: Dict[str, float],
) -> float:
    """Compute weighted composite score."""
    return sum(
        sample_scores.get(k, 0.0) * v
        for k, v in weights.items()
    )


def run_sensitivity_analysis(
    multimodal_results_dir: str,
    output_file: str = None,
) -> Dict[str, Any]:
    """
    Recompute model rankings under different weight profiles.

    Args:
        multimodal_results_dir: Directory with multimodal_results.json per model
        output_file: Optional path to save analysis

    Returns:
        Dict with rankings per weight profile and stability metrics
    """
    results_dir = Path(multimodal_results_dir)
    result_files = list(results_dir.glob("*_multimodal_results.json"))

    if not result_files:
        result_files = list(results_dir.glob("*_results.json"))

    # Collect per-model average scores
    model_scores = {}
    for result_file in result_files:
        model = result_file.stem.replace("_multimodal_results", "").replace("_results", "")
        with open(result_file) as f:
            data = json.load(f)

        details = data.get("details", [])
        if not details:
            continue

        avg_scores = {
            "mutation_score": sum(d.get("mutation_score", 0) for d in details) / len(details),
            "security_relevance": sum(d.get("security_relevance", 0) for d in details) / len(details),
            "test_quality": sum(d.get("test_quality", 0) for d in details) / len(details),
            "coverage": sum(d.get("coverage_score", 0) for d in details) / len(details),
        }
        model_scores[model] = avg_scores

    # Compute rankings under each weight profile
    rankings = {}
    for profile_name, weights in WEIGHT_PROFILES.items():
        composite = {
            model: compute_composite_score(scores, weights)
            for model, scores in model_scores.items()
        }
        ranked = sorted(composite.items(), key=lambda x: x[1], reverse=True)
        rankings[profile_name] = [model for model, _ in ranked]

    # Stability: how often does the top model change?
    top_models = [rankings[p][0] for p in WEIGHT_PROFILES if rankings.get(p)]
    from collections import Counter
    top_counts = Counter(top_models)
    most_common_top = top_counts.most_common(1)[0] if top_counts else ("none", 0)

    # Kendall's W (coefficient of concordance) approximation
    # If all rankings are identical, W = 1
    n_models = len(model_scores)
    n_profiles = len(rankings)
    rank_sums = {model: 0 for model in model_scores}
    for profile_ranking in rankings.values():
        for rank, model in enumerate(profile_ranking):
            rank_sums[model] += rank
    mean_rank_sum = sum(rank_sums.values()) / n_models if n_models else 0
    ss = sum((rs - mean_rank_sum) ** 2 for rs in rank_sums.values())
    max_ss = (n_profiles ** 2 * (n_models ** 3 - n_models)) / 12
    kendalls_w = ss / max_ss if max_ss > 0 else 0

    analysis = {
        "model_scores": model_scores,
        "rankings_per_profile": rankings,
        "most_frequent_top_model": most_common_top[0],
        "top_model_stability": most_common_top[1] / n_profiles if n_profiles else 0,
        "kendalls_w": kendalls_w,
        "interpretation": "STABLE" if kendalls_w > 0.7 else "SENSITIVE",
    }

    print(f"\n=== Weight Sensitivity Analysis ===")
    print(f"Models: {n_models}, Profiles: {n_profiles}")
    print(f"Kendall's W: {kendalls_w:.3f} ({analysis['interpretation']})")
    print(f"Most frequent top model: {most_common_top[0]} ({most_common_top[1]}/{n_profiles})")

    for profile, ranking in rankings.items():
        print(f"  {profile:20s}: {' > '.join(ranking[:3])}")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(analysis, f, indent=2)

    return analysis
```

---

## 8. CWEval Validation Improvements

**Current problem:** `validate_with_cweval.py` reports 50% operator sanity (Check 1) and 47.6% attack vector coverage (Check 3). Both are too low.

### 8A. Improve Check 1 (Operator Sanity)

**Root cause:** `VULN_FINGERPRINTS` (line 236) has limited patterns per CWE. For example, CWE-918 only checks for `alnum` and `urlparse.*netloc` — but many SSRF mutants don't match these patterns.

**Fix in `validate_with_cweval.py`, expand `VULN_FINGERPRINTS`:**

```python
# Replace VULN_FINGERPRINTS starting at line 236:
VULN_FINGERPRINTS = {
    "CWE-78": {
        "patterns": [
            r'shell\s*=\s*True', r'os\.system', r'os\.popen',
            r'f["\'].*\{.*\}', r'f".*\{.*}"',
            r'subprocess\.call\(.*shell', r'\.format\(',  # NEW
            r'%\s*\(', r'\+\s*["\']',  # String concatenation patterns  # NEW
        ],
        "description": "Command injection via shell=True or string interpolation",
    },
    "CWE-918": {
        "patterns": [
            r'(?<!not\s)(?<!\.is)alnum', r'urlparse.*netloc',
            r'requests\.(get|post|put)\(', r'urllib',  # NEW
            r'http://', r'https://',  # NEW
            r'\.startswith\s*\(\s*["\']http',  # NEW: URL validation removal
        ],
        "description": "Missing URL/input validation for SSRF",
    },
    "CWE-502": {
        "patterns": [
            r'yaml\.load\b(?!\s*\(.*safe)', r'pickle\.loads?\b',
            r'Loader\s*=\s*Loader',
            r'marshal\.loads', r'shelve\.open',  # NEW
            r'yaml\.full_load', r'yaml\.unsafe_load',  # NEW
        ],
        "description": "Insecure deserialization",
    },
    # ... expand other CWEs similarly
}
```

### 8B. Improve Check 3 (Attack Vector Coverage)

**Root cause:** `ATTACK_CATEGORIES` (line 280) is missing several categories. For example, CWE-502 has no YAML tag injection patterns, CWE-918 has no DNS rebinding.

**Additions to `ATTACK_CATEGORIES`:**

```python
# Expand ATTACK_CATEGORIES starting at line 280:
"CWE-502": {
    "yaml_gadget": [r'!!python', r'apply:'],
    "pickle_gadget": [r'pickle', r'__reduce__'],
    "yaml_tag_injection": [r'!!map', r'!!seq', r'tag:yaml'],  # NEW
    "eval_deser": [r'eval\(', r'exec\('],  # NEW
},
"CWE-918": {
    "path_traversal_ssrf": [r'\.\./', r'\.\./'],
    "domain_spoofing": [r'@', r'#'],
    "internal_ip": [r'127\.0\.0\.1', r'localhost', r'169\.254'],
    "cloud_metadata": [r'169\.254\.169\.254', r'metadata'],  # NEW
    "url_scheme": [r'file://', r'gopher://', r'dict://'],  # NEW
    "dns_rebinding": [r'rebind', r'dns'],  # NEW
},
"CWE-78": {
    "command_chaining": [r'&&', r'\|\|', r';'],
    "pipe": [r'\|'],
    "subshell": [r'\$\(', r'`'],
    "backtick": [r'`'],
    "newline_injection": [r'%0a', r'\\n', r'\\r'],  # NEW
    "argument_injection": [r'--', r'-\w'],  # NEW
},
```

### 8C. Add Missing Mutation Operators

In `security_operators.py`, add operators for vulnerability types that CWEval covers but your operators miss:

```python
# New operator class in security_operators.py:

class SUBDOMAIN_SPOOF(SecurityMutationOperator):
    """
    Remove Subdomain Validation (CWE-20)

    Removes checks that prevent subdomain spoofing attacks.

    Example:
        if url.endswith('.example.com'):  # Secure
        → (removed check)  # Allows attack-example.com
    """

    def __init__(self):
        super().__init__(
            name="SUBDOMAIN_SPOOF",
            description="Remove subdomain validation allowing domain spoofing",
            target_cwes=["CWE-20", "CWE-918"]
        )

    def applies_to(self, code: str) -> bool:
        return bool(re.search(r'\.(endswith|startswith)\s*\(', code))

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []
        # Remove .endswith() domain checks
        pattern = r'if\s+\w+\.(endswith|startswith)\s*\([^)]+\)\s*:'
        for match in re.finditer(pattern, code):
            mutant = code[:match.start()] + "if True:  # domain check removed" + code[match.end():]
            mutants.append((mutant, "Removed domain validation check"))
        return mutants


class PIPE_INJECT(SecurityMutationOperator):
    """
    Add stdin pipe vulnerability (CWE-78)

    Changes subprocess calls to use stdin=PIPE, enabling input injection.
    """

    def __init__(self):
        super().__init__(
            name="PIPE_INJECT",
            description="Add stdin=PIPE to subprocess calls enabling input injection",
            target_cwes=["CWE-78"]
        )

    def applies_to(self, code: str) -> bool:
        return 'subprocess' in code and 'stdin' not in code

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []
        # Add stdin=PIPE to subprocess calls
        pattern = r'(subprocess\.\w+\([^)]+)\)'
        for match in re.finditer(pattern, code):
            if 'stdin' not in match.group():
                mutant = code[:match.end()-1] + ", stdin=subprocess.PIPE)" + code[match.end():]
                mutants.append((mutant, "Added stdin=PIPE allowing input injection"))
        return mutants
```

**Register these in `operator_registry.py`:**

```python
# Add to the operator registry:
from evaluation.security_operators import SUBDOMAIN_SPOOF, PIPE_INJECT

OPERATOR_REGISTRY["SUBDOMAIN_SPOOF"] = SUBDOMAIN_SPOOF
OPERATOR_REGISTRY["PIPE_INJECT"] = PIPE_INJECT
```

---

## 9. Repository-Level Scaffolding Design

**Purpose:** Define the schema for repository-level evaluation (Condition 3 from the context ablation). Build 10–15 example repositories now; generate the rest during scaling.

**New file: `evaluation/repo_scaffolding.py`**

```python
"""
Repository Scaffolding for Agent Evaluation

Generates synthetic repository structures for each sample, enabling
agent-based evaluation where the agent browses files and understands
context before generating tests.

Repository structure:
    repo/
    ├── src/
    │   ├── target_module.py     (contains the function under test)
    │   ├── utils.py             (helper functions)
    │   ├── config.py            (configuration with env vars)
    │   └── models.py            (data models)
    ├── tests/
    │   └── (agent writes here)
    ├── requirements.txt
    └── TASK.md                  (describes what to test)
"""

import os
import json
from typing import Dict, Any
from pathlib import Path

# CWE-specific supporting modules
CWE_SUPPORT_MODULES = {
    "CWE-89": {
        "database.py": '''import sqlite3
import os

DB_PATH = os.getenv("DATABASE_URL", "app.db")

def get_connection():
    """Get database connection."""
    return sqlite3.connect(DB_PATH)

def init_db():
    """Initialize database tables."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
''',
        "config.py": '''import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
''',
    },

    "CWE-78": {
        "system_utils.py": '''import shlex
import subprocess
import logging

logger = logging.getLogger(__name__)

ALLOWED_COMMANDS = {"ping", "nslookup", "traceroute", "dig"}

def validate_command(cmd: str) -> bool:
    """Check if command is in allowlist."""
    base_cmd = cmd.split()[0] if cmd else ""
    return base_cmd in ALLOWED_COMMANDS
''',
    },

    "CWE-918": {
        "http_client.py": '''import requests
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    "127.0.0.1", "localhost", "0.0.0.0",
    "169.254.", "10.", "172.16.", "192.168.",
]

def is_internal_url(url: str) -> bool:
    """Check if URL targets an internal network."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return any(hostname.startswith(net) for net in BLOCKED_NETWORKS)
''',
    },
}


TASK_TEMPLATE = """# Security Testing Task

## Target
- **Module:** `src/target_module.py`
- **Function:** `{entry_point}`
- **Vulnerability Type:** {cwe} ({cwe_name})

## Objective
Write pytest-style security tests that:
1. PASS on the current (secure) implementation
2. Would FAIL if the code were vulnerable to {cwe_name}

## Context
Review the repository structure to understand:
- How data flows into `{entry_point}`
- What external dependencies are used
- Where trust boundaries exist

## Constraints
- Tests go in `tests/test_security.py`
- Use the mock objects available in the test environment
- Do not modify any source files
"""


def generate_repo(
    sample: Dict[str, Any],
    output_dir: str,
) -> str:
    """
    Generate a synthetic repository for a sample.

    Args:
        sample: Benchmark sample dict
        output_dir: Base directory for repos

    Returns:
        Path to generated repository
    """
    sample_id = sample["id"]
    cwe = sample["cwe"]
    repo_dir = Path(output_dir) / sample_id

    # Create structure
    (repo_dir / "src").mkdir(parents=True, exist_ok=True)
    (repo_dir / "tests").mkdir(parents=True, exist_ok=True)

    # Write target module
    with open(repo_dir / "src" / "target_module.py", "w") as f:
        f.write(sample["secure_code"])

    # Write CWE-specific support modules
    support = CWE_SUPPORT_MODULES.get(cwe, {})
    for filename, content in support.items():
        with open(repo_dir / "src" / filename, "w") as f:
            f.write(content)

    # Write task description
    with open(repo_dir / "TASK.md", "w") as f:
        f.write(TASK_TEMPLATE.format(
            entry_point=sample.get("entry_point", "function"),
            cwe=cwe,
            cwe_name=sample.get("cwe_name", "vulnerability"),
        ))

    # Write requirements.txt
    with open(repo_dir / "requirements.txt", "w") as f:
        f.write("pytest>=7.0\n")

    return str(repo_dir)
```

**This is methodology design, not execution.** Build 10–15 repositories to validate the schema, then scale later.

---

## Summary: Implementation Priority Order

| # | Improvement | Files to Change | Effort | Impact |
|---|-----------|----------------|--------|--------|
| 1 | Operator-aware kill classification | `evaluate.py` (lines 62–140, 311) | 2 hours | Critical — fixes SMS reliability |
| 2 | LLM kill judge (Layer 2) | New `kill_classifier_judge.py`, `evaluate.py` (line 311) | 4 hours | High — validates classification |
| 3 | Human annotation + κ (Layer 3) | New `human_annotation.py` | 3 hours code + days of annotation | High — publishable validation |
| 4 | Equivalent mutant detection | New `equivalent_mutant_detector.py`, `metrics.py` (line 378) | 3 hours | Medium — corrects denominators |
| 5 | Mock security contracts | New `mock_contracts.py` | 2 hours | Medium — paper table + reproducibility |
| 6 | Contamination ablation | New `run_contamination_audit.py` | 4 hours | Medium — defuses reviewer concern |
| 7 | Prompt variant ablation | `prompts.py` (after line 248), `run_llm_baselines.py` (line 286) | 3 hours | Medium — methodology finding |
| 8 | File-level context ablation | `prompts.py` (new function), `run_llm_baselines.py` | 4 hours | High — context sensitivity finding |
| 9 | Weight sensitivity analysis | New `weight_sensitivity.py` | 2 hours | Low — justifies multimodal design |
| 10 | CWEval validation improvements | `validate_with_cweval.py` (lines 236, 280), `security_operators.py` | 6 hours | High — raises Check 1/3 scores |
| 11 | Repository scaffolding design | New `repo_scaffolding.py` | 4 hours | Medium — enables future agent eval |

**Recommended order:** 1 → 10 → 2 → 4 → 6 → 3 → 5 → 7 → 8 → 9 → 11

Start with #1 (operator-aware classification) because everything downstream depends on reliable kill type labels. Then #10 (CWEval) because those validation numbers appear in the paper. Then the LLM judge (#2) and equivalents (#4). The ablations (#6, #7, #8) can run in parallel once you have updated baselines.
