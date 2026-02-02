# SecMutBench Project Reflection

**Date:** January 6, 2026
**Purpose:** Honest assessment of project state and roadmap to a working benchmark

---

## 1. The Objective

**Goal:** Create a benchmark to evaluate LLM-generated security tests using mutation testing.

**Success Criteria:**
1. Samples have real, detectable vulnerabilities
2. Secure code actually fixes the vulnerability
3. Functional tests pass on BOTH versions
4. Security tests pass on secure, FAIL on insecure
5. Mutation operators can inject vulnerabilities into secure code
6. LLMs can be evaluated on their ability to generate effective tests

---

## 2. Current State Assessment

### 2.1 What We Have

| Component | Status | Quality |
|-----------|--------|---------|
| Template Generator | Built | Good structure |
| 35 Template Samples | Built | **Broken** - 32/35 fail runtime |
| Mock Objects | Built | Functional |
| Mutation Operators (16) | Built | Untested on working samples |
| Validation Pipeline | Built | Working - surfaced issues |
| Bandit Integration | Built | Working |
| LLM-as-Judge | Built | Untested on working samples |
| Human Review System | Built | Working |

### 2.2 Validation Results Summary

| Validation Type | Result |
|-----------------|--------|
| **Static checks** | 35/35 pass |
| **Runtime tests** | 3/35 pass (CWE-327 only) |
| **Bandit detection** | 21/35 vulnerabilities detectable |

### 2.3 Issues by CWE

| CWE | Samples | Runtime | Bandit | Status |
|-----|---------|---------|--------|--------|
| CWE-89 (SQL Injection) | 10 | FAIL | Detected | Tests broken |
| CWE-78 (Command Injection) | 8 | FAIL | Detected | Security tests don't detect |
| CWE-22 (Path Traversal) | 4 | FAIL | Not detected | Tests broken |
| CWE-79 (XSS) | 4 | FAIL | Not detected | Tests broken |
| CWE-502 (Deserialization) | 3 | FAIL | Detected | Tests broken |
| CWE-327 (Weak Crypto) | 3 | **PASS** | Not detected | **Working** |
| CWE-798 (Hardcoded Creds) | 3 | FAIL | Not detected | Tests broken |

---

## 3. Root Cause Analysis

### 3.1 Why Runtime Tests Fail

**Primary Issue:** Template functional tests reference mock objects that don't exist or behave differently than expected.

**Example (CWE-89):**
```python
# Template test expects:
db.add_row("users", {"name": "test_value", "id": 1})
result = get_user("test_value")
assert result is not None

# But MockDatabase.execute() returns results differently
# Test fails because assertion doesn't match mock behavior
```

### 3.2 Why Security Tests Don't Detect Vulnerabilities (CWE-78)

**Issue:** Security tests for command injection check output, not whether injection occurred.

```python
# Current test (doesn't work):
result = ping_host("; rm -rf /")
assert "error" in result  # Doesn't verify injection was prevented

# Should test:
result = ping_host("; rm -rf /")
assert ";" not in last_executed_command  # Verify injection blocked
```

### 3.3 Why Bandit Doesn't Detect Some CWEs

| CWE | Why Not Detected |
|-----|------------------|
| CWE-22 | Path traversal patterns need context Bandit lacks |
| CWE-79 | XSS is output context-dependent |
| CWE-327 | Our patterns use hashlib which Bandit treats carefully |
| CWE-798 | Hardcoded values in test code look like constants |

---

## 4. Gap Analysis

### 4.1 Infrastructure vs Content

```
INFRASTRUCTURE (what we built):
├── Template generator structure     ✅
├── Mock objects                     ✅
├── Test runner                      ✅
├── Mutation engine                  ✅
├── Validation pipeline              ✅
├── Bandit integration               ✅
└── LLM-as-Judge                     ✅

CONTENT (what we need):
├── Working samples                  ❌ (3/35 work)
├── Validated secure/insecure pairs  ❌
├── Effective security tests         ❌
└── Tested mutation operators        ❌
```

### 4.2 What's Missing for a Real Benchmark

1. **Working samples** - Currently 91% (32/35) are broken
2. **Validation that samples detect vulnerabilities** - Not just pass tests
3. **Mutation operator validation** - Do operators actually inject vulnerabilities?
4. **End-to-end test** - Can the full pipeline evaluate an LLM?

---

## 5. Recommended Next Steps

### Phase 1: Fix Existing Samples (Priority: CRITICAL)

**Goal:** Get all 35 samples to pass runtime validation

| Task | Effort | Impact |
|------|--------|--------|
| Fix CWE-327 functional tests (already working) | - | Reference |
| Fix CWE-89 mock/test mismatch | Medium | 10 samples |
| Fix CWE-78 security tests | High | 8 samples |
| Fix CWE-22 path handling | Medium | 4 samples |
| Fix CWE-79 HTML escaping | Medium | 4 samples |
| Fix CWE-502 deserialization | Medium | 3 samples |
| Fix CWE-798 credential tests | Medium | 3 samples |

**Approach:**
1. Study why CWE-327 works (it's the only passing CWE)
2. Apply same patterns to other CWEs
3. Run validation after each fix
4. Target: 35/35 samples at LOW priority

### Phase 2: Validate Mutation Operators

**Goal:** Verify mutation operators inject real vulnerabilities

| Task | Description |
|------|-------------|
| Test PSQLI | Does it convert parameterized to injectable? |
| Test CMDINJECT | Does it enable command injection? |
| Test each operator | On a working sample, inject, run tests |

### Phase 3: End-to-End Pipeline Test

**Goal:** Run full evaluation on a small set

1. Take 5 working samples
2. Generate tests with an LLM (GPT-4, Claude)
3. Run mutation testing on generated tests
4. Verify metrics make sense

### Phase 4: Scale Up

**Goal:** Reach target of 155 samples

1. Add more template variants
2. Import from SecurityEval/CyberSecEval (with validation)
3. Add missing CWEs

---

## 6. Definition of Done

**The benchmark is ready when:**

- [ ] All samples pass runtime validation (functional tests pass, security tests distinguish)
- [ ] Bandit detects vulnerabilities where applicable (or documented why not)
- [ ] Mutation operators demonstrably inject vulnerabilities
- [ ] At least one LLM has been evaluated end-to-end
- [ ] Results are reproducible
- [ ] Documentation explains how to use the benchmark

---

## 7. Honest Assessment

### What Went Wrong

1. **Built infrastructure before validating content** - We have a sophisticated pipeline but broken samples
2. **Assumed templates would work** - "template-generated, verified" was aspirational, not true
3. **Didn't run runtime tests early** - Static validation passed, hid real issues

### What Went Right

1. **Validation pipeline works** - It correctly identified broken samples
2. **Human review system** - Prioritizes what to fix
3. **Bandit integration** - Provides additional validation dimension
4. **Mock objects are comprehensive** - Just need test alignment

### Key Insight

> **A benchmark with broken samples is not a benchmark. Fix the content before adding features.**

---

## 8. Immediate Action Items

1. **TODAY:** Investigate why CWE-327 works, document the pattern
2. **NEXT:** Fix CWE-89 samples (largest group, 10 samples)
3. **THEN:** Fix CWE-78 security tests (critical - tests don't detect)
4. **VALIDATION:** After each fix, run: `python scripts/validate.py --samples data/samples_template.json --add-review-status data/samples_with_review.json --bandit`

---

*This reflection is an honest assessment intended to guide development toward a working, useful benchmark.*
