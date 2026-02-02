# SecMutBench Multi-Source Dataset Generator Plan

**Version:** 2.0
**Date:** 2026-01-06
**Status:** Implementation In Progress

---

## Quick Summary

**Goal:** Generate 300 security samples using Template-with-Research approach

**Key Files to Create:**
1. `scripts/cwe_research.py` - Fetch CWE pages from mitre.org
2. `scripts/source_handlers.py` - Load SecurityEval, CyberSecEval, OWASP
3. `scripts/generate_dataset.py` - Main generator with 7-step workflow
4. `data/dataset.json` - Output (300 samples)

**Workflow:**
```
1. PICK CWE (OWASP Top 10 + CWE Top 25 priority)
2. READ CWE PAGE (mitre.org - description, mitigations)
3. FIND EXAMPLES (templates + SecurityEval + CyberSecEval)
4. WRITE INSECURE (adapt vulnerable patterns)
5. WRITE SECURE (apply CWE mitigations)
6. WRITE TESTS (OWASP attack payloads)
7. VALIDATE (only validation, not full evaluation)
```

**Run Commands:**
```bash
python scripts/generate_dataset.py --output data/dataset.json --samples 300
python scripts/validate.py --samples data/dataset.json --add-review-status data/dataset_validated.json
```

---

## Reflection: Current State Analysis

### Generation Pipeline - CRITICAL GAPS

| Component | Desired | Current State | Gap Level |
|-----------|---------|---------------|-----------|
| CWE Research | Fetch from mitre.org | Static markdown docs only | **MISSING** |
| SecurityEval | Extract real examples | Downloaded but NOT used | **MISSING** |
| CyberSecEval | Extract real examples | Downloaded but NOT used | **MISSING** |
| OWASP Payloads | Dynamic fetch | Hardcoded in `payloads.json` | **PARTIAL** |
| CVE Descriptions | Research source | Not implemented | **MISSING** |
| Snyk Database | Research source | Not implemented | **MISSING** |
| GitHub Advisories | Research source | Not implemented | **MISSING** |
| CodeQL Examples | Research source | Not implemented | **MISSING** |
| Sample Count | 300 balanced | ~30 hardcoded templates | **INSUFFICIENT** |

**Current Workflow:**
```
1. SELECT from hardcoded dictionary (CWE89_SAMPLES, etc.)
2. [SKIP CWE research] - only static docs exist
3. [SKIP real examples] - payloads hardcoded
4. [HARDCODED] insecure code
5. [HARDCODED] secure code
6. [HARDCODED] tests
7. Run validation
```

**Desired Workflow:**
```
1. PICK A CWE
2. READ THE CWE PAGE from cwe.mitre.org/data/definitions/[NUMBER].html
   └── Extract: Description, Examples, Mitigations
3. FIND REAL EXAMPLES
   └── SecurityEval, CyberSecEval, OWASP, CVE, Snyk, GitHub, CodeQL
4. WRITE INSECURE VERSION (based on vulnerable patterns)
5. WRITE SECURE VERSION (apply mitigations from CWE page)
6. WRITE TESTS (OWASP attack payloads)
7. VALIDATE
```

### Validation Pipeline - MOSTLY COMPLETE

| Component | Status | Notes |
|-----------|--------|-------|
| Static validation | Working | 11 required fields, syntax, format |
| Runtime validation | Disabled | Exists but commented out (slow) |
| Contamination prevention | Working | Perturbation, temporal filter, n-gram audit |
| Bandit integration | Working | Optional static analysis |
| Quality management | Working | Quality tiers, deduplication |

---

## Implementation Plan

### Phase 1: Create CWE Research Infrastructure

**File: `scripts/cwe_research.py`** (CREATED)

```python
# Fetches and parses CWE pages from mitre.org
class CWEResearcher:
    def fetch_cwe(cwe_id: str) -> CWEInfo:
        # GET https://cwe.mitre.org/data/definitions/{id}.html
        # Parse: description, examples, mitigations, related CWEs

    def get_attack_patterns(cwe_id: str) -> List[str]:
        # Extract attack patterns and payloads
```

### Phase 2: Create Multi-Source Handler (Web Scraping, No APIs)

**File: `scripts/source_handlers.py`**

```python
class SecurityEvalHandler:
    """Load from downloaded HuggingFace dataset (already in data/)"""
    def load_samples() -> List[Sample]
    def extract_by_cwe(cwe_id: str) -> List[Sample]

class CyberSecEvalHandler:
    """Load from downloaded Meta dataset (already in data/)"""
    def load_samples() -> List[Sample]
    def extract_by_cwe(cwe_id: str) -> List[Sample]

class OWASPHandler:
    """Web scrape OWASP Testing Guide for payloads"""
    def get_payloads(cwe_id: str) -> List[str]
    # Scrape: https://owasp.org/www-project-web-security-testing-guide/
    def get_mitigations(cwe_id: str) -> List[str]

class WebSearchHandler:
    """Use web search to find CVE examples (no API keys)"""
    def search_cve_examples(cwe_id: str) -> List[str]
    # Search: "CWE-89 python example site:github.com"
    def search_vulnerability_writeups(cwe_id: str) -> List[str]

class CodeQLHandler:
    """Scrape CodeQL queries from public GitHub repo"""
    def get_query_examples(cwe_id: str) -> List[str]
    # Fetch from: github.com/github/codeql/tree/main/python/ql/src/Security
```

### Phase 3: Create Template-with-Research Generator

**File: `scripts/generate_dataset.py`** (NEW main generator)

**Approach: Template with Research** - Use existing templates, enrich with CWE research

```python
class TemplateWithResearchGenerator:
    """
    7-step workflow with template base:
    1. Pick CWE (from priority list)
    2. Read CWE page (fetch description, mitigations)
    3. Find real examples (existing templates + SecurityEval + CyberSecEval)
    4. Write insecure version (adapt templates with CWE patterns)
    5. Write secure version (apply mitigations from CWE page)
    6. Write tests (OWASP attack payloads)
    7. Validate
    """

    def generate_for_cwe(cwe_id: str, target_count: int) -> List[Sample]:
        # Step 1-2: Research CWE from mitre.org
        cwe_info = self.cwe_researcher.fetch_cwe(cwe_id)

        samples = []

        # Step 3a: Start with existing templates (highest quality)
        templates = self.load_existing_templates(cwe_id)  # From generate_samples.py
        for template in templates:
            sample = self.enrich_template(template, cwe_info)
            samples.append(sample)

        # Step 3b: Add samples from SecurityEval/CyberSecEval
        external = self.securityeval.extract_by_cwe(cwe_id)
        external += self.cyberseceval.extract_by_cwe(cwe_id)

        for ext_sample in external:
            # Step 4-5: Adapt external sample with CWE mitigations
            adapted = self.adapt_external_sample(ext_sample, cwe_info)
            samples.append(adapted)

        # Step 3c: Generate new variants if needed to reach target
        while len(samples) < target_count:
            variant = self.generate_variant(cwe_id, cwe_info, samples)
            samples.append(variant)

        # Step 6: Enrich all samples with OWASP payloads
        payloads = self.owasp.get_payloads(cwe_id)
        for sample in samples:
            sample.security_tests = self.generate_tests(sample, payloads)

        # Step 7: Validate each sample
        valid_samples = [s for s in samples if self.validator.validate(s)]

        return valid_samples[:target_count]

    def generate_dataset(priority_distribution: Dict[str, int]) -> List[Sample]:
        """Generate 300 samples based on CWE priority distribution."""
        all_samples = []

        for cwe_id, count in priority_distribution.items():
            samples = self.generate_for_cwe(cwe_id, count)
            all_samples.extend(samples)

        # Apply contamination prevention
        processor = ContaminationPreventionProcessor()
        clean_samples = processor.process(all_samples)

        return clean_samples
```

### Phase 4: CWE Coverage Expansion

**Target CWEs (22 categories):**

| CWE | Name | Sources |
|-----|------|---------|
| CWE-89 | SQL Injection | SecurityEval, OWASP, CVE |
| CWE-78 | OS Command Injection | SecurityEval, OWASP |
| CWE-22 | Path Traversal | SecurityEval, OWASP |
| CWE-79 | XSS | SecurityEval, OWASP |
| CWE-502 | Insecure Deserialization | CyberSecEval |
| CWE-327 | Weak Cryptography | CyberSecEval |
| CWE-798 | Hardcoded Credentials | Snyk, GitHub |
| CWE-20 | Input Validation | OWASP |
| CWE-287 | Authentication Bypass | CyberSecEval |
| CWE-611 | XXE | OWASP, CodeQL |
| CWE-918 | SSRF | OWASP |
| CWE-352 | CSRF | OWASP |
| CWE-284 | Access Control | CyberSecEval |
| CWE-319 | Cleartext Transmission | Snyk |
| CWE-94 | Code Injection | SecurityEval |
| CWE-1336 | SSTI | CodeQL |
| CWE-942 | Permissive CORS | OWASP |
| CWE-306 | Missing Authentication | CyberSecEval |
| CWE-338 | Weak PRNG | SecurityEval |
| CWE-295 | Certificate Validation | Snyk |
| CWE-312 | Cleartext Storage | GitHub Advisories |
| CWE-639 | IDOR | OWASP |

**Target Distribution (300 samples):**
- ~14 samples per CWE (300 / 22 = 14)
- Difficulty: 30% easy, 50% medium, 20% hard

### Phase 5: Output

**File: `data/dataset.json`**

```json
{
  "metadata": {
    "version": "2.0",
    "generated": "2026-01-06",
    "total_samples": 300,
    "sources": ["SecurityEval", "CyberSecEval", "OWASP", "CVE", "Snyk", "GitHub", "CodeQL"],
    "contamination_prevention": true
  },
  "samples": [...]
}
```

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `scripts/cwe_research.py` | CREATED | CWE page fetching from mitre.org |
| `scripts/source_handlers.py` | CREATE | Multi-source handlers |
| `scripts/generate_dataset.py` | CREATE | Research-driven generator |
| `data/dataset.json` | CREATE | Output file (300 samples) |
| `scripts/contamination_prevention.py` | KEEP | Already implemented |
| `scripts/validate.py` | KEEP | Already implemented |

---

## Execution Plan

```bash
# Step 1: Generate dataset with research workflow
python scripts/generate_dataset.py \
    --output data/dataset.json \
    --samples 300 \
    --contamination-prevention \
    --sources securityeval,cyberseceval,owasp,cve,snyk,github,codeql

# Step 2: Run validation ONLY (not full evaluation)
python scripts/validate.py \
    --samples data/dataset.json \
    --add-review-status data/dataset_validated.json \
    --bandit
```

---

## User Preferences (Confirmed)

1. **Data Sources:** Use internet search/web scraping (not paid APIs)
   - Fetch CWE pages from mitre.org
   - Web search for examples instead of API calls
   - Use downloaded datasets (SecurityEval, CyberSecEval)

2. **CWE Distribution:** Based on:
   - OWASP Top 10 (2021)
   - CWE Top 25 (2025): https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
   - CWEs from evaluation datasets (SecurityEval, CyberSecEval)

3. **Approach:** Template with Research
   - Use existing templates as base
   - Enrich with CWE page mitigations
   - Add OWASP attack payloads
   - Faster than full research, higher quality than quick generation

---

## Updated CWE Priority List

### Tier 1: OWASP Top 10 + CWE Top 25 (2025) - Most Samples
| CWE | Name | Priority | Samples |
|-----|------|----------|---------|
| CWE-79 | XSS | Critical | 25 |
| CWE-89 | SQL Injection | Critical | 25 |
| CWE-78 | OS Command Injection | Critical | 20 |
| CWE-22 | Path Traversal | High | 20 |
| CWE-287 | Authentication Bypass | High | 15 |
| CWE-798 | Hardcoded Credentials | High | 15 |
| CWE-502 | Insecure Deserialization | High | 15 |
| CWE-20 | Input Validation | High | 15 |

### Tier 2: From Evaluation Datasets - Medium Samples
| CWE | Name | Priority | Samples |
|-----|------|----------|---------|
| CWE-327 | Weak Cryptography | Medium | 15 |
| CWE-352 | CSRF | Medium | 15 |
| CWE-611 | XXE | Medium | 15 |
| CWE-918 | SSRF | Medium | 15 |
| CWE-94 | Code Injection | Medium | 10 |
| CWE-306 | Missing Authentication | Medium | 10 |

### Tier 3: Additional Coverage - Fewer Samples
| CWE | Name | Priority | Samples |
|-----|------|----------|---------|
| CWE-284 | Access Control | Low | 10 |
| CWE-319 | Cleartext Transmission | Low | 10 |
| CWE-338 | Weak PRNG | Low | 10 |
| CWE-942 | Permissive CORS | Low | 10 |
| CWE-1336 | SSTI | Low | 10 |
| CWE-639 | IDOR | Low | 10 |
| CWE-295 | Certificate Validation | Low | 5 |
| CWE-312 | Cleartext Storage | Low | 5 |

**Total: ~300 samples**

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | 2026-01-06 | Multi-source dataset generator with research workflow |
| 1.0 | 2026-01-06 | Initial evaluation summary (27 samples) |
