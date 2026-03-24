# Datasheet for SecMutBench

Following the framework proposed by Gebru et al. (2021) in "Datasheets for Datasets."

**Version:** 2.8.0

## Motivation

### For what purpose was the dataset created?

SecMutBench was created to evaluate whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

### Who created the dataset and on behalf of which entity?

The SecMutBench Team created this dataset for academic research purposes.

### Who funded the creation of the dataset?

[To be specified by authors]

## Composition

### What do the instances that comprise the dataset represent?

Each instance represents a security-relevant code sample containing:
- **Secure code**: A correctly implemented function that handles security properly
- **Insecure code**: A vulnerable version with a specific security flaw
- **Reference security tests**: pytest-style tests that detect the vulnerability
- **Functional tests**: Tests verifying basic functionality
- **Pre-generated mutants**: 4-9 mutants per sample with operator and category labels
- **Metadata**: CWE type, difficulty level, entry point, source type, mutation operators

### How many instances are there in total?

339 samples distributed across:
- **By difficulty**: Easy (136), Medium (101), Hard (102)
- **By source**: SecMutBench originals (75), CWEval (3), SecurityEval (3), LLM_Variation (258)
- **By CWE**: 30 different vulnerability types
- **Pre-generated mutants**: 1,869 total (avg 5.5/sample)
- **Mutant categories**: CWE-specific (1,252, 67%), Generic (617, 33%)

### Does the dataset contain all possible instances or is it a sample?

The dataset is a curated sample covering 30 major vulnerability categories. It is not exhaustive of all possible security vulnerabilities.

### What data does each instance consist of?

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique identifier (SHA-based hash) |
| cwe | string | CWE identifier (e.g., CWE-89) |
| cwe_name | string | Vulnerability name (e.g., SQL Injection) |
| difficulty | string | easy, medium, or hard (complexity-based) |
| source_type | string | SecMutBench, CWEval, SecurityEval, or LLM_Variation |
| secure_code | string | Python code - secure version |
| insecure_code | string | Python code - vulnerable version |
| security_tests | string | pytest tests for vulnerability detection |
| functional_tests | string | pytest tests for functionality |
| entry_point | string | Main function to test |
| mutation_operators | array | Applicable mutation operator names |
| mutants | array | Pre-generated mutant objects with id, operator, description, mutated_code, mutant_category |
| source | string | Sample origin identifier |

### Is there a label or target associated with each instance?

Yes, each instance has:
- CWE classification (vulnerability type label)
- Difficulty level (complexity-based: easy, medium, hard)
- Reference tests (ground truth for evaluation)
- Pre-generated mutants (ground truth for mutation testing)

### Is any information missing from individual instances?

Some instances may have empty `functional_tests` if they focus solely on security testing.

### Are relationships between individual instances made explicit?

Instances are grouped by:
- CWE type (same vulnerability category)
- Difficulty level
- Source type (original vs. variation)
- LLM_Variation samples are derived from original samples (parent-child relationship via code transformation)

### Are there recommended data splits?

Yes, predefined splits by difficulty:
- `data/splits/easy.json` (136 samples)
- `data/splits/medium.json` (101 samples)
- `data/splits/hard.json` (102 samples)

### Are there any errors, sources of noise, or redundancies?

- All samples validated for Python syntax correctness (100% compilability)
- Zero cross-contamination between secure code and mutants
- Structural deduplication applied (max 2 per structural pattern)
- LLM variations maintain semantic equivalence with originals

### Is the dataset self-contained?

Yes, all code samples, tests, and mutants are included in the JSON files. No external dependencies for the data itself. Evaluation requires Python packages listed in requirements.txt.

### Does the dataset contain data that might be considered confidential?

No. All samples are synthetic code examples created for security testing evaluation.

### Does the dataset contain data that might be considered offensive?

No. The dataset contains technical code samples only.

## Collection Process

### How was the data associated with each instance acquired?

Four sources:
1. **SecMutBench originals (75 samples)**: Originally authored security code pairs
2. **CWEval (3 samples)**: Adapted from the CWEval benchmark (contributed 3 new CWEs: CWE-326, CWE-347, CWE-643)
3. **SecurityEval (3 samples)**: Adapted from s2e-lab/SecurityEval on HuggingFace
4. **LLM_Variation (258 samples)**: Generated via LLM-based semantic-preserving code transformations from the 81 original samples

### What mechanisms or procedures were used to collect the data?

1. Original samples authored following CWE specifications
2. Public datasets downloaded via HuggingFace datasets library
3. Transformation pipeline to convert to SecMutBench format
4. LLM variation pipeline generates 3-4 variations per original sample
5. Validation to ensure compilability, vulnerability detection, and zero cross-contamination
6. Pre-generated mutants stored with each sample for deterministic evaluation

### If the dataset is a sample from a larger set, what was the sampling strategy?

- SecurityEval/CWEval: Python samples with supported CWE types
- Filtered for syntax validity and CWE coverage
- LLM variations: Semantic-preserving transformations validated for compilability

### Who was involved in the data collection process?

SecMutBench Team (researchers) using automated collection, transformation, and variation generation scripts.

### Over what timeframe was the data collected?

2024-2026

### Were any ethical review processes conducted?

The dataset contains only synthetic code samples with no personal or sensitive data.

## Preprocessing/Cleaning/Labeling

### Was any preprocessing/cleaning/labeling of the data done?

Yes:
1. **Syntax validation**: All code samples verified to compile (100%)
2. **CWE mapping**: Standardized CWE identifiers across sources
3. **Difficulty assignment**: Based on cyclomatic complexity and code metrics
4. **Test generation**: Reference tests created for each sample
5. **Mutant generation**: 25 security operators generate 4-9 mutants per sample
6. **Mutant categorization**: Each mutant labeled as `cwe_specific` or `generic`
7. **Structural deduplication**: Max 2 samples per structural code pattern
8. **Cross-contamination check**: Ensures mutant code never appears in secure code

### Was the "raw" data saved in addition to the preprocessed/cleaned/labeled data?

Yes:
- `data/raw/` contains raw source files
- `data/variations*.json` contains LLM variation intermediates

### Is the software that was used to preprocess/clean/label the data available?

Yes, in the `scripts/` directory:
- `dataset_builder.py` — Main orchestrator
- `sample_generator.py` — Sample generation
- `source_ingestion.py` / `source_handlers.py` — Source processing
- `generate_variations.py` — LLM variation pipeline
- `validate_dataset_quality.py` — Quality validation

## Uses

### Has the dataset been used for any tasks already?

The dataset is designed for:
- Evaluating LLM-generated security tests
- Measuring mutation score and vulnerability detection rate
- Comparing security test generation approaches
- LLM-as-Judge evaluation of test quality and security relevance

### Is there a repository that links to any or all papers or systems that use the dataset?

[To be updated with publications]

### What (other) tasks could the dataset be used for?

- Training models for security test generation
- Studying vulnerability patterns across 30 CWE types
- Benchmarking static analysis tools (Bandit, Semgrep)
- Educational purposes in security testing
- Evaluating mutation testing techniques

### Is there anything about the composition or collection that might impact future uses?

- Python-only: Results may not generalize to other languages
- 30 CWE types covered, not all vulnerability categories
- Web/application focus: May not cover embedded/IoT security
- LLM variations may share structural patterns with originals

### Are there tasks for which the dataset should not be used?

- Should not be used to create actual malware
- Not suitable for production security scanning without validation
- Not a substitute for comprehensive security audits

## Distribution

### Will the dataset be distributed to third parties outside of the entity?

Yes, the dataset is publicly available under MIT License.

### How will the dataset be distributed?

- [GitHub repository](https://github.com/Mars-2030/secmutbench)
- [HuggingFace Datasets](https://huggingface.co/datasets/Mars203020/secmutbench)

### When will the dataset be distributed?

Available now.

### Will the dataset be distributed under a copyright or intellectual property license?

MIT License

### Have any third parties imposed IP-based or other restrictions?

- SecurityEval: Apache 2.0 License
- CWEval: MIT License

## Maintenance

### Who will be supporting/hosting/maintaining the dataset?

SecMutBench Team via GitHub repository.

### How can the owner/curator/manager of the dataset be contacted?

Via GitHub issues or repository contact information.

### Is there an erratum?

Will be maintained in GitHub repository CHANGELOG.

### Will the dataset be updated?

Yes, planned updates include:
- Additional samples and CWE types
- Multi-language support (Java, JavaScript)
- Enhanced mutant generation strategies

### If others want to extend/augment/build on/contribute to the dataset, is there a mechanism?

Yes, via GitHub pull requests. Contribution guidelines in CONTRIBUTING.md.

### Will older versions of the dataset continue to be supported?

Yes, via Git tags and releases. The original dataset (v2.6.2) remains available at `data/dataset.json`.

---

## Submission

Submitted to [ACM AIWare 2026 — Benchmark and Dataset Track](https://2026.aiwareconf.org/track/aiware-2026-benchmark---dataset-track). Paper under review. Author names withheld for double-blind review.

## References

Gebru, T., Morgenstern, J., Vecchione, B., Vaughan, J. W., Wallach, H., Daume III, H., & Crawford, K. (2021). Datasheets for datasets. Communications of the ACM, 64(12), 86-92.
