# Datasheet for SecMutBench

Following the framework proposed by Gebru et al. (2021) in "Datasheets for Datasets."

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
- **Metadata**: CWE type, difficulty level, entry point, source

### How many instances are there in total?

180 samples distributed across:
- **By difficulty**: Easy (37), Medium (98), Hard (45)
- **By source**: SecMutBench (26), SecurityEval (118), CyberSecEval (36)
- **By CWE**: 78 different vulnerability types

### Does the dataset contain all possible instances or is it a sample?

The dataset is a curated sample covering major vulnerability categories. It is not exhaustive of all possible security vulnerabilities.

### What data does each instance consist of?

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique identifier |
| cwe | string | CWE identifier (e.g., CWE-89) |
| cwe_name | string | Vulnerability name (e.g., SQL Injection) |
| difficulty | string | easy, medium, or hard |
| secure_code | string | Python code - secure version |
| insecure_code | string | Python code - vulnerable version |
| security_tests | string | pytest tests for vulnerability detection |
| functional_tests | string | pytest tests for functionality |
| entry_point | string | Main function to test |
| source | string | Sample origin |
| mutation_operators | array | Applicable mutation operators |

### Is there a label or target associated with each instance?

Yes, each instance has:
- CWE classification (vulnerability type label)
- Difficulty level
- Reference tests (ground truth for evaluation)

### Is any information missing from individual instances?

Some instances may have empty `functional_tests` if they focus solely on security testing.

### Are relationships between individual instances made explicit?

Instances are grouped by:
- CWE type (same vulnerability category)
- Difficulty level
- Source dataset

### Are there recommended data splits?

Yes, predefined splits by difficulty:
- `data/splits/easy.json` (37 samples)
- `data/splits/medium.json` (98 samples)
- `data/splits/hard.json` (45 samples)

### Are there any errors, sources of noise, or redundancies?

- All samples validated for Python syntax correctness
- Some adapted samples may have simplified code structures
- Perturbation pipeline applied to reduce training data contamination

### Is the dataset self-contained?

Yes, all code samples and tests are included in the JSON files. No external dependencies for the data itself. Evaluation requires Python packages listed in requirements.txt.

### Does the dataset contain data that might be considered confidential?

No. All samples are synthetic code examples created for security testing evaluation.

### Does the dataset contain data that might be considered offensive?

No. The dataset contains technical code samples only.

## Collection Process

### How was the data associated with each instance acquired?

Three sources:
1. **SecMutBench (26 samples)**: Originally authored security code pairs
2. **SecurityEval (118 samples)**: Adapted from s2e-lab/SecurityEval on HuggingFace
3. **CyberSecEval (36 samples)**: Adapted from Meta's PurpleLlama/CyberSecEval

### What mechanisms or procedures were used to collect the data?

1. Original samples authored following CWE specifications
2. Public datasets downloaded via HuggingFace datasets library
3. Transformation pipeline to convert to SecMutBench format
4. Validation to ensure syntax correctness and security test quality

### If the dataset is a sample from a larger set, what was the sampling strategy?

- SecurityEval: Python samples with supported CWE types
- CyberSecEval: Python samples from instruct variant
- Filtered for syntax validity and CWE coverage

### Who was involved in the data collection process?

SecMutBench Team (researchers) using automated collection and transformation scripts.

### Over what timeframe was the data collected?

2024-2025

### Were any ethical review processes conducted?

The dataset contains only synthetic code samples with no personal or sensitive data.

## Preprocessing/Cleaning/Labeling

### Was any preprocessing/cleaning/labeling of the data done?

Yes:
1. **Syntax validation**: All code samples verified to compile
2. **CWE mapping**: Standardized CWE identifiers across sources
3. **Difficulty assignment**: Based on code complexity metrics
4. **Test generation**: Reference tests created for each sample
5. **Perturbation**: Adapted samples modified to prevent contamination

### Was the "raw" data saved in addition to the preprocessed/cleaned/labeled data?

Yes:
- `data/raw/securityeval_raw.json`
- `data/raw/cyberseceval_raw.json`

### Is the software that was used to preprocess/clean/label the data available?

Yes, in the `scripts/` directory:
- `transform_datasets.py`
- `validate.py`
- `contamination_prevention.py`
- `rebuild_dataset.py`

## Uses

### Has the dataset been used for any tasks already?

The dataset is designed for:
- Evaluating LLM-generated security tests
- Measuring mutation score and vulnerability detection rate
- Comparing security test generation approaches

### Is there a repository that links to any or all papers or systems that use the dataset?

[To be updated with publications]

### What (other) tasks could the dataset be used for?

- Training models for security test generation
- Studying vulnerability patterns
- Benchmarking static analysis tools
- Educational purposes in security testing

### Is there anything about the composition or collection that might impact future uses?

- Python-only: Results may not generalize to other languages
- CWE subset: 78 types covered, not all vulnerability categories
- Web/application focus: May not cover embedded/IoT security

### Are there tasks for which the dataset should not be used?

- Should not be used to create actual malware
- Not suitable for production security scanning without validation
- Not a substitute for comprehensive security audits

## Distribution

### Will the dataset be distributed to third parties outside of the entity?

Yes, the dataset is publicly available under MIT License.

### How will the dataset be distributed?

- GitHub repository
- HuggingFace datasets (planned)

### When will the dataset be distributed?

Available upon publication.

### Will the dataset be distributed under a copyright or intellectual property license?

MIT License

### Have any third parties imposed IP-based or other restrictions?

- SecurityEval: Apache 2.0 License
- CyberSecEval: MIT License

## Maintenance

### Who will be supporting/hosting/maintaining the dataset?

SecMutBench Team via GitHub repository.

### How can the owner/curator/manager of the dataset be contacted?

Via GitHub issues or repository contact information.

### Is there an erratum?

Will be maintained in GitHub repository CHANGELOG.

### Will the dataset be updated?

Yes, planned updates include:
- Additional samples
- New CWE types
- Multi-language support

### If others want to extend/augment/build on/contribute to the dataset, is there a mechanism?

Yes, via GitHub pull requests. Contribution guidelines in CONTRIBUTING.md.

### Will older versions of the dataset continue to be supported?

Yes, via Git tags and releases.

---

## Citation

```bibtex
@inproceedings{secmutbench2025,
  title={SecMutBench: A Benchmark for Evaluating LLM Security Test Generation via Mutation Testing},
  author={SecMutBench Team},
  booktitle={Proceedings},
  year={2025}
}
```

## References

Gebru, T., Morgenstern, J., Vecchione, B., Vaughan, J. W., Wallach, H., Daumé III, H., & Crawford, K. (2021). Datasheets for datasets. Communications of the ACM, 64(12), 86-92.
