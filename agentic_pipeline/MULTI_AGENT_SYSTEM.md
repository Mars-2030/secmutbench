# SecMutBench Multi-Agent System

## Overview

A long-running, multi-agent system for Claude Code that autonomously:
1. **Improves** SecMutBench (fixes bugs, expands dataset)
2. **Runs** experiments (multi-model evaluation)
3. **Analyzes** results (statistical analysis, reporting)
4. **Provides Feedback** (reviews results and improves dataset) - **NEW**

**Status: FULLY INTEGRATED** - All sub-agents use the real SecMutBench evaluation code with a feedback loop for continuous improvement.

## Integration Status

| Component | Status | Description |
|-----------|--------|-------------|
| SecMutBench Evaluation | **INTEGRATED** | Uses real `evaluation.evaluate` module |
| Mutation Engine | **INTEGRATED** | Uses real `MutationEngine` class |
| Test Runner | **INTEGRATED** | Uses real `TestRunner` class |
| LLM Judge | **INTEGRATED** | Uses real `llm_judge` module |
| Dataset Builder | **INTEGRATED** | Uses `rebuild_dataset.py` |
| Sample Validator | **INTEGRATED** | Pre-checks samples before evaluation |
| Attack Vectors | **INTEGRATED** | CWE-specific coverage checking |
| Feedback Loop | **INTEGRATED** | Reviews results and improves dataset |

## Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR AGENT                                │
│                  (Integrates with Real SecMutBench)                      │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
      ┌────────────────────────────┼────────────────────────────┐
      │                            │                            │
      ▼                            ▼                            ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│  IMPROVEMENT  │      │  EXPERIMENT   │      │   ANALYSIS    │
│    PHASE      │      │    PHASE      │      │    PHASE      │
│               │      │               │      │               │
│ DataGenerator │      │ ModelRunner   │      │ StatAgent     │
│               │      │ JudgeRunner   │      │ ChartAgent    │
│               │      │               │      │ ReportAgent   │
└───────────────┘      └───────────────┘      └───────────────┘
                                                      │
                                                      ▼
                              ┌───────────────────────────────────┐
                              │         FEEDBACK PHASE            │
                              │              (NEW)                 │
                              │                                    │
                              │  ResultReviewer → DatasetImprover  │
                              │         │                │         │
                              │         ▼                ▼         │
                              │  Identify Issues   Apply Fixes     │
                              │         │                │         │
                              │         └────────┬───────┘         │
                              │                  ▼                 │
                              │        Improved Dataset            │
                              │                  │                 │
                              └──────────────────┼─────────────────┘
                                                 │
                                                 ▼
                              ┌───────────────────────────────────┐
                              │     NEXT ITERATION (Optional)     │
                              │   Re-run experiments on improved  │
                              │            dataset                │
                              └───────────────────────────────────┘
```

## Phases & Tasks

### Phase 1: Improvement
| Task ID | Description | Agent |
|---------|-------------|-------|
| I001 | Generate samples for Tier 1 CWEs | DataGenerator |
| I002 | Generate samples for Tier 2 CWEs | DataGenerator |

### Phase 2: Experiment
| Task ID | Description | Agent |
|---------|-------------|-------|
| E001 | Run evaluation on qwen2.5-coder:7b | ModelRunner |
| E002 | Run evaluation on codellama:13b | ModelRunner |
| E003 | Run evaluation on deepseek-coder:6.7b | ModelRunner |
| E004 | Run evaluation on qwen3-coder | ModelRunner |
| E007 | Run LLM Judge on all generated tests | JudgeRunner |

### Phase 3: Analysis
| Task ID | Description | Agent |
|---------|-------------|-------|
| A001 | Calculate Cohen's d effect sizes | StatAgent |
| A002 | Run ANOVA across CWEs | StatAgent |
| A003 | Calculate ICC for judge agreement | StatAgent |
| A004 | Generate mutation score heatmap | ChartAgent |
| A005 | Generate model comparison charts | ChartAgent |
| A006 | Generate CWE distribution plots | ChartAgent |
| A007 | Create evaluation report (Markdown) | ReportAgent |
| A008 | Create paper tables (LaTeX) | ReportAgent |

### Phase 4: Feedback (NEW)
| Task ID | Description | Agent |
|---------|-------------|-------|
| F001 | Identify weak CWEs | ResultReviewer |
| F002 | Flag problematic samples | ResultReviewer |
| F003 | Analyze operator effectiveness | ResultReviewer |
| F004 | Generate improvement recommendations | ResultReviewer |
| F005 | Add samples for weak CWEs | DatasetImprover |
| F006 | Fix or remove problematic samples | DatasetImprover |
| F007 | Update mutation operators | DatasetImprover |
| F008 | Apply all improvements and rebuild dataset | DatasetImprover |

---

## Feedback Loop Details

### ResultReviewer Agent

Analyzes evaluation results to identify improvement opportunities:

```python
# Thresholds for identifying issues
WEAK_CWE_THRESHOLD = 0.5        # CWEs with avg score below this need attention
PROBLEMATIC_SAMPLE_THRESHOLD = 0.3  # Samples below this are problematic
ZERO_KILL_THRESHOLD = 0.1       # Samples that kill < 10% of mutants
MIN_SAMPLES_PER_CWE = 3         # CWEs with fewer samples need more
ATTACK_COVERAGE_THRESHOLD = 0.6 # Attack coverage below this is concerning
```

**Outputs:**
- `review_results.json` - Complete review with recommendations
- Weak CWEs list
- Problematic samples list
- Operator effectiveness analysis
- Attack coverage gaps

### DatasetImprover Agent

Implements improvements based on review:

**Actions:**
1. **Add samples** - Generate placeholder samples for weak CWEs
2. **Flag samples** - Mark problematic samples for manual review
3. **Note issues** - Add improvement notes to samples
4. **Backup dataset** - Before any modifications

**Outputs:**
- `improvement_report.json` - Actions taken
- Updated `dataset.json`
- `data/backups/` - Dataset backups

### Feedback Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                       FEEDBACK FLOW                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. REVIEW PHASE (ResultReviewer)                               │
│     ├─ Load all experiment results                              │
│     ├─ Find weak CWEs (avg score < 50%)                        │
│     ├─ Flag problematic samples (score < 30%)                  │
│     ├─ Analyze operator kill rates                              │
│     ├─ Check attack vector coverage                             │
│     └─ Generate recommendations                                  │
│                                                                  │
│  2. IMPROVEMENT PHASE (DatasetImprover)                         │
│     ├─ Backup current dataset                                   │
│     ├─ Add samples for weak CWEs                               │
│     ├─ Flag problematic samples for review                     │
│     ├─ Generate operator recommendations                        │
│     └─ Save improvement report                                  │
│                                                                  │
│  3. OUTPUT                                                       │
│     ├─ review_results.json                                      │
│     ├─ improvement_report.json                                  │
│     ├─ operator_recommendations.json                            │
│     └─ Updated dataset.json                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
agentic_pipeline/
├── MULTI_AGENT_SYSTEM.md          # This file
├── agents/
│   ├── orchestrator.py            # Main coordinator
│   └── sub_agents/
│       ├── data_generator.py      # Sample generation
│       ├── model_runner.py        # Model evaluation (uses real SecMutBench)
│       ├── judge_runner.py        # LLM judge (uses real llm_judge)
│       ├── stat_agent.py          # Statistical analysis
│       ├── chart_agent.py         # Visualizations
│       ├── report_agent.py        # Report generation
│       ├── result_reviewer.py     # NEW: Review results
│       └── dataset_improver.py    # NEW: Improve dataset
├── outputs/
│   └── experiments/{experiment_id}/
│       ├── orchestrator_results.json
│       ├── {model_name}/
│       │   ├── results/{sample_id}.json
│       │   ├── summary.json
│       │   ├── skipped_samples.json
│       │   └── judge_scores.json
│       ├── charts/
│       ├── reports/
│       ├── review_results.json         # NEW
│       ├── improvement_report.json     # NEW
│       └── operator_recommendations.json # NEW
└── README.md
```

---

## Usage

### Run Full Pipeline with Feedback
```bash
python orchestrator.py
```
Runs: improvement → experiment → analysis → feedback

### Run Without Feedback
```bash
python orchestrator.py --no-feedback
```
Runs: improvement → experiment → analysis

### Run Only Feedback Phase
```bash
python orchestrator.py --feedback-only
```
Runs feedback on the most recent experiment results.

### Run Specific Phase
```bash
python orchestrator.py --phase experiment
python orchestrator.py --phase analysis
python orchestrator.py --phase feedback
```

### Check Status
```bash
python orchestrator.py --status
```

### Model & Judge Selection
```bash
# Run only specific models
python orchestrator.py --models E001,E003,E005

# Run only specific judges
python orchestrator.py --judges gpt-4,gemini-1.5-pro

# Combine selections
python orchestrator.py --models E001,E002 --judges gpt-4
```

### Error Handling & Retry
```bash
# Enable retry with exponential backoff
python orchestrator.py --retry

# Specify retry count
python orchestrator.py --retry 5
```

### Prerequisite Checking
```bash
# Check all prerequisites
python orchestrator.py --status

# Check model prerequisites
python sub_agents/model_runner.py --check

# Check judge prerequisites
python sub_agents/judge_runner.py --check
```

---

## Agent Specifications

### 1. ResultReviewer

**Role**: Analyze results and identify improvement opportunities

**Capabilities**:
- Find CWEs with consistently low mutation scores
- Identify samples that kill few/no mutants
- Analyze mutation operator effectiveness
- Detect attack vector coverage gaps
- Generate prioritized recommendations

**Output Format**:
```json
{
  "experiment_id": "2026-01-31_10-00-00",
  "overall_health": "needs_improvement",
  "improvement_score": 0.35,
  "weak_cwes": [
    {"cwe": "CWE-918", "avg_score": 0.25, "severity": "critical"}
  ],
  "problematic_samples": [
    {"sample_id": "abc123", "avg_score": 0.1, "issues": ["zero_kills"]}
  ],
  "recommendations": [
    {"category": "dataset", "priority": "critical", "target": "CWE-918", ...}
  ]
}
```

### 2. DatasetImprover

**Role**: Implement improvements based on recommendations

**Capabilities**:
- Add placeholder samples for weak CWEs
- Flag problematic samples for manual review
- Generate operator improvement suggestions
- Backup dataset before modifications
- Update dataset version

**CWE Templates Supported**:
- CWE-89 (SQL Injection)
- CWE-78 (Command Injection)
- CWE-22 (Path Traversal)
- CWE-79 (XSS)
- CWE-798 (Hardcoded Credentials)
- CWE-502 (Deserialization)
- CWE-327 (Weak Crypto)
- CWE-287 (Authentication)

---

## Integration with Real SecMutBench

### ModelRunner (E001-E004)
```python
from evaluation.evaluate import load_benchmark, evaluate_generated_tests
from evaluation.mutation_engine import MutationEngine
from evaluation.test_runner import TestRunner
from evaluation.sample_validator import SampleValidator
from evaluation.attack_vectors import check_attack_coverage

# Pre-validate samples
validator = SampleValidator()
valid_samples = [s for s in samples if validator.validate(s).is_valid]

# Use real evaluation
result = evaluate_generated_tests(
    sample=sample,
    generated_tests=generated_test,
    engine=self.engine,
    runner=self.runner,
)

# Check attack coverage
coverage, covered, missing = check_attack_coverage(test, cwe)
```

### JudgeRunner (E007)
```python
from evaluation.llm_judge import create_evaluator

# Supports: anthropic, openai, google
evaluator = create_evaluator(provider="google", model="gemini-1.5-pro")
result = evaluator.evaluate(sample=sample, generated_tests=test)
```

---

## Success Criteria

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| SecMutBench Integration | **YES** | Yes | ✅ COMPLETE |
| Sample Count | **180** | 100+ | ✅ COMPLETE |
| Models Configured | **4** | 3+ | ✅ COMPLETE |
| Judges Configured | **3** | 3+ | ✅ COMPLETE |
| Sample Validator | **YES** | Yes | ✅ COMPLETE |
| Attack Vectors | **YES** | Yes | ✅ COMPLETE |
| Feedback Loop | **YES** | Yes | ✅ COMPLETE |
| Improvements Tracking | **YES** | Yes | ✅ COMPLETE |
| Iterative Cycles | **YES** | Yes | ✅ COMPLETE |
| Statistical Tests | 3 | 3+ | ✅ READY |
| Visualization Types | 3 | 5+ | 🔄 PENDING |
| Final Report | No | Yes | 🔄 PENDING |

---

## Example Feedback Cycle

```
Experiment Results:
  CWE-918 (SSRF): avg_score = 0.25 (critical)
  Sample xyz_001: zero kills across all models
  Operator SSRF: kill_rate = 0.15 (too hard)

ResultReviewer Recommendations:
  1. [CRITICAL] CWE-918: Add more samples (only 2 exist)
  2. [CRITICAL] xyz_001: Flag for review - no mutants killed
  3. [MEDIUM] SSRF operator: Review implementation

DatasetImprover Actions:
  1. Added placeholder sample for CWE-918 (needs_review=true)
  2. Flagged xyz_001 with review_reason="Zero mutation kills"
  3. Generated operator_recommendations.json

Next Iteration:
  - Developer reviews flagged samples
  - Developer implements placeholder samples
  - Re-run experiments to verify improvement
```

---

## Configuration

### Judges
```python
JUDGES = [
    {"name": "claude-4.5-opus", "provider": "anthropic"},
    {"name": "gpt-5", "provider": "openai"},
    {"name": "gemini-3-pro", "provider": "google"},
]
```

### Models
```python
MODELS = {
    "E001": {"name": "qwen2.5-coder:7b", "type": "ollama"},
    "E002": {"name": "codellama:13b", "type": "ollama"},
    "E003": {"name": "deepseek-coder:6.7b", "type": "ollama"},
    "E004": {"name": "qwen3-coder:latest", "type": "ollama"},
}
```

### Feedback Thresholds
```python
WEAK_CWE_THRESHOLD = 0.5
PROBLEMATIC_SAMPLE_THRESHOLD = 0.3
ZERO_KILL_THRESHOLD = 0.1
MIN_SAMPLES_PER_CWE = 3
ATTACK_COVERAGE_THRESHOLD = 0.6
```

### Error Handling

The system includes robust error handling with automatic diagnosis and retry:

**Error Types:**
- `OllamaNotRunningError` - Ollama service not running
- `OllamaModelNotFoundError` - Model not pulled
- `APIKeyMissingError` - API key not set
- `APIRateLimitError` - Rate limit exceeded
- `ModelTimeoutError` - Generation timeout

**Auto-fix Actions:**
- `fix_ollama` - Attempts to start Ollama service
- `retry` - Retries with exponential backoff
- `skip` - Skips task and continues
- `skip_no_key` - Skips tasks requiring missing API keys

**Retry Configuration:**
```python
DEFAULT_RETRY_COUNT = 3
RETRY_DELAYS = [5, 15, 30]  # seconds (exponential backoff)
```
