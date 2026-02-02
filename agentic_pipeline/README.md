# SecMutBench Multi-Agent System

A long-running, multi-agent system for improving SecMutBench, running experiments, analyzing results, and **providing feedback for continuous improvement**. Fully integrated with the real SecMutBench evaluation code.

## Integration Status

| Component | Status | Description |
|-----------|--------|-------------|
| SecMutBench Evaluation | **INTEGRATED** | Uses real `evaluation.evaluate` module |
| Mutation Engine | **INTEGRATED** | Uses real `MutationEngine` class |
| Test Runner | **INTEGRATED** | Uses real `TestRunner` class |
| LLM Judge | **INTEGRATED** | Uses real `llm_judge` module (Claude, GPT, Gemini) |
| Dataset Builder | **INTEGRATED** | Uses `rebuild_dataset.py` |
| Sample Validator | **INTEGRATED** | Pre-checks samples before evaluation |
| Attack Vectors | **INTEGRATED** | CWE-specific coverage checking |
| **Feedback Loop** | **INTEGRATED** | Reviews results and improves dataset |

## Architecture

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
                              │                                    │
                              │  ResultReviewer → DatasetImprover  │
                              │         │                │         │
                              │    Identify         Apply          │
                              │    Issues           Fixes          │
                              │         │                │         │
                              │         └────────────────┘         │
                              │                  │                 │
                              │          Improved Dataset          │
                              └──────────────────┼─────────────────┘
                                                 │
                                                 ▼
                                        Next Iteration
```

## Quick Start

```bash
# Navigate to agents directory
cd agentic_pipeline/agents

# Check status and prerequisites
python orchestrator.py --status

# Run full pipeline with feedback loop (default)
python orchestrator.py

# Run without feedback loop
python orchestrator.py --no-feedback

# Run only feedback phase on existing results
python orchestrator.py --feedback-only

# Run specific phase
python orchestrator.py --phase experiment
python orchestrator.py --phase analysis
python orchestrator.py --phase feedback
```

## Model & Judge Selection

Select specific models and judges to run instead of all configured ones:

```bash
# Run only specific models (by task ID)
python orchestrator.py --models E001,E003,E005

# Run only specific judges (by name)
python orchestrator.py --judges gpt-4,gemini-1.5-pro

# Combine both
python orchestrator.py --models E001,E002 --judges gpt-4
```

**Available Models:**
| Task ID | Model | Type |
|---------|-------|------|
| E001 | qwen2.5-coder:7b | Ollama |
| E002 | codellama:13b | Ollama |
| E003 | deepseek-coder:6.7b | Ollama |
| E004 | qwen3-coder:latest | Ollama |

**Available Judges:**
- claude-4.5-opus (Anthropic)
- gpt-5 (OpenAI)
- gemini-3-pro (Google)

## Error Handling & Retry

The orchestrator includes automatic error handling and retry mechanisms:

```bash
# Enable retry with exponential backoff (default: 3 retries)
python orchestrator.py --retry

# Specify number of retries
python orchestrator.py --retry 5
```

**Auto-fix capabilities:**
- **Ollama not running**: Automatically attempts to start Ollama
- **Missing API keys**: Skips models/judges that require missing API keys
- **Rate limits**: Retries with exponential backoff
- **Timeouts**: Retries with longer timeout

**Check prerequisites before running:**
```bash
# Check all prerequisites
python orchestrator.py --status

# Check model prerequisites only
python sub_agents/model_runner.py --check

# Check judge prerequisites only
python sub_agents/judge_runner.py --check
```

## Improvements Tracking

All improvements to SecMutBench are tracked in `IMPROVEMENTS_LOG.md`. This includes:
- Automated improvements from the feedback loop
- Manual changes and features
- Experiment completions

**View improvements:**
```bash
# View recent improvements
python agents/log_improvement.py --view

# View last 20 improvements
python agents/log_improvement.py --view --view-count 20
```

**Log manual improvements:**
```bash
# Interactive mode
python agents/log_improvement.py --interactive

# Command-line mode
python agents/log_improvement.py --type FEATURE --component "Dataset" \
    --description "Added new CWE samples" \
    --changes "Added 5 samples for CWE-89" "Added 3 samples for CWE-78"
```

**Improvement Types:**
- `FEATURE` - New features
- `FIX` - Bug fixes
- `DATASET` - Dataset changes (auto-logged by DatasetImprover)
- `OPERATOR` - Mutation operator changes
- `EXPERIMENT` - Experiment completions (auto-logged by Orchestrator)
- `CONFIG` - Configuration changes
- `DOC` - Documentation updates

## Directory Structure

```
agentic_pipeline/
├── README.md                      # This file
├── MULTI_AGENT_SYSTEM.md          # Detailed architecture doc
├── IMPROVEMENTS_LOG.md            # Tracks all improvements
├── agents/
│   ├── orchestrator.py            # Main coordinator
│   ├── log_improvement.py         # Utility for logging improvements
│   └── sub_agents/
│       ├── data_generator.py      # Generate samples
│       ├── model_runner.py        # Run model evals (REAL SecMutBench)
│       ├── judge_runner.py        # Run LLM judges (REAL llm_judge)
│       ├── stat_agent.py          # Statistical analysis
│       ├── chart_agent.py         # Generate charts
│       ├── report_agent.py        # Generate reports
│       ├── result_reviewer.py     # Review results
│       └── dataset_improver.py    # Improve dataset & log improvements
│
└── outputs/
    └── experiments/{experiment_id}/
        ├── orchestrator_results.json
        ├── {model_name}/
        │   ├── results/{sample_id}.json
        │   ├── summary.json
        │   ├── skipped_samples.json
        │   └── judge_scores.json
        ├── charts/
        ├── reports/
        ├── review_results.json         # Feedback review
        └── improvement_report.json     # Improvement actions
```

## Phases

### Phase 1: Improvement
| Task | Description | Agent |
|------|-------------|-------|
| I001 | Generate samples for Tier 1 CWEs | DataGenerator |
| I002 | Generate samples for Tier 2 CWEs | DataGenerator |

### Phase 2: Experiment (Uses Real SecMutBench)
| Task | Description | Agent |
|------|-------------|-------|
| E001 | Run evaluation on qwen2.5-coder:7b | ModelRunner |
| E002 | Run evaluation on codellama:13b | ModelRunner |
| E003 | Run evaluation on deepseek-coder:6.7b | ModelRunner |
| E004 | Run evaluation on qwen3-coder | ModelRunner |
| E007 | Run LLM Judge on all generated tests | JudgeRunner |

### Phase 3: Analysis
| Task | Description | Agent |
|------|-------------|-------|
| A001 | Calculate Cohen's d effect sizes | StatAgent |
| A002 | Run ANOVA across CWEs | StatAgent |
| A003 | Calculate ICC for judge agreement | StatAgent |
| A004 | Generate mutation score heatmap | ChartAgent |
| A005 | Generate model comparison charts | ChartAgent |
| A006 | Generate CWE distribution plots | ChartAgent |
| A007 | Create evaluation report (Markdown) | ReportAgent |
| A008 | Create paper tables (LaTeX) | ReportAgent |

### Phase 4: Feedback (NEW)
| Task | Description | Agent |
|------|-------------|-------|
| F001 | Identify weak CWEs | ResultReviewer |
| F002 | Flag problematic samples | ResultReviewer |
| F003 | Analyze operator effectiveness | ResultReviewer |
| F004 | Generate improvement recommendations | ResultReviewer |
| F005 | Add samples for weak CWEs | DatasetImprover |
| F006 | Fix or remove problematic samples | DatasetImprover |
| F007 | Update mutation operators | DatasetImprover |
| F008 | Apply all improvements | DatasetImprover |

## Feedback Loop

The new feedback loop analyzes experiment results and improves the dataset:

### ResultReviewer
- Identifies CWEs with low mutation scores (< 50%)
- Flags samples that kill few/no mutants
- Analyzes mutation operator effectiveness
- Detects attack vector coverage gaps
- Generates prioritized recommendations

### DatasetImprover
- Adds placeholder samples for weak CWEs
- Flags problematic samples for manual review
- Generates operator improvement suggestions
- Backs up dataset before modifications

### Example Feedback Cycle
```
Experiment Results:
  CWE-918 (SSRF): avg_score = 0.25 (critical)
  Sample xyz_001: zero kills across all models

ResultReviewer:
  → [CRITICAL] CWE-918: Add more samples
  → [CRITICAL] xyz_001: Flag for review

DatasetImprover:
  → Added placeholder sample for CWE-918
  → Flagged xyz_001 for manual review

Next: Developer reviews flagged items, re-run experiments
```

## Iterations

The system supports iterative improvement cycles. Each iteration:

1. **Run Experiment** → Evaluate models on current dataset
2. **Analyze Results** → Generate statistics and reports
3. **Review & Improve** → Feedback loop identifies issues and improves dataset
4. **Repeat** → Run next iteration on improved dataset

```
┌─────────────────────────────────────────────────────────────────┐
│                    ITERATION CYCLE                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Iteration 1                                                     │
│  ├─ Run experiments on dataset v1.0                             │
│  ├─ Analyze: CWE-918 weak (25%), 5 samples flagged              │
│  ├─ Improve: Add 3 samples, flag 5 for review                   │
│  └─ Output: dataset v1.1                                        │
│                                                                  │
│  Iteration 2                                                     │
│  ├─ Developer reviews flagged samples                           │
│  ├─ Run experiments on dataset v1.1                             │
│  ├─ Analyze: CWE-918 improved (45%), 2 samples flagged          │
│  ├─ Improve: Add 2 samples, update operators                    │
│  └─ Output: dataset v1.2                                        │
│                                                                  │
│  Iteration 3                                                     │
│  ├─ Run experiments on dataset v1.2                             │
│  ├─ Analyze: All CWEs above threshold                           │
│  └─ Output: Final results for publication                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Running Multiple Iterations:**
```bash
# First iteration
python orchestrator.py

# Review flagged samples in improvement_report.json
# Make manual fixes if needed

# Second iteration
python orchestrator.py

# Continue until satisfied with results
```

**Tracking Iterations:**
- Each experiment has a unique ID (timestamp-based)
- All results stored in `outputs/experiments/{experiment_id}/`
- Improvements logged to `IMPROVEMENTS_LOG.md`
- Dataset version updated automatically

## Models & Judges

### Models Evaluated
- **Local (Ollama)**: qwen2.5-coder:7b, codellama:13b, deepseek-coder:6.7b, qwen3-coder

### LLM Judges
- **Anthropic**: claude-4.5-opus
- **OpenAI**: gpt-5
- **Google**: gemini-3-pro

## Prerequisites

```bash
# Install Ollama for local models
brew install ollama  # macOS
ollama pull qwen2.5-coder:7b
ollama pull codellama:13b

# Set API keys
export OPENAI_API_KEY="your-key"
export GOOGLE_API_KEY="your-key"      # or GEMINI_API_KEY
export ANTHROPIC_API_KEY="your-key"

# Install Python dependencies
pip install matplotlib numpy openai google-generativeai anthropic
```

## Current Status

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Dataset Samples | **180** | 100+ | ✅ |
| SecMutBench Integration | **YES** | Yes | ✅ |
| Models Configured | **4** | 3+ | ✅ |
| Judges Configured | **3** | 3+ | ✅ |
| Sample Validator | **YES** | Yes | ✅ |
| Attack Vectors | **YES** | Yes | ✅ |
| Feedback Loop | **YES** | Yes | ✅ |
| Improvements Tracking | **YES** | Yes | ✅ |
| Iterative Cycles | **YES** | Yes | ✅ |
| Statistical Tests | 3 | 3+ | ✅ |

## How Integration Works

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

### ResultReviewer (F001-F004)
```python
from sub_agents.result_reviewer import ResultReviewer

reviewer = ResultReviewer(experiment_id="2026-01-31_10-00-00")
review = reviewer.full_review()
# Returns: weak_cwes, problematic_samples, recommendations
```

### DatasetImprover (F005-F008)
```python
from sub_agents.dataset_improver import DatasetImprover

improver = DatasetImprover(experiment_id="2026-01-31_10-00-00")
result = improver.apply_all_improvements()
# Returns: samples_added, samples_fixed, dataset_rebuilt
```

## Outputs

After running the full pipeline with feedback:

```
outputs/experiments/2026-01-31_21-05-31/
├── orchestrator_results.json      # Overall results
├── qwen2.5-coder_7b/
│   ├── results/                   # Per-sample results
│   ├── summary.json               # Model summary
│   ├── skipped_samples.json       # Samples that failed pre-validation
│   └── judge_scores.json          # LLM judge scores
├── charts/
│   ├── mutation_score_heatmap.png
│   ├── model_comparison.png
│   └── cwe_distribution.png
├── reports/
│   ├── EVALUATION_REPORT.md       # Full report
│   ├── paper_tables.tex           # LaTeX tables
│   ├── cohens_d.json
│   ├── anova.json
│   └── icc.json
├── review_results.json            # NEW: Feedback review
├── improvement_report.json        # NEW: Improvement actions
└── operator_recommendations.json  # NEW: Operator suggestions
```

## Verification

Test that the integration is working:

```bash
cd /path/to/SecMutBench
python3 -c "
from evaluation.evaluate import load_benchmark
from evaluation.mutation_engine import MutationEngine
from evaluation.sample_validator import SampleValidator
from evaluation.attack_vectors import check_attack_coverage

samples = load_benchmark()
print(f'Dataset: {len(samples)} samples')

engine = MutationEngine()
print('MutationEngine: OK')

validator = SampleValidator()
print('SampleValidator: OK')

print('Integration: WORKING')
"
```

## See Also

- [MULTI_AGENT_SYSTEM.md](MULTI_AGENT_SYSTEM.md) - Detailed architecture documentation
- [../README.md](../README.md) - Main SecMutBench documentation
- [../DATASET_CARD.md](../DATASET_CARD.md) - Dataset documentation
