# SecMutBench Improvements Log

This file tracks all improvements made to SecMutBench, including automated improvements from the feedback loop and manual changes.

## Log Format

Each entry follows this format:
```
### [DATE] - [TYPE] - [COMPONENT]
**Author**: Manual | DatasetImprover | ResultReviewer
**Experiment**: experiment_id (if applicable)

Description of the improvement.

**Changes:**
- Item 1
- Item 2
```

---

## Improvement History

### 2026-01-31 - FEATURE - Multi-Agent System
**Author**: Manual
**Experiment**: N/A

Added comprehensive error handling and model/judge selection to the multi-agent system.

**Changes:**
- Added `--models` flag to select specific models (E001-E006)
- Added `--judges` flag to select specific judges
- Added `--retry` flag with exponential backoff
- Added prerequisite checking (`--check` option)
- Added custom exceptions for better error diagnosis
- Added auto-fix for Ollama not running

---

### 2026-01-31 - FEATURE - Feedback Loop
**Author**: Manual
**Experiment**: N/A

Added feedback loop to analyze results and improve dataset automatically.

**Changes:**
- Created ResultReviewer agent (identifies weak CWEs, problematic samples)
- Created DatasetImprover agent (adds samples, flags issues)
- Added Phase 4: Feedback with tasks F001-F008
- Integrated with experiment pipeline

---

<!-- AUTOMATED ENTRIES BELOW - DO NOT EDIT MANUALLY -->
### 2026-02-01 - EXPERIMENT - Orchestrator
**Author**: Orchestrator
**Experiment**: 2026-02-01_10-01-05

Completed experiment run with 20 tasks.

**Changes:**
- Ran 4 phases: improvement, experiment, analysis, feedback
- Completed: 20 tasks
- Models: E004
- Judges: gpt-5

---

### 2026-02-01 - DATASET - Dataset
**Author**: DatasetImprover
**Experiment**: 2026-02-01_10-01-05

Automated dataset improvements based on experiment results.

**Changes:**
- Added 2 new sample(s)
- add: CWE-79 - Added placeholder sample for CWE-79
- add: CWE-78 - Added placeholder sample for CWE-78
- noted: d07ded395aff - Added improvement suggestion
- noted: 6e92a4e2cffc - Added improvement suggestion
- noted: 6cdb2d1de893 - Added improvement suggestion
- noted: 895ef060da88 - Added improvement suggestion
- noted: b4a3747c33f0 - Added improvement suggestion
- noted: 7edd05874906 - Added improvement suggestion
- noted: d19d47e852a7 - Added improvement suggestion
- noted: c9e1cfc5885c - Added improvement suggestion

---

### 2026-02-01 - EXPERIMENT - Orchestrator
**Author**: Orchestrator
**Experiment**: 2026-02-01_09-42-39

Completed experiment run with 20 tasks.

**Changes:**
- Ran 4 phases: improvement, experiment, analysis, feedback
- Completed: 20 tasks
- Models: E001
- Judges: gpt-5

---

### 2026-02-01 - DATASET - Dataset
**Author**: DatasetImprover
**Experiment**: 2026-02-01_09-42-39

Automated dataset improvements based on experiment results.

**Changes:**
- Added 1 new sample(s)
- add: CWE-89 - Added placeholder sample for CWE-89
- noted: d07ded395aff - Added improvement suggestion
- noted: c9e1cfc5885c - Added improvement suggestion
- noted: e02aa4c9d3ec - Added improvement suggestion

---

<!-- The DatasetImprover agent will append entries here -->

