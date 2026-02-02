#!/bin/bash
# =============================================================================
# SecMutBench Complete Evaluation Runner
# =============================================================================
# This script runs the complete evaluation pipeline:
# 1. Uses existing dataset.json (300 samples)
# 2. Runs LLM baseline evaluation with specified models (Ollama)
# 3. Uses OpenAI and/or Anthropic as LLM-as-Judge
#
# Usage: ./run_evaluation.sh [OPTIONS]
#
# Options:
#   --samples N          Number of samples to evaluate (default: all)
#   --test               Test mode: run only 1 sample
#   --models "m1 m2"     Models to evaluate (default: qwen2.5-coder:14b deepseek-coder-v2:latest)
#   --judge PROVIDER     Judge provider: openai, anthropic, both (default: both)
#   --skip-generation    Skip sample generation (always skipped, uses dataset.json)
#   --dataset PATH       Path to dataset file (default: data/dataset.json)
#   --shuffle            Shuffle samples for CWE diversity
#   --seed N             Random seed for shuffle (default: 42)
#   --help               Show this help message
# =============================================================================

set -e

# Configuration
MAX_SAMPLES=${MAX_SAMPLES:-""}
TEST_MODE=${TEST_MODE:-false}
MODELS=${MODELS:-"qwen2.5-coder:14b-instruct deepseek-coder-v2:latest"}
JUDGE_PROVIDER=${JUDGE_PROVIDER:-"both"}
DATASET_PATH=${DATASET_PATH:-"data/dataset.json"}
SHUFFLE=${SHUFFLE:-false}
SEED=${SEED:-42}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --samples)
            MAX_SAMPLES="$2"
            shift 2
            ;;
        --test)
            TEST_MODE=true
            MAX_SAMPLES=1
            shift
            ;;
        --models)
            MODELS="$2"
            shift 2
            ;;
        --judge)
            JUDGE_PROVIDER="$2"
            shift 2
            ;;
        --dataset)
            DATASET_PATH="$2"
            shift 2
            ;;
        --skip-generation)
            # Always skip generation - we use dataset.json
            shift
            ;;
        --shuffle)
            SHUFFLE=true
            shift
            ;;
        --seed)
            SEED="$2"
            shift 2
            ;;
        --help)
            head -25 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         SecMutBench Complete Evaluation Pipeline             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$TEST_MODE" = true ]; then
    echo -e "${YELLOW}>>> TEST MODE: Running with 1 sample only <<<${NC}"
    echo ""
fi

# =============================================================================
# Step 0: Check Prerequisites
# =============================================================================
echo -e "${YELLOW}[0/4] Checking prerequisites...${NC}"

# Check dataset exists
if [ ! -f "$DATASET_PATH" ]; then
    echo -e "${RED}ERROR: Dataset not found at $DATASET_PATH${NC}"
    exit 1
fi
SAMPLE_COUNT=$(python -c "import json; d=json.load(open('$DATASET_PATH')); print(len(d.get('samples', d)) if isinstance(d, dict) else len(d))")
echo -e "  ${GREEN}✓${NC} Dataset found: $DATASET_PATH ($SAMPLE_COUNT samples)"

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Ollama is not running. Please start Ollama first:${NC}"
    echo "  ollama serve"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Ollama is running"

# Check if models are available
for MODEL in $MODELS; do
    MODEL_BASE="${MODEL%%:*}"
    if ! ollama list | grep -q "$MODEL_BASE"; then
        echo -e "${YELLOW}  Model $MODEL not found. Pulling...${NC}"
        ollama pull "$MODEL"
    fi
    echo -e "  ${GREEN}✓${NC} Model $MODEL is available"
done

# Check API keys based on judge provider
if [ "$JUDGE_PROVIDER" = "openai" ] || [ "$JUDGE_PROVIDER" = "both" ]; then
    if [ -z "$OPENAI_API_KEY" ]; then
        if [ -f ".env" ]; then
            export $(grep -v '^#' .env | xargs)
        fi
    fi
    if [ -z "$OPENAI_API_KEY" ]; then
        echo -e "${RED}ERROR: OPENAI_API_KEY not set. Required for OpenAI judge.${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} OpenAI API key configured"
fi

if [ "$JUDGE_PROVIDER" = "anthropic" ] || [ "$JUDGE_PROVIDER" = "both" ]; then
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        if [ -f ".env" ]; then
            export $(grep -v '^#' .env | xargs)
        fi
    fi
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        echo -e "${RED}ERROR: ANTHROPIC_API_KEY not set. Required for Anthropic judge.${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} Anthropic API key configured"
fi

echo ""

# =============================================================================
# Step 1: Display Dataset Info
# =============================================================================
echo -e "${YELLOW}[1/4] Dataset information...${NC}"
python -c "
import json
with open('$DATASET_PATH') as f:
    data = json.load(f)
samples = data.get('samples', data) if isinstance(data, dict) else data
from collections import Counter
cwe_counts = Counter(s.get('cwe', 'unknown') for s in samples)
diff_counts = Counter(s.get('difficulty', 'unknown') for s in samples)
print(f'  Total samples: {len(samples)}')
print(f'  CWE categories: {len(cwe_counts)}')
print(f'  Difficulty: {dict(diff_counts)}')
"
echo ""

# =============================================================================
# Step 2: Run LLM Baseline Evaluation
# =============================================================================
echo -e "${YELLOW}[2/4] Running LLM baseline evaluation...${NC}"
echo "  Models: $MODELS"
echo "  Judge: $JUDGE_PROVIDER"

# Build max-samples flag
MAX_FLAG=""
if [ -n "$MAX_SAMPLES" ]; then
    MAX_FLAG="--max-samples $MAX_SAMPLES"
    echo "  Max samples: $MAX_SAMPLES"
fi

# Build shuffle flag
SHUFFLE_FLAG=""
if [ "$SHUFFLE" = true ]; then
    SHUFFLE_FLAG="--shuffle --seed $SEED"
    echo "  Shuffle: enabled (seed=$SEED)"
fi

# Create results directory
mkdir -p results

# Run evaluation for each model with each judge
for MODEL in $MODELS; do
    echo ""
    echo -e "${BLUE}>>> Evaluating model: $MODEL${NC}"

    if [ "$JUDGE_PROVIDER" = "both" ]; then
        # Run with OpenAI judge
        echo -e "  ${YELLOW}Running with OpenAI judge...${NC}"
        python baselines/run_llm_baselines.py \
            --models "$MODEL" \
            --provider ollama \
            --use-judge \
            --judge-provider openai \
            $MAX_FLAG \
            $SHUFFLE_FLAG \
            --output results

        # Run with Anthropic judge
        echo -e "  ${YELLOW}Running with Anthropic judge...${NC}"
        python baselines/run_llm_baselines.py \
            --models "$MODEL" \
            --provider ollama \
            --use-judge \
            --judge-provider anthropic \
            $MAX_FLAG \
            $SHUFFLE_FLAG \
            --output results
    else
        # Run with specified judge
        python baselines/run_llm_baselines.py \
            --models "$MODEL" \
            --provider ollama \
            --use-judge \
            --judge-provider "$JUDGE_PROVIDER" \
            $MAX_FLAG \
            $SHUFFLE_FLAG \
            --output results
    fi
done

echo ""

# =============================================================================
# Step 3: Display Results Summary
# =============================================================================
echo -e "${YELLOW}[3/4] Evaluation complete!${NC}"
echo ""

# Find latest results files
LATEST_RESULTS=$(ls -t results/baseline_results_*.json 2>/dev/null | head -1)

if [ -n "$LATEST_RESULTS" ]; then
    echo -e "${GREEN}Latest results: $LATEST_RESULTS${NC}"
    echo ""

    # Display summary
    python -c "
import json
with open('$LATEST_RESULTS') as f:
    data = json.load(f)

print('='*70)
print('EVALUATION SUMMARY')
print('='*70)

for result in data['results']:
    print(f\"Model: {result['model_name']}\")
    print(f\"  Samples evaluated: {result['samples_evaluated']}\")
    print(f\"  Mutation Score: {result['avg_mutation_score']:.1%}\")
    print(f\"  Vuln Detection: {result['avg_vuln_detection']:.1%}\")
    print(f\"  Line Coverage: {result['avg_line_coverage']:.1%}\")
    if result.get('avg_security_relevance', 0) > 0:
        print(f\"  Security Relevance: {result['avg_security_relevance']:.1%}\")
        print(f\"  Test Quality: {result['avg_test_quality']:.1%}\")
        print(f\"  Composite Score: {result['avg_composite_score']:.1%}\")
    print(f\"  Errors: {result['errors']}\")
    print(f\"  Time: {result['evaluation_time']:.1f}s\")
    print()
print('='*70)
"
fi

echo ""

# =============================================================================
# Step 4: Generate Report
# =============================================================================
echo -e "${YELLOW}[4/4] Generating final report...${NC}"

REPORT_FILE="results/evaluation_report_$(date +%Y%m%d_%H%M%S).md"

cat > "$REPORT_FILE" << EOF
# SecMutBench Evaluation Report

**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Models:** $MODELS
**Provider:** Ollama (local)
**Judge:** $JUDGE_PROVIDER
**Dataset:** $DATASET_PATH

## Configuration

- **Samples Evaluated:** ${MAX_SAMPLES:-"all"}
- **Test Mode:** $TEST_MODE

## Dataset Distribution

\`\`\`
$(python -c "
import json
with open('$DATASET_PATH') as f:
    data = json.load(f)
samples = data.get('samples', data) if isinstance(data, dict) else data
from collections import Counter
cwe_counts = Counter(s.get('cwe', 'unknown') for s in samples)
diff_counts = Counter(s.get('difficulty', 'unknown') for s in samples)
print(f'Total samples: {len(samples)}')
print()
print('By CWE:')
for cwe, count in sorted(cwe_counts.items()):
    print(f'  {cwe}: {count}')
print()
print('By Difficulty:')
for diff, count in sorted(diff_counts.items()):
    print(f'  {diff}: {count}')
")
\`\`\`

## Results

$(if [ -n "$LATEST_RESULTS" ]; then
python -c "
import json
with open('$LATEST_RESULTS') as f:
    data = json.load(f)

for result in data['results']:
    print(f\"### {result['model_name']}\")
    print()
    print('| Metric | Value |')
    print('|--------|-------|')
    print(f\"| Samples Evaluated | {result['samples_evaluated']} |\")
    print(f\"| Mutation Score | {result['avg_mutation_score']:.1%} |\")
    print(f\"| Vulnerability Detection | {result['avg_vuln_detection']:.1%} |\")
    print(f\"| Line Coverage | {result['avg_line_coverage']:.1%} |\")
    if result.get('avg_security_relevance', 0) > 0:
        print(f\"| Security Relevance | {result['avg_security_relevance']:.1%} |\")
        print(f\"| Test Quality | {result['avg_test_quality']:.1%} |\")
        print(f\"| Composite Score | {result['avg_composite_score']:.1%} |\")
    print(f\"| Errors | {result['errors']} |\")
    print(f\"| Evaluation Time | {result['evaluation_time']:.1f}s |\")
    print()
"
fi)

## Files Generated

- Dataset: \`$DATASET_PATH\`
- Results: \`$LATEST_RESULTS\`

---
*Generated by SecMutBench Evaluation Pipeline*
EOF

echo -e "${GREEN}Report saved to: $REPORT_FILE${NC}"
echo ""

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Evaluation Complete!                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
