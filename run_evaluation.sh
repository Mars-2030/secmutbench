#!/bin/bash
# =============================================================================
# SecMutBench LLM Evaluation Runner (v2.8.0)
# =============================================================================
# This script runs LLM baseline evaluation:
# 1. Runs LLM baseline evaluation with specified models (Ollama or API)
# 2. Uses OpenAI and/or Anthropic as LLM-as-Judge (optional)
# 3. Optionally runs static analysis baselines (Bandit/Semgrep)
#
# PRE-REQUISITE: Build dataset first with:
#   ./build_db.sh 500
#
# Usage: ./run_evaluation.sh [OPTIONS]
#
# Options:
#   --samples N          Number of samples to evaluate (default: all)
#   --test               Test mode: run only 1 sample
#   --models "m1 m2"     Models to evaluate (default: qwen2.5-coder:14b deepseek-coder-v2:latest)
#   --provider PROVIDER  Model provider: ollama, openai, anthropic, google (default: ollama)
#   --judge PROVIDER     Judge provider: openai, anthropic, both, none (default: none)
#   --dataset PATH       Path to dataset file (default: data/dataset.json)
#   --shuffle            Shuffle samples for CWE diversity
#   --seed N             Random seed for shuffle (default: 42)
#   --prompt-variant V   Prompt variant: full, no-hint, cwe-only, all (default: full)
#   --ablation           Shortcut for --prompt-variant all (run all 3 variants)
#   --skip-invalid       Skip samples that fail validation
#   --static-analysis    Run Bandit/Semgrep static analysis baseline
#   --vllm-base-url URL  vLLM server URL (default: http://localhost:8000/v1)
#   --vllm-api-key KEY   vLLM API key (default: secmutbench2026)
#   --batch              Use batch API for 50% cost savings (Anthropic/OpenAI)
#   --batch-judge        Use batch API for LLM-as-Judge (50% cost savings)
#   --version            Show version information
#   --help               Show this help message
#
# Results: results/baseline_results_TIMESTAMP.json
# =============================================================================

set -e

# Configuration
MAX_SAMPLES=${MAX_SAMPLES:-""}
TEST_MODE=${TEST_MODE:-false}
MODELS=${MODELS:-"qwen2.5-coder:14b-instruct deepseek-coder-v2:latest"}
MODEL_PROVIDER=${MODEL_PROVIDER:-"ollama"}
JUDGE_PROVIDER=${JUDGE_PROVIDER:-"none"}
DATASET_PATH=${DATASET_PATH:-"data/dataset2.json"}
SHUFFLE=${SHUFFLE:-false}
SEED=${SEED:-2026}
RUN_STATIC_ANALYSIS=${RUN_STATIC_ANALYSIS:-false}
PROMPT_VARIANT=${PROMPT_VARIANT:-"full"}
SKIP_INVALID=${SKIP_INVALID:-false}
BATCH_MODE=${BATCH_MODE:-false}
BATCH_JUDGE=${BATCH_JUDGE:-false}
VLLM_BASE_URL=${VLLM_BASE_URL:-"http://localhost:8000/v1"}
VLLM_API_KEY=${VLLM_API_KEY:-"secmutbench2026"}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --samples) MAX_SAMPLES="$2"; shift 2 ;;
        --test) TEST_MODE=true; MAX_SAMPLES=1; shift ;;
        --models) MODELS="$2"; shift 2 ;;
        --provider) MODEL_PROVIDER="$2"; shift 2 ;;
        --judge) JUDGE_PROVIDER="$2"; shift 2 ;;
        --dataset) DATASET_PATH="$2"; shift 2 ;;
        --shuffle) SHUFFLE=true; shift ;;
        --seed) SEED="$2"; shift 2 ;;
        --static-analysis) RUN_STATIC_ANALYSIS=true; shift ;;
        --prompt-variant) PROMPT_VARIANT="$2"; shift 2 ;;
        --ablation) PROMPT_VARIANT="all"; shift ;;
        --skip-invalid) SKIP_INVALID=true; shift ;;
        --vllm-base-url) VLLM_BASE_URL="$2"; shift 2 ;;
        --vllm-api-key) VLLM_API_KEY="$2"; shift 2 ;;
        --batch) BATCH_MODE=true; shift ;;
        --batch-judge) BATCH_JUDGE=true; shift ;;
        --version)
            python -c "from evaluation.version import format_version_string; print(format_version_string())"
            exit 0
            ;;
        --help) head -35 "$0" | tail -30; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║             SecMutBench LLM Evaluation                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

VERSION=$(python -c "from evaluation.version import __version__; print(__version__)" 2>/dev/null || echo "unknown")
echo -e "Version: ${GREEN}$VERSION${NC}"
echo ""

if [ "$TEST_MODE" = true ]; then
    echo -e "${YELLOW}>>> TEST MODE: Running with 1 sample only <<<${NC}"
    echo ""
fi

if [ "$BATCH_MODE" = true ]; then
    echo -e "${YELLOW}>>> BATCH MODE: 50% cost savings for API providers <<<${NC}"
    echo ""
fi

# =============================================================================
# Step 1: Check Prerequisites
# =============================================================================
echo -e "${YELLOW}[1/5] Checking prerequisites...${NC}"

# Check dataset exists
if [ ! -f "$DATASET_PATH" ]; then
    echo -e "${RED}ERROR: Dataset not found at $DATASET_PATH${NC}"
    echo -e "${YELLOW}Build dataset first: ./build_db.sh 500${NC}"
    exit 1
fi
SAMPLE_COUNT=$(python -c "import json; d=json.load(open('$DATASET_PATH')); print(len(d.get('samples', d)) if isinstance(d, dict) else len(d))")
echo -e "  ${GREEN}✓${NC} Dataset: $DATASET_PATH ($SAMPLE_COUNT samples)"

# Check provider-specific prerequisites
if [ "$MODEL_PROVIDER" = "ollama" ]; then
    # Check Ollama
    if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "${RED}ERROR: Ollama not running. Start with: ollama serve${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} Ollama running"

    # Check models
    for MODEL in $MODELS; do
        MODEL_BASE="${MODEL%%:*}"
        if ! ollama list | grep -q "$MODEL_BASE"; then
            echo -e "${YELLOW}  Pulling $MODEL...${NC}"
            ollama pull "$MODEL"
        fi
        echo -e "  ${GREEN}✓${NC} Model: $MODEL"
    done
elif [ "$MODEL_PROVIDER" = "openai" ]; then
    [ -z "$OPENAI_API_KEY" ] && [ -f ".env" ] && export $(grep -v '^#' .env | xargs)
    [ -z "$OPENAI_API_KEY" ] && echo -e "${RED}ERROR: OPENAI_API_KEY not set${NC}" && exit 1
    echo -e "  ${GREEN}✓${NC} OpenAI API key"
elif [ "$MODEL_PROVIDER" = "anthropic" ]; then
    [ -z "$ANTHROPIC_API_KEY" ] && [ -f ".env" ] && export $(grep -v '^#' .env | xargs)
    [ -z "$ANTHROPIC_API_KEY" ] && echo -e "${RED}ERROR: ANTHROPIC_API_KEY not set${NC}" && exit 1
    echo -e "  ${GREEN}✓${NC} Anthropic API key"
elif [ "$MODEL_PROVIDER" = "google" ]; then
    [ -z "$GOOGLE_API_KEY" ] && [ -f ".env" ] && export $(grep -v '^#' .env | xargs)
    [ -z "$GOOGLE_API_KEY" ] && echo -e "${RED}ERROR: GOOGLE_API_KEY not set${NC}" && exit 1
    echo -e "  ${GREEN}✓${NC} Google API key"
elif [ "$MODEL_PROVIDER" = "vllm" ]; then
    if ! curl -s "$VLLM_BASE_URL/models" -H "Authorization: Bearer $VLLM_API_KEY" > /dev/null 2>&1; then
        echo -e "${RED}ERROR: vLLM server not reachable at $VLLM_BASE_URL${NC}"
        echo -e "${YELLOW}Make sure the SLURM job is running and SSH tunnel is open${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} vLLM server: $VLLM_BASE_URL"
    for MODEL in $MODELS; do
        echo -e "  ${GREEN}✓${NC} Model: $MODEL"
    done
elif [ "$MODEL_PROVIDER" = "together" ]; then
    [ -z "$TOGETHER_API_KEY" ] && [ -f ".env" ] && export $(grep -v '^#' .env | xargs)
    [ -z "$TOGETHER_API_KEY" ] && echo -e "${RED}ERROR: TOGETHER_API_KEY not set${NC}" && exit 1
    echo -e "  ${GREEN}✓${NC} Together.ai API key"
elif [ "$MODEL_PROVIDER" = "zhipu" ]; then
    [ -z "$ZHIPU_API_KEY" ] && [ -f ".env" ] && export $(grep -v '^#' .env | xargs)
    [ -z "$ZHIPU_API_KEY" ] && echo -e "${RED}ERROR: ZHIPU_API_KEY not set${NC}" && exit 1
    echo -e "  ${GREEN}✓${NC} Zhipu AI API key"
elif [ "$MODEL_PROVIDER" = "fireworks" ]; then
    [ -z "$FIREWORKS_API_KEY" ] && [ -f ".env" ] && export $(grep -v '^#' .env | xargs)
    [ -z "$FIREWORKS_API_KEY" ] && echo -e "${RED}ERROR: FIREWORKS_API_KEY not set${NC}" && exit 1
    echo -e "  ${GREEN}✓${NC} Fireworks AI API key"
fi

# Check API keys for judge
if [ "$JUDGE_PROVIDER" = "openai" ] || [ "$JUDGE_PROVIDER" = "both" ]; then
    [ -z "$OPENAI_API_KEY" ] && [ -f ".env" ] && export $(grep -v '^#' .env | xargs)
    [ -z "$OPENAI_API_KEY" ] && echo -e "${RED}ERROR: OPENAI_API_KEY not set${NC}" && exit 1
    echo -e "  ${GREEN}✓${NC} OpenAI API key (judge)"
fi

if [ "$JUDGE_PROVIDER" = "anthropic" ] || [ "$JUDGE_PROVIDER" = "both" ]; then
    [ -z "$ANTHROPIC_API_KEY" ] && [ -f ".env" ] && export $(grep -v '^#' .env | xargs)
    [ -z "$ANTHROPIC_API_KEY" ] && echo -e "${RED}ERROR: ANTHROPIC_API_KEY not set${NC}" && exit 1
    echo -e "  ${GREEN}✓${NC} Anthropic API key (judge)"
fi

echo ""

# =============================================================================
# Step 2: Display Dataset Info
# =============================================================================
echo -e "${YELLOW}[2/5] Dataset info...${NC}"
python -c "
import json
with open('$DATASET_PATH') as f:
    data = json.load(f)
samples = data.get('samples', data) if isinstance(data, dict) else data
from collections import Counter
cwe_counts = Counter(s.get('cwe', 'unknown') for s in samples)
diff_counts = Counter(s.get('difficulty', 'unknown') for s in samples)
print(f'  Samples: {len(samples)}, CWEs: {len(cwe_counts)}, Difficulty: {dict(diff_counts)}')
"
echo ""

# =============================================================================
# Step 3: Run LLM Baseline Evaluation
# =============================================================================
echo -e "${YELLOW}[3/5] Running LLM evaluation...${NC}"
echo "  Provider: $MODEL_PROVIDER"
echo "  Models: $MODELS"
echo "  Judge: $JUDGE_PROVIDER"

# Build flags
MAX_FLAG=""
[ -n "$MAX_SAMPLES" ] && MAX_FLAG="--max-samples $MAX_SAMPLES" && echo "  Samples: $MAX_SAMPLES"

SHUFFLE_FLAG=""
[ "$SHUFFLE" = true ] && SHUFFLE_FLAG="--shuffle --seed $SEED" && echo "  Shuffle: seed=$SEED"

PROMPT_FLAG="--prompt-variant $PROMPT_VARIANT"
[ "$PROMPT_VARIANT" = "all" ] && echo "  Ablation: full, no-hint, cwe-only" || echo "  Prompt: $PROMPT_VARIANT"

SKIP_INVALID_FLAG=""
[ "$SKIP_INVALID" = true ] && SKIP_INVALID_FLAG="--skip-invalid"

BATCH_FLAG=""
[ "$BATCH_MODE" = true ] && BATCH_FLAG="--batch" && echo "  Batch: enabled (50% cost savings)"

BATCH_JUDGE_FLAG=""
[ "$BATCH_JUDGE" = true ] && BATCH_JUDGE_FLAG="--batch-judge" && echo "  Batch Judge: enabled (50% cost savings)"

VLLM_FLAGS=""
[ "$MODEL_PROVIDER" = "vllm" ] && VLLM_FLAGS="--vllm-base-url $VLLM_BASE_URL --vllm-api-key $VLLM_API_KEY" && echo "  vLLM: $VLLM_BASE_URL"

mkdir -p results

# Run evaluation for each model
for MODEL in $MODELS; do
    echo ""
    echo -e "${BLUE}>>> Evaluating: $MODEL ($MODEL_PROVIDER)${NC}"

    if [ "$JUDGE_PROVIDER" = "both" ]; then
        python baselines/run_llm_baselines.py --models "$MODEL" --provider "$MODEL_PROVIDER" \
            --dataset "$DATASET_PATH" --use-judge --judge-provider openai $MAX_FLAG $SHUFFLE_FLAG $PROMPT_FLAG $SKIP_INVALID_FLAG $BATCH_FLAG $BATCH_JUDGE_FLAG $VLLM_FLAGS --output results
        python baselines/run_llm_baselines.py --models "$MODEL" --provider "$MODEL_PROVIDER" \
            --dataset "$DATASET_PATH" --use-judge --judge-provider anthropic $MAX_FLAG $SHUFFLE_FLAG $PROMPT_FLAG $SKIP_INVALID_FLAG $BATCH_FLAG $BATCH_JUDGE_FLAG $VLLM_FLAGS --output results
    elif [ "$JUDGE_PROVIDER" = "none" ]; then
        python baselines/run_llm_baselines.py --models "$MODEL" --provider "$MODEL_PROVIDER" \
            --dataset "$DATASET_PATH" $MAX_FLAG $SHUFFLE_FLAG $PROMPT_FLAG $SKIP_INVALID_FLAG $BATCH_FLAG $VLLM_FLAGS --output results
    else
        python baselines/run_llm_baselines.py --models "$MODEL" --provider "$MODEL_PROVIDER" \
            --dataset "$DATASET_PATH" --use-judge --judge-provider "$JUDGE_PROVIDER" $MAX_FLAG $SHUFFLE_FLAG $PROMPT_FLAG $SKIP_INVALID_FLAG $BATCH_FLAG $BATCH_JUDGE_FLAG $VLLM_FLAGS --output results
    fi
done

echo ""

# =============================================================================
# Step 4: Optional Static Analysis
# =============================================================================
if [ "$RUN_STATIC_ANALYSIS" = true ]; then
    echo -e "${YELLOW}[4/5] Running static analysis...${NC}"
    python baselines/run_static_analysis.py --dataset "$DATASET_PATH" --tool both --verbose
    echo ""
else
    echo -e "${YELLOW}[4/5] Skipping static analysis (use --static-analysis)${NC}"
fi

# =============================================================================
# Step 5: Results Summary
# =============================================================================
echo -e "${YELLOW}[5/5] Results summary...${NC}"
echo ""

# Find all recent results across model subdirectories
ALL_RESULTS=$(find results -name "baseline_results_*.json" -newer results 2>/dev/null | sort)

if [ -z "$ALL_RESULTS" ]; then
    # Fallback: find most recent across all subdirs
    ALL_RESULTS=$(find results -name "baseline_results_*.json" 2>/dev/null | sort -t_ -k3 -r)
fi

if [ -n "$ALL_RESULTS" ]; then
    echo -e "${GREEN}Results directories:${NC}"
    ls -d results/*/ 2>/dev/null | while read dir; do
        count=$(ls "$dir"baseline_results_*.json 2>/dev/null | wc -l)
        [ "$count" -gt 0 ] && echo -e "  ${GREEN}✓${NC} $dir ($count files)"
    done
    echo ""

    # Summarize each results file
    for RESULT_FILE in $ALL_RESULTS; do
        echo -e "${GREEN}$RESULT_FILE${NC}"
        python -c "
import json
with open('$RESULT_FILE') as f:
    data = json.load(f)
print('='*60)
for result in data['results']:
    print(f\"Model: {result['model_name']}\")
    print(f\"  Mutation Score: {result['avg_mutation_score']:.1%}\")
    sms = result.get('avg_security_mutation_score')
    if sms: print(f\"  Security MS: {sms:.1%}\")
    print(f\"  Vuln Detection: {result['avg_vuln_detection']:.1%}\")
    # Kill breakdown from detailed results
    details = result.get('detailed_results', [])
    if details:
        all_mutants = [m for d in details for m in d.get('mutant_details', [])]
        killed = [m for m in all_mutants if m.get('killed')]
        sem = sum(1 for m in killed if m.get('kill_type') == 'semantic')
        inc = sum(1 for m in killed if m.get('kill_type') == 'assertion_incidental')
        crash = sum(1 for m in killed if m.get('kill_type') == 'crash')
        print(f\"  Kills: {len(killed)}/{len(all_mutants)} (Semantic:{sem} Incidental:{inc} Crash:{crash})\")
    print(f\"  Errors: {result['errors']}, Time: {result['evaluation_time']:.1f}s\")
    print()
print('='*60)
"
        echo ""
    done
fi

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Evaluation Complete!                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
