#!/bin/bash
#
# SecMutBench Dataset Build and Evaluation Pipeline
#
# This script builds the dataset and runs all validation/evaluation scripts.
#
# Usage: ./build_db.sh [samples] [seed]
#   samples: Number of target samples (default: 3000)
#   seed:    Random seed (default: 2026)
#
# Examples:
#   ./build_db.sh              # 3000 samples, seed 2026
#   ./build_db.sh 500          # 500 samples, seed 2026
#   ./build_db.sh 500 42       # 500 samples, seed 42
#

set -e  # Exit on error

# Parse arguments with defaults
SAMPLES=${1:-3000}
SEED=${2:-2026}

echo "============================================================"
echo "SecMutBench Build and Evaluation Pipeline"
echo "============================================================"
echo "  Target samples: $SAMPLES"
echo "  Random seed:    $SEED"
echo "============================================================"
echo ""

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Create results directory if it doesn't exist
mkdir -p results

# Step 1: Build the dataset
echo "[Step 1/5] Building dataset..."
echo "------------------------------------------------------------"
VARIATIONS_FLAG=""
if [ -f "data/variations.json" ]; then
    echo "  Found data/variations.json — including LLM variations"
    VARIATIONS_FLAG="--include-variations data/variations.json"
fi
python scripts/dataset_builder.py --target "$SAMPLES" --seed "$SEED" --min-samples 3 --verbose-drop $VARIATIONS_FLAG 2>&1 | tee build_db.log
echo ""

# Step 2: Validate dataset quality (VD validation)
echo "[Step 2/5] Validating dataset quality..."
echo "------------------------------------------------------------"
python scripts/validate_dataset_quality.py --output results/dataset_quality.json
echo ""

# Step 3: Compute mutant validity (syntax check)
echo "[Step 3/5] Computing mutant validity..."
echo "------------------------------------------------------------"
python scripts/compute_mutant_validity.py --output results/mutant_validity.json
echo ""

# Step 4: Build validation dataset and run CWEval validation
# echo "[Step 4/5] Running CWEval validation..."
# echo "------------------------------------------------------------"
# python scripts/build_validation_dataset.py
# python evaluation/validate_with_cweval.py --output results/validationcweval.json
# echo ""

# Step 5: Evaluate reference tests (upper bound)
echo "[Step 5/5] Evaluating reference tests..."
echo "------------------------------------------------------------"
python scripts/evaluate_reference_tests.py --output results/reference_baseline.json
echo ""

echo "============================================================"
echo "Pipeline Complete!"
echo "============================================================"
echo ""
echo "Results saved to:"
echo "  - results/dataset_quality.json"
echo "  - results/mutant_validity.json"
# echo "  - results/validationcweval.json"
echo "  - results/reference_baseline.json"
echo ""
