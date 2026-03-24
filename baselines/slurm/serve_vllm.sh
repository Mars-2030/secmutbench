#!/bin/bash
# =============================================================================
# Generic vLLM serving script for ARC cluster
# Usage: sbatch serve_vllm.sh <model_path> <served_name> <port> [gpus] [max_len]
#
# Examples:
#   sbatch serve_vllm.sh openai--gpt-oss-120b gpt-oss-120b 8000
#   sbatch serve_vllm.sh moonshotai--Kimi-K2.5 Kimi-K2.5 8001 2 32768
#   sbatch serve_vllm.sh zai-org--GLM-5 GLM-5 8002
#   sbatch serve_vllm.sh zai-org--GLM-4.7 GLM-4.7 8003
#   sbatch serve_vllm.sh moonshotai--Kimi-K2-Thinking Kimi-K2-Thinking 8004
#
# To run all 5 in parallel (different ports):
#   sbatch serve_vllm.sh openai--gpt-oss-120b gpt-oss-120b 8000
#   sbatch serve_vllm.sh moonshotai--Kimi-K2.5 Kimi-K2.5 8001
#   sbatch serve_vllm.sh zai-org--GLM-5 GLM-5 8002
#   sbatch serve_vllm.sh zai-org--GLM-4.7 GLM-4.7 8003
#   sbatch serve_vllm.sh moonshotai--Kimi-K2-Thinking Kimi-K2-Thinking 8004
# =============================================================================

#SBATCH --account=fllm
#SBATCH --partition=l40s_normal_q
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=32
#SBATCH --gres=gpu:l40s:2
#SBATCH --time=1-0:00:00
#SBATCH --output=vllm_%j.log

# Parse arguments (with defaults)
MODEL_PATH="${1:?Usage: sbatch serve_vllm.sh <model_path> <served_name> <port>}"
SERVED_NAME="${2:?Usage: sbatch serve_vllm.sh <model_path> <served_name> <port>}"
PORT="${3:?Usage: sbatch serve_vllm.sh <model_path> <served_name> <port>}"
GPUS="${4:-2}"
MAX_MODEL_LEN="${5:-32768}"
API_KEY="${VLLM_API_KEY:-secmutbench2026}"

module load vLLM

echo "Starting vLLM server:"
echo "  Model: /common/data/models/${MODEL_PATH}"
echo "  Served as: ${SERVED_NAME}"
echo "  Port: ${PORT}"
echo "  GPUs: ${GPUS}"
echo "  Max model len: ${MAX_MODEL_LEN}"
echo "  Node: $(hostname)"

vllm serve "/common/data/models/${MODEL_PATH}" \
    --served-model-name "${SERVED_NAME}" \
    --tensor-parallel-size "${GPUS}" \
    --max-model-len "${MAX_MODEL_LEN}" \
    --port "${PORT}" \
    --api-key "${API_KEY}" \
    --trust-remote-code
