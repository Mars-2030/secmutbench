"""
SecMutBench Evaluation Module

Provides tools for evaluating LLM-generated security tests
using mutation testing with multi-modal LLM-as-Judge support.
"""

from .mutation_engine import MutationEngine, generate_mutants
from .test_runner import TestRunner, run_tests
from .metrics import (
    calculate_mutation_score,
    calculate_metrics,
    aggregate_by_cwe,
    aggregate_by_difficulty,
    aggregate_by_operator,
    get_survived_mutants,
    analyze_survival_patterns,
    format_metrics_report,
)
from .evaluate import (
    evaluate_generated_tests,
    evaluate_model,
    evaluate_multimodal,
    load_benchmark,
)
from .llm_judge import (
    MultiModalEvaluator,
    MultiModalEvaluation,
    SecurityRelevanceJudge,
    TestQualityJudge,
    create_evaluator,
    format_multimodal_report,
)

__all__ = [
    # Mutation Engine
    'MutationEngine',
    'generate_mutants',
    # Test Runner
    'TestRunner',
    'run_tests',
    # Metrics
    'calculate_mutation_score',
    'calculate_metrics',
    'aggregate_by_cwe',
    'aggregate_by_difficulty',
    'aggregate_by_operator',
    'get_survived_mutants',
    'analyze_survival_patterns',
    'format_metrics_report',
    # Evaluation
    'evaluate_generated_tests',
    'evaluate_model',
    'evaluate_multimodal',
    'load_benchmark',
    # LLM-as-Judge
    'MultiModalEvaluator',
    'MultiModalEvaluation',
    'SecurityRelevanceJudge',
    'TestQualityJudge',
    'create_evaluator',
    'format_multimodal_report',
]
