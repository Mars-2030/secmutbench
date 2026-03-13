"""
LLM-as-Judge Evaluation for SecMutBench

Provides multi-modal evaluation using LLM judges to assess:
- Security relevance of generated tests
- Test quality and completeness
- Attack vector coverage

Supports Claude (Anthropic), GPT-4 (OpenAI), and Gemini (Google) as judge models.
"""

import json
import os
import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from abc import ABC, abstractmethod
import time
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

# Import unified prompts (lazy import to avoid circular dependency)
def _get_prompts():
    from evaluation.prompts import (
        SECURITY_RELEVANCE_SYSTEM_PROMPT,
        format_security_relevance_prompt,
        TEST_QUALITY_SYSTEM_PROMPT,
        format_test_quality_prompt,
    )
    return {
        'security_system': SECURITY_RELEVANCE_SYSTEM_PROMPT,
        'security_prompt': format_security_relevance_prompt,
        'quality_system': TEST_QUALITY_SYSTEM_PROMPT,
        'quality_prompt': format_test_quality_prompt,
    }

# Load .env file if it exists
def load_dotenv():
    """Load environment variables from .env file."""
    env_paths = [
        Path(__file__).parent.parent / ".env",  # Project root
        Path.cwd() / ".env",  # Current directory
    ]
    for env_path in env_paths:
        if env_path.exists():
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key and value:
                            os.environ.setdefault(key, value)
            break

load_dotenv()

# Default judge model - configurable via environment variable
DEFAULT_JUDGE_MODEL = os.getenv("SECMUTBENCH_JUDGE_MODEL", "claude-opus-4-6")
DEFAULT_JUDGE_PROVIDER = os.getenv("SECMUTBENCH_JUDGE_PROVIDER", "anthropic")
DEFAULT_OPENAI_MODEL = os.getenv("SECMUTBENCH_OPENAI_MODEL", "gpt-5.2-2025-12-11")


@dataclass
class JudgeScore:
    """Score from LLM judge evaluation."""
    metric: str
    score: float  # 0-1 normalized
    reasoning: str
    confidence: float  # 0-1
    raw_response: Optional[str] = None


@dataclass
class SecurityRelevanceScore(JudgeScore):
    """Detailed security relevance assessment."""
    cwe_addressed: bool = False
    attack_vectors_tested: List[str] = field(default_factory=list)
    security_properties_checked: List[str] = field(default_factory=list)


@dataclass
class TestQualityScore(JudgeScore):
    """Detailed test quality assessment."""
    assertions_count: int = 0
    edge_cases_covered: int = 0
    follows_best_practices: bool = False
    issues_found: List[str] = field(default_factory=list)


@dataclass
class MultiModalEvaluation:
    """Complete multi-modal evaluation result."""
    sample_id: str
    generated_tests: str

    # Execution-based metrics (from mutation testing)
    mutation_score: float = 0.0
    coverage_score: float = 0.0

    # LLM-as-Judge metrics
    security_relevance: Optional[SecurityRelevanceScore] = None
    test_quality: Optional[TestQualityScore] = None

    # Weighted composite score
    composite_score: float = 0.0

    # Weights used
    weights: Dict[str, float] = field(default_factory=dict)

    def calculate_composite(self, weights: Optional[Dict[str, float]] = None):
        """Calculate weighted composite score."""
        if weights is None:
            weights = {
                'mutation_score': 0.50,
                'security_relevance': 0.20,
                'test_quality': 0.15,
                'coverage': 0.15,
            }

        self.weights = weights

        scores = {
            'mutation_score': self.mutation_score,
            'coverage': self.coverage_score,
        }

        if self.security_relevance:
            scores['security_relevance'] = self.security_relevance.score
        if self.test_quality:
            scores['test_quality'] = self.test_quality.score

        self.composite_score = sum(
            scores.get(metric, 0) * weight
            for metric, weight in weights.items()
        )

        return self.composite_score


class LLMJudge(ABC):
    """Abstract base class for LLM judges."""

    @abstractmethod
    def evaluate(
        self,
        generated_tests: str,
        sample: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> JudgeScore:
        """Evaluate generated tests."""
        pass


class AnthropicJudge(LLMJudge):
    """LLM judge using Anthropic Claude API."""

    def __init__(
        self,
        model: str = DEFAULT_JUDGE_MODEL,
        api_key: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ):
        self.model = model
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("anthropic package required: pip install anthropic")
        return self._client

    def _call_api(self, prompt: str, system_prompt: str) -> str:
        """Call Anthropic Claude API."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[
                {"role": "user", "content": prompt},
            ],
            temperature=self.temperature,
        )
        return response.content[0].text

    def evaluate(
        self,
        generated_tests: str,
        sample: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> JudgeScore:
        """Generic evaluation - override in subclasses."""
        raise NotImplementedError("Use specific judge classes")


class OpenAIJudge(LLMJudge):
    """LLM judge using OpenAI API."""

    def __init__(
        self,
        model: str = DEFAULT_OPENAI_MODEL,
        api_key: Optional[str] = None,
        temperature: float = 0.0,
    ):
        self.model = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.temperature = temperature
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("openai package required: pip install openai")
        return self._client

    def _call_api(self, prompt: str, system_prompt: str) -> str:
        """Call OpenAI API."""
        # Build request parameters
        params = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
        }
        # gpt-5 doesn't support temperature=0.0, only default (1.0)
        if "gpt-5" not in self.model:
            params["temperature"] = self.temperature

        response = self.client.chat.completions.create(**params)
        return response.choices[0].message.content

    def evaluate(
        self,
        generated_tests: str,
        sample: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> JudgeScore:
        """Generic evaluation - override in subclasses."""
        raise NotImplementedError("Use specific judge classes")


class GeminiJudge(LLMJudge):
    """LLM judge using Google Gemini API."""

    def __init__(
        self,
        model: str = "gemini-3.0-flash",
        api_key: Optional[str] = None,
        temperature: float = 0.0,
    ):
        self.model = model
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.temperature = temperature
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(self.model)
            except ImportError:
                raise ImportError("google-generativeai package required: pip install google-generativeai")
        return self._client

    def _call_api(self, prompt: str, system_prompt: str) -> str:
        """Call Google Gemini API."""
        # Gemini combines system prompt with user prompt
        full_prompt = f"{system_prompt}\n\n{prompt}"

        generation_config = {
            "temperature": self.temperature,
            "max_output_tokens": 1024,
        }

        response = self.client.generate_content(
            full_prompt,
            generation_config=generation_config,
        )
        return response.text

    def evaluate(
        self,
        generated_tests: str,
        sample: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> JudgeScore:
        """Generic evaluation - override in subclasses."""
        raise NotImplementedError("Use specific judge classes")


class SecurityRelevanceJudge(LLMJudge):
    """Judge for evaluating security relevance of tests. Supports Claude, GPT-4, and Gemini."""

    def __init__(
        self,
        model: str = DEFAULT_JUDGE_MODEL,
        provider: str = DEFAULT_JUDGE_PROVIDER,
        api_key: Optional[str] = None,
        temperature: float = 0.0,
    ):
        self.model = model
        self.provider = provider.lower()
        self.temperature = temperature
        self._prompts = None  # Lazy load

        if self.provider == "anthropic":
            self._base_judge = AnthropicJudge(model=model, api_key=api_key, temperature=temperature)
        elif self.provider == "google":
            self._base_judge = GeminiJudge(model=model, api_key=api_key, temperature=temperature)
        else:
            self._base_judge = OpenAIJudge(model=model, api_key=api_key, temperature=temperature)

    @property
    def prompts(self):
        """Lazy load prompts to avoid circular import."""
        if self._prompts is None:
            self._prompts = _get_prompts()
        return self._prompts

    def evaluate(
        self,
        generated_tests: str,
        sample: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityRelevanceScore:
        """Evaluate security relevance of generated tests."""
        # Use unified prompt from evaluation.prompts
        prompt = self.prompts['security_prompt'](
            code=sample.get('secure_code', ''),
            tests=generated_tests,
            cwe=sample.get('cwe', 'unknown'),
            cwe_name=sample.get('cwe_name', 'vulnerability'),
        )
        system_prompt = self.prompts['security_system']

        try:
            response = self._base_judge._call_api(prompt, system_prompt)
            result = self._parse_response(response)

            return SecurityRelevanceScore(
                metric="security_relevance",
                score=result.get("score", 0) / 100,
                reasoning=result.get("reasoning", ""),
                confidence=result.get("confidence", 0) / 100,
                raw_response=response,
                cwe_addressed=result.get("cwe_addressed", False),
                attack_vectors_tested=result.get("attack_vectors_tested", []),
                security_properties_checked=result.get("security_properties_checked", []),
            )
        except Exception as e:
            return SecurityRelevanceScore(
                metric="security_relevance",
                score=0.0,
                reasoning=f"Evaluation error: {str(e)}",
                confidence=0.0,
            )

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response from LLM."""
        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return {}


class TestQualityJudge(LLMJudge):
    """Judge for evaluating test quality. Supports Claude, GPT-4, and Gemini."""

    def __init__(
        self,
        model: str = DEFAULT_JUDGE_MODEL,
        provider: str = DEFAULT_JUDGE_PROVIDER,
        api_key: Optional[str] = None,
        temperature: float = 0.0,
    ):
        self.model = model
        self.provider = provider.lower()
        self.temperature = temperature
        self._prompts = None  # Lazy load

        if self.provider == "anthropic":
            self._base_judge = AnthropicJudge(model=model, api_key=api_key, temperature=temperature)
        elif self.provider == "google":
            self._base_judge = GeminiJudge(model=model, api_key=api_key, temperature=temperature)
        else:
            self._base_judge = OpenAIJudge(model=model, api_key=api_key, temperature=temperature)

    @property
    def prompts(self):
        """Lazy load prompts to avoid circular import."""
        if self._prompts is None:
            self._prompts = _get_prompts()
        return self._prompts

    def evaluate(
        self,
        generated_tests: str,
        sample: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> TestQualityScore:
        """Evaluate quality of generated tests."""
        # Use unified prompt from evaluation.prompts
        prompt = self.prompts['quality_prompt'](
            tests=generated_tests,
            entry_point=sample.get('entry_point', 'function'),
            cwe=sample.get('cwe', ''),
            difficulty=sample.get('difficulty', 'unknown'),
        )
        system_prompt = self.prompts['quality_system']

        try:
            response = self._base_judge._call_api(prompt, system_prompt)
            result = self._parse_response(response)

            return TestQualityScore(
                metric="test_quality",
                score=result.get("score", 0) / 100,
                reasoning=result.get("reasoning", ""),
                confidence=result.get("confidence", 0) / 100,
                raw_response=response,
                assertions_count=result.get("assertions_count", 0),
                edge_cases_covered=result.get("edge_cases_covered", 0),
                follows_best_practices=result.get("follows_best_practices", False),
                issues_found=result.get("issues_found", []),
            )
        except Exception as e:
            return TestQualityScore(
                metric="test_quality",
                score=0.0,
                reasoning=f"Evaluation error: {str(e)}",
                confidence=0.0,
            )

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response from LLM."""
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return {}


class MultiModalEvaluator:
    """
    Complete multi-modal evaluator combining execution and LLM-as-judge metrics.

    Weights:
    - Mutation Score: 50%
    - Security Relevance (LLM Judge): 20%
    - Test Quality (LLM Judge): 15%
    - Coverage: 15%
    """

    DEFAULT_WEIGHTS = {
        'mutation_score': 0.50,
        'security_relevance': 0.20,
        'test_quality': 0.15,
        'coverage': 0.15,
    }

    def __init__(
        self,
        security_judge: Optional[LLMJudge] = None,
        quality_judge: Optional[LLMJudge] = None,
        weights: Optional[Dict[str, float]] = None,
    ):
        self.security_judge = security_judge or SecurityRelevanceJudge()
        self.quality_judge = quality_judge or TestQualityJudge()
        self.weights = weights or self.DEFAULT_WEIGHTS

    def evaluate(
        self,
        sample: Dict[str, Any],
        generated_tests: str,
        execution_results: Optional[Dict[str, Any]] = None,
    ) -> MultiModalEvaluation:
        """
        Perform complete multi-modal evaluation.

        Args:
            sample: Benchmark sample
            generated_tests: LLM-generated test code
            execution_results: Results from mutation testing

        Returns:
            MultiModalEvaluation with all scores
        """
        eval_result = MultiModalEvaluation(
            sample_id=sample.get("id", "unknown"),
            generated_tests=generated_tests,
        )

        # Get execution-based scores
        if execution_results:
            metrics = execution_results.get("metrics", {})
            eval_result.mutation_score = metrics.get("mutation_score", 0.0)
            eval_result.coverage_score = metrics.get("line_coverage", 0.0)

        # Get LLM judge scores
        if generated_tests.strip():
            try:
                security_score = self.security_judge.evaluate(
                    generated_tests, sample
                )
                if isinstance(security_score, SecurityRelevanceScore):
                    eval_result.security_relevance = security_score
                else:
                    eval_result.security_relevance = SecurityRelevanceScore(
                        metric="security_relevance",
                        score=security_score.score,
                        reasoning=security_score.reasoning,
                        confidence=security_score.confidence,
                    )
            except Exception as e:
                eval_result.security_relevance = SecurityRelevanceScore(
                    metric="security_relevance",
                    score=0.0,
                    reasoning=f"Error: {str(e)}",
                    confidence=0.0,
                )

            try:
                quality_score = self.quality_judge.evaluate(
                    generated_tests, sample
                )
                if isinstance(quality_score, TestQualityScore):
                    eval_result.test_quality = quality_score
                else:
                    eval_result.test_quality = TestQualityScore(
                        metric="test_quality",
                        score=quality_score.score,
                        reasoning=quality_score.reasoning,
                        confidence=quality_score.confidence,
                    )
            except Exception as e:
                eval_result.test_quality = TestQualityScore(
                    metric="test_quality",
                    score=0.0,
                    reasoning=f"Error: {str(e)}",
                    confidence=0.0,
                )

        # Calculate composite score
        eval_result.calculate_composite(self.weights)

        return eval_result

    def evaluate_batch(
        self,
        samples: List[Dict[str, Any]],
        generated_tests_list: List[str],
        execution_results_list: Optional[List[Dict[str, Any]]] = None,
        progress_callback: Optional[callable] = None,
    ) -> List[MultiModalEvaluation]:
        """Evaluate multiple samples."""
        results = []

        if execution_results_list is None:
            execution_results_list = [None] * len(samples)

        for i, (sample, tests, exec_results) in enumerate(
            zip(samples, generated_tests_list, execution_results_list)
        ):
            if progress_callback:
                progress_callback(i + 1, len(samples))

            result = self.evaluate(sample, tests, exec_results)
            results.append(result)

            # Rate limiting for API calls
            time.sleep(0.5)

        return results

    def aggregate_results(
        self,
        results: List[MultiModalEvaluation],
    ) -> Dict[str, Any]:
        """Aggregate multi-modal evaluation results."""
        if not results:
            return {"error": "No results to aggregate"}

        mutation_scores = [r.mutation_score for r in results]
        coverage_scores = [r.coverage_score for r in results]
        security_scores = [
            r.security_relevance.score
            for r in results if r.security_relevance
        ]
        quality_scores = [
            r.test_quality.score
            for r in results if r.test_quality
        ]
        composite_scores = [r.composite_score for r in results]

        def safe_mean(lst):
            return sum(lst) / len(lst) if lst else 0.0

        return {
            "samples": len(results),
            "weights": self.weights,
            "execution_metrics": {
                "avg_mutation_score": safe_mean(mutation_scores),
                "avg_coverage": safe_mean(coverage_scores),
            },
            "llm_judge_metrics": {
                "avg_security_relevance": safe_mean(security_scores),
                "avg_test_quality": safe_mean(quality_scores),
            },
            "composite": {
                "avg_composite_score": safe_mean(composite_scores),
                "min_composite": min(composite_scores) if composite_scores else 0,
                "max_composite": max(composite_scores) if composite_scores else 0,
            },
        }

    def evaluate_batch_api(
        self,
        samples: List[Dict[str, Any]],
        generated_tests_list: List[str],
        execution_results_list: Optional[List[Dict[str, Any]]] = None,
        provider: str = "anthropic",
        model: Optional[str] = None,
        progress_callback: Optional[callable] = None,
    ) -> List[MultiModalEvaluation]:
        """
        Evaluate multiple samples using batch API for cost savings.

        Uses native batch APIs for Anthropic/OpenAI (50% savings) or
        async concurrency for Google.

        Args:
            samples: List of benchmark samples
            generated_tests_list: List of generated test code strings
            execution_results_list: Optional execution results per sample
            provider: "anthropic", "openai", or "google"
            model: Model to use (defaults to provider default)
            progress_callback: Optional callback(completed, total)

        Returns:
            List of MultiModalEvaluation results
        """
        from baselines.batch_api import create_batch_processor, BatchRequest

        if execution_results_list is None:
            execution_results_list = [None] * len(samples)

        # Get prompts module
        prompts = _get_prompts()

        # Prepare batch requests for both security and quality evaluation
        security_requests = []
        quality_requests = []

        for i, (sample, tests) in enumerate(zip(samples, generated_tests_list)):
            if not tests.strip():
                continue

            # Security relevance prompt
            sec_prompt = prompts['security_prompt'](
                code=sample.get('secure_code', ''),
                tests=tests,
                cwe=sample.get('cwe', 'Unknown'),
                cwe_name=sample.get('cwe_name', 'vulnerability'),
            )
            security_requests.append(BatchRequest(
                custom_id=f"sec-{sample.get('id', i)}",
                prompt=sec_prompt,
                system_prompt=prompts['security_system'],
                metadata={"sample_idx": i, "type": "security"},
            ))

            # Test quality prompt
            qual_prompt = prompts['quality_prompt'](
                tests=tests,
                entry_point=sample.get('entry_point', 'function'),
                cwe=sample.get('cwe', 'Unknown'),
                difficulty=sample.get('difficulty', 'unknown'),
            )
            quality_requests.append(BatchRequest(
                custom_id=f"qual-{sample.get('id', i)}",
                prompt=qual_prompt,
                system_prompt=prompts['quality_system'],
                metadata={"sample_idx": i, "type": "quality"},
            ))

        # Determine model
        if model is None:
            if provider == "anthropic":
                model = DEFAULT_JUDGE_MODEL
            elif provider == "google":
                model = "gemini-3.0-flash"
            else:
                model = DEFAULT_OPENAI_MODEL

        # Process both batches
        processor = create_batch_processor(provider)

        print(f"  Submitting {len(security_requests)} security evaluation requests...")
        sec_result = processor.process_batch(security_requests, model)

        print(f"  Submitting {len(quality_requests)} quality evaluation requests...")
        qual_result = processor.process_batch(quality_requests, model)

        # Map responses back
        sec_responses = {r.custom_id: r for r in sec_result.responses}
        qual_responses = {r.custom_id: r for r in qual_result.responses}

        # Build evaluation results
        results = []
        for i, (sample, tests, exec_results) in enumerate(
            zip(samples, generated_tests_list, execution_results_list)
        ):
            eval_result = MultiModalEvaluation(
                sample_id=sample.get("id", "unknown"),
                generated_tests=tests,
            )

            # Get execution-based scores
            if exec_results:
                metrics = exec_results.get("metrics", {})
                eval_result.mutation_score = metrics.get("mutation_score", 0.0)
                eval_result.coverage_score = metrics.get("line_coverage", 0.0)

            # Parse security response
            sec_resp = sec_responses.get(f"sec-{sample.get('id', i)}")
            if sec_resp and sec_resp.success:
                try:
                    parsed = self._parse_judge_response(sec_resp.content)
                    eval_result.security_relevance = SecurityRelevanceScore(
                        metric="security_relevance",
                        score=parsed.get("score", 0) / 100,
                        reasoning=parsed.get("reasoning", ""),
                        confidence=parsed.get("confidence", 0) / 100,
                        raw_response=sec_resp.content,
                    )
                except Exception:
                    eval_result.security_relevance = SecurityRelevanceScore(
                        metric="security_relevance",
                        score=0.0,
                        reasoning="Parse error",
                        confidence=0.0,
                    )

            # Parse quality response
            qual_resp = qual_responses.get(f"qual-{sample.get('id', i)}")
            if qual_resp and qual_resp.success:
                try:
                    parsed = self._parse_judge_response(qual_resp.content)
                    eval_result.test_quality = TestQualityScore(
                        metric="test_quality",
                        score=parsed.get("score", 0) / 100,
                        reasoning=parsed.get("reasoning", ""),
                        confidence=parsed.get("confidence", 0) / 100,
                        raw_response=qual_resp.content,
                    )
                except Exception:
                    eval_result.test_quality = TestQualityScore(
                        metric="test_quality",
                        score=0.0,
                        reasoning="Parse error",
                        confidence=0.0,
                    )

            # Calculate composite score
            eval_result.calculate_composite(self.weights)
            results.append(eval_result)

            if progress_callback:
                progress_callback(i + 1, len(samples))

        return results

    def _parse_judge_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response from judge."""
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return {}


def format_multimodal_report(
    aggregate: Dict[str, Any],
    detailed_results: Optional[List[MultiModalEvaluation]] = None,
) -> str:
    """Format multi-modal evaluation results as a report."""
    lines = [
        "=" * 70,
        "SecMutBench Multi-Modal Evaluation Report",
        "=" * 70,
        "",
        "Evaluation Weights:",
    ]

    weights = aggregate.get("weights", {})
    for metric, weight in weights.items():
        lines.append(f"  {metric}: {weight:.0%}")

    lines.extend([
        "",
        "-" * 70,
        "Execution-Based Metrics:",
        f"  Avg Mutation Score:     {aggregate['execution_metrics']['avg_mutation_score']:.2%}",
        f"  Avg Coverage:           {aggregate['execution_metrics']['avg_coverage']:.2%}",
        "",
        "LLM-as-Judge Metrics:",
        f"  Avg Security Relevance: {aggregate['llm_judge_metrics']['avg_security_relevance']:.2%}",
        f"  Avg Test Quality:       {aggregate['llm_judge_metrics']['avg_test_quality']:.2%}",
        "",
        "-" * 70,
        "Composite Score:",
        f"  Average: {aggregate['composite']['avg_composite_score']:.2%}",
        f"  Range:   [{aggregate['composite']['min_composite']:.2%} - {aggregate['composite']['max_composite']:.2%}]",
        "",
        "=" * 70,
    ])

    return "\n".join(lines)


# Convenience functions
def create_evaluator(
    provider: str = "anthropic",
    model: Optional[str] = None,
    weights: Optional[Dict[str, float]] = None,
) -> MultiModalEvaluator:
    """
    Create a multi-modal evaluator with specified configuration.

    Args:
        provider: "anthropic" for Claude, "openai" for GPT, or "google" for Gemini
        model: Model name (defaults based on provider)
        weights: Custom weights for evaluation metrics

    Returns:
        MultiModalEvaluator instance

    Raises:
        ValueError: If API key is not set for the specified provider
    """
    provider = provider.lower()

    # Set default model based on provider
    if model is None:
        if provider == "anthropic":
            model = DEFAULT_JUDGE_MODEL  # claude-sonnet-4-5-20250929
        elif provider == "google":
            model = "gemini-3.0-flash"
        else:
            model = DEFAULT_OPENAI_MODEL  # gpt-5.2-2025-12-11

    # Check for API key
    if provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. Please set it in .env file or environment variable.\n"
                "Example: echo 'ANTHROPIC_API_KEY=your-key' > .env"
            )
    elif provider == "google":
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY not set. Please set it in .env file or environment variable.\n"
                "Example: echo 'GEMINI_API_KEY=your-key' > .env"
            )
    else:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not set. Please set it in .env file or environment variable.\n"
                "Example: echo 'OPENAI_API_KEY=your-key' > .env"
            )

    return MultiModalEvaluator(
        security_judge=SecurityRelevanceJudge(model=model, provider=provider),
        quality_judge=TestQualityJudge(model=model, provider=provider),
        weights=weights,
    )


if __name__ == "__main__":
    # Demo - requires ANTHROPIC_API_KEY to be set
    sample = {
        "id": "sql_injection_001",
        "cwe": "CWE-89",
        "cwe_name": "SQL Injection",
        "secure_code": "def get_user(id): cursor.execute('SELECT * FROM users WHERE id = ?', (id,))",
        "entry_point": "get_user",
        "difficulty": "easy",
    }

    generated_tests = """
def test_sql_injection():
    result = get_user("1 OR 1=1")
    assert result is None or len(result) <= 1

def test_union_injection():
    result = get_user("1 UNION SELECT * FROM passwords")
    assert 'password' not in str(result)
"""

    execution_results = {
        "metrics": {
            "mutation_score": 0.75,
            "line_coverage": 0.85,
        }
    }

    try:
        evaluator = create_evaluator(provider="anthropic")
        result = evaluator.evaluate(sample, generated_tests, execution_results)

        print("Sample:", result.sample_id)
        print(f"Mutation Score: {result.mutation_score:.2%}")
        print(f"Coverage: {result.coverage_score:.2%}")
        if result.security_relevance:
            print(f"Security Relevance: {result.security_relevance.score:.2%}")
        if result.test_quality:
            print(f"Test Quality: {result.test_quality.score:.2%}")
        print(f"Composite Score: {result.composite_score:.2%}")
    except ValueError as e:
        print(f"Error: {e}")
