#!/usr/bin/env python3
"""
Batch API Support for SecMutBench

Provides batch processing for LLM API calls to reduce costs and improve throughput:
- Anthropic: Native Message Batches API (50% cost savings)
- OpenAI: Native Batch API (50% cost savings)
- Google: Async concurrent calls (no native batch, but parallel execution)

Usage:
    from baselines.batch_api import create_batch_processor

    processor = create_batch_processor("anthropic")
    results = processor.process_batch(requests)
"""

import os
import json
import time
import asyncio
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


@dataclass
class BatchRequest:
    """A single request in a batch."""
    custom_id: str
    prompt: str
    system_prompt: str = "You are a security testing expert. Generate only Python test code, no explanations."
    max_tokens: int = 2048
    temperature: float = 0.2
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BatchResponse:
    """Response from a batch request."""
    custom_id: str
    content: str
    success: bool = True
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BatchResult:
    """Result of a batch processing job."""
    batch_id: str
    provider: str
    status: str  # "pending", "processing", "completed", "failed"
    total_requests: int
    completed_requests: int
    failed_requests: int
    responses: List[BatchResponse] = field(default_factory=list)
    created_at: str = ""
    completed_at: str = ""
    cost_savings: str = "50%"  # Anthropic/OpenAI batch discount


class BatchProcessor(ABC):
    """Abstract base class for batch processors."""

    @abstractmethod
    def create_batch(self, requests: List[BatchRequest], model: str) -> str:
        """Create a batch job and return batch ID."""
        pass

    @abstractmethod
    def get_batch_status(self, batch_id: str) -> BatchResult:
        """Get the status of a batch job."""
        pass

    @abstractmethod
    def get_batch_results(self, batch_id: str) -> BatchResult:
        """Get results when batch is complete."""
        pass

    def process_batch(
        self,
        requests: List[BatchRequest],
        model: str,
        poll_interval: int = 60,
        max_wait_hours: int = 24,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> BatchResult:
        """
        Process a batch synchronously (submit and wait for completion).

        Args:
            requests: List of batch requests
            model: Model name to use
            poll_interval: Seconds between status checks
            max_wait_hours: Maximum hours to wait for completion
            progress_callback: Optional callback(status, completed, total)

        Returns:
            BatchResult with all responses
        """
        batch_id = self.create_batch(requests, model)
        print(f"  Batch submitted: {batch_id}")

        max_polls = (max_wait_hours * 3600) // poll_interval

        for poll in range(max_polls):
            time.sleep(poll_interval)
            result = self.get_batch_status(batch_id)

            if progress_callback:
                progress_callback(result.status, result.completed_requests, result.total_requests)

            print(f"  Status: {result.status} ({result.completed_requests}/{result.total_requests})")

            if result.status == "completed":
                return self.get_batch_results(batch_id)
            elif result.status == "failed":
                raise RuntimeError(f"Batch failed: {batch_id}")

        raise TimeoutError(f"Batch {batch_id} did not complete within {max_wait_hours} hours")


class AnthropicBatchProcessor(BatchProcessor):
    """
    Anthropic Message Batches API processor.

    Benefits:
    - 50% cost reduction
    - Higher rate limits
    - Results available within 24 hours

    Docs: https://docs.anthropic.com/en/docs/build-with-claude/batch-processing
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def create_batch(self, requests: List[BatchRequest], model: str) -> str:
        """Create an Anthropic message batch."""
        batch_requests = []

        for req in requests:
            batch_requests.append({
                "custom_id": req.custom_id,
                "params": {
                    "model": model,
                    "max_tokens": req.max_tokens,
                    "temperature": req.temperature,
                    "system": req.system_prompt,
                    "messages": [
                        {"role": "user", "content": req.prompt}
                    ]
                }
            })

        batch = self.client.messages.batches.create(requests=batch_requests)
        return batch.id

    def get_batch_status(self, batch_id: str) -> BatchResult:
        """Get status of an Anthropic batch."""
        batch = self.client.messages.batches.retrieve(batch_id)

        # Map Anthropic status to our status
        status_map = {
            "in_progress": "processing",
            "ended": "completed",
            "canceling": "processing",
            "canceled": "failed",
        }

        return BatchResult(
            batch_id=batch_id,
            provider="anthropic",
            status=status_map.get(batch.processing_status, batch.processing_status),
            total_requests=batch.request_counts.processing + batch.request_counts.succeeded + batch.request_counts.errored,
            completed_requests=batch.request_counts.succeeded,
            failed_requests=batch.request_counts.errored,
            created_at=str(batch.created_at),
        )

    def get_batch_results(self, batch_id: str) -> BatchResult:
        """Get results from a completed Anthropic batch."""
        responses = []

        for result in self.client.messages.batches.results(batch_id):
            if result.result.type == "succeeded":
                content = result.result.message.content[0].text
                responses.append(BatchResponse(
                    custom_id=result.custom_id,
                    content=content,
                    success=True,
                ))
            else:
                responses.append(BatchResponse(
                    custom_id=result.custom_id,
                    content="",
                    success=False,
                    error=str(result.result.error) if hasattr(result.result, 'error') else "Unknown error",
                ))

        return BatchResult(
            batch_id=batch_id,
            provider="anthropic",
            status="completed",
            total_requests=len(responses),
            completed_requests=sum(1 for r in responses if r.success),
            failed_requests=sum(1 for r in responses if not r.success),
            responses=responses,
            completed_at=datetime.now().isoformat(),
        )


class OpenAIBatchProcessor(BatchProcessor):
    """
    OpenAI Batch API processor.

    Benefits:
    - 50% cost reduction
    - Higher rate limits
    - Results available within 24 hours

    Docs: https://platform.openai.com/docs/guides/batch
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key)
        return self._client

    def create_batch(self, requests: List[BatchRequest], model: str) -> str:
        """Create an OpenAI batch job."""
        # Create JSONL file with requests
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            for req in requests:
                # Build request body - gpt-5 doesn't support temperature
                body = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": req.system_prompt},
                        {"role": "user", "content": req.prompt}
                    ],
                    "max_tokens": req.max_tokens,
                }
                if "gpt-5" not in model.lower():
                    body["temperature"] = req.temperature

                request_obj = {
                    "custom_id": req.custom_id,
                    "method": "POST",
                    "url": "/v1/chat/completions",
                    "body": body
                }
                f.write(json.dumps(request_obj) + "\n")

            jsonl_path = f.name

        # Upload the file
        with open(jsonl_path, "rb") as f:
            batch_file = self.client.files.create(file=f, purpose="batch")

        # Clean up temp file
        os.unlink(jsonl_path)

        # Create batch
        batch = self.client.batches.create(
            input_file_id=batch_file.id,
            endpoint="/v1/chat/completions",
            completion_window="24h"
        )

        return batch.id

    def get_batch_status(self, batch_id: str) -> BatchResult:
        """Get status of an OpenAI batch."""
        batch = self.client.batches.retrieve(batch_id)

        # Map OpenAI status
        status_map = {
            "validating": "pending",
            "in_progress": "processing",
            "finalizing": "processing",
            "completed": "completed",
            "failed": "failed",
            "expired": "failed",
            "cancelled": "failed",
        }

        completed = batch.request_counts.completed if batch.request_counts else 0
        failed = batch.request_counts.failed if batch.request_counts else 0
        total = batch.request_counts.total if batch.request_counts else 0

        return BatchResult(
            batch_id=batch_id,
            provider="openai",
            status=status_map.get(batch.status, batch.status),
            total_requests=total,
            completed_requests=completed,
            failed_requests=failed,
            created_at=str(batch.created_at),
        )

    def get_batch_results(self, batch_id: str) -> BatchResult:
        """Get results from a completed OpenAI batch."""
        batch = self.client.batches.retrieve(batch_id)

        if not batch.output_file_id:
            raise ValueError(f"Batch {batch_id} has no output file")

        # Download results
        content = self.client.files.content(batch.output_file_id)

        responses = []
        for line in content.text.strip().split("\n"):
            result = json.loads(line)
            custom_id = result["custom_id"]

            if result.get("error"):
                responses.append(BatchResponse(
                    custom_id=custom_id,
                    content="",
                    success=False,
                    error=str(result["error"]),
                ))
            else:
                content_text = result["response"]["body"]["choices"][0]["message"]["content"]
                responses.append(BatchResponse(
                    custom_id=custom_id,
                    content=content_text,
                    success=True,
                ))

        return BatchResult(
            batch_id=batch_id,
            provider="openai",
            status="completed",
            total_requests=len(responses),
            completed_requests=sum(1 for r in responses if r.success),
            failed_requests=sum(1 for r in responses if not r.success),
            responses=responses,
            completed_at=datetime.now().isoformat(),
        )


class GoogleBatchProcessor(BatchProcessor):
    """
    Google AI Studio batch processor using async concurrency.

    Note: Google AI Studio doesn't have a native batch API like Anthropic/OpenAI.
    This implementation uses asyncio for concurrent execution.

    For true batch processing with cost savings, use Vertex AI instead.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        max_concurrent: int = 10,
        retry_on_rate_limit: bool = True,
    ):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.max_concurrent = max_concurrent
        self.retry_on_rate_limit = retry_on_rate_limit
        self._client = None
        self._pending_batches: Dict[str, Dict] = {}

    @property
    def client(self):
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)
        return self._client

    async def _call_single(
        self,
        request: BatchRequest,
        model: str,
        semaphore: asyncio.Semaphore,
    ) -> BatchResponse:
        """Make a single API call with rate limiting."""
        async with semaphore:
            try:
                # Run sync API call in thread pool
                response = await asyncio.to_thread(
                    self.client.models.generate_content,
                    model=model,
                    contents=f"{request.system_prompt}\n\n{request.prompt}",
                    config={
                        "temperature": request.temperature,
                        "max_output_tokens": request.max_tokens,
                    },
                )
                return BatchResponse(
                    custom_id=request.custom_id,
                    content=response.text,
                    success=True,
                    metadata=request.metadata,
                )
            except Exception as e:
                error_str = str(e)
                # Handle rate limiting
                if self.retry_on_rate_limit and ("429" in error_str or "RESOURCE_EXHAUSTED" in error_str):
                    await asyncio.sleep(60)
                    # Retry once
                    try:
                        response = await asyncio.to_thread(
                            self.client.models.generate_content,
                            model=model,
                            contents=f"{request.system_prompt}\n\n{request.prompt}",
                            config={
                                "temperature": request.temperature,
                                "max_output_tokens": request.max_tokens,
                            },
                        )
                        return BatchResponse(
                            custom_id=request.custom_id,
                            content=response.text,
                            success=True,
                            metadata=request.metadata,
                        )
                    except Exception as retry_e:
                        return BatchResponse(
                            custom_id=request.custom_id,
                            content="",
                            success=False,
                            error=f"Retry failed: {retry_e}",
                            metadata=request.metadata,
                        )

                return BatchResponse(
                    custom_id=request.custom_id,
                    content="",
                    success=False,
                    error=error_str,
                    metadata=request.metadata,
                )

    async def _process_batch_async(
        self,
        requests: List[BatchRequest],
        model: str,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> List[BatchResponse]:
        """Process all requests concurrently."""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [self._call_single(req, model, semaphore) for req in requests]

        responses = []
        for i, coro in enumerate(asyncio.as_completed(tasks)):
            response = await coro
            responses.append(response)
            if progress_callback:
                progress_callback("processing", i + 1, len(requests))

        return responses

    def create_batch(self, requests: List[BatchRequest], model: str) -> str:
        """Create a 'virtual' batch (stores requests for async processing)."""
        batch_id = f"google-batch-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(requests)}"
        self._pending_batches[batch_id] = {
            "requests": requests,
            "model": model,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
        }
        return batch_id

    def get_batch_status(self, batch_id: str) -> BatchResult:
        """Get status of a Google batch."""
        if batch_id not in self._pending_batches:
            raise ValueError(f"Unknown batch: {batch_id}")

        batch = self._pending_batches[batch_id]
        return BatchResult(
            batch_id=batch_id,
            provider="google",
            status=batch["status"],
            total_requests=len(batch["requests"]),
            completed_requests=0,
            failed_requests=0,
            created_at=batch["created_at"],
            cost_savings="0% (use concurrent calls)",
        )

    def get_batch_results(self, batch_id: str) -> BatchResult:
        """Get results (triggers async processing for Google)."""
        if batch_id not in self._pending_batches:
            raise ValueError(f"Unknown batch: {batch_id}")

        batch = self._pending_batches[batch_id]
        if "responses" in batch:
            return BatchResult(
                batch_id=batch_id,
                provider="google",
                status="completed",
                total_requests=len(batch["responses"]),
                completed_requests=sum(1 for r in batch["responses"] if r.success),
                failed_requests=sum(1 for r in batch["responses"] if not r.success),
                responses=batch["responses"],
                created_at=batch["created_at"],
                completed_at=datetime.now().isoformat(),
                cost_savings="0% (no batch discount)",
            )

        raise ValueError(f"Batch {batch_id} not yet processed")

    def process_batch(
        self,
        requests: List[BatchRequest],
        model: str,
        poll_interval: int = 1,  # Not used for Google
        max_wait_hours: int = 1,  # Google is immediate
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> BatchResult:
        """Process batch immediately using async concurrency."""
        batch_id = self.create_batch(requests, model)
        print(f"  Processing {len(requests)} requests concurrently (max {self.max_concurrent} parallel)...")

        # Run async processing
        responses = asyncio.run(
            self._process_batch_async(requests, model, progress_callback)
        )

        # Store results
        self._pending_batches[batch_id]["responses"] = responses
        self._pending_batches[batch_id]["status"] = "completed"

        return BatchResult(
            batch_id=batch_id,
            provider="google",
            status="completed",
            total_requests=len(responses),
            completed_requests=sum(1 for r in responses if r.success),
            failed_requests=sum(1 for r in responses if not r.success),
            responses=responses,
            created_at=self._pending_batches[batch_id]["created_at"],
            completed_at=datetime.now().isoformat(),
            cost_savings="0% (use Vertex AI for batch discounts)",
        )


def create_batch_processor(
    provider: str,
    api_key: Optional[str] = None,
    **kwargs,
) -> BatchProcessor:
    """
    Factory function to create a batch processor.

    Args:
        provider: "anthropic", "openai", or "google"
        api_key: Optional API key (defaults to environment variable)
        **kwargs: Provider-specific options
            - google: max_concurrent (default 10)

    Returns:
        BatchProcessor instance
    """
    if provider == "anthropic":
        return AnthropicBatchProcessor(api_key=api_key)
    elif provider == "openai":
        return OpenAIBatchProcessor(api_key=api_key)
    elif provider == "google":
        return GoogleBatchProcessor(
            api_key=api_key,
            max_concurrent=kwargs.get("max_concurrent", 10),
        )
    else:
        raise ValueError(f"Unknown provider: {provider}. Use 'anthropic', 'openai', or 'google'.")


def prepare_batch_requests(
    samples: List[Dict],
    prompt_formatter: Callable[[Dict], str],
    system_prompt: str = "You are a security testing expert. Generate only Python test code, no explanations.",
) -> List[BatchRequest]:
    """
    Helper to prepare batch requests from benchmark samples.

    Args:
        samples: List of benchmark samples
        prompt_formatter: Function to format sample into prompt
        system_prompt: System prompt to use

    Returns:
        List of BatchRequest objects
    """
    requests = []
    for sample in samples:
        requests.append(BatchRequest(
            custom_id=sample["id"],
            prompt=prompt_formatter(sample),
            system_prompt=system_prompt,
            metadata={
                "cwe": sample.get("cwe", ""),
                "difficulty": sample.get("difficulty", ""),
            }
        ))
    return requests


# CLI for testing batch processing
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test batch API processing")
    parser.add_argument("--provider", choices=["anthropic", "openai", "google"], required=True)
    parser.add_argument("--model", help="Model to use")
    parser.add_argument("--test", action="store_true", help="Run a simple test")

    args = parser.parse_args()

    if args.test:
        # Simple test with 3 requests
        processor = create_batch_processor(args.provider)

        test_requests = [
            BatchRequest(
                custom_id="test-1",
                prompt="Write a simple Python function that adds two numbers.",
            ),
            BatchRequest(
                custom_id="test-2",
                prompt="Write a Python function that reverses a string.",
            ),
            BatchRequest(
                custom_id="test-3",
                prompt="Write a Python function that checks if a number is prime.",
            ),
        ]

        # Default models
        models = {
            "anthropic": "claude-sonnet-4-5-20250929",
            "openai": "gpt-4o",
            "google": "gemini-2.0-flash",
        }
        model = args.model or models[args.provider]

        print(f"Testing {args.provider} batch API with model {model}...")
        result = processor.process_batch(test_requests, model)

        print(f"\nResults:")
        print(f"  Status: {result.status}")
        print(f"  Completed: {result.completed_requests}/{result.total_requests}")
        print(f"  Cost savings: {result.cost_savings}")

        for resp in result.responses:
            print(f"\n  [{resp.custom_id}] {'SUCCESS' if resp.success else 'FAILED'}")
            if resp.success:
                print(f"    {resp.content[:100]}...")
            else:
                print(f"    Error: {resp.error}")
