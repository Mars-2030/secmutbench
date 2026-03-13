#!/usr/bin/env python3
"""
LLM-Based Sample Variation Generator for SecMutBench

Generates variations of existing samples using Anthropic Claude API.
Supports batch processing for 50% cost savings.

Each variation maintains the same vulnerability pattern but with different
function contexts, variable names, and implementation details.

Default model: claude-opus-4-6
"""

import os
import re
import sys
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, rely on environment variables

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("Warning: anthropic package not installed. Install with: pip install anthropic")

# Batch API support
try:
    from baselines.batch_api import create_batch_processor, BatchRequest
    BATCH_AVAILABLE = True
except ImportError:
    BATCH_AVAILABLE = False


# =============================================================================
# Variation Prompt Templates
# =============================================================================

VARIATION_SYSTEM_PROMPT = """You are a security-focused code generator. Your task is to create variations of Python code samples that demonstrate the same vulnerability pattern but in different contexts.

For each variation, you must:
1. Keep the same vulnerability type (e.g., SQL injection, XSS, path traversal)
2. Change the function name and purpose (different domain/context)
3. Use different variable names
4. Keep the same secure vs insecure pattern

Output ONLY valid JSON with no markdown formatting, no code blocks, no explanation."""

VARIATION_USER_PROMPT = """Generate {num_variations} variations of this security code sample.

Original sample:
- CWE: {cwe}
- Entry point: {entry_point}
- Vulnerability: {vulnerability_name}

Secure code:
```python
{secure_code}
```

Insecure code:
```python
{insecure_code}
```

Generate {num_variations} DIFFERENT variations. Each variation must:
1. Have a DIFFERENT function name and purpose (e.g., if original is "get_user", use domains like "fetch_product", "load_document", "retrieve_order")
2. Maintain the EXACT SAME vulnerability pattern
3. Use different variable names
4. Be syntactically valid Python

Return a JSON array with this exact structure (no markdown, no code blocks):
[
  {{
    "entry_point": "new_function_name",
    "prompt": "Short description of what the function does",
    "secure": "full secure code as string",
    "insecure": "full insecure code as string",
    "difficulty": "easy|medium|hard"
  }}
]"""


# =============================================================================
# CWE Information for Context
# =============================================================================

CWE_VULNERABILITY_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-74": "Injection (Neutralization)",
    "CWE-77": "OS Command Injection (via API)",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-116": "Improper Output Encoding",
    "CWE-117": "Log Injection",
    "CWE-200": "Information Exposure",
    "CWE-209": "Error Message Info Exposure",
    "CWE-269": "Improper Privilege Management",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-312": "Cleartext Storage of Sensitive Data",
    "CWE-319": "Cleartext Transmission",
    "CWE-327": "Weak Cryptography",
    "CWE-328": "Weak Hash (Reversible One-Way)",
    "CWE-338": "Weak PRNG",
    "CWE-347": "Improper Signature Verification",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-367": "TOCTOU Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Insecure Deserialization",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XXE Injection",
    "CWE-639": "Authorization Bypass (IDOR)",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-798": "Hardcoded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Mass Assignment",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-942": "Permissive CORS",
    "CWE-1333": "ReDoS (Regular Expression Denial of Service)",
    "CWE-1336": "Server-Side Template Injection",
}


@dataclass
class Variation:
    """A single code variation."""
    id: str
    cwe: str
    cwe_name: str
    entry_point: str
    prompt: str
    secure_code: str
    insecure_code: str
    difficulty: str
    functional_tests: str
    security_tests: str
    mutation_operators: List[str]
    source_sample_id: str
    source: str = "LLM_Variation"


class VariationGenerator:
    """Generates code variations using Anthropic Claude API with optional batch processing."""

    DEFAULT_MODEL = "claude-opus-4-6"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-opus-4-6",
    ):
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("anthropic package required. Install with: pip install anthropic")

        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

        self.model = model or self.DEFAULT_MODEL
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.rate_limit_delay = 1.0  # seconds between requests

    def _call_api(self, user_prompt: str, max_retries: int = 3) -> Optional[str]:
        """Call the Anthropic API."""
        for attempt in range(max_retries):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=8192,
                    system=VARIATION_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}]
                )
                return response.content[0].text.strip()

            except Exception as e:
                error_str = str(e)
                if "rate" in error_str.lower() or "429" in error_str:
                    print(f"  Rate limited, waiting 60s...")
                    time.sleep(60)
                else:
                    print(f"  API error: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(2)

        return None

    def generate_variations(
        self,
        sample: Dict,
        num_variations: int = 3,
        max_retries: int = 3
    ) -> List[Variation]:
        """Generate variations for a single sample."""

        cwe = sample.get("cwe", "")
        entry_point = sample.get("entry_point", "")
        secure_code = sample.get("secure_code", "")
        insecure_code = sample.get("insecure_code", "")
        sample_id = sample.get("id", "unknown")

        if not all([cwe, entry_point, secure_code, insecure_code]):
            print(f"  Skipping {sample_id}: missing required fields")
            return []

        vulnerability_name = CWE_VULNERABILITY_NAMES.get(cwe, cwe)

        user_prompt = VARIATION_USER_PROMPT.format(
            num_variations=num_variations,
            cwe=cwe,
            entry_point=entry_point,
            vulnerability_name=vulnerability_name,
            secure_code=secure_code,
            insecure_code=insecure_code
        )

        response_text = self._call_api(user_prompt, max_retries)

        if response_text:
            variations = self._parse_variations(response_text, cwe, sample_id)
            if variations:
                time.sleep(self.rate_limit_delay)
                return variations

        return []

    def generate_variations_batch(
        self,
        samples: List[Dict],
        num_variations: int = 3,
        poll_interval: int = 60,
    ) -> Dict[str, List[Variation]]:
        """
        Generate variations for multiple samples using batch API.

        Uses native batch APIs for 50% cost savings (Anthropic/OpenAI).

        Args:
            samples: List of source samples
            num_variations: Number of variations per sample
            poll_interval: Seconds between batch status checks

        Returns:
            Dict mapping sample_id to list of variations
        """
        if not BATCH_AVAILABLE:
            raise ImportError("Batch API not available. Check baselines/batch_api.py")

        print(f"  Preparing batch requests for {len(samples)} samples...")

        # Prepare batch requests
        batch_requests = []
        sample_map = {}  # custom_id -> sample

        for sample in samples:
            cwe = sample.get("cwe", "")
            entry_point = sample.get("entry_point", "")
            secure_code = sample.get("secure_code", "")
            insecure_code = sample.get("insecure_code", "")
            sample_id = sample.get("id", "unknown")

            if not all([cwe, entry_point, secure_code, insecure_code]):
                continue

            vulnerability_name = CWE_VULNERABILITY_NAMES.get(cwe, cwe)

            user_prompt = VARIATION_USER_PROMPT.format(
                num_variations=num_variations,
                cwe=cwe,
                entry_point=entry_point,
                vulnerability_name=vulnerability_name,
                secure_code=secure_code,
                insecure_code=insecure_code
            )

            custom_id = f"var-{sample_id}"
            batch_requests.append(BatchRequest(
                custom_id=custom_id,
                prompt=user_prompt,
                system_prompt=VARIATION_SYSTEM_PROMPT,
                max_tokens=8192,
                metadata={"sample_id": sample_id, "cwe": cwe},
            ))
            sample_map[custom_id] = sample

        if not batch_requests:
            print("  No valid samples to process")
            return {}

        # Process batch (Anthropic only)
        processor = create_batch_processor("anthropic", api_key=self.api_key)

        print(f"  Submitting batch of {len(batch_requests)} requests to Anthropic...")
        print(f"  Cost savings: 50% (batch discount)")

        batch_result = processor.process_batch(
            batch_requests,
            self.model,
            poll_interval=poll_interval,
        )

        print(f"  Batch completed: {batch_result.completed_requests}/{batch_result.total_requests}")

        # Parse results
        results = {}
        for response in batch_result.responses:
            if not response.success:
                continue

            sample = sample_map.get(response.custom_id)
            if not sample:
                continue

            sample_id = sample.get("id", "unknown")
            cwe = sample.get("cwe", "")

            variations = self._parse_variations(response.content, cwe, sample_id)
            if variations:
                results[sample_id] = variations

        return results

    def _parse_variations(
        self,
        response_text: str,
        cwe: str,
        source_sample_id: str
    ) -> List[Variation]:
        """Parse LLM response into Variation objects."""
        variations = []

        # Import test generation and operator registry
        try:
            from sample_generator import generate_security_test, generate_functional_test
        except ImportError:
            print("  Warning: sample_generator not available, variations will have empty tests")
            generate_security_test = None
            generate_functional_test = None

        try:
            from operators.operator_registry import CWE_OPERATOR_MAP
        except ImportError:
            CWE_OPERATOR_MAP = {}

        try:
            # Clean response text (remove markdown code blocks if present)
            text = response_text.strip()
            if text.startswith("```"):
                # Remove markdown code block
                lines = text.split("\n")
                lines = [l for l in lines if not l.startswith("```")]
                text = "\n".join(lines)

            # Sanitize common LLM JSON issues
            # Remove trailing commas before } or ]
            text = re.sub(r',\s*([}\]])', r'\1', text)
            # Remove single-line // comments
            text = re.sub(r'//[^\n]*', '', text)

            # Parse JSON
            data = json.loads(text)

            if not isinstance(data, list):
                data = [data]

            for var_idx, item in enumerate(data):
                entry_point = item.get("entry_point", "")
                prompt = item.get("prompt", "")
                secure = item.get("secure", "")
                insecure = item.get("insecure", "")
                difficulty = item.get("difficulty", "medium")

                if not all([entry_point, secure, insecure]):
                    continue

                # Validate code compiles
                try:
                    compile(secure, "<secure>", "exec")
                    compile(insecure, "<insecure>", "exec")
                except SyntaxError:
                    continue

                # Validate entry_point function exists in generated code
                if f"def {entry_point}(" not in secure:
                    print(f"    Skipping: entry_point '{entry_point}' not found in secure code")
                    continue

                # Generate unique ID (includes source_sample_id + index to avoid collisions)
                var_id = hashlib.md5(
                    f"{source_sample_id}_{cwe}_{entry_point}_{var_idx}_{secure[:100]}".encode()
                ).hexdigest()[:12]

                # Generate tests (same as dataset_builder pipeline)
                security_tests = ""
                functional_tests = ""
                if generate_security_test:
                    security_tests = generate_security_test(entry_point, cwe, secure)
                if generate_functional_test:
                    functional_tests = generate_functional_test(entry_point, cwe, secure)

                # Get mutation operators for this CWE
                operators = CWE_OPERATOR_MAP.get(cwe, [])

                variations.append(Variation(
                    id=var_id,
                    cwe=cwe,
                    cwe_name=CWE_VULNERABILITY_NAMES.get(cwe, cwe),
                    entry_point=entry_point,
                    prompt=prompt,
                    secure_code=secure,
                    insecure_code=insecure,
                    difficulty=difficulty,
                    functional_tests=functional_tests,
                    security_tests=security_tests,
                    mutation_operators=operators,
                    source_sample_id=source_sample_id,
                    source="LLM_Variation"
                ))

        except json.JSONDecodeError as e:
            print(f"  JSON parse error: {e}")
        except Exception as e:
            print(f"  Parse error: {e}")

        return variations


def load_dataset(dataset_path: str) -> List[Dict]:
    """Load samples from dataset JSON file."""
    with open(dataset_path) as f:
        data = json.load(f)
    return data.get("samples", data) if isinstance(data, dict) else data


def validate_variation(variation: Variation) -> Tuple[bool, str]:
    """
    Validate a variation using VD check (secure passes, insecure fails).

    Uses the stored security_tests from the variation (generated during
    _parse_variations) and the same TestRunner with mock injection as
    dataset_builder.py to ensure consistent validation behavior.

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        from evaluation.test_runner import TestRunner
    except ImportError:
        return True, "Skipping VD check (TestRunner not available)"

    # Use the stored security_tests from the variation
    test_code = variation.security_tests
    if not test_code or not test_code.strip():
        return False, "No security tests generated for this variation"

    runner = TestRunner()

    # Run tests on secure code - should PASS
    secure_result = runner.run_tests(test_code, variation.secure_code)
    if not secure_result.all_passed:
        err = secure_result.tests[0].error if secure_result.tests else "unknown"
        return False, f"Secure code fails test: {str(err)[:200]}"

    # Run tests on insecure code - should FAIL
    insecure_result = runner.run_tests(test_code, variation.insecure_code)
    if insecure_result.all_passed:
        return False, "Insecure code passes test (should fail)"

    return True, "VD check passed"


def main():
    parser = argparse.ArgumentParser(
        description="Generate LLM-based variations of security code samples"
    )
    parser.add_argument(
        "--dataset", "-d",
        default="data/dataset.json",
        help="Input dataset path"
    )
    parser.add_argument(
        "--output", "-o",
        default="data/variations.json",
        help="Output file for variations"
    )
    parser.add_argument(
        "--variations", "-n",
        type=int,
        default=3,
        help="Number of variations per sample"
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum number of source samples to process"
    )
    parser.add_argument(
        "--cwes",
        nargs="+",
        default=None,
        help="Filter to specific CWEs (e.g., CWE-89 CWE-79)"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run VD validation on generated variations"
    )
    parser.add_argument(
        "--model",
        default="claude-opus-4-6",
        help="Anthropic model to use (default: claude-opus-4-6)"
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)"
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Use Anthropic batch API for 50%% cost savings. "
             "Submits all requests at once, results within 24h."
    )
    parser.add_argument(
        "--batch-poll-interval",
        type=int,
        default=60,
        help="Seconds between batch status checks (default: 60)"
    )

    args = parser.parse_args()

    print(f"Loading dataset from {args.dataset}...")
    samples = load_dataset(args.dataset)
    print(f"Loaded {len(samples)} samples")

    # Filter by CWE if specified
    if args.cwes:
        samples = [s for s in samples if s.get("cwe") in args.cwes]
        print(f"Filtered to {len(samples)} samples for CWEs: {args.cwes}")

    # Limit samples if specified
    if args.max_samples:
        samples = samples[:args.max_samples]
        print(f"Limited to {len(samples)} samples")

    # Initialize generator
    try:
        generator = VariationGenerator(
            api_key=args.api_key,
            model=args.model,
        )
        print(f"Using model: {generator.model}")
    except Exception as e:
        print(f"Failed to initialize generator: {e}")
        sys.exit(1)

    # Generate variations
    all_variations = []
    total_generated = 0
    total_valid = 0

    if args.batch:
        # Batch mode - process all samples at once
        if not BATCH_AVAILABLE:
            print("Error: Batch API not available. Install with: pip install anthropic")
            sys.exit(1)

        print(f"\nUsing BATCH API mode for {len(samples)} samples...")
        print("Cost savings: 50% (Anthropic batch discount)")

        try:
            batch_results = generator.generate_variations_batch(
                samples,
                num_variations=args.variations,
                poll_interval=args.batch_poll_interval,
            )

            for sample_id, variations in batch_results.items():
                total_generated += len(variations)

                # Optionally validate
                if args.validate:
                    valid_variations = []
                    for var in variations:
                        is_valid, msg = validate_variation(var)
                        if is_valid:
                            valid_variations.append(var)
                            total_valid += 1
                        else:
                            print(f"    Invalid: {var.entry_point} - {msg}")
                    variations = valid_variations

                all_variations.extend(variations)

            print(f"\nBatch complete: {len(batch_results)} samples processed, {total_generated} variations")

        except Exception as e:
            print(f"Batch processing failed: {e}")
            sys.exit(1)

    else:
        # Sequential mode - process samples one by one
        for i, sample in enumerate(samples):
            sample_id = sample.get("id", f"sample_{i}")[:8]
            cwe = sample.get("cwe", "unknown")
            print(f"[{i+1}/{len(samples)}] Generating {args.variations} variations for {sample_id} ({cwe})...")

            variations = generator.generate_variations(sample, num_variations=args.variations)

            if variations:
                total_generated += len(variations)

                # Optionally validate
                if args.validate:
                    valid_variations = []
                    for var in variations:
                        is_valid, msg = validate_variation(var)
                        if is_valid:
                            valid_variations.append(var)
                            total_valid += 1
                        else:
                            print(f"    Invalid: {var.entry_point} - {msg}")
                    variations = valid_variations

                all_variations.extend(variations)
                print(f"  Generated {len(variations)} variations")
            else:
                print(f"  No variations generated")

    # Save results
    output_data = {
        "metadata": {
            "source_dataset": args.dataset,
            "provider": "anthropic",
            "model": generator.model,
            "batch_mode": args.batch,
            "variations_per_sample": args.variations,
            "total_source_samples": len(samples),
            "total_variations": len(all_variations),
            "validated": args.validate
        },
        "variations": [asdict(v) for v in all_variations]
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Generated {total_generated} total variations")
    if args.validate:
        print(f"Valid variations: {total_valid}")
    print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
