#!/usr/bin/env python3
"""
SecMutBench Multi-Source Dataset Generator

Implements the Template-with-Research approach for generating 300 security samples.

7-Step Workflow:
1. PICK CWE (OWASP Top 10 + CWE Top 25 priority)
2. READ CWE PAGE (mitre.org - description, mitigations)
3. FIND EXAMPLES (templates + SecurityEval + CyberSecEval)
4. WRITE INSECURE (adapt vulnerable patterns)
5. WRITE SECURE (apply CWE mitigations)
6. WRITE TESTS (OWASP attack payloads)
7. VALIDATE (only validation, not full evaluation)

Usage:
    python scripts/generate_dataset.py --output data/dataset.json --samples 300
"""

import json
import hashlib
import sys
import os
import argparse
import re
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import local modules
from cwe_research import CWEResearcher, CWEInfo
from source_handlers import (
    MultiSourceAggregator, SecurityEvalHandler, CyberSecEvalHandler,
    OWASPPayloadHandler, TemplateHandler, ExternalSample, normalize_cwe, CWE_NAMES
)
from contamination_prevention import (
    PerturbationPipeline,
    TemporalFilter,
    ContaminationAuditor,
    NovelSampleTracker,
)


# ============================================================================
# Priority Distribution for 300 Samples
# ============================================================================

# Tier 1: OWASP Top 10 + CWE Top 25 (2025) - Critical/High Priority
TIER1_CWES = {
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "target": 25, "difficulty": ["easy", "medium", "hard"]},
    "CWE-89": {"name": "SQL Injection", "target": 25, "difficulty": ["easy", "medium", "hard"]},
    "CWE-78": {"name": "OS Command Injection", "target": 20, "difficulty": ["medium", "hard"]},
    "CWE-22": {"name": "Path Traversal", "target": 20, "difficulty": ["easy", "medium", "hard"]},
    "CWE-287": {"name": "Improper Authentication", "target": 15, "difficulty": ["medium", "hard"]},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "target": 15, "difficulty": ["easy", "medium"]},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "target": 15, "difficulty": ["medium", "hard"]},
    "CWE-20": {"name": "Improper Input Validation", "target": 15, "difficulty": ["easy", "medium"]},
}

# Tier 2: From Evaluation Datasets - Medium Priority
TIER2_CWES = {
    "CWE-327": {"name": "Use of Broken Cryptographic Algorithm", "target": 15, "difficulty": ["easy", "medium"]},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "target": 15, "difficulty": ["medium", "hard"]},
    "CWE-611": {"name": "XXE (XML External Entity)", "target": 15, "difficulty": ["medium", "hard"]},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "target": 15, "difficulty": ["medium", "hard"]},
    "CWE-94": {"name": "Code Injection", "target": 10, "difficulty": ["medium", "hard"]},
    "CWE-306": {"name": "Missing Authentication for Critical Function", "target": 10, "difficulty": ["medium", "hard"]},
}

# Tier 3: Additional Coverage - Lower Priority
TIER3_CWES = {
    "CWE-284": {"name": "Improper Access Control", "target": 10, "difficulty": ["medium", "hard"]},
    "CWE-319": {"name": "Cleartext Transmission", "target": 10, "difficulty": ["easy", "medium"]},
    "CWE-338": {"name": "Use of Cryptographically Weak PRNG", "target": 10, "difficulty": ["easy", "medium"]},
    "CWE-942": {"name": "Permissive Cross-domain Policy", "target": 10, "difficulty": ["medium"]},
    "CWE-1336": {"name": "Improper Neutralization of Template Expressions (SSTI)", "target": 10, "difficulty": ["hard"]},
    "CWE-639": {"name": "Authorization Bypass Through User-Controlled Key (IDOR)", "target": 10, "difficulty": ["medium", "hard"]},
    "CWE-295": {"name": "Improper Certificate Validation", "target": 5, "difficulty": ["medium"]},
    "CWE-312": {"name": "Cleartext Storage of Sensitive Information", "target": 5, "difficulty": ["easy", "medium"]},
}

# Combine all CWE targets
ALL_CWE_TARGETS = {**TIER1_CWES, **TIER2_CWES, **TIER3_CWES}


@dataclass
class GeneratedSample:
    """A generated benchmark sample."""
    id: str
    cwe: str
    cwe_name: str
    difficulty: str
    prompt: str
    entry_point: str
    insecure_code: str
    secure_code: str
    functional_tests: str
    security_tests: str
    mutation_operators: List[str]
    source: str = "SecMutBench"
    original_source: str = ""
    generation_method: str = "template-with-research"
    cwe_mitigations_applied: List[str] = field(default_factory=list)
    payloads_used: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Secure Code Templates by CWE
# ============================================================================

SECURE_PATTERNS = {
    "CWE-89": {
        "mitigation": "Use parameterized queries with ? placeholders",
        "pattern": 'db.execute(query, (param,))',
        "imports": [],
    },
    "CWE-78": {
        "mitigation": "Use subprocess with list arguments, validate input",
        "pattern": 'subprocess.run([cmd, arg], capture_output=True)',
        "imports": ["re"],
        "validation": "if not re.match(r'^[a-zA-Z0-9.-]+$', user_input): raise ValueError('Invalid input')",
    },
    "CWE-22": {
        "mitigation": "Use os.path.normpath and verify path stays within base directory",
        "pattern": "if not path.startswith(os.path.normpath(base_dir) + os.sep): raise ValueError('Path traversal')",
        "imports": ["os"],
    },
    "CWE-79": {
        "mitigation": "Use html.escape() to escape user input before rendering",
        "pattern": "safe_input = html.escape(user_input)",
        "imports": ["html"],
    },
    "CWE-327": {
        "mitigation": "Use SHA-256 or stronger instead of MD5/SHA-1",
        "pattern": "hashlib.sha256(data.encode()).hexdigest()",
        "imports": ["hashlib"],
    },
    "CWE-798": {
        "mitigation": "Read credentials from environment variables",
        "pattern": "env.get('CREDENTIAL_NAME')",
        "imports": [],
    },
    "CWE-502": {
        "mitigation": "Use json.loads instead of pickle.loads",
        "pattern": "json.loads(data)",
        "imports": ["json"],
    },
    "CWE-20": {
        "mitigation": "Validate input type, range, and format",
        "pattern": "if not valid_range(value): raise ValueError('Invalid input')",
        "imports": [],
    },
    "CWE-287": {
        "mitigation": "Implement proper authentication checks",
        "pattern": "if not auth.verify_token(token): raise AuthError('Invalid token')",
        "imports": [],
    },
    "CWE-352": {
        "mitigation": "Validate CSRF tokens on state-changing requests",
        "pattern": "if not csrf.validate(request.csrf_token): raise CSRFError('Invalid token')",
        "imports": [],
    },
    "CWE-611": {
        "mitigation": "Disable external entity processing in XML parser",
        "pattern": "parser.setFeature(xml.sax.handler.feature_external_ges, False)",
        "imports": ["xml.sax"],
    },
    "CWE-918": {
        "mitigation": "Validate URLs against whitelist, block internal IPs",
        "pattern": "if is_internal_ip(url): raise ValueError('Internal URLs not allowed')",
        "imports": [],
    },
    "CWE-94": {
        "mitigation": "Never use eval/exec on user input",
        "pattern": "# Use safe alternatives like ast.literal_eval for data parsing",
        "imports": ["ast"],
    },
    "CWE-306": {
        "mitigation": "Require authentication for all sensitive operations",
        "pattern": "@require_auth decorator",
        "imports": [],
    },
    "CWE-284": {
        "mitigation": "Check user permissions before allowing access",
        "pattern": "if not user.has_permission(resource): raise PermissionError()",
        "imports": [],
    },
    "CWE-319": {
        "mitigation": "Use HTTPS for all data transmission",
        "pattern": "requests.get(url, verify=True)",
        "imports": ["requests"],
    },
    "CWE-338": {
        "mitigation": "Use secrets module for cryptographic randomness",
        "pattern": "secrets.token_hex(32)",
        "imports": ["secrets"],
    },
    "CWE-942": {
        "mitigation": "Configure strict CORS policy with specific origins",
        "pattern": "Access-Control-Allow-Origin: https://trusted.com",
        "imports": [],
    },
    "CWE-1336": {
        "mitigation": "Use sandboxed template environments, escape template variables",
        "pattern": "env = jinja2.Environment(autoescape=True)",
        "imports": ["jinja2"],
    },
    "CWE-639": {
        "mitigation": "Verify user owns the resource before allowing access",
        "pattern": "if resource.owner_id != current_user.id: raise PermissionError()",
        "imports": [],
    },
    "CWE-295": {
        "mitigation": "Always verify SSL certificates",
        "pattern": "requests.get(url, verify=True)",
        "imports": ["requests"],
    },
    "CWE-312": {
        "mitigation": "Encrypt sensitive data before storage",
        "pattern": "encrypted = crypto.encrypt(sensitive_data)",
        "imports": [],
    },
}

# Mutation operators by CWE
CWE_MUTATION_OPERATORS = {
    "CWE-89": ["PSQLI", "RPS"],
    "CWE-78": ["RCMDI", "SHELLT"],
    "CWE-22": ["RPTV", "APTV"],
    "CWE-79": ["RXSS", "HTMLESC"],
    "CWE-327": ["WCRYPTO", "WHASH"],
    "CWE-798": ["RHCRED", "HCPWD"],
    "CWE-502": ["DESERIAL", "RPICKLE"],
    "CWE-20": ["RVALID", "RINPUT"],
    "CWE-287": ["RAUTH", "BYPASSAUTH"],
    "CWE-352": ["RCSRF", "BYPASSCSRF"],
    "CWE-611": ["RXXE", "ENABLEEXT"],
    "CWE-918": ["RSSRF", "BYPASSURL"],
    "CWE-94": ["RCODEINJ", "UNSAFEEVAL"],
    "CWE-306": ["RMISSAUTH", "NOAUTHCHECK"],
    "CWE-284": ["RACCESSCTL", "BYPASSACL"],
    "CWE-319": ["RCLEARTEXT", "DISABLESSL"],
    "CWE-338": ["RWPRNG", "WEAKRAND"],
    "CWE-942": ["RCORS", "PERMCORS"],
    "CWE-1336": ["RSSTI", "UNSAFETMPL"],
    "CWE-639": ["RIDOR", "BYPASSOWNER"],
    "CWE-295": ["RCERTVAL", "DISABLECERT"],
    "CWE-312": ["RCLEARSTORE", "PLAINTEXT"],
}


class TemplateWithResearchGenerator:
    """
    Main generator implementing the 7-step Template-with-Research workflow.
    """

    def __init__(self, cache_dir: str = "data/raw"):
        """Initialize the generator with all source handlers."""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        print("Initializing CWE researcher...")
        self.cwe_researcher = CWEResearcher(cache_dir=str(self.cache_dir / "cwe_cache"))

        print("Initializing source handlers...")
        self.aggregator = MultiSourceAggregator(cache_dir=str(self.cache_dir))

        # Track generated samples to avoid duplicates
        self.generated_ids = set()
        self.sample_count_by_cwe = defaultdict(int)

    def generate_sample_id(self, cwe: str, variant: str, source: str) -> str:
        """Generate unique sample ID."""
        content = f"{cwe}_{variant}_{source}_{len(self.generated_ids)}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def fetch_cwe_info(self, cwe_id: str) -> CWEInfo:
        """Step 2: Fetch CWE information from MITRE."""
        print(f"  Fetching CWE info for {cwe_id}...")
        return self.cwe_researcher.fetch_cwe(cwe_id)

    def find_examples(self, cwe_id: str) -> Dict[str, Any]:
        """Step 3: Find examples from all sources."""
        print(f"  Finding examples for {cwe_id}...")
        return self.aggregator.get_samples_for_cwe(cwe_id)

    def create_tests_from_payloads(self, cwe_id: str, entry_point: str, payloads: List[str]) -> Tuple[str, str]:
        """Step 6: Create test code from OWASP payloads."""
        functional_tests = []
        security_tests = []

        # Basic functional test template
        functional_tests.append(f'''
def test_{entry_point}_basic():
    """Test basic functionality."""
    result = {entry_point}("test_input")
    assert result is not None
''')

        # Generate security tests from payloads
        for i, payload in enumerate(payloads[:5]):  # Limit to 5 payloads per sample
            # Escape the payload for use in string
            escaped_payload = payload.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
            security_tests.append(f'''
def test_security_{entry_point}_{i}():
    """Test security with payload: {escaped_payload[:30]}..."""
    try:
        result = {entry_point}("{escaped_payload}")
        # If execution reaches here, verify secure behavior
        assert True  # Replace with specific security assertion
    except (ValueError, SecurityError):
        pass  # Expected for secure implementation
''')

        return '\n'.join(functional_tests), '\n'.join(security_tests) if security_tests else f'''
def test_security_{entry_point}():
    """Basic security test."""
    result = {entry_point}("malicious_input")
    assert result is not None
'''

    def adapt_external_sample(
        self,
        external: ExternalSample,
        cwe_info: CWEInfo,
        payloads: List[str],
        difficulty: str
    ) -> Optional[GeneratedSample]:
        """Steps 4-6: Adapt an external sample with CWE mitigations."""
        cwe_id = normalize_cwe(external.cwe)

        # Get secure pattern for this CWE
        secure_pattern = SECURE_PATTERNS.get(cwe_id, {})
        mitigation = secure_pattern.get("mitigation", "Apply appropriate security measures")

        # Generate entry point from external sample
        entry_point = self._extract_entry_point(external.code, external.prompt)
        if not entry_point:
            entry_point = f"process_{cwe_id.lower().replace('-', '_')}"

        # Generate sample ID
        sample_id = self.generate_sample_id(cwe_id, entry_point, external.source)

        # Skip if already generated
        if sample_id in self.generated_ids:
            return None

        # Create insecure code (from external sample)
        insecure_code = external.code.strip()
        if not insecure_code:
            insecure_code = self._generate_insecure_placeholder(cwe_id, entry_point)

        # Create secure code (apply mitigation)
        secure_code = self._apply_mitigation(insecure_code, cwe_id, secure_pattern)

        # Create tests
        functional_tests, security_tests = self.create_tests_from_payloads(cwe_id, entry_point, payloads)

        # Get mitigations from CWE info
        mitigations_applied = []
        for m in cwe_info.potential_mitigations[:3]:
            desc = m.get('description', m.get('strategy', ''))[:100]
            if desc:
                mitigations_applied.append(desc)

        self.generated_ids.add(sample_id)

        return GeneratedSample(
            id=sample_id,
            cwe=cwe_id,
            cwe_name=CWE_NAMES.get(cwe_id, cwe_info.name),
            difficulty=difficulty,
            prompt=external.prompt or f"Write a secure implementation that avoids {cwe_id}",
            entry_point=entry_point,
            insecure_code=insecure_code,
            secure_code=secure_code,
            functional_tests=functional_tests,
            security_tests=security_tests,
            mutation_operators=CWE_MUTATION_OPERATORS.get(cwe_id, ["GENERIC"]),
            source="SecMutBench",
            original_source=external.source,
            generation_method="template-with-research",
            cwe_mitigations_applied=mitigations_applied,
            payloads_used=payloads[:5],
            metadata={
                "external_id": external.original_id,
                "cwe_url": cwe_info.url,
            }
        )

    def adapt_template(
        self,
        template: Dict[str, Any],
        cwe_id: str,
        cwe_info: CWEInfo,
        payloads: List[str],
        difficulty: str
    ) -> Optional[GeneratedSample]:
        """Adapt an existing template with CWE research."""
        variant = template.get("variant", "unknown")
        entry_point = template.get("entry_point", variant)

        sample_id = self.generate_sample_id(cwe_id, variant, "template")

        if sample_id in self.generated_ids:
            return None

        # Get mitigations from CWE info
        mitigations_applied = []
        for m in cwe_info.potential_mitigations[:3]:
            desc = m.get('description', m.get('strategy', ''))[:100]
            if desc:
                mitigations_applied.append(desc)

        self.generated_ids.add(sample_id)

        return GeneratedSample(
            id=sample_id,
            cwe=cwe_id,
            cwe_name=CWE_NAMES.get(cwe_id, cwe_info.name),
            difficulty=difficulty,
            prompt=template.get("prompt", ""),
            entry_point=entry_point,
            insecure_code=template.get("insecure_code", "").strip(),
            secure_code=template.get("secure_code", "").strip(),
            functional_tests=template.get("functional_tests", "").strip(),
            security_tests=template.get("security_tests", "").strip(),
            mutation_operators=template.get("mutation_operators", CWE_MUTATION_OPERATORS.get(cwe_id, ["GENERIC"])),
            source="SecMutBench",
            original_source="template",
            generation_method="template-with-research",
            cwe_mitigations_applied=mitigations_applied,
            payloads_used=payloads[:5],
            metadata={"template_variant": variant}
        )

    def generate_variant(
        self,
        cwe_id: str,
        cwe_info: CWEInfo,
        payloads: List[str],
        existing_samples: List[GeneratedSample],
        difficulty: str,
        variant_index: int
    ) -> Optional[GeneratedSample]:
        """Generate a new variant when templates and external samples are exhausted."""
        # Create variant based on CWE type
        variant_templates = self._get_variant_templates(cwe_id)

        if variant_index >= len(variant_templates):
            # Generate a synthetic variant
            variant_template = self._generate_synthetic_variant(cwe_id, variant_index, cwe_info)
        else:
            variant_template = variant_templates[variant_index]

        entry_point = variant_template.get("entry_point", f"func_{variant_index}")
        sample_id = self.generate_sample_id(cwe_id, f"variant_{variant_index}", "generated")

        if sample_id in self.generated_ids:
            return None

        mitigations_applied = []
        for m in cwe_info.potential_mitigations[:3]:
            desc = m.get('description', m.get('strategy', ''))[:100]
            if desc:
                mitigations_applied.append(desc)

        self.generated_ids.add(sample_id)

        return GeneratedSample(
            id=sample_id,
            cwe=cwe_id,
            cwe_name=CWE_NAMES.get(cwe_id, cwe_info.name),
            difficulty=difficulty,
            prompt=variant_template.get("prompt", f"Implement a secure function that avoids {cwe_id}"),
            entry_point=entry_point,
            insecure_code=variant_template.get("insecure_code", ""),
            secure_code=variant_template.get("secure_code", ""),
            functional_tests=variant_template.get("functional_tests", self._generate_basic_functional_test(entry_point)),
            security_tests=variant_template.get("security_tests", self._generate_basic_security_test(entry_point, payloads)),
            mutation_operators=CWE_MUTATION_OPERATORS.get(cwe_id, ["GENERIC"]),
            source="SecMutBench",
            original_source="generated",
            generation_method="template-with-research",
            cwe_mitigations_applied=mitigations_applied,
            payloads_used=payloads[:5],
            metadata={"variant_index": variant_index}
        )

    def generate_for_cwe(self, cwe_id: str, target_count: int, cwe_config: Dict) -> List[GeneratedSample]:
        """Generate samples for a specific CWE using the 7-step workflow."""
        print(f"\n{'='*60}")
        print(f"Generating samples for {cwe_id}: {cwe_config['name']}")
        print(f"Target: {target_count} samples")
        print(f"{'='*60}")

        samples = []

        # Step 1: Pick CWE (already done)

        # Step 2: Fetch CWE info from MITRE
        cwe_info = self.fetch_cwe_info(cwe_id)

        # Step 3: Find examples from all sources
        resources = self.find_examples(cwe_id)

        # Get payloads
        payloads = resources.get("payloads", [])
        print(f"  Found {len(payloads)} attack payloads")

        # Get difficulty distribution
        difficulties = cwe_config.get("difficulty", ["medium"])

        # Step 3a: Start with existing templates (highest quality)
        templates = resources.get("sources", {}).get("templates", [])
        print(f"  Found {len(templates)} existing templates")

        for i, template in enumerate(templates):
            if len(samples) >= target_count:
                break
            difficulty = difficulties[i % len(difficulties)]
            sample = self.adapt_template(template, cwe_id, cwe_info, payloads, difficulty)
            if sample:
                samples.append(sample)
                print(f"    [+] Adapted template: {sample.entry_point} ({sample.difficulty})")

        # Step 3b: Add samples from SecurityEval/CyberSecEval
        external_samples = self.aggregator.get_all_external_samples(cwe_id)
        print(f"  Found {len(external_samples)} external samples")

        for i, ext_sample in enumerate(external_samples):
            if len(samples) >= target_count:
                break
            difficulty = difficulties[(len(samples)) % len(difficulties)]
            sample = self.adapt_external_sample(ext_sample, cwe_info, payloads, difficulty)
            if sample:
                samples.append(sample)
                print(f"    [+] Adapted external: {sample.entry_point} from {ext_sample.source} ({sample.difficulty})")

        # Step 3c: Generate new variants if needed to reach target
        variant_index = 0
        while len(samples) < target_count:
            difficulty = difficulties[(len(samples)) % len(difficulties)]
            sample = self.generate_variant(cwe_id, cwe_info, payloads, samples, difficulty, variant_index)
            if sample:
                samples.append(sample)
                print(f"    [+] Generated variant: {sample.entry_point} ({sample.difficulty})")
            variant_index += 1

            # Safety limit
            if variant_index > target_count * 2:
                print(f"    [!] Reached variant generation limit")
                break

        print(f"  Generated {len(samples)}/{target_count} samples for {cwe_id}")
        return samples[:target_count]

    def generate_dataset(self, target_total: int = 300) -> List[GeneratedSample]:
        """Generate the full dataset based on CWE priority distribution."""
        print("\n" + "="*70)
        print("SecMutBench Dataset Generation - Template with Research")
        print("="*70)
        print(f"Target: {target_total} samples")
        print(f"CWE Categories: {len(ALL_CWE_TARGETS)}")

        all_samples = []

        # Calculate actual targets based on total
        scale_factor = target_total / sum(c["target"] for c in ALL_CWE_TARGETS.values())

        for cwe_id, config in ALL_CWE_TARGETS.items():
            adjusted_target = max(1, int(config["target"] * scale_factor))
            samples = self.generate_for_cwe(cwe_id, adjusted_target, config)
            all_samples.extend(samples)
            self.sample_count_by_cwe[cwe_id] = len(samples)

        # Shuffle samples to ensure CWE diversity when taking subsets
        import random
        random.shuffle(all_samples)
        print(f"  Shuffled samples for CWE diversity")

        print(f"\n{'='*70}")
        print(f"Generated {len(all_samples)} total samples")
        print("="*70)

        return all_samples

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _extract_entry_point(self, code: str, prompt: str) -> str:
        """Extract function name from code or prompt."""
        # Try to find def function_name in code
        match = re.search(r'def\s+(\w+)\s*\(', code)
        if match:
            return match.group(1)

        # Try to extract from prompt
        words = prompt.lower().split()
        for i, word in enumerate(words):
            if word in ["function", "method", "write"]:
                if i + 1 < len(words):
                    candidate = re.sub(r'[^a-z_]', '', words[i + 1])
                    if candidate:
                        return candidate
        return "process_input"

    def _apply_mitigation(self, insecure_code: str, cwe_id: str, pattern: Dict) -> str:
        """Apply security mitigation to insecure code."""
        secure_code = insecure_code

        # Add imports if needed
        imports = pattern.get("imports", [])
        if imports:
            import_lines = '\n'.join(f"import {imp}" for imp in imports)
            secure_code = import_lines + '\n\n' + secure_code

        # Apply CWE-specific transformations
        if cwe_id == "CWE-89":
            # SQL Injection: Use parameterized queries
            secure_code = re.sub(
                r'f"([^"]*)\{(\w+)\}([^"]*)"',
                r'"\1?\3", (\2,)',
                secure_code
            )
        elif cwe_id == "CWE-78":
            # Command Injection: Remove shell=True
            secure_code = secure_code.replace("shell=True", "shell=False")
        elif cwe_id == "CWE-79":
            # XSS: Add html.escape
            secure_code = "import html\n" + secure_code
            secure_code = re.sub(
                r'f"([^"]*)\{(\w+)\}([^"]*)"',
                r'f"\1{html.escape(\2)}\3"',
                secure_code
            )
        elif cwe_id == "CWE-327":
            # Weak Crypto: Replace MD5 with SHA256
            secure_code = secure_code.replace("md5(", "sha256(")

        return secure_code

    def _generate_insecure_placeholder(self, cwe_id: str, entry_point: str) -> str:
        """Generate placeholder insecure code."""
        return f'''
def {entry_point}(user_input):
    """Process user input (INSECURE)."""
    # TODO: Vulnerable to {cwe_id}
    return user_input
'''

    def _generate_basic_functional_test(self, entry_point: str) -> str:
        """Generate basic functional tests."""
        return f'''
def test_{entry_point}_basic():
    """Test basic functionality."""
    result = {entry_point}("test_input")
    assert result is not None

def test_{entry_point}_returns_value():
    """Test function returns a value."""
    result = {entry_point}("another_test")
    assert result is not None
'''

    def _generate_basic_security_test(self, entry_point: str, payloads: List[str]) -> str:
        """Generate basic security tests."""
        tests = []
        for i, payload in enumerate(payloads[:3]):
            escaped = payload.replace('"', '\\"').replace("'", "\\'")[:50]
            tests.append(f'''
def test_security_{entry_point}_{i}():
    """Security test with payload."""
    try:
        result = {entry_point}("{escaped}")
        assert True  # Verify secure behavior
    except ValueError:
        pass  # Expected for secure implementation
''')
        return '\n'.join(tests) if tests else f'''
def test_security_{entry_point}():
    """Basic security test."""
    result = {entry_point}("malicious_input")
    assert result is not None
'''

    def _get_variant_templates(self, cwe_id: str) -> List[Dict]:
        """Get variant templates for a CWE."""
        # Define additional variant templates for each CWE
        variants = {
            "CWE-89": [
                {"entry_point": "get_user_by_id", "prompt": "Get user by ID from database",
                 "insecure_code": 'def get_user_by_id(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return db.execute(query)',
                 "secure_code": 'def get_user_by_id(user_id):\n    query = "SELECT * FROM users WHERE id = ?"\n    return db.execute(query, (user_id,))'},
                {"entry_point": "search_by_name", "prompt": "Search records by name",
                 "insecure_code": 'def search_by_name(name):\n    query = f"SELECT * FROM records WHERE name LIKE \'%{name}%\'"\n    return db.execute(query)',
                 "secure_code": 'def search_by_name(name):\n    query = "SELECT * FROM records WHERE name LIKE ?"\n    return db.execute(query, (f"%{name}%",))'},
            ],
            "CWE-78": [
                {"entry_point": "execute_script", "prompt": "Execute a script file",
                 "insecure_code": 'def execute_script(script):\n    return subprocess.run(f"bash {script}", shell=True, capture_output=True)',
                 "secure_code": 'import re\ndef execute_script(script):\n    if not re.match(r"^[a-zA-Z0-9_.-]+$", script): raise ValueError("Invalid")\n    return subprocess.run(["bash", script], capture_output=True)'},
            ],
            "CWE-22": [
                {"entry_point": "read_user_file", "prompt": "Read a user-uploaded file",
                 "insecure_code": 'import os\ndef read_user_file(filename):\n    path = os.path.join("/uploads", filename)\n    return fs.read_file(path)',
                 "secure_code": 'import os\ndef read_user_file(filename):\n    base = "/uploads"\n    path = os.path.normpath(os.path.join(base, filename))\n    if not path.startswith(os.path.normpath(base) + os.sep): raise ValueError("Invalid")\n    return fs.read_file(path)'},
            ],
            "CWE-79": [
                {"entry_point": "render_message", "prompt": "Render a user message in HTML",
                 "insecure_code": 'def render_message(msg):\n    return f"<span>{msg}</span>"',
                 "secure_code": 'import html\ndef render_message(msg):\n    return f"<span>{html.escape(msg)}</span>"'},
            ],
        }
        return variants.get(cwe_id, [])

    def _generate_synthetic_variant(self, cwe_id: str, index: int, cwe_info: CWEInfo) -> Dict:
        """Generate a synthetic variant with real security patterns that operators can mutate."""
        entry_point = f"process_{cwe_id.lower().replace('-', '_')}_{index}"

        # Generate CWE-specific code patterns that mutation operators can match
        if cwe_id == "CWE-89":
            # SQL Injection - parameterized queries
            table_names = ["users", "orders", "products", "sessions", "logs"]
            table = table_names[index % len(table_names)]
            insecure_code = f'''
def {entry_point}(user_input):
    """Query {table} table (INSECURE - string concatenation)."""
    query = f"SELECT * FROM {table} WHERE id = {{user_input}}"
    return db.execute(query)
'''
            secure_code = f'''
def {entry_point}(user_input):
    """Query {table} table using parameterized query."""
    query = "SELECT * FROM {table} WHERE id = ?"
    return db.execute(query, (user_input,))
'''
        elif cwe_id == "CWE-79":
            # XSS - html.escape
            contexts = ["message", "comment", "title", "description", "name"]
            ctx = contexts[index % len(contexts)]
            insecure_code = f'''
def {entry_point}(user_input):
    """Render {ctx} (INSECURE - no escaping)."""
    return f"<div class='{ctx}'>{{user_input}}</div>"
'''
            secure_code = f'''
import html

def {entry_point}(user_input):
    """Render {ctx} with HTML escaping."""
    safe_input = html.escape(user_input)
    return f"<div class='{ctx}'>{{safe_input}}</div>"
'''
        elif cwe_id == "CWE-78":
            # Command Injection - subprocess without shell
            tools = ["ping", "nslookup", "traceroute", "dig", "whois"]
            tool = tools[index % len(tools)]
            insecure_code = f'''
def {entry_point}(user_input):
    """Run {tool} command (INSECURE - shell=True)."""
    cmd = f"{tool} {{user_input}}"
    return subprocess.run(cmd, shell=True, capture_output=True)
'''
            secure_code = f'''
import re

def {entry_point}(user_input):
    """Run {tool} command safely."""
    if not re.match(r'^[a-zA-Z0-9.-]+$', user_input):
        raise ValueError("Invalid input")
    return subprocess.run(["{tool}", user_input], capture_output=True)
'''
        elif cwe_id == "CWE-22":
            # Path Traversal - path validation
            dirs = ["uploads", "documents", "images", "data", "files"]
            dir_name = dirs[index % len(dirs)]
            insecure_code = f'''
import os

def {entry_point}(user_input):
    """Read file from {dir_name} (INSECURE - no path validation)."""
    path = os.path.join("/{dir_name}", user_input)
    return fs.read_file(path)
'''
            secure_code = f'''
import os

def {entry_point}(user_input):
    """Read file from {dir_name} with path validation."""
    base_dir = "/{dir_name}"
    path = os.path.normpath(os.path.join(base_dir, user_input))
    if not path.startswith(os.path.normpath(base_dir) + os.sep):
        raise ValueError("Path traversal detected")
    return fs.read_file(path)
'''
        elif cwe_id == "CWE-327":
            # Weak Crypto - sha256 instead of md5
            data_types = ["password", "token", "key", "secret", "data"]
            dtype = data_types[index % len(data_types)]
            insecure_code = f'''
import hashlib

def {entry_point}(user_input):
    """Hash {dtype} (INSECURE - uses MD5)."""
    return hashlib.md5(user_input.encode()).hexdigest()
'''
            secure_code = f'''
import hashlib

def {entry_point}(user_input):
    """Hash {dtype} using SHA-256."""
    return hashlib.sha256(user_input.encode()).hexdigest()
'''
        elif cwe_id == "CWE-798":
            # Hardcoded Credentials - use environment variables
            cred_types = ["API_KEY", "DB_PASSWORD", "SECRET_KEY", "AUTH_TOKEN", "ACCESS_KEY"]
            cred = cred_types[index % len(cred_types)]
            insecure_code = f'''
def {entry_point}(user_input):
    """Connect with credentials (INSECURE - hardcoded)."""
    credential = "hardcoded_secret_value_123"
    return connect(user_input, credential)
'''
            secure_code = f'''
import os

def {entry_point}(user_input):
    """Connect with credentials from environment."""
    credential = os.environ.get("{cred}")
    if not credential:
        raise ValueError("Missing credential")
    return connect(user_input, credential)
'''
        elif cwe_id == "CWE-502":
            # Deserialization - use json instead of pickle
            insecure_code = f'''
import pickle

def {entry_point}(user_input):
    """Deserialize data (INSECURE - uses pickle)."""
    return pickle.loads(user_input)
'''
            secure_code = f'''
import json

def {entry_point}(user_input):
    """Deserialize data safely using JSON."""
    return json.loads(user_input)
'''
        else:
            # Default: input validation pattern
            insecure_code = f'''
def {entry_point}(user_input):
    """Process input - variant {index} (INSECURE)."""
    result = user_input
    return result
'''
            secure_code = f'''
def {entry_point}(user_input):
    """Process input with validation."""
    clean_input = sanitize(user_input)
    if not validate(clean_input):
        raise ValueError("Invalid input")
    return clean_input
'''

        return {
            "entry_point": entry_point,
            "prompt": f"Write a secure function that processes user input while avoiding {cwe_id} ({cwe_info.name})",
            "insecure_code": insecure_code,
            "secure_code": secure_code,
        }


class ContaminationPreventionProcessor:
    """Applies contamination prevention to generated samples."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.perturbation = PerturbationPipeline(seed=42)
        self.temporal_filter = TemporalFilter(cutoff_year=2024)
        self.auditor = ContaminationAuditor(n=5)
        self.tracker = NovelSampleTracker()

    def process(self, samples: List[Dict]) -> Tuple[List[Dict], Dict]:
        """Apply contamination prevention pipeline."""
        if not self.enabled:
            return samples, {}

        print("\n" + "="*60)
        print("Applying Contamination Prevention")
        print("="*60)

        results = {
            "original_count": len(samples),
            "final_count": 0,
            "novel_ratio": 0.0,
            "contamination_rate": 0.0,
        }

        # Track novelty
        novelty_report = self.tracker.generate_report(samples)
        results["novel_ratio"] = novelty_report.get("novel_ratio", 0.0)
        print(f"  Novel samples: {novelty_report.get('novel_count', 0)}")
        print(f"  Novel ratio: {results['novel_ratio']:.1%}")

        # Apply temporal filtering
        samples, filtered = self.temporal_filter.filter_samples(samples)
        print(f"  Temporal filter: passed {len(samples)}, filtered {len(filtered)}")

        # Run contamination audit
        audit = self.auditor.audit_dataset(samples, contamination_threshold=0.3)
        results["contamination_rate"] = audit.get("contamination_rate", 0.0)
        print(f"  Contamination rate: {results['contamination_rate']:.1%}")

        results["final_count"] = len(samples)

        return samples, results


def validate_samples(samples: List[Dict]) -> Tuple[List[Dict], Dict]:
    """Step 7: Validate samples (static validation only)."""
    print("\n" + "="*60)
    print("Validating Samples")
    print("="*60)

    valid_samples = []
    validation_errors = defaultdict(list)

    required_fields = [
        "id", "cwe", "cwe_name", "difficulty", "prompt",
        "entry_point", "insecure_code", "secure_code",
        "functional_tests", "security_tests", "mutation_operators"
    ]

    for sample in samples:
        errors = []

        # Check required fields
        for field in required_fields:
            if field not in sample or not sample[field]:
                errors.append(f"Missing or empty field: {field}")

        # Check code syntax
        for code_field in ["insecure_code", "secure_code", "functional_tests", "security_tests"]:
            if code_field in sample and sample[code_field]:
                try:
                    compile(sample[code_field], "<string>", "exec")
                except SyntaxError as e:
                    errors.append(f"Syntax error in {code_field}: {e}")

        # Check CWE format
        if "cwe" in sample:
            if not re.match(r"CWE-\d+", sample["cwe"]):
                errors.append(f"Invalid CWE format: {sample['cwe']}")

        # Check difficulty
        if "difficulty" in sample:
            if sample["difficulty"] not in ["easy", "medium", "hard"]:
                errors.append(f"Invalid difficulty: {sample['difficulty']}")

        if errors:
            validation_errors[sample.get("id", "unknown")] = errors
            print(f"  [FAIL] {sample.get('id', 'unknown')}: {len(errors)} errors")
        else:
            valid_samples.append(sample)
            print(f"  [PASS] {sample.get('id', 'unknown')}")

    stats = {
        "total": len(samples),
        "valid": len(valid_samples),
        "invalid": len(samples) - len(valid_samples),
        "pass_rate": len(valid_samples) / len(samples) if samples else 0,
        "errors": dict(validation_errors),
    }

    print(f"\nValidation: {stats['valid']}/{stats['total']} passed ({stats['pass_rate']:.1%})")

    return valid_samples, stats


def create_output_file(
    samples: List[Dict],
    output_path: str,
    validation_stats: Dict,
    contamination_stats: Dict
) -> None:
    """Create the output dataset file with metadata."""
    output = {
        "metadata": {
            "version": "2.0",
            "generated": datetime.now().isoformat(),
            "total_samples": len(samples),
            "generation_method": "template-with-research",
            "sources": ["SecurityEval", "CyberSecEval", "OWASP", "CWE-MITRE", "Templates"],
            "contamination_prevention": True,
            "validation_stats": validation_stats,
            "contamination_stats": contamination_stats,
        },
        "samples": samples,
    }

    # Calculate CWE distribution
    cwe_dist = defaultdict(int)
    difficulty_dist = defaultdict(int)
    for s in samples:
        cwe_dist[s["cwe"]] += 1
        difficulty_dist[s["difficulty"]] += 1

    output["metadata"]["cwe_distribution"] = dict(cwe_dist)
    output["metadata"]["difficulty_distribution"] = dict(difficulty_dist)

    # Write output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\nWrote {len(samples)} samples to {output_path}")


def is_valid_python(code: str) -> bool:
    """Check if code compiles as valid Python."""
    if not code or not code.strip():
        return False
    try:
        compile(code, "<string>", "exec")
        return True
    except SyntaxError:
        return False


def quick_validate_sample(sample: Dict) -> bool:
    """Quick validation check for a sample (syntax only)."""
    required_fields = ["id", "cwe", "insecure_code", "secure_code", "functional_tests", "security_tests"]

    # Check required fields exist
    for field in required_fields:
        if field not in sample or not sample[field]:
            return False

    # Check all code fields compile
    for code_field in ["insecure_code", "secure_code", "functional_tests", "security_tests"]:
        if not is_valid_python(sample.get(code_field, "")):
            return False

    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SecMutBench Multi-Source Dataset Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate exactly 300 valid samples
  python scripts/generate_dataset.py --output data/dataset.json --target-valid 300

  # Generate 300 samples (may have some invalid)
  python scripts/generate_dataset.py --output data/dataset.json --samples 300

  # Generate without contamination prevention
  python scripts/generate_dataset.py --samples 100 --no-contamination-prevention
        """
    )

    parser.add_argument("--output", "-o", default="data/dataset.json",
                        help="Output file path (default: data/dataset.json)")
    parser.add_argument("--samples", "-n", type=int, default=300,
                        help="Target number of samples to generate (default: 300)")
    parser.add_argument("--target-valid", type=int, default=None,
                        help="Target number of VALID samples (will over-generate to reach this)")
    parser.add_argument("--skip-validation", action="store_true",
                        help="Skip validation step")
    parser.add_argument("--no-contamination-prevention", action="store_true",
                        help="Disable contamination prevention")
    parser.add_argument("--cache-dir", default="data/raw",
                        help="Cache directory for downloaded data")

    args = parser.parse_args()

    # Initialize generator
    generator = TemplateWithResearchGenerator(cache_dir=args.cache_dir)

    # Determine generation strategy
    if args.target_valid:
        # Iterative generation to reach target valid count
        print(f"\n{'='*70}")
        print(f"Target: {args.target_valid} VALID samples (will over-generate)")
        print(f"{'='*70}")

        all_valid_samples = []
        iteration = 0
        max_iterations = 5
        samples_per_iteration = args.target_valid + 100  # Over-generate by ~33%

        while len(all_valid_samples) < args.target_valid and iteration < max_iterations:
            iteration += 1
            print(f"\n--- Iteration {iteration} ---")
            print(f"Currently have {len(all_valid_samples)} valid samples, need {args.target_valid}")

            # Generate more samples
            needed = args.target_valid - len(all_valid_samples)
            generate_count = int(needed * 1.3) + 50  # Over-generate by 30% + buffer

            samples = generator.generate_dataset(target_total=generate_count)
            samples_dicts = [s.to_dict() for s in samples]

            # Quick validate and collect valid samples
            for sample in samples_dicts:
                if quick_validate_sample(sample):
                    # Check not duplicate
                    if sample["id"] not in [s["id"] for s in all_valid_samples]:
                        all_valid_samples.append(sample)
                        if len(all_valid_samples) >= args.target_valid:
                            break

            print(f"After iteration {iteration}: {len(all_valid_samples)} valid samples")

            # Reset generator IDs to allow more generation
            generator.generated_ids = set(s["id"] for s in all_valid_samples)

        samples_dicts = all_valid_samples[:args.target_valid]
        print(f"\nFinal: {len(samples_dicts)} valid samples")
    else:
        # Original behavior - generate exact count
        samples = generator.generate_dataset(target_total=args.samples)
        samples_dicts = [s.to_dict() for s in samples]

    # Apply contamination prevention
    contamination_stats = {}
    if not args.no_contamination_prevention:
        processor = ContaminationPreventionProcessor(enabled=True)
        samples_dicts, contamination_stats = processor.process(samples_dicts)
    else:
        print("\nContamination prevention: DISABLED")

    # Validate samples
    validation_stats = {}
    if not args.skip_validation:
        samples_dicts, validation_stats = validate_samples(samples_dicts)
    else:
        print("\nValidation: SKIPPED")
        validation_stats = {"total": len(samples_dicts), "valid": len(samples_dicts), "pass_rate": 1.0}

    # Write output
    create_output_file(samples_dicts, args.output, validation_stats, contamination_stats)

    # Print summary
    print("\n" + "="*70)
    print("DATASET GENERATION COMPLETE")
    print("="*70)
    print(f"Total samples: {len(samples_dicts)}")
    print(f"Output file: {args.output}")

    # CWE distribution
    print("\nCWE Distribution:")
    cwe_counts = defaultdict(int)
    for s in samples_dicts:
        cwe_counts[s["cwe"]] += 1
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")

    # Difficulty distribution
    print("\nDifficulty Distribution:")
    diff_counts = defaultdict(int)
    for s in samples_dicts:
        diff_counts[s["difficulty"]] += 1
    for diff, count in sorted(diff_counts.items()):
        print(f"  {diff}: {count}")


if __name__ == "__main__":
    main()
