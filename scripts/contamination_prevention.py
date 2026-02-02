"""
Contamination Prevention Pipeline for SecMutBench

Implements strategies to prevent data contamination from LLM training data:
1. Perturbation Pipeline - Systematic modification of public dataset samples
2. Novel Sample Tracking - Identify originally authored samples
3. Temporal Filtering - Filter CVE-based samples by disclosure date
4. Contamination Audit - N-gram overlap analysis with known corpora
"""

import ast
import json
import random
import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import Counter
import string


@dataclass
class PerturbationResult:
    """Result of applying perturbation to a sample."""
    original_hash: str
    perturbed_hash: str
    transformations_applied: List[str]
    renamed_identifiers: Dict[str, str]
    success: bool
    error: Optional[str] = None


@dataclass
class ContaminationAuditResult:
    """Result of contamination audit for a sample."""
    sample_id: str
    ngram_overlaps: Dict[str, float]  # corpus_name -> overlap_ratio
    is_potentially_contaminated: bool
    confidence: float
    details: Dict[str, Any]


class IdentifierRenamer(ast.NodeTransformer):
    """AST transformer to rename functions and variables."""

    def __init__(self, rename_map: Dict[str, str]):
        self.rename_map = rename_map
        self.preserved = {
            'self', 'cls', 'True', 'False', 'None',
            'print', 'len', 'range', 'str', 'int', 'float', 'list', 'dict',
            'open', 'read', 'write', 'close', 'append', 'extend',
            'Exception', 'ValueError', 'TypeError', 'KeyError',
            'os', 'sys', 'json', 're', 'subprocess', 'hashlib',
            'sqlite3', 'pickle', 'yaml', 'xml', 'html',
        }

    def visit_Name(self, node):
        if node.id in self.rename_map and node.id not in self.preserved:
            node.id = self.rename_map[node.id]
        return node

    def visit_FunctionDef(self, node):
        if node.name in self.rename_map and node.name not in self.preserved:
            node.name = self.rename_map[node.name]
        # Rename arguments
        for arg in node.args.args:
            if arg.arg in self.rename_map and arg.arg not in self.preserved:
                arg.arg = self.rename_map[arg.arg]
        self.generic_visit(node)
        return node

    def visit_arg(self, node):
        if node.arg in self.rename_map and node.arg not in self.preserved:
            node.arg = self.rename_map[node.arg]
        return node


class PerturbationPipeline:
    """
    Applies systematic perturbations to samples to prevent contamination.

    Transformations:
    - Function/variable renaming
    - Control flow restructuring
    - Data type variations
    - Comment modification
    - String literal variation
    """

    def __init__(self, seed: int = 42):
        self.random = random.Random(seed)
        self.name_prefixes = [
            'process_', 'handle_', 'execute_', 'run_', 'perform_',
            'do_', 'check_', 'validate_', 'compute_', 'calculate_'
        ]
        self.name_suffixes = [
            '_data', '_input', '_value', '_result', '_output',
            '_item', '_element', '_entry', '_record', '_info'
        ]

    def generate_new_name(self, original: str, context: str = 'var') -> str:
        """Generate a new name for an identifier."""
        # Use hash for deterministic but different naming
        hash_val = hashlib.md5(f"{original}_{context}".encode()).hexdigest()[:6]

        if context == 'function':
            prefix = self.random.choice(self.name_prefixes)
            return f"{prefix}{hash_val}"
        else:
            suffix = self.random.choice(self.name_suffixes)
            return f"v_{hash_val}{suffix}"

    def extract_identifiers(self, code: str) -> Tuple[Set[str], Set[str]]:
        """Extract function names and variable names from code."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return set(), set()

        functions = set()
        variables = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.add(node.name)
                for arg in node.args.args:
                    variables.add(arg.arg)
            elif isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    variables.add(node.id)

        # Filter out built-ins
        builtins = {'self', 'cls', 'True', 'False', 'None', 'print', 'len', 'range'}
        variables = variables - builtins

        return functions, variables

    def rename_identifiers(self, code: str) -> Tuple[str, Dict[str, str]]:
        """Rename all user-defined identifiers in code."""
        functions, variables = self.extract_identifiers(code)

        rename_map = {}
        for func in functions:
            if not func.startswith('_'):  # Preserve dunder methods
                rename_map[func] = self.generate_new_name(func, 'function')

        for var in variables:
            if var not in rename_map:
                rename_map[var] = self.generate_new_name(var, 'var')

        try:
            tree = ast.parse(code)
            renamer = IdentifierRenamer(rename_map)
            new_tree = renamer.visit(tree)
            ast.fix_missing_locations(new_tree)
            new_code = ast.unparse(new_tree)
            return new_code, rename_map
        except Exception:
            return code, {}

    def restructure_control_flow(self, code: str) -> str:
        """Apply control flow restructuring transformations."""
        # Transform: if x: return True; return False -> return x
        # Transform: if not x: ... else: ... -> if x: ... else: ...

        transformations = [
            # Swap if-else branches with negated condition
            (r'if not (\w+):\s*\n(\s+)(.+?)\n\2else:\s*\n\2(.+)',
             r'if \1:\n\2\4\n\2else:\n\2\3'),
            # Transform explicit True/False returns
            (r'if (.+?):\s*\n\s+return True\s*\n\s*return False',
             r'return bool(\1)'),
        ]

        result = code
        for pattern, replacement in transformations:
            try:
                result = re.sub(pattern, replacement, result)
            except Exception:
                pass

        return result

    def vary_string_literals(self, code: str) -> str:
        """Apply variations to string literals."""
        # Change quote styles
        def swap_quotes(match):
            content = match.group(1) or match.group(2)
            if match.group(1):  # Was double-quoted
                if "'" not in content:
                    return f"'{content}'"
            else:  # Was single-quoted
                if '"' not in content:
                    return f'"{content}"'
            return match.group(0)

        # Simple string literal swap (avoiding complex cases)
        result = re.sub(r'"([^"\\]*)"', swap_quotes, code)
        return result

    def modify_comments(self, code: str) -> str:
        """Remove or modify comments to prevent matching."""
        lines = code.split('\n')
        result_lines = []

        for line in lines:
            # Remove inline comments
            if '#' in line and not line.strip().startswith('#'):
                comment_idx = line.index('#')
                # Check if # is inside a string
                before_hash = line[:comment_idx]
                if before_hash.count('"') % 2 == 0 and before_hash.count("'") % 2 == 0:
                    line = line[:comment_idx].rstrip()
            # Remove full-line comments
            elif line.strip().startswith('#'):
                continue

            result_lines.append(line)

        return '\n'.join(result_lines)

    def apply_structural_perturbation(self, code: str, cwe: str) -> Tuple[str, str]:
        """Apply CWE-specific structural perturbations.

        Unlike renaming, these change the actual code patterns to prevent
        LLMs from recognizing vulnerability patterns from training data.

        Returns:
            Tuple of (perturbed_code, perturbation_name)
        """

        # CWE-89: SQL Injection - Vary database interaction patterns
        if cwe == "CWE-89":
            patterns = [
                ('direct_execute', self._sql_direct_execute),
                ('cursor_based', self._sql_cursor_based),
                ('context_manager', self._sql_context_manager),
                ('fetchone_variant', self._sql_fetchone_variant),
            ]
            choice = self.random.choice(patterns)
            try:
                result = choice[1](code)
                return result, f'structural_sql_{choice[0]}'
            except Exception:
                pass

        # CWE-78: Command Injection - Vary subprocess patterns
        elif cwe == "CWE-78":
            patterns = [
                ('subprocess_run', self._cmd_subprocess_run),
                ('subprocess_popen', self._cmd_subprocess_popen),
                ('check_output', self._cmd_check_output),
            ]
            choice = self.random.choice(patterns)
            try:
                result = choice[1](code)
                return result, f'structural_cmd_{choice[0]}'
            except Exception:
                pass

        # CWE-22: Path Traversal - Vary file access patterns
        elif cwe == "CWE-22":
            patterns = [
                ('pathlib', self._path_pathlib),
                ('os_path', self._path_os_path),
                ('context_manager', self._path_context_manager),
            ]
            choice = self.random.choice(patterns)
            try:
                result = choice[1](code)
                return result, f'structural_path_{choice[0]}'
            except Exception:
                pass

        # CWE-502: Deserialization - Vary loading patterns
        elif cwe == "CWE-502":
            patterns = [
                ('json_loads', self._deser_json_loads),
                ('with_validation', self._deser_with_validation),
            ]
            choice = self.random.choice(patterns)
            try:
                result = choice[1](code)
                return result, f'structural_deser_{choice[0]}'
            except Exception:
                pass

        # Generic: Add wrapper function pattern
        if self.random.random() < 0.3:
            try:
                result = self._add_wrapper_function(code)
                return result, 'structural_wrapper'
            except Exception:
                pass

        return code, 'none'

    def _sql_direct_execute(self, code: str) -> str:
        """Keep direct execute pattern but vary the style."""
        # Change db.execute to connection.execute
        code = re.sub(r'\bdb\.execute\b', 'conn.execute', code)
        return code

    def _sql_cursor_based(self, code: str) -> str:
        """Transform to cursor-based pattern."""
        # Add cursor creation before execute
        if 'db.execute' in code:
            code = re.sub(
                r'(\s*)(\w+)\s*=\s*db\.execute\((.+?)\)',
                r'\1cursor = db.cursor()\n\1cursor.execute(\3)\n\1\2 = cursor.fetchall()',
                code
            )
        return code

    def _sql_context_manager(self, code: str) -> str:
        """Wrap in context manager."""
        if 'def ' in code and 'db.execute' in code:
            # Find the function body and wrap db operations
            code = re.sub(
                r'(def \w+\([^)]*\):)\n(\s+)(.+db\.execute.+)',
                r'\1\n\2with db.connection() as conn:\n\2    \3',
                code,
                flags=re.DOTALL
            )
        return code

    def _sql_fetchone_variant(self, code: str) -> str:
        """Use fetchone instead of direct result."""
        code = re.sub(
            r'(\w+)\s*=\s*db\.execute\((.+?)\)\.fetchall\(\)',
            r'cursor = db.execute(\2)\n\1 = cursor.fetchone()',
            code
        )
        return code

    def _cmd_subprocess_run(self, code: str) -> str:
        """Use subprocess.run pattern."""
        code = re.sub(
            r'subprocess\.call\((.+?)\)',
            r'subprocess.run(\1, capture_output=True)',
            code
        )
        return code

    def _cmd_subprocess_popen(self, code: str) -> str:
        """Use Popen pattern."""
        code = re.sub(
            r'subprocess\.run\((.+?)\)',
            r'proc = subprocess.Popen(\1, stdout=subprocess.PIPE)\noutput, _ = proc.communicate()',
            code
        )
        return code

    def _cmd_check_output(self, code: str) -> str:
        """Use check_output pattern."""
        code = re.sub(
            r'subprocess\.(run|call)\((.+?)\)',
            r'subprocess.check_output(\2)',
            code
        )
        return code

    def _path_pathlib(self, code: str) -> str:
        """Convert to pathlib style."""
        if 'os.path' in code:
            code = 'from pathlib import Path\n' + code
            code = re.sub(r'os\.path\.join\((.+?),\s*(.+?)\)', r'Path(\1) / \2', code)
            code = re.sub(r'os\.path\.exists\((.+?)\)', r'Path(\1).exists()', code)
        return code

    def _path_os_path(self, code: str) -> str:
        """Use os.path style (may already be this)."""
        if 'pathlib' in code.lower():
            code = re.sub(r'Path\((.+?)\)\s*/\s*(.+)', r'os.path.join(\1, \2)', code)
        return code

    def _path_context_manager(self, code: str) -> str:
        """Wrap file operations in context manager."""
        code = re.sub(
            r'(\w+)\s*=\s*open\((.+?)\)\.read\(\)',
            r'with open(\2) as f:\n    \1 = f.read()',
            code
        )
        return code

    def _deser_json_loads(self, code: str) -> str:
        """Ensure json.loads style."""
        code = code.replace('json.load(', 'json.loads(')
        return code

    def _deser_with_validation(self, code: str) -> str:
        """Add validation wrapper."""
        if 'json.loads' in code:
            validation = '''
def safe_json_loads(data):
    """Safely load JSON with size limit."""
    if len(data) > 1000000:
        raise ValueError("Data too large")
    return json.loads(data)
'''
            code = validation + code
            code = code.replace('json.loads(', 'safe_json_loads(')
        return code

    def _add_wrapper_function(self, code: str) -> str:
        """Wrap the main function in another function."""
        match = re.search(r'def (\w+)\(([^)]*)\):', code)
        if match:
            func_name = match.group(1)
            args = match.group(2)
            wrapper = f'''
def {func_name}_impl({args}):
    """Implementation detail."""
'''
            # Rename original function
            code = code.replace(f'def {func_name}(', f'def _{func_name}_inner(')
            # Add wrapper that calls it
            code = code + f'''

def {func_name}({args}):
    """Public interface."""
    return _{func_name}_inner({args.split(":")[0] if ":" in args else args})
'''
        return code

    def perturb_sample(self, sample: Dict[str, Any]) -> Tuple[Dict[str, Any], PerturbationResult]:
        """Apply all perturbations to a sample including structural changes."""
        transformations = []
        rename_map = {}

        original_secure = sample.get('secure_code', '')
        original_insecure = sample.get('insecure_code', '')
        original_tests = sample.get('security_tests', '')
        cwe = sample.get('cwe', '')

        original_hash = hashlib.sha256(
            f"{original_secure}{original_insecure}".encode()
        ).hexdigest()[:16]

        try:
            # 1. Apply structural perturbation FIRST (changes code patterns)
            new_secure, struct_transform = self.apply_structural_perturbation(original_secure, cwe)
            new_insecure, _ = self.apply_structural_perturbation(original_insecure, cwe)
            if struct_transform != 'none':
                transformations.append(struct_transform)

            # 2. Rename identifiers
            new_secure, secure_map = self.rename_identifiers(new_secure)
            rename_map.update(secure_map)
            if secure_map:
                transformations.append('identifier_renaming')

            # Apply same renaming to insecure code
            for old_name, new_name in rename_map.items():
                new_insecure = re.sub(rf'\b{old_name}\b', new_name, new_insecure)

            # Apply renaming to tests
            new_tests = original_tests
            for old_name, new_name in rename_map.items():
                new_tests = re.sub(rf'\b{old_name}\b', new_name, new_tests)

            # 3. Modify comments
            new_secure = self.modify_comments(new_secure)
            new_insecure = self.modify_comments(new_insecure)
            transformations.append('comment_modification')

            # 4. Vary string literals
            new_secure = self.vary_string_literals(new_secure)
            new_insecure = self.vary_string_literals(new_insecure)
            transformations.append('string_variation')

            # 5. Validate perturbed code compiles
            try:
                compile(new_secure, "<perturbed_secure>", "exec")
                compile(new_insecure, "<perturbed_insecure>", "exec")
            except SyntaxError as e:
                # If perturbation broke syntax, fall back to original
                new_secure = original_secure
                new_insecure = original_insecure
                transformations = ['fallback_to_original']

            # Create perturbed sample
            perturbed_sample = sample.copy()
            perturbed_sample['secure_code'] = new_secure
            perturbed_sample['insecure_code'] = new_insecure
            perturbed_sample['security_tests'] = new_tests
            perturbed_sample['perturbation_applied'] = True
            perturbed_sample['original_id'] = sample.get('id', '')

            perturbed_hash = hashlib.sha256(
                f"{new_secure}{new_insecure}".encode()
            ).hexdigest()[:16]

            result = PerturbationResult(
                original_hash=original_hash,
                perturbed_hash=perturbed_hash,
                transformations_applied=transformations,
                renamed_identifiers=rename_map,
                success=True
            )

            return perturbed_sample, result

        except Exception as e:
            result = PerturbationResult(
                original_hash=original_hash,
                perturbed_hash=original_hash,
                transformations_applied=[],
                renamed_identifiers={},
                success=False,
                error=str(e)
            )
            return sample, result


class TemporalFilter:
    """
    Filter samples based on temporal criteria.

    Ensures CVE-based samples use vulnerabilities disclosed after
    a specified cutoff date to avoid training data contamination.
    """

    CVE_PATTERN = re.compile(r'CVE-(\d{4})-\d+')

    def __init__(self, cutoff_year: int = 2024):
        self.cutoff_year = cutoff_year

    def extract_cve_year(self, text: str) -> Optional[int]:
        """Extract the year from a CVE identifier."""
        match = self.CVE_PATTERN.search(text)
        if match:
            return int(match.group(1))
        return None

    def is_after_cutoff(self, sample: Dict[str, Any]) -> bool:
        """Check if sample's CVE is after the cutoff date."""
        # Check various fields for CVE references
        fields_to_check = [
            sample.get('id', ''),
            sample.get('description', ''),
            sample.get('cve_id', ''),
            str(sample.get('metadata', {})),
        ]

        for field in fields_to_check:
            year = self.extract_cve_year(field)
            if year is not None:
                return year >= self.cutoff_year

        # No CVE found, assume it's safe
        return True

    def filter_samples(self, samples: List[Dict[str, Any]]) -> Tuple[List[Dict], List[Dict]]:
        """
        Filter samples by temporal criteria.

        Returns:
            Tuple of (passing_samples, filtered_out_samples)
        """
        passing = []
        filtered = []

        for sample in samples:
            if self.is_after_cutoff(sample):
                passing.append(sample)
            else:
                filtered.append(sample)

        return passing, filtered


class ContaminationAuditor:
    """
    Audit samples for potential contamination with known training corpora.

    Uses n-gram overlap analysis to detect similarity with:
    - The Stack
    - GitHub Code
    - Other known training datasets
    """

    def __init__(self, n: int = 5):
        self.n = n  # N-gram size
        self.known_patterns: Dict[str, Set[str]] = {}

    def extract_ngrams(self, text: str) -> Set[str]:
        """Extract character n-grams from text."""
        # Normalize text
        text = text.lower()
        text = re.sub(r'\s+', ' ', text)

        ngrams = set()
        for i in range(len(text) - self.n + 1):
            ngrams.add(text[i:i + self.n])

        return ngrams

    def extract_code_ngrams(self, code: str) -> Set[str]:
        """Extract normalized code n-grams (tokens rather than chars)."""
        # Tokenize code
        tokens = re.findall(r'\w+|[^\w\s]', code.lower())

        ngrams = set()
        for i in range(len(tokens) - self.n + 1):
            ngram = ' '.join(tokens[i:i + self.n])
            ngrams.add(ngram)

        return ngrams

    def load_corpus_patterns(self, corpus_name: str, patterns_file: str):
        """Load known patterns from a corpus for comparison."""
        if Path(patterns_file).exists():
            with open(patterns_file, 'r') as f:
                patterns = json.load(f)
                self.known_patterns[corpus_name] = set(patterns)

    def compute_overlap(self, sample_ngrams: Set[str], corpus_ngrams: Set[str]) -> float:
        """Compute Jaccard similarity between sample and corpus n-grams."""
        if not sample_ngrams or not corpus_ngrams:
            return 0.0

        intersection = sample_ngrams & corpus_ngrams
        union = sample_ngrams | corpus_ngrams

        return len(intersection) / len(union) if union else 0.0

    def audit_sample(
        self,
        sample: Dict[str, Any],
        contamination_threshold: float = 0.3
    ) -> ContaminationAuditResult:
        """
        Audit a single sample for contamination.

        Args:
            sample: The sample to audit
            contamination_threshold: Overlap ratio above which sample is flagged

        Returns:
            ContaminationAuditResult with overlap analysis
        """
        code = sample.get('secure_code', '') + sample.get('insecure_code', '')
        sample_ngrams = self.extract_code_ngrams(code)

        overlaps = {}
        max_overlap = 0.0

        for corpus_name, corpus_patterns in self.known_patterns.items():
            overlap = self.compute_overlap(sample_ngrams, corpus_patterns)
            overlaps[corpus_name] = overlap
            max_overlap = max(max_overlap, overlap)

        is_contaminated = max_overlap >= contamination_threshold

        return ContaminationAuditResult(
            sample_id=sample.get('id', 'unknown'),
            ngram_overlaps=overlaps,
            is_potentially_contaminated=is_contaminated,
            confidence=max_overlap,
            details={
                'ngram_size': self.n,
                'sample_ngram_count': len(sample_ngrams),
                'threshold': contamination_threshold,
            }
        )

    def audit_dataset(
        self,
        samples: List[Dict[str, Any]],
        contamination_threshold: float = 0.3
    ) -> Dict[str, Any]:
        """
        Audit entire dataset for contamination.

        Returns summary statistics and per-sample results.
        """
        results = []
        contaminated_count = 0

        for sample in samples:
            result = self.audit_sample(sample, contamination_threshold)
            results.append(asdict(result))
            if result.is_potentially_contaminated:
                contaminated_count += 1

        return {
            'total_samples': len(samples),
            'potentially_contaminated': contaminated_count,
            'contamination_rate': contaminated_count / len(samples) if samples else 0,
            'threshold': contamination_threshold,
            'ngram_size': self.n,
            'per_sample_results': results,
        }

    def generate_corpus_fingerprint(self, samples: List[Dict[str, Any]], output_file: str):
        """
        Generate n-gram fingerprint of dataset for external comparison.

        This can be shared for others to check overlap with their training data.
        """
        all_ngrams = Counter()

        for sample in samples:
            code = sample.get('secure_code', '') + sample.get('insecure_code', '')
            ngrams = self.extract_code_ngrams(code)
            all_ngrams.update(ngrams)

        # Keep only frequent n-grams (appear in 3+ samples)
        fingerprint = [ng for ng, count in all_ngrams.items() if count >= 3]

        with open(output_file, 'w') as f:
            json.dump({
                'dataset': 'SecMutBench',
                'ngram_size': self.n,
                'total_unique_ngrams': len(all_ngrams),
                'fingerprint_size': len(fingerprint),
                'fingerprint': fingerprint[:10000],  # Limit size
            }, f, indent=2)

        return len(fingerprint)


class NovelSampleTracker:
    """Track which samples are originally authored vs adapted."""

    def __init__(self):
        self.novel_samples: Set[str] = set()
        self.adapted_samples: Dict[str, str] = {}  # sample_id -> source

    def mark_novel(self, sample_id: str):
        """Mark a sample as originally authored."""
        self.novel_samples.add(sample_id)

    def mark_adapted(self, sample_id: str, source: str):
        """Mark a sample as adapted from a source."""
        self.adapted_samples[sample_id] = source

    def get_novel_ratio(self, total_samples: int) -> float:
        """Get the ratio of novel samples."""
        return len(self.novel_samples) / total_samples if total_samples > 0 else 0

    def categorize_samples(self, samples: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Categorize samples by their origin."""
        categories = {
            'novel': [],
            'adapted_securityeval': [],
            'adapted_cyberseceval': [],
            'adapted_other': [],
        }

        for sample in samples:
            sample_id = sample.get('id', '')
            source = sample.get('source', '')

            if source == 'SecMutBench':
                categories['novel'].append(sample_id)
                self.mark_novel(sample_id)
            elif source == 'SecurityEval':
                categories['adapted_securityeval'].append(sample_id)
                self.mark_adapted(sample_id, 'SecurityEval')
            elif source == 'CyberSecEval':
                categories['adapted_cyberseceval'].append(sample_id)
                self.mark_adapted(sample_id, 'CyberSecEval')
            else:
                categories['adapted_other'].append(sample_id)
                self.mark_adapted(sample_id, source or 'unknown')

        return categories

    def generate_report(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a report on sample origins."""
        categories = self.categorize_samples(samples)
        total = len(samples)

        return {
            'total_samples': total,
            'novel_count': len(categories['novel']),
            'novel_ratio': len(categories['novel']) / total if total > 0 else 0,
            'adapted_count': total - len(categories['novel']),
            'by_source': {
                'SecMutBench (novel)': len(categories['novel']),
                'SecurityEval (adapted)': len(categories['adapted_securityeval']),
                'CyberSecEval (adapted)': len(categories['adapted_cyberseceval']),
                'Other (adapted)': len(categories['adapted_other']),
            },
            'meets_30_percent_novel': len(categories['novel']) / total >= 0.30 if total > 0 else False,
        }


def apply_contamination_prevention(
    samples: List[Dict[str, Any]],
    output_dir: str,
    cutoff_year: int = 2024,
    apply_perturbation: bool = True,
) -> Dict[str, Any]:
    """
    Apply full contamination prevention pipeline to samples.

    Args:
        samples: List of benchmark samples
        output_dir: Directory to save results
        cutoff_year: Year for temporal filtering
        apply_perturbation: Whether to apply code perturbations

    Returns:
        Summary of contamination prevention results
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    results = {
        'original_count': len(samples),
        'steps': [],
    }

    # 1. Track novel vs adapted samples
    tracker = NovelSampleTracker()
    origin_report = tracker.generate_report(samples)
    results['origin_report'] = origin_report
    results['steps'].append('novel_sample_tracking')

    # 2. Temporal filtering
    temporal_filter = TemporalFilter(cutoff_year=cutoff_year)
    samples, filtered_out = temporal_filter.filter_samples(samples)
    results['temporal_filter'] = {
        'cutoff_year': cutoff_year,
        'passed': len(samples),
        'filtered_out': len(filtered_out),
    }
    results['steps'].append('temporal_filtering')

    # 3. Apply perturbations
    if apply_perturbation:
        pipeline = PerturbationPipeline()
        perturbed_samples = []
        perturbation_results = []

        for sample in samples:
            # Only perturb adapted samples, not novel ones
            if sample.get('source') != 'SecMutBench':
                perturbed, result = pipeline.perturb_sample(sample)
                perturbed_samples.append(perturbed)
                perturbation_results.append(asdict(result))
            else:
                perturbed_samples.append(sample)

        samples = perturbed_samples
        results['perturbation'] = {
            'samples_perturbed': len([r for r in perturbation_results if r['success']]),
            'samples_failed': len([r for r in perturbation_results if not r['success']]),
        }
        results['steps'].append('perturbation_pipeline')

    # 4. Contamination audit
    auditor = ContaminationAuditor(n=5)
    audit_results = auditor.audit_dataset(samples)
    results['contamination_audit'] = {
        'potentially_contaminated': audit_results['potentially_contaminated'],
        'contamination_rate': audit_results['contamination_rate'],
    }
    results['steps'].append('contamination_audit')

    # Generate fingerprint for external comparison
    fingerprint_file = output_path / 'dataset_fingerprint.json'
    auditor.generate_corpus_fingerprint(samples, str(fingerprint_file))

    # Save processed samples
    samples_file = output_path / 'samples_decontaminated.json'
    with open(samples_file, 'w') as f:
        json.dump(samples, f, indent=2)

    # Save full audit results
    audit_file = output_path / 'contamination_audit.json'
    with open(audit_file, 'w') as f:
        json.dump(audit_results, f, indent=2)

    results['final_count'] = len(samples)
    results['output_files'] = {
        'samples': str(samples_file),
        'fingerprint': str(fingerprint_file),
        'audit': str(audit_file),
    }

    return results


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Apply contamination prevention to SecMutBench')
    parser.add_argument('--input', default='data/samples.json', help='Input samples file')
    parser.add_argument('--output', default='data/decontaminated', help='Output directory')
    parser.add_argument('--cutoff-year', type=int, default=2024, help='CVE cutoff year')
    parser.add_argument('--no-perturbation', action='store_true', help='Skip perturbation')

    args = parser.parse_args()

    # Load samples
    with open(args.input, 'r') as f:
        samples = json.load(f)

    print(f"Loaded {len(samples)} samples")

    # Apply contamination prevention
    results = apply_contamination_prevention(
        samples,
        args.output,
        cutoff_year=args.cutoff_year,
        apply_perturbation=not args.no_perturbation,
    )

    print("\n=== Contamination Prevention Results ===")
    print(f"Original samples: {results['original_count']}")
    print(f"Final samples: {results['final_count']}")
    print(f"\nOrigin Report:")
    for source, count in results['origin_report']['by_source'].items():
        print(f"  {source}: {count}")
    print(f"  Novel ratio: {results['origin_report']['novel_ratio']:.1%}")
    print(f"  Meets 30% novel requirement: {results['origin_report']['meets_30_percent_novel']}")
    print(f"\nTemporal Filter (cutoff {args.cutoff_year}):")
    print(f"  Passed: {results['temporal_filter']['passed']}")
    print(f"  Filtered out: {results['temporal_filter']['filtered_out']}")
    print(f"\nContamination Audit:")
    print(f"  Potentially contaminated: {results['contamination_audit']['potentially_contaminated']}")
    print(f"  Contamination rate: {results['contamination_audit']['contamination_rate']:.1%}")
    print(f"\nOutput files:")
    for name, path in results['output_files'].items():
        print(f"  {name}: {path}")
