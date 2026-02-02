"""
Mutation Engine for SecMutBench

Generates security-relevant mutants from source code using
the security mutation operators.
"""

import hashlib
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

# Import operators - works when package is installed via pip install -e .
try:
    from operators import OPERATORS, get_applicable_operators
except ImportError:
    # Fallback for running scripts directly without package installation
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from operators import OPERATORS, get_applicable_operators


@dataclass
class Mutant:
    """Represents a single mutant."""
    id: str
    original_code: str
    mutated_code: str
    operator: str
    description: str
    line_number: Optional[int] = None
    killed: bool = False
    error: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            # Generate ID from hash of mutated code
            hash_input = f"{self.operator}:{self.mutated_code}"
            self.id = hashlib.md5(hash_input.encode()).hexdigest()[:8]


@dataclass
class MutationResult:
    """Result of mutation generation."""
    original_code: str
    mutants: List[Mutant] = field(default_factory=list)
    operators_applied: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_mutants(self) -> int:
        return len(self.mutants)

    @property
    def unique_operators(self) -> int:
        return len(set(m.operator for m in self.mutants))


class MutationEngine:
    """
    Engine for generating security-relevant mutants.

    Uses security mutation operators to inject realistic
    vulnerability patterns into secure code.
    """

    def __init__(self, operators: Optional[List[str]] = None):
        """
        Initialize the mutation engine.

        Args:
            operators: List of operator names to use. If None, uses all.
        """
        if operators:
            self.operators = {
                name: OPERATORS[name]
                for name in operators
                if name in OPERATORS
            }
        else:
            self.operators = OPERATORS

    def generate_mutants(
        self,
        code: str,
        cwe: Optional[str] = None,
        max_mutants: Optional[int] = None,
    ) -> MutationResult:
        """
        Generate mutants from the given code.

        Args:
            code: Source code to mutate
            cwe: Optional CWE to target specific operators
            max_mutants: Maximum number of mutants to generate

        Returns:
            MutationResult containing all generated mutants
        """
        result = MutationResult(original_code=code)

        # Get applicable operators
        if cwe:
            applicable = get_applicable_operators(code, cwe)
            operators_to_use = {
                name: self.operators[name]
                for name in applicable
                if name in self.operators
            }
        else:
            operators_to_use = {
                name: op
                for name, op in self.operators.items()
                if op.applies_to(code)
            }

        # Generate mutants for each operator
        mutant_count = 0
        for name, operator in operators_to_use.items():
            try:
                mutations = operator.mutate(code)
                result.operators_applied.append(name)

                for mutated_code, description in mutations:
                    if mutated_code != code:  # Only add if actually different
                        mutant = Mutant(
                            id="",
                            original_code=code,
                            mutated_code=mutated_code,
                            operator=name,
                            description=description,
                        )
                        result.mutants.append(mutant)
                        mutant_count += 1

                        if max_mutants and mutant_count >= max_mutants:
                            return result

            except Exception as e:
                result.errors.append(f"{name}: {str(e)}")

        # Remove duplicate mutants (same mutated code)
        seen = set()
        unique_mutants = []
        for mutant in result.mutants:
            if mutant.mutated_code not in seen:
                seen.add(mutant.mutated_code)
                unique_mutants.append(mutant)
        result.mutants = unique_mutants

        return result

    def get_operator_coverage(self, code: str) -> Dict[str, bool]:
        """
        Check which operators can be applied to the code.

        Returns:
            Dict mapping operator names to applicability
        """
        return {
            name: op.applies_to(code)
            for name, op in self.operators.items()
        }


def generate_mutants(
    code: str,
    operators: Optional[List[str]] = None,
    cwe: Optional[str] = None,
    max_mutants: Optional[int] = None,
) -> List[Mutant]:
    """
    Convenience function to generate mutants.

    Args:
        code: Source code to mutate
        operators: List of operator names to use
        cwe: Optional CWE to target
        max_mutants: Maximum mutants to generate

    Returns:
        List of Mutant objects
    """
    engine = MutationEngine(operators)
    result = engine.generate_mutants(code, cwe, max_mutants)
    return result.mutants


def generate_mutants_for_sample(sample: Dict) -> List[Mutant]:
    """
    Generate mutants for a benchmark sample.

    Args:
        sample: Benchmark sample dict with 'secure_code', 'cwe', 'mutation_operators'

    Returns:
        List of Mutant objects
    """
    code = sample.get("secure_code", "")
    cwe = sample.get("cwe")
    operators = sample.get("mutation_operators", [])

    engine = MutationEngine(operators if operators else None)
    result = engine.generate_mutants(code, cwe)
    return result.mutants


if __name__ == "__main__":
    # Test the mutation engine
    test_code = '''
def get_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (username,))
'''

    engine = MutationEngine()
    result = engine.generate_mutants(test_code, cwe="CWE-89")

    print(f"Generated {result.total_mutants} mutants")
    print(f"Operators applied: {result.operators_applied}")

    for mutant in result.mutants:
        print(f"\n[{mutant.operator}] {mutant.description}")
        print(mutant.mutated_code[:200])
