"""
Security-Specific Mutation Operators for SecMutBench

These operators inject realistic vulnerability patterns to evaluate
whether security tests can detect common weaknesses.
"""

import ast
import re
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from copy import deepcopy


class SecurityMutationOperator(ABC):
    """Base class for security mutation operators"""

    def __init__(self, name: str, description: str, target_cwes: List[str]):
        self.name = name
        self.description = description
        self.target_cwes = target_cwes

    @abstractmethod
    def applies_to(self, code: str) -> bool:
        """Check if this operator can mutate the given code"""
        pass

    @abstractmethod
    def mutate(self, code: str) -> List[Tuple[str, str]]:
        """
        Generate mutants from the code.

        Returns:
            List of tuples (mutant_code, mutation_description)
        """
        pass

    def get_mutation_locations(self, code: str) -> List[int]:
        """Return line numbers where mutations can be applied"""
        return []


class PSQLI(SecurityMutationOperator):
    """
    Parameterized SQL to String Injection (PSQLI)

    Transforms secure parameterized queries into vulnerable string concatenation.

    Example:
        db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        → db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    """

    def __init__(self):
        super().__init__(
            name="PSQLI",
            description="Convert parameterized query to string concatenation",
            target_cwes=["CWE-89"]
        )
        # Patterns for parameterized queries
        self.patterns = [
            # cursor.execute(query, params)
            r'\.execute\s*\(\s*["\']([^"\']*\?[^"\']*)["\'],\s*\(([^)]+)\)\s*\)',
            # cursor.execute(query, [params])
            r'\.execute\s*\(\s*["\']([^"\']*\?[^"\']*)["\'],\s*\[([^\]]+)\]\s*\)',
            # %s style parameters
            r'\.execute\s*\(\s*["\']([^"\']*%s[^"\']*)["\'],\s*\(([^)]+)\)\s*\)',
            # Named parameters :name
            r'\.execute\s*\(\s*["\']([^"\']*:[a-zA-Z_][a-zA-Z0-9_]*[^"\']*)["\'],\s*\{([^}]+)\}\s*\)',
        ]

    def applies_to(self, code: str) -> bool:
        for pattern in self.patterns:
            if re.search(pattern, code):
                return True
        # Also check for common secure patterns
        # Fixed: was ('?', ')' which is a tuple, should be '?' in code
        if '.execute(' in code and ('?' in code or '%s' in code or ':' in code):
            return True

        # NEW: Broader SQL detection patterns
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
        code_upper = code.upper()

        # Check for execute with SQL keywords (indicates SQL code)
        if '.execute(' in code.lower() or 'cursor.' in code.lower():
            if any(kw in code_upper for kw in sql_keywords):
                return True

        # Check for ORM-style queries that might be parameterized
        if any(pattern in code for pattern in ['.filter(', '.where(', '.query(', 'raw(']):
            return True

        # Check for sqlalchemy text() with params
        if 'text(' in code and (':' in code or 'bindparams' in code):
            return True

        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Pattern 1: ? placeholders with tuple
        pattern1 = r'(\.execute\s*\(\s*)["\']([^"\']*)["\'],\s*\(([^)]+)\)\s*\)'
        matches = list(re.finditer(pattern1, code))

        for match in matches:
            query = match.group(2)
            params_str = match.group(3)
            params = [p.strip() for p in params_str.split(',')]

            if '?' in query:
                # Variant 1: f-string interpolation
                new_query_fstr = query
                for param in params:
                    new_query_fstr = new_query_fstr.replace('?', '{' + param + '}', 1)
                mutant = code[:match.start()] + f'{match.group(1)}f"{new_query_fstr}")' + code[match.end():]
                mutants.append((mutant, f"[Variant 1] f-string: {query[:30]}..."))

                # Variant 2: String concatenation
                new_query_concat = query
                for param in params:
                    new_query_concat = new_query_concat.replace('?', f'" + str({param}) + "', 1)
                mutant2 = code[:match.start()] + f'{match.group(1)}"{new_query_concat}")' + code[match.end():]
                mutants.append((mutant2, f"[Variant 2] Concatenation: {query[:30]}..."))

                # Variant 3: % formatting
                new_query_pct = query.replace('?', '%s')
                param_tuple = ', '.join(params)
                mutant3 = code[:match.start()] + f'{match.group(1)}"{new_query_pct}" % ({param_tuple},))' + code[match.end():]
                mutants.append((mutant3, f"[Variant 3] % formatting: {query[:30]}..."))

                # Variant 4: .format() method
                new_query_fmt = query
                for i, param in enumerate(params):
                    new_query_fmt = new_query_fmt.replace('?', '{}', 1)
                param_args = ', '.join(params)
                mutant4 = code[:match.start()] + f'{match.group(1)}"{new_query_fmt}".format({param_args}))' + code[match.end():]
                mutants.append((mutant4, f"[Variant 4] .format(): {query[:30]}..."))

        # Pattern 2: %s placeholders
        pattern2 = r'(\.execute\s*\(\s*)["\']([^"\']*%s[^"\']*)["\'],\s*\(([^)]+)\)\s*\)'
        matches = list(re.finditer(pattern2, code))

        for match in matches:
            query = match.group(2)
            params_str = match.group(3)
            params = [p.strip() for p in params_str.split(',')]

            # Variant 1: f-string interpolation
            new_query_fstr = query
            for param in params:
                new_query_fstr = new_query_fstr.replace('%s', '{' + param + '}', 1)
            mutant = code[:match.start()] + f'{match.group(1)}f"{new_query_fstr}")' + code[match.end():]
            mutants.append((mutant, f"[Variant 1] f-string from %s: {query[:30]}..."))

            # Variant 2: String concatenation
            new_query_concat = query
            for param in params:
                new_query_concat = new_query_concat.replace('%s', f'" + str({param}) + "', 1)
            mutant2 = code[:match.start()] + f'{match.group(1)}"{new_query_concat}")' + code[match.end():]
            mutants.append((mutant2, f"[Variant 2] Concatenation from %s: {query[:30]}..."))

            # Variant 3: .format() method
            new_query_fmt = query.replace('%s', '{}')
            param_args = ', '.join(params)
            mutant3 = code[:match.start()] + f'{match.group(1)}"{new_query_fmt}".format({param_args}))' + code[match.end():]
            mutants.append((mutant3, f"[Variant 3] .format() from %s: {query[:30]}..."))

        # If no regex matches, try AST-based mutation
        if not mutants:
            mutants.extend(self._ast_mutate(code))

        return mutants

    def _ast_mutate(self, code: str) -> List[Tuple[str, str]]:
        """AST-based mutation for more complex cases including variable-based queries"""
        mutants = []

        # Pattern: query = "SELECT ... WHERE x = ?" then db.execute(query, (param,))
        # Find query assignments with placeholders
        query_pattern = r'(\w+)\s*=\s*["\']([^"\']*\?[^"\']*)["\']'
        execute_pattern = r'\.execute\s*\(\s*(\w+)\s*,\s*\(([^)]+)\)\s*\)'

        query_matches = list(re.finditer(query_pattern, code))
        execute_matches = list(re.finditer(execute_pattern, code))

        for qm in query_matches:
            query_var = qm.group(1)
            query_str = qm.group(2)

            # Find corresponding execute call
            for em in execute_matches:
                if em.group(1) == query_var:
                    params = [p.strip() for p in em.group(2).split(',')]

                    # Variant 1: f-string interpolation
                    new_query_fstr = query_str
                    for param in params:
                        new_query_fstr = new_query_fstr.replace('?', '{' + param + '}', 1)
                    new_assignment = f'{query_var} = f"{new_query_fstr}"'
                    mutant = code[:qm.start()] + new_assignment + code[qm.end():]
                    mutant = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant
                    )
                    mutants.append((mutant, f"[Variant 1] f-string: query '{query_var}'"))

                    # Variant 2: String concatenation
                    new_query_concat = query_str
                    for param in params:
                        new_query_concat = new_query_concat.replace('?', f'" + str({param}) + "', 1)
                    new_assignment2 = f'{query_var} = "{new_query_concat}"'
                    mutant2 = code[:qm.start()] + new_assignment2 + code[qm.end():]
                    mutant2 = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant2
                    )
                    mutants.append((mutant2, f"[Variant 2] Concatenation: query '{query_var}'"))

                    # Variant 3: % formatting
                    new_query_pct = query_str.replace('?', '%s')
                    param_tuple = ', '.join(params)
                    new_assignment3 = f'{query_var} = "{new_query_pct}" % ({param_tuple})'
                    mutant3 = code[:qm.start()] + new_assignment3 + code[qm.end():]
                    mutant3 = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant3
                    )
                    mutants.append((mutant3, f"[Variant 3] % format: query '{query_var}'"))

                    # Variant 4: .format() method
                    new_query_fmt = query_str.replace('?', '{}')
                    param_args = ', '.join(params)
                    new_assignment4 = f'{query_var} = "{new_query_fmt}".format({param_args})'
                    mutant4 = code[:qm.start()] + new_assignment4 + code[qm.end():]
                    mutant4 = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant4
                    )
                    mutants.append((mutant4, f"[Variant 4] .format(): query '{query_var}'"))
                    break

        # Also handle %s placeholders with multiple variants
        query_pattern_pct = r'(\w+)\s*=\s*["\']([^"\']*%s[^"\']*)["\']'
        query_matches_pct = list(re.finditer(query_pattern_pct, code))

        for qm in query_matches_pct:
            query_var = qm.group(1)
            query_str = qm.group(2)

            for em in execute_matches:
                if em.group(1) == query_var:
                    params = [p.strip() for p in em.group(2).split(',')]

                    # Variant 1: f-string interpolation
                    new_query_fstr = query_str
                    for param in params:
                        new_query_fstr = new_query_fstr.replace('%s', '{' + param + '}', 1)
                    new_assignment = f'{query_var} = f"{new_query_fstr}"'
                    mutant = code[:qm.start()] + new_assignment + code[qm.end():]
                    mutant = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant
                    )
                    mutants.append((mutant, f"[Variant 1] f-string from %s: query '{query_var}'"))

                    # Variant 2: String concatenation
                    new_query_concat = query_str
                    for param in params:
                        new_query_concat = new_query_concat.replace('%s', f'" + str({param}) + "', 1)
                    new_assignment2 = f'{query_var} = "{new_query_concat}"'
                    mutant2 = code[:qm.start()] + new_assignment2 + code[qm.end():]
                    mutant2 = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant2
                    )
                    mutants.append((mutant2, f"[Variant 2] Concatenation from %s: query '{query_var}'"))

                    # Variant 3: .format() method
                    new_query_fmt = query_str.replace('%s', '{}')
                    param_args = ', '.join(params)
                    new_assignment3 = f'{query_var} = "{new_query_fmt}".format({param_args})'
                    mutant3 = code[:qm.start()] + new_assignment3 + code[qm.end():]
                    mutant3 = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant3
                    )
                    mutants.append((mutant3, f"[Variant 3] .format() from %s: query '{query_var}'"))
                    break

        return mutants


class RVALID(SecurityMutationOperator):
    """
    Remove Validation (RVALID)

    Removes input validation, sanitization, and escaping functions.

    Example:
        sanitized = escape_html(user_input)
        → sanitized = user_input
    """

    def __init__(self):
        super().__init__(
            name="RVALID",
            description="Remove input validation/sanitization",
            target_cwes=["CWE-20", "CWE-79", "CWE-89"]
        )
        # More specific patterns to reduce false positives
        # Format: (pattern_to_match, is_function_call)
        self.validation_patterns = [
            # Security-specific sanitization functions (high confidence)
            ('sanitize_input', True),
            ('sanitize_html', True),
            ('sanitize(', True),
            ('escape_html', True),
            ('html.escape', True),
            ('html_escape', True),
            ('markupsafe.escape', True),
            ('markupsafe.Markup', True),
            ('cgi.escape', True),
            ('bleach.clean', True),
            ('bleach.sanitize', True),
            ('strip_tags', True),
            # Input validation functions
            ('validate_input', True),
            ('validate_email', True),
            ('validate_url', True),
            ('check_input', True),
            # SQL escaping
            ('escape_string', True),
            ('mysql_real_escape', True),
            ('quote(', True),
            ('shlex.quote', True),
            # Regex validation patterns
            ('re.sub(', True),
            ('re.match(', True),
            ('re.search(', True),
            ('re.fullmatch(', True),
            # String validation methods (must be called on input)
            ('.isalnum()', True),
            ('.isalpha()', True),
            ('.isdigit()', True),
            ('.isnumeric()', True),
        ]
        # Keep backward compatibility
        self.validation_functions = [p[0].rstrip('(') for p in self.validation_patterns]

    def applies_to(self, code: str) -> bool:
        for pattern, _ in self.validation_patterns:
            if pattern in code:
                return True
        # Also check for validation patterns in conditionals
        if re.search(r'if\s+(not\s+)?\w*valid\w*\s*\(', code, re.IGNORECASE):
            return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Pattern: var = sanitize(input) OR var = module.sanitize(input)
        for func in self.validation_functions:
            # Function call with optional module prefix: html.escape(x), bleach.clean(x), etc.
            pattern = rf'(\w+)\s*=\s*(?:\w+\.)*{re.escape(func)}\s*\(([^)]+)\)'
            matches = list(re.finditer(pattern, code))

            for match in matches:
                var_name = match.group(1)
                arg = match.group(2).strip()
                mutant = code[:match.start()] + f'{var_name} = {arg}' + code[match.end():]
                mutants.append((mutant, f"Removed {func}() validation"))

        # Pattern: remove validation checks like if not validate(x): return
        validation_check_pattern = r'if\s+not\s+(\w*valid\w*)\s*\([^)]*\)\s*:\s*\n\s*(return|raise)[^\n]*\n'
        matches = list(re.finditer(validation_check_pattern, code, re.IGNORECASE))

        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, f"Removed validation check: {match.group(1)}"))

        # Remove regex validation
        regex_pattern = r'if\s+(not\s+)?re\.(match|search|fullmatch)\s*\([^)]+\)\s*:\s*\n\s*(return|raise)[^\n]*\n'
        matches = list(re.finditer(regex_pattern, code))

        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed regex validation check"))

        # NEW: Method call in return: return escape(x) → return x
        for func in self.validation_functions:
            return_pattern = rf'return\s+(?:\w+\.)*{re.escape(func)}\s*\(([^)]+)\)'
            for match in re.finditer(return_pattern, code):
                arg = match.group(1).strip()
                mutant = code[:match.start()] + f'return {arg}' + code[match.end():]
                mutants.append((mutant, f"Removed {func}() from return"))

        # NEW: Inline in expression: f(escape(x)) → f(x) for common validation functions
        inline_funcs = ['html.escape', 'escape', 'sanitize', 'bleach.clean', 'markupsafe.escape',
                        'cgi.escape', 'escape_html', 'sanitize_html', 'shlex.quote']
        for func in inline_funcs:
            # Match function call with optional module prefix
            inline_pattern = rf'(?:\w+\.)*{re.escape(func)}\s*\(([^)]+)\)'
            for match in re.finditer(inline_pattern, code):
                arg = match.group(1).strip()
                # Make sure we're not replacing an already processed assignment pattern
                context_start = max(0, match.start() - 10)
                context = code[context_start:match.start()]
                if '=' in context and not '==' in context:
                    continue  # Skip assignment patterns (handled above)
                mutant = code[:match.start()] + arg + code[match.end():]
                if mutant != code:
                    mutants.append((mutant, f"Removed inline {func}()"))

        # NEW: Template autoescaping: autoescape=True → autoescape=False
        if 'autoescape' in code:
            autoescape_pattern = r'autoescape\s*=\s*True'
            if re.search(autoescape_pattern, code):
                mutant = re.sub(autoescape_pattern, 'autoescape=False', code)
                mutants.append((mutant, "Disabled template autoescaping"))

        # NEW: Jinja2/Django template escaping
        if 'Environment(' in code and 'autoescape' not in code:
            # Add autoescape=False to Environment() call
            env_pattern = r'(Environment\s*\([^)]*)\)'
            match = re.search(env_pattern, code)
            if match:
                mutant = code[:match.start()] + match.group(1) + ', autoescape=False)' + code[match.end():]
                mutants.append((mutant, "Disabled Jinja2 autoescaping"))

        return mutants


class INPUTVAL(SecurityMutationOperator):
    """
    Remove Input Validation (INPUTVAL)

    Removes various forms of input validation including range checks,
    type validation, and boundary conditions.

    Difficulty Levels:
    - Easy: Remove simple range check (if x < 0)
    - Medium: Remove compound range check (if x < 0 or x > 100)
    - Hard: Remove try/except ValueError block, remove type checks
    """

    def __init__(self):
        super().__init__(
            name="INPUTVAL",
            description="Remove input validation checks",
            target_cwes=["CWE-20"]
        )

    def applies_to(self, code: str) -> bool:
        indicators = [
            'if', '<', '>', '<=', '>=', '< 0', '> 0',
            'int(', 'float(', 'ValueError', 'TypeError',
            'range', 'between', 'valid', 'invalid',
            '.isdigit()', '.isnumeric()', '.isalpha()',
        ]
        # Need at least a comparison with a number
        if re.search(r'if\s+.*[<>]=?\s*\d+', code):
            return True
        if 'ValueError' in code or 'TypeError' in code:
            return True
        return any(x in code for x in ['.isdigit()', '.isnumeric()', 'int(', 'float('])

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # === EASY: Remove simple range check ===
        # Pattern: if age < 0:\n    raise ValueError
        simple_range = r'if\s+\w+\s*[<>]=?\s*\d+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(simple_range, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Easy] Removed simple range check"))

        # === MEDIUM: Remove compound range check ===
        # Pattern: if age < 0 or age > 150:
        compound_range = r'if\s+\w+\s*[<>]=?\s*\d+\s+or\s+\w+\s*[<>]=?\s*\d+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(compound_range, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed compound range validation"))

        # === MEDIUM: Remove range with 'not' pattern ===
        # Pattern: if not (0 <= age <= 150):
        not_range = r'if\s+not\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(not_range, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed 'not in range' validation"))

        # === HARD: Remove try/except ValueError block ===
        # This removes the entire exception handling for bad input
        try_pattern = r'try\s*:\s*\n(\s+)([^\n]*int\([^\n]+|[^\n]*float\([^\n]+)\n\s*except\s+ValueError[^:]*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(try_pattern, code))
        for match in matches:
            indent = match.group(1)
            inner_code = match.group(2)
            # Keep the inner code but remove try/except
            mutant = code[:match.start()] + indent + inner_code + '\n' + code[match.end():]
            mutants.append((mutant, "[Hard] Removed try/except ValueError - invalid input not caught"))

        # === HARD: Remove type checking (isdigit, isnumeric) ===
        type_check = r'if\s+not\s+\w+\.(isdigit|isnumeric|isalpha|isalnum)\s*\(\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(type_check, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, f"[Hard] Removed {match.group(1)}() type check"))

        # === HARD: Remove length validation ===
        len_check = r'if\s+(len\([^)]+\)|not\s+len\([^)]+\))\s*[<>=!]+\s*\d+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(len_check, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Hard] Removed length validation"))

        return mutants


class SUBDOMAIN_SPOOF(SecurityMutationOperator):
    """
    Remove Subdomain Validation (SUBDOMAIN_SPOOF)

    Removes or weakens domain/subdomain validation checks, enabling
    subdomain spoofing attacks.

    Example:
        if not url.endswith('.example.com'):
            raise ValueError("Invalid domain")
        → (removed check, accepts any URL)

    Difficulty Levels:
    - Easy: Remove endswith('.domain.com') check
    - Medium: Remove parsed.netloc validation
    - Hard: Remove multi-condition domain validation
    """

    def __init__(self):
        super().__init__(
            name="SUBDOMAIN_SPOOF",
            description="Remove subdomain/domain validation for URL spoofing",
            target_cwes=["CWE-20", "CWE-918"]
        )
        self.domain_validators = [
            'endswith', 'startswith', 'netloc', 'hostname',
            'allowed_domains', 'valid_domains', 'trusted_domains',
            'domain_whitelist', 'check_domain', 'validate_domain',
        ]

    def applies_to(self, code: str) -> bool:
        code_lower = code.lower()
        # Check for domain validation patterns
        if any(v in code_lower for v in self.domain_validators):
            return True
        # Check for URL parsing with domain checks
        if 'urlparse' in code_lower and ('netloc' in code_lower or 'hostname' in code_lower):
            return True
        # Check for domain suffix validation
        if re.search(r'\.endswith\s*\([^)]*\.(com|org|net|io)', code):
            return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # === EASY: Remove endswith('.domain.com') check ===
        # Pattern: if not url.endswith('.example.com'):
        endswith_pattern = r'if\s+not\s+[\w.]+\.endswith\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(endswith_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Easy] Removed domain endswith() validation"))

        # === EASY: Remove 'in allowed_domains' check ===
        allowed_pattern = r'if\s+[\w.]+\s+not\s+in\s+(allowed_domains|valid_domains|trusted_domains|ALLOWED_DOMAINS)[^\n]*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(allowed_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Easy] Removed allowed_domains check"))

        # === MEDIUM: Remove netloc validation ===
        # Pattern: if parsed.netloc not in ALLOWED_HOSTS:
        netloc_pattern = r'if\s+[\w.]+\.netloc\s+(not\s+in|!=)[^\n]+:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(netloc_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed netloc domain validation"))

        # === MEDIUM: Remove hostname check ===
        hostname_pattern = r'if\s+[\w.]+\.hostname\s+(not\s+in|!=|not\s+endswith)[^\n]+:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(hostname_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed hostname validation"))

        # === MEDIUM: Replace strict domain check with permissive ===
        # Pattern: if domain in url → if True (always allow)
        domain_in_pattern = r'if\s+[\w.]+\s+in\s+[\w.]+\s*:'
        matches = list(re.finditer(domain_in_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + 'if True:' + code[match.end():]
            mutants.append((mutant, "[Medium] Replaced domain check with True"))

        # === HARD: Remove validate_domain function call ===
        validate_pattern = r'if\s+not\s+(validate_domain|check_domain|is_valid_domain)\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(validate_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Hard] Removed domain validation function"))

        # === HARD: Replace domain validation function with True ===
        for func in ['validate_domain', 'check_domain', 'is_valid_domain', 'is_trusted_domain']:
            func_pattern = rf'{func}\s*\([^)]*\)'
            matches = list(re.finditer(func_pattern, code, re.IGNORECASE))
            for match in matches:
                mutant = code[:match.start()] + 'True' + code[match.end():]
                mutants.append((mutant, f"[Hard] Replaced {func}() with True"))

        # === HARD: Remove compound domain validation ===
        # Pattern: if not (domain.endswith('.example.com') or domain in trusted):
        compound_pattern = r'if\s+not\s*\([^)]+endswith[^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(compound_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Hard] Removed compound domain validation"))

        return mutants


class RHTTPO(SecurityMutationOperator):
    """
    Remove HttpOnly Flag (RHTTPO)

    Removes httponly=True from cookie settings.

    Example:
        response.set_cookie('session', token, httponly=True)
        → response.set_cookie('session', token)
    """

    def __init__(self):
        super().__init__(
            name="RHTTPO",
            description="Remove HttpOnly flag from cookies",
            target_cwes=["CWE-1004"]
        )

    def applies_to(self, code: str) -> bool:
        return 'httponly' in code.lower() or 'set_cookie' in code

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove httponly=True
        patterns = [
            (r',\s*httponly\s*=\s*True', ''),
            (r'httponly\s*=\s*True\s*,\s*', ''),
            (r',\s*HttpOnly\s*=\s*True', ''),
            (r"'httponly':\s*True\s*,?\s*", ''),
        ]

        for pattern, replacement in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                mutant = re.sub(pattern, replacement, code, flags=re.IGNORECASE)
                mutants.append((mutant, "Removed HttpOnly flag from cookie"))

        # Change httponly=True to httponly=False
        if 'httponly=True' in code.lower():
            mutant = re.sub(r'httponly\s*=\s*True', 'httponly=False', code, flags=re.IGNORECASE)
            mutants.append((mutant, "Changed HttpOnly=True to HttpOnly=False"))

        return mutants


class WEAKCRYPTO(SecurityMutationOperator):
    """
    Weak Cryptography (WEAKCRYPTO)

    Replaces strong cryptographic algorithms with weak ones.

    Example:
        hashlib.sha256(data)
        → hashlib.md5(data)
    """

    def __init__(self):
        super().__init__(
            name="WEAKCRYPTO",
            description="Replace strong crypto with weak algorithms",
            target_cwes=["CWE-327", "CWE-328"]
        )
        # Multi-target replacements: strong → [list of weak options]
        self.multi_replacements = {
            'sha256': ['md5', 'sha1'],
            'sha384': ['md5', 'sha1'],
            'sha512': ['md5', 'sha1', 'sha256'],
            'sha3_256': ['md5', 'sha1'],
            'sha3_512': ['md5', 'sha1'],
            'pbkdf2_hmac': ['md5', 'sha1'],
            'bcrypt': ['md5', 'sha1'],
            'scrypt': ['md5', 'sha1'],
            'argon2': ['md5', 'sha1'],
            'AES': ['DES'],
            'Fernet': ['DES'],
        }

    def applies_to(self, code: str) -> bool:
        for strong in self.multi_replacements.keys():
            if strong.lower() in code.lower():
                return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Multi-target algorithm replacement
        for strong, weak_list in self.multi_replacements.items():
            if strong in code:
                for weak in weak_list:
                    mutant = code.replace(strong, weak)
                    if mutant != code:
                        mutants.append((mutant, f"{strong} → {weak}"))

            # Case insensitive for some
            elif strong.lower() in code.lower():
                pattern = re.compile(re.escape(strong), re.IGNORECASE)
                for weak in weak_list:
                    mutant = pattern.sub(weak, code)
                    if mutant != code:
                        mutants.append((mutant, f"{strong} → {weak} (case-insensitive)"))

        # Remove salt from hashing
        salt_pattern = r',\s*salt\s*=\s*[^,)]+'
        if re.search(salt_pattern, code):
            mutant = re.sub(salt_pattern, '', code)
            mutants.append((mutant, "Removed salt from cryptographic operation"))

        # Reduce iteration count
        iter_pattern = r'iterations\s*=\s*(\d+)'
        match = re.search(iter_pattern, code)
        if match:
            original_iter = int(match.group(1))
            weak_iter = 1
            mutant = re.sub(iter_pattern, f'iterations={weak_iter}', code)
            mutants.append((mutant, f"Reduced iterations from {original_iter} to {weak_iter}"))

        # Remove rounds parameter (used by bcrypt, argon2)
        rounds_pattern = r',\s*rounds\s*=\s*\d+'
        if re.search(rounds_pattern, code):
            mutant = re.sub(rounds_pattern, '', code)
            mutants.append((mutant, "Removed rounds parameter"))

        return mutants


class HARDCODE(SecurityMutationOperator):
    """
    Hardcode Credentials (HARDCODE)

    Injects hardcoded credentials into the code.

    Difficulty Levels:
    - Easy: Replace os.environ["KEY"] with hardcoded value
    - Medium: Replace os.environ.get(), os.getenv() with hardcoded value
    - Hard: Replace get_secret(), config.get() with hardcoded value
    """

    def __init__(self):
        super().__init__(
            name="HARDCODE",
            description="Inject hardcoded credentials",
            target_cwes=["CWE-798", "CWE-259"]
        )
        self.secret_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
            'token', 'auth', 'credential', 'private_key', 'access_key',
        ]
        # Multiple weak password variants for more mutants
        self.weak_passwords = [
            '"password"',      # OWASP top weak password
            '"123456"',        # Most common password
            '"admin"',         # Default credential
            '"password123"',   # Slightly "complex" weak password
        ]
        self.hardcoded_values = {
            'password': '"SuperSecret123!"',
            'user': '"admin"',
            'host': '"localhost"',
            'database': '"myapp"',
            'default': '"admin123"',
        }

    def applies_to(self, code: str) -> bool:
        code_lower = code.lower()
        for pattern in self.secret_patterns:
            if pattern in code_lower:
                return True
        if 'os.environ' in code or 'get_secret' in code or 'getenv' in code:
            return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # === EASY: Replace os.environ["KEY"] bracket notation ===
        # Generate MULTIPLE variants with different weak passwords
        env_bracket_pattern = r'os\.environ\s*\[\s*["\']([^"\']+)["\']\s*\]'
        matches = list(re.finditer(env_bracket_pattern, code))
        for match in matches:
            key = match.group(1).lower()
            # Generate variants with different weak passwords
            if 'password' in key or 'passwd' in key or 'secret' in key or 'key' in key:
                for i, weak_pwd in enumerate(self.weak_passwords):
                    mutant = code[:match.start()] + weak_pwd + code[match.end():]
                    mutants.append((mutant, f"[Easy-V{i+1}] Replaced os.environ['{match.group(1)}'] with {weak_pwd}"))
            else:
                # Single variant for non-sensitive keys
                mutant = code[:match.start()] + self.hardcoded_values.get(key, '"admin123"') + code[match.end():]
                mutants.append((mutant, f"[Easy] Replaced os.environ['{match.group(1)}'] with hardcoded value"))

        # === MEDIUM: Replace os.environ.get() with multiple weak password variants ===
        env_get_pattern = r'os\.environ\.get\s*\(\s*["\']([^"\']*)["\'](?:\s*,\s*[^)]+)?\s*\)'
        matches = list(re.finditer(env_get_pattern, code))
        for match in matches:
            key = match.group(1).lower()
            if 'password' in key or 'secret' in key or 'key' in key or 'token' in key:
                for i, weak_pwd in enumerate(self.weak_passwords):
                    mutant = code[:match.start()] + weak_pwd + code[match.end():]
                    mutants.append((mutant, f"[Medium-V{i+1}] Replaced os.environ.get('{match.group(1)}') with {weak_pwd}"))
            else:
                mutant = code[:match.start()] + self.hardcoded_values['default'] + code[match.end():]
                mutants.append((mutant, f"[Medium] Replaced os.environ.get('{match.group(1)}') with hardcoded value"))

        # === MEDIUM: Replace os.getenv() with multiple variants ===
        getenv_pattern = r'os\.getenv\s*\(\s*["\']([^"\']*)["\'](?:\s*,\s*[^)]+)?\s*\)'
        matches = list(re.finditer(getenv_pattern, code))
        for match in matches:
            key = match.group(1).lower()
            if 'password' in key or 'secret' in key or 'key' in key:
                for i, weak_pwd in enumerate(self.weak_passwords):
                    mutant = code[:match.start()] + weak_pwd + code[match.end():]
                    mutants.append((mutant, f"[Medium-V{i+1}] Replaced os.getenv('{match.group(1)}') with {weak_pwd}"))
            else:
                mutant = code[:match.start()] + self.hardcoded_values['default'] + code[match.end():]
                mutants.append((mutant, "[Medium] Replaced os.getenv() with hardcoded credential"))

        # === HARD: Replace get_secret() calls with multiple variants ===
        secret_pattern = r'get_secret\s*\(\s*[^)]+\s*\)'
        matches = list(re.finditer(secret_pattern, code))
        for match in matches:
            for i, weak_pwd in enumerate(self.weak_passwords):
                mutant = code[:match.start()] + weak_pwd + code[match.end():]
                mutants.append((mutant, f"[Hard-V{i+1}] Replaced get_secret() with {weak_pwd}"))

        # === HARD: Replace config.get() for secrets with multiple variants ===
        config_pattern = r'config\.get\s*\(\s*["\'](?:password|secret|api_key|token)["\'][^)]*\)'
        matches = list(re.finditer(config_pattern, code, re.IGNORECASE))
        for match in matches:
            for i, weak_pwd in enumerate(self.weak_passwords):
                mutant = code[:match.start()] + weak_pwd + code[match.end():]
                mutants.append((mutant, f"[Hard-V{i+1}] Replaced config secret with {weak_pwd}"))

        # === HARD: Replace vault/secrets manager calls with multiple variants ===
        vault_pattern = r'(vault|secrets_manager|ssm|secretsmanager)\.get[_a-z]*\s*\([^)]+\)'
        matches = list(re.finditer(vault_pattern, code, re.IGNORECASE))
        for match in matches:
            for i, weak_pwd in enumerate(self.weak_passwords):
                mutant = code[:match.start()] + weak_pwd + code[match.end():]
                mutants.append((mutant, f"[Hard-V{i+1}] Replaced secrets manager with {weak_pwd}"))

        # === NEW: Direct assignment pattern ===
        # Match: password = get_password() or secret = fetch_secret() etc.
        # But NOT: password = "already hardcoded"
        assign_pattern = r'(\w*(?:password|secret|token|api_key|auth_token|credential)\w*)\s*=\s*([^"\'\n][^\n;]+)'
        for match in re.finditer(assign_pattern, code, re.IGNORECASE):
            var_name = match.group(1)
            value = match.group(2).strip()
            # Skip if already a string literal or None/True/False
            if value.startswith(('"', "'")) or value in ('None', 'True', 'False'):
                continue
            # Skip if it's a simple identifier (could be a parameter assignment)
            if re.match(r'^\w+$', value) and not '(' in value:
                continue
            mutant = code[:match.start()] + f'{var_name} = "admin123"' + code[match.end():]
            mutants.append((mutant, f"Hardcoded {var_name} credential"))

        # === NEW: Dictionary access pattern ===
        # Match: config["password"] or settings["SECRET_KEY"] or data['api_key']
        dict_pattern = r'(\w+)\s*\[\s*["\'](\w*(?:password|secret|token|key|credential)\w*)["\']\\s*\]'
        for match in re.finditer(dict_pattern, code, re.IGNORECASE):
            dict_name = match.group(1)
            key_name = match.group(2)
            mutant = code[:match.start()] + '"hardcoded_secret_123"' + code[match.end():]
            mutants.append((mutant, f"Hardcoded {dict_name}['{key_name}']"))

        return mutants


class RMAUTH(SecurityMutationOperator):
    """
    Remove Authentication Check (RMAUTH)

    Removes authentication verification logic.

    Example:
        if not is_authenticated(user):
            raise UnauthorizedError()
        → (removed)
    """

    def __init__(self):
        super().__init__(
            name="RMAUTH",
            description="Remove authentication check",
            target_cwes=["CWE-287", "CWE-306"]
        )
        self.auth_patterns = [
            'is_authenticated', 'check_auth', 'verify_auth', 'authenticate',
            'is_logged_in', 'check_login', 'verify_login', 'require_auth',
            'login_required', 'auth_required', 'check_permission', 'has_permission',
            'is_authorized', 'check_token', 'verify_token', 'validate_session',
        ]

    def applies_to(self, code: str) -> bool:
        code_lower = code.lower()
        for pattern in self.auth_patterns:
            if pattern.lower() in code_lower:
                return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        for auth_func in self.auth_patterns:
            # Pattern: if not auth_func(): raise/return
            pattern = rf'if\s+not\s+{auth_func}\s*\([^)]*\)\s*:\s*\n(\s+)(raise|return)[^\n]*\n'
            matches = list(re.finditer(pattern, code, re.IGNORECASE))

            for match in matches:
                mutant = code[:match.start()] + code[match.end():]
                mutants.append((mutant, f"Removed authentication check: {auth_func}"))

            # Pattern: if auth_func(): ... else: raise
            # Note: Avoid re.DOTALL to prevent matching across multiple lines incorrectly
            pattern2 = rf'if\s+{auth_func}\s*\([^)]*\)\s*:\s*\n((?:\s+[^\n]+\n)+?)(\s*)else\s*:\s*\n\s*(raise|return)[^\n]*\n'
            matches = list(re.finditer(pattern2, code, re.IGNORECASE))

            for match in matches:
                # Keep the if body, remove the else block
                if_body = match.group(1)
                mutant = code[:match.start()] + f'if True:  # Auth check removed\n{if_body}' + code[match.end():]
                mutants.append((mutant, f"Bypassed authentication check: {auth_func}"))

        # Remove @login_required decorator
        decorator_pattern = r'@(login_required|auth_required|require_auth|authenticated)\s*\n'
        matches = list(re.finditer(decorator_pattern, code, re.IGNORECASE))

        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, f"Removed auth decorator: {match.group(1)}"))

        # Replace auth check with True
        for auth_func in self.auth_patterns:
            pattern = rf'{auth_func}\s*\([^)]*\)'
            matches = list(re.finditer(pattern, code, re.IGNORECASE))

            for match in matches:
                mutant = code[:match.start()] + 'True' + code[match.end():]
                mutants.append((mutant, f"Replaced {auth_func}() with True"))

        # NEW: Method-based auth: self.check_auth() or self.authenticate() → True
        method_auth_pattern = r'(self\.(?:check_auth|authenticate|verify_auth|is_authenticated|validate_credentials)\s*\([^)]*\))'
        for match in re.finditer(method_auth_pattern, code, re.IGNORECASE):
            mutant = code[:match.start()] + 'True' + code[match.end():]
            mutants.append((mutant, f"Bypassed {match.group(1)} with True"))

        # NEW: Request user auth: if not request.user.is_authenticated: ... → remove
        # Fixed: Use single-line matching to avoid indentation issues
        request_auth_pattern = r'if\s+not\s+request\.user\.is_authenticated\s*:\s*\n\s+(return|raise)[^\n]*\n'
        for match in re.finditer(request_auth_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed request.user.is_authenticated check"))

        # NEW: Flask-Login current_user check
        # Fixed: Use single-line matching to avoid indentation issues
        flask_auth_pattern = r'if\s+not\s+current_user\.is_authenticated\s*:\s*\n\s+(return|raise|redirect)[^\n]*\n'
        for match in re.finditer(flask_auth_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed current_user.is_authenticated check"))

        # NEW: Replace request.user.is_authenticated with True
        if 'request.user.is_authenticated' in code:
            mutant = code.replace('request.user.is_authenticated', 'True')
            mutants.append((mutant, "Replaced request.user.is_authenticated with True"))

        # NEW: Replace current_user.is_authenticated with True
        if 'current_user.is_authenticated' in code:
            mutant = code.replace('current_user.is_authenticated', 'True')
            mutants.append((mutant, "Replaced current_user.is_authenticated with True"))

        # NEW: Django permission decorators
        perm_decorator_pattern = r'@permission_required\s*\([^)]+\)\s*\n'
        for match in re.finditer(perm_decorator_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed @permission_required decorator"))

        # NEW: Django user_passes_test decorator
        user_test_pattern = r'@user_passes_test\s*\([^)]+\)\s*\n'
        for match in re.finditer(user_test_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed @user_passes_test decorator"))

        return mutants


class PATHCONCAT(SecurityMutationOperator):
    """
    Unsafe Path Concatenation (PATHCONCAT)

    Replaces safe path operations with vulnerable patterns.

    Difficulty Levels:
    - Easy: Remove .resolve(), remove startswith check
    - Medium: Replace Path / with f-string, remove normpath
    - Hard: Replace os.path.join with concat, subtle path bypass
    """

    def __init__(self):
        super().__init__(
            name="PATHCONCAT",
            description="Replace safe path join with string concatenation",
            target_cwes=["CWE-22", "CWE-73"]
        )

    def applies_to(self, code: str) -> bool:
        indicators = [
            'os.path.join', 'pathlib', 'Path(', '.resolve()',
            'startswith', 'normpath', 'realpath', 'abspath',
            '/ filename', '/ user', '/ path', '/ name'  # pathlib division
        ]
        return any(x in code for x in indicators)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # === EASY: Remove .resolve() ===
        resolve_pattern = r'\.resolve\(\)'
        if re.search(resolve_pattern, code):
            mutant = re.sub(resolve_pattern, '', code)
            mutants.append((mutant, "[Easy] Removed .resolve() - path not canonicalized"))

        # === EASY: Remove str().startswith() path validation ===
        # Pattern: if not str(target).startswith(str(base)):
        startswith_pattern = r'if\s+not\s+str\([^)]+\)\.startswith\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(startswith_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Easy] Removed path prefix validation"))

        # === EASY: Remove variable.startswith() check ===
        startswith_var_pattern = r'if\s+not\s+\w+\.startswith\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(startswith_var_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Easy] Removed path startswith validation"))

        # === MEDIUM: Replace pathlib / operator with f-string (variable form) ===
        # Pattern: (base / filename) where base is a variable
        pathlib_var_pattern = r'\((\w+)\s*/\s*(\w+)\)'
        matches = list(re.finditer(pathlib_var_pattern, code))
        for match in matches:
            base_var = match.group(1)
            file_var = match.group(2)
            replacement = f'f"{{str({base_var})}}/{{str({file_var})}}"'
            mutant = code[:match.start()] + replacement + code[match.end():]
            mutants.append((mutant, f"[Medium] Replaced ({base_var} / {file_var}) with f-string"))

        # === MEDIUM: Replace Path(...) / operator ===
        pathlib_pattern = r'(Path\([^)]+\))\s*/\s*(\w+)'
        matches = list(re.finditer(pathlib_pattern, code))
        for match in matches:
            path_obj = match.group(1)
            filename = match.group(2)
            replacement = f'f"{{str({path_obj})}}/{{str({filename})}}"'
            mutant = code[:match.start()] + replacement + code[match.end():]
            mutants.append((mutant, "[Medium] Replaced Path / operator with f-string"))

        # === MEDIUM: Remove normpath/realpath/abspath ===
        for func in ['normpath', 'realpath', 'abspath']:
            pattern = rf'os\.path\.{func}\s*\(\s*([^)]+)\s*\)'
            matches = list(re.finditer(pattern, code))
            for match in matches:
                inner = match.group(1)
                mutant = code[:match.start()] + inner + code[match.end():]
                mutants.append((mutant, f"[Medium] Removed os.path.{func}"))

        # === HARD: Replace os.path.join with string concatenation ===
        join_pattern = r'os\.path\.join\s*\(\s*([^,]+),\s*([^)]+)\)'
        matches = list(re.finditer(join_pattern, code))
        for match in matches:
            arg1 = match.group(1).strip()
            arg2 = match.group(2).strip()
            replacement = f'{arg1} + "/" + {arg2}'
            mutant = code[:match.start()] + replacement + code[match.end():]
            mutants.append((mutant, "[Hard] Replaced os.path.join with string concatenation"))

        # === HARD: Remove entire path validation block ===
        # Pattern: if not str(target).startswith(str(base)):\n    raise ...
        full_block_pattern = r'if\s+not\s+[^:]+:\s*\n\s*(raise\s+ValueError\([^)]*(?:traversal|path|invalid)[^)]*\)|return\s+None)\n?'
        matches = list(re.finditer(full_block_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Hard] Removed path validation block"))

        return mutants


class CMDINJECT(SecurityMutationOperator):
    """
    Command Injection (CMDINJECT)

    Introduces command injection vulnerabilities.

    Example:
        subprocess.run(["ls", "-l", directory])
        → subprocess.run(f"ls -l {directory}", shell=True)
    """

    def __init__(self):
        super().__init__(
            name="CMDINJECT",
            description="Enable shell command injection",
            target_cwes=["CWE-78", "CWE-77"]
        )

    def applies_to(self, code: str) -> bool:
        return any(x in code for x in ['subprocess', 'os.system', 'os.popen', 'Popen', 'check_output'])

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Change shell=False to shell=True
        if 'shell=False' in code:
            mutant = code.replace('shell=False', 'shell=True')
            mutants.append((mutant, "[Variant 1] Changed shell=False to shell=True"))

        # Add shell=True where missing
        patterns = [
            (r'subprocess\.run\s*\(\s*(\[[^\]]+\])\s*\)',
             lambda m: f'subprocess.run({m.group(1)}, shell=True)'),
            (r'subprocess\.Popen\s*\(\s*(\[[^\]]+\])\s*\)',
             lambda m: f'subprocess.Popen({m.group(1)}, shell=True)'),
            (r'subprocess\.call\s*\(\s*(\[[^\]]+\])\s*\)',
             lambda m: f'subprocess.call({m.group(1)}, shell=True)'),
            (r'subprocess\.check_output\s*\(\s*(\[[^\]]+\])\s*\)',
             lambda m: f'subprocess.check_output({m.group(1)}, shell=True)'),
        ]

        for pattern, replacement_func in patterns:
            for match in re.finditer(pattern, code):
                mutant = code[:match.start()] + replacement_func(match) + code[match.end():]
                mutants.append((mutant, "[Variant 2] Added shell=True to subprocess call"))

        # Convert list args to string with shell=True (f-string variant)
        list_pattern = r'subprocess\.(run|call|Popen|check_output)\s*\(\s*\[([^\]]+)\]'
        matches = list(re.finditer(list_pattern, code))

        for match in matches:
            func = match.group(1)
            args = match.group(2)
            # Convert list to f-string, preserving variables
            parts = []
            vars_used = []
            for a in args.split(','):
                a = a.strip()
                if a.startswith('"') or a.startswith("'"):
                    # String literal - strip quotes
                    parts.append(a.strip('"\''))
                else:
                    # Variable - use f-string interpolation
                    parts.append('{' + a + '}')
                    vars_used.append(a)
            cmd_string = ' '.join(parts)

            # Variant 3: f-string with shell=True
            replacement = f'subprocess.{func}(f"{cmd_string}", shell=True'
            mutant = code[:match.start()] + replacement + code[match.end():]
            mutants.append((mutant, "[Variant 3] Converted to f-string shell command"))

            # Variant 4: Replace with os.system
            os_cmd = f'os.system(f"{cmd_string}")'
            mutant2 = code[:match.start()] + os_cmd + code[match.end():]
            if 'import os' not in mutant2 and 'from os' not in mutant2:
                mutant2 = 'import os\n' + mutant2
            mutants.append((mutant2, "[Variant 4] Replaced subprocess with os.system"))

            # Variant 5: Replace with os.popen
            os_popen_cmd = f'os.popen(f"{cmd_string}")'
            mutant3 = code[:match.start()] + os_popen_cmd + code[match.end():]
            if 'import os' not in mutant3 and 'from os' not in mutant3:
                mutant3 = 'import os\n' + mutant3
            mutants.append((mutant3, "[Variant 5] Replaced subprocess with os.popen"))

        # Remove shlex.quote
        shlex_pattern = r'shlex\.quote\s*\(\s*([^)]+)\s*\)'
        matches = list(re.finditer(shlex_pattern, code))

        for match in matches:
            inner = match.group(1)
            mutant = code[:match.start()] + inner + code[match.end():]
            mutants.append((mutant, "[Variant 6] Removed shlex.quote"))

        # Handle os.popen: multiple injection variants
        popen_pattern = r'os\.popen\s*\(([^)]+)\)'
        for match in re.finditer(popen_pattern, code):
            arg = match.group(1).strip()
            # Variant: append shell command via concatenation
            mutant = code[:match.start()] + f'os.popen({arg} + "; cat /etc/passwd")' + code[match.end():]
            mutants.append((mutant, "[Variant 7] Injected command via os.popen"))

        # Handle os.system: multiple injection variants
        system_pattern = r'os\.system\s*\(([^)]+)\)'
        for match in re.finditer(system_pattern, code):
            arg = match.group(1).strip()
            # Variant: append shell command
            mutant = code[:match.start()] + f'os.system({arg} + "; id")' + code[match.end():]
            mutants.append((mutant, "[Variant 8] Injected command via os.system"))

        # NEW: Replace safe subprocess patterns with dangerous eval-based patterns
        # Pattern: subprocess.run(["cmd", arg]) → eval("__import__('os').system('cmd ' + arg)")
        safe_subprocess = r'subprocess\.(run|call)\s*\(\s*\[([^\]]+)\][^)]*\)'
        for match in re.finditer(safe_subprocess, code):
            args = match.group(2)
            parts = [a.strip().strip('"\'') for a in args.split(',')]
            if len(parts) >= 2:
                cmd = parts[0]
                var = parts[1] if not parts[1].startswith('"') else parts[1]
                # Only if there's a variable involved
                if not var.startswith('"') and not var.startswith("'"):
                    eval_cmd = f"eval(f\"__import__('os').system('{cmd} ' + {var})\")"
                    mutant = code[:match.start()] + eval_cmd + code[match.end():]
                    mutants.append((mutant, "[Variant 9] Replaced subprocess with eval-based injection"))

        return mutants


class RENCRYPT(SecurityMutationOperator):
    """
    Remove Encryption (RENCRYPT)

    Removes or disables encryption.

    Example:
        conn = ssl.wrap_socket(sock, ...)
        → conn = sock
    """

    def __init__(self):
        super().__init__(
            name="RENCRYPT",
            description="Remove encryption/TLS configuration",
            target_cwes=["CWE-319", "CWE-311"]
        )

    def applies_to(self, code: str) -> bool:
        return any(x in code for x in ['ssl', 'tls', 'https', 'encrypt', 'cipher', 'verify_ssl'])

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove ssl.wrap_socket
        wrap_pattern = r'ssl\.wrap_socket\s*\(\s*(\w+)[^)]*\)'
        matches = list(re.finditer(wrap_pattern, code))

        for match in matches:
            inner_socket = match.group(1)
            mutant = code[:match.start()] + inner_socket + code[match.end():]
            mutants.append((mutant, "Removed ssl.wrap_socket"))

        # Disable SSL verification
        if 'verify=True' in code:
            mutant = code.replace('verify=True', 'verify=False')
            mutants.append((mutant, "Changed verify=True to verify=False"))

        # Replace https with http
        if 'https://' in code:
            mutant = code.replace('https://', 'http://')
            mutants.append((mutant, "Replaced https with http"))

        # Remove SSL context creation
        ctx_pattern = r'ssl\.create_default_context\s*\([^)]*\)'
        matches = list(re.finditer(ctx_pattern, code))

        for match in matches:
            mutant = code[:match.start()] + 'None' + code[match.end():]
            mutants.append((mutant, "Removed SSL context"))

        # Disable hostname checking
        if 'check_hostname = True' in code:
            mutant = code.replace('check_hostname = True', 'check_hostname = False')
            mutants.append((mutant, "Disabled hostname checking"))

        # Disable certificate verification
        cert_patterns = [
            ('ssl.CERT_REQUIRED', 'ssl.CERT_NONE'),
            ('CERT_REQUIRED', 'CERT_NONE'),
        ]

        for orig, repl in cert_patterns:
            if orig in code:
                mutant = code.replace(orig, repl)
                mutants.append((mutant, f"Changed {orig} to {repl}"))

        return mutants


class DESERIAL(SecurityMutationOperator):
    """
    Unsafe Deserialization (DESERIAL)

    Replaces safe deserialization with unsafe methods.

    Example:
        data = json.loads(user_input)
        → data = pickle.loads(user_input)

    Also handles YAML gadget patterns for CWE-502.
    """

    def __init__(self):
        super().__init__(
            name="DESERIAL",
            description="Replace safe deserialization with unsafe methods",
            target_cwes=["CWE-502", "CWE-94"]
        )

    def applies_to(self, code: str) -> bool:
        safe_patterns = ['json.loads', 'json.load', 'yaml.safe_load', 'ast.literal_eval',
                         'SafeLoader', 'safe_load', 'literal_eval']
        # Also check for YAML with Loader specification
        if 'yaml.load' in code and 'Loader' in code:
            return True
        return any(p in code for p in safe_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Replace json.loads with multiple unsafe options
        if 'json.loads' in code:
            # Variant 1: pickle.loads
            mutant = code.replace('json.loads', 'pickle.loads')
            if 'import pickle' not in mutant and 'from pickle' not in mutant:
                mutant = 'import pickle\n' + mutant
            mutants.append((mutant, "json.loads → pickle.loads"))

            # Variant 2: yaml.unsafe_load
            mutant2 = code.replace('json.loads', 'yaml.unsafe_load')
            if 'import yaml' not in mutant2 and 'from yaml' not in mutant2:
                mutant2 = 'import yaml\n' + mutant2
            mutants.append((mutant2, "json.loads → yaml.unsafe_load"))

            # Variant 3: eval
            mutant3 = code.replace('json.loads', 'eval')
            mutants.append((mutant3, "json.loads → eval"))

        # Replace json.load with multiple unsafe options
        if 'json.load' in code and 'json.loads' not in code:
            # Variant 1: pickle.load
            mutant = code.replace('json.load', 'pickle.load')
            if 'import pickle' not in mutant:
                mutant = 'import pickle\n' + mutant
            mutants.append((mutant, "json.load → pickle.load"))

            # Variant 2: yaml.unsafe_load (read file first)
            mutant2 = code.replace('json.load', 'yaml.unsafe_load')
            if 'import yaml' not in mutant2:
                mutant2 = 'import yaml\n' + mutant2
            mutants.append((mutant2, "json.load → yaml.unsafe_load"))

        # Replace yaml.safe_load with multiple unsafe options
        if 'yaml.safe_load' in code:
            # Variant 1: yaml.load (unsafe)
            mutant = code.replace('yaml.safe_load', 'yaml.load')
            mutants.append((mutant, "yaml.safe_load → yaml.load (unsafe)"))

            # Variant 2: yaml.unsafe_load
            mutant2 = code.replace('yaml.safe_load', 'yaml.unsafe_load')
            mutants.append((mutant2, "yaml.safe_load → yaml.unsafe_load"))

            # Variant 3: yaml.load with FullLoader (allows some Python objects)
            mutant3 = code.replace('yaml.safe_load', 'yaml.load')
            mutant3 = mutant3.replace('yaml.load(', 'yaml.load(Loader=yaml.FullLoader, ')
            mutants.append((mutant3, "yaml.safe_load → yaml.load with FullLoader"))

        # Replace SafeLoader with unsafe Loader
        if 'SafeLoader' in code:
            mutant = code.replace('SafeLoader', 'Loader')
            mutants.append((mutant, "SafeLoader → Loader (unsafe)"))

            mutant2 = code.replace('SafeLoader', 'UnsafeLoader')
            mutants.append((mutant2, "SafeLoader → UnsafeLoader"))

            mutant3 = code.replace('SafeLoader', 'FullLoader')
            mutants.append((mutant3, "SafeLoader → FullLoader (allows Python objects)"))

        # Handle yaml.load with Loader=SafeLoader → remove Loader restriction
        loader_pattern = r'yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader[^)]*\)'
        matches = list(re.finditer(loader_pattern, code))
        for match in matches:
            # Remove the Loader argument
            original = match.group(0)
            unsafe = re.sub(r',?\s*Loader\s*=\s*(?:yaml\.)?SafeLoader', '', original)
            mutant = code[:match.start()] + unsafe + code[match.end():]
            mutants.append((mutant, "Removed SafeLoader restriction from yaml.load"))

        # Replace ast.literal_eval with multiple unsafe options
        if 'ast.literal_eval' in code:
            # Variant 1: eval
            mutant = code.replace('ast.literal_eval', 'eval')
            mutants.append((mutant, "ast.literal_eval → eval"))

            # Variant 2: exec (different behavior but dangerous)
            mutant2 = code.replace('ast.literal_eval', 'exec')
            mutants.append((mutant2, "ast.literal_eval → exec"))

        # === NEW: YAML Gadget injection patterns ===
        # If code validates YAML content, inject gadget acceptance
        if 'yaml' in code.lower():
            # Pattern: Remove checks that block !!python tags
            python_tag_check = r'if\s+["\']!!python["\'].*in.*:\s*\n\s*(raise|return)[^\n]*\n'
            matches = list(re.finditer(python_tag_check, code))
            for match in matches:
                mutant = code[:match.start()] + code[match.end():]
                mutants.append((mutant, "Removed !!python tag validation (YAML gadget)"))

            # Pattern: Remove tag validation
            tag_check = r'if\s+[\w.]+\.startswith\s*\(["\']!!["\'][^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
            matches = list(re.finditer(tag_check, code))
            for match in matches:
                mutant = code[:match.start()] + code[match.end():]
                mutants.append((mutant, "Removed YAML tag prefix validation"))

        return mutants


class SSRF(SecurityMutationOperator):
    """
    Server-Side Request Forgery (SSRF)

    Removes URL validation allowing arbitrary URL requests.

    Difficulty Levels:
    - Easy: Remove 'hostname in BLOCKED_HOSTS' check
    - Medium: Remove urlparse validation, remove startswith check
    - Hard: Remove is_safe_url, bypass validation function
    """

    def __init__(self):
        super().__init__(
            name="SSRF",
            description="Remove URL validation to enable SSRF",
            target_cwes=["CWE-918"]
        )
        self.url_validators = [
            'urlparse', 'is_safe_url', 'validate_url', 'check_url',
            'is_valid_url', 'allowed_hosts', 'whitelist', 'startswith',
            'blocked', 'internal', 'private', 'hostname',
        ]

    def applies_to(self, code: str) -> bool:
        if any(v in code.lower() for v in self.url_validators):
            return True
        if 'requests.' in code or 'urllib' in code or 'http.client' in code:
            return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # === EASY: Remove 'hostname in BLOCKED_HOSTS' check ===
        # Pattern: if parsed.hostname in BLOCKED_HOSTS or ...
        # Include leading whitespace to avoid indentation issues
        blocked_hosts_pattern = r'[ \t]*if\s+[\w.]+\.hostname\s+in\s+\w+[^:]*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(blocked_hosts_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Easy] Removed hostname blocklist check"))

        # === EASY: Remove 'hostname.startswith' check (compound conditions) ===
        # Pattern: if ... or hostname.startswith('192.168.'):
        startswith_compound = r'\s+or\s+[\w.]+\.startswith\s*\([^)]+\)'
        if re.search(startswith_compound, code):
            mutant = re.sub(startswith_compound, '', code)
            mutants.append((mutant, "[Easy] Removed hostname prefix check from compound condition"))

        # === MEDIUM: Remove URL startswith/endswith validation ===
        # Include leading whitespace to avoid indentation issues
        url_check_pattern = r'[ \t]*if\s+not\s+[\w.]+\.(startswith|endswith)\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(url_check_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed URL prefix/suffix validation"))

        # === MEDIUM: Remove urlparse validation ===
        urlparse_check = r'[ \t]*if\s+urlparse\s*\([^)]+\)\.netloc\s*(not\s+in|!=)[^\n]+:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(urlparse_check, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed urlparse host validation"))

        # === MEDIUM: Remove 'not in allowed_hosts' check ===
        allowed_pattern = r'[ \t]*if\s+[\w.]+\s+not\s+in\s+(allowed_hosts|ALLOWED_HOSTS|whitelist)[^\n]*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(allowed_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed allowed hosts validation"))

        # === HARD: Remove is_safe_url check ===
        safe_url_pattern = r'[ \t]*if\s+not\s+is_safe_url\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(safe_url_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Hard] Removed is_safe_url validation"))

        # === HARD: Replace validated URL with user input directly ===
        validated_pattern = r'(\w+)\s*=\s*validate_url\s*\(([^)]+)\)'
        matches = list(re.finditer(validated_pattern, code))
        for match in matches:
            var_name = match.group(1)
            arg = match.group(2)
            mutant = code[:match.start()] + f'{var_name} = {arg}' + code[match.end():]
            mutants.append((mutant, "[Hard] Bypassed URL validation function"))

        # === HARD: Remove entire validation block with multi-line condition ===
        # Include leading whitespace to avoid indentation issues
        multi_line_check = r'[ \t]*if\s+[\w.]+\s+in\s+\w+\s+or\s+[^:]+:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(multi_line_check, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Hard] Removed multi-condition URL validation"))

        return mutants


class IDOR(SecurityMutationOperator):
    """
    Insecure Direct Object Reference (IDOR)

    Removes authorization checks for object access.

    Example:
        if document.owner_id != current_user.id:
            raise PermissionError()
        return document
        → return document  # No ownership check
    """

    def __init__(self):
        super().__init__(
            name="IDOR",
            description="Remove object ownership/authorization checks",
            target_cwes=["CWE-639", "CWE-284"]
        )
        self.ownership_patterns = [
            'owner', 'user_id', 'author_id', 'created_by', 'belongs_to',
            'has_permission', 'can_access', 'is_owner', 'check_ownership',
        ]

    def applies_to(self, code: str) -> bool:
        code_lower = code.lower()
        return any(p in code_lower for p in self.ownership_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove owner_id check
        owner_check_pattern = r'if\s+[\w.]+\.owner_id\s*(!=|==)\s*[\w.]+:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(owner_check_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed owner_id authorization check"))

        # Remove user_id comparison
        user_check_pattern = r'if\s+[\w.]+\s*(!=|==)\s*(current_user|request\.user|session\[.user.\])[\w.]*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(user_check_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed user authorization check"))

        # Remove has_permission check
        perm_pattern = r'if\s+not\s+[\w.]+\.has_permission\s*\([^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(perm_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed has_permission check"))

        # Remove can_access check
        access_pattern = r'if\s+not\s+(can_access|check_access|is_authorized)\s*\([^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(access_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed access authorization check"))

        # Replace authorization function with True
        for pattern in ['has_permission', 'can_access', 'is_owner', 'check_ownership']:
            func_pattern = rf'{pattern}\s*\([^)]*\)'
            matches = list(re.finditer(func_pattern, code, re.IGNORECASE))
            for match in matches:
                mutant = code[:match.start()] + 'True' + code[match.end():]
                mutants.append((mutant, f"Replaced {pattern}() with True"))

        return mutants


class XXE(SecurityMutationOperator):
    """
    XML External Entity Injection (XXE)

    Enables external entity processing in XML parsers.

    Example:
        parser = etree.XMLParser(resolve_entities=False)
        → parser = etree.XMLParser(resolve_entities=True)
    """

    def __init__(self):
        super().__init__(
            name="XXE",
            description="Enable XML external entity processing",
            target_cwes=["CWE-611"]
        )

    def applies_to(self, code: str) -> bool:
        # Direct XML library indicators
        xml_indicators = [
            'xml', 'etree', 'ElementTree', 'lxml', 'XMLParser', 'parse',
            'minidom', 'pulldom', 'sax', 'expat', 'xmlrpc',
            'defusedxml', 'parseString', 'fromstring', 'iterparse'
        ]
        if any(x in code for x in xml_indicators):
            return True

        # Check for XML file operations
        if re.search(r'\.xml[\'"\)]', code) or re.search(r'[\'"].*\.xml[\'"]', code):
            return True

        # Check for XML content patterns
        if '<?xml' in code or 'DOCTYPE' in code or 'ENTITY' in code:
            return True

        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Enable resolve_entities
        if 'resolve_entities=False' in code:
            mutant = code.replace('resolve_entities=False', 'resolve_entities=True')
            mutants.append((mutant, "Enabled resolve_entities in XML parser"))

        # Remove no_network restriction
        if 'no_network=True' in code:
            mutant = code.replace('no_network=True', 'no_network=False')
            mutants.append((mutant, "Disabled no_network restriction"))

        # Enable DTD loading
        if 'load_dtd=False' in code:
            mutant = code.replace('load_dtd=False', 'load_dtd=True')
            mutants.append((mutant, "Enabled DTD loading"))

        # Remove defusedxml usage
        if 'defusedxml' in code:
            mutant = code.replace('defusedxml.ElementTree', 'xml.etree.ElementTree')
            mutant = mutant.replace('from defusedxml', 'from xml.etree')
            mutant = mutant.replace('import defusedxml', 'import xml.etree.ElementTree')
            mutants.append((mutant, "Replaced defusedxml with standard xml library"))

        # Replace safe parse with unsafe
        if 'defusedxml.parse' in code:
            mutant = code.replace('defusedxml.parse', 'etree.parse')
            mutants.append((mutant, "Replaced defusedxml.parse with etree.parse"))

        # Remove XMLParser security settings
        secure_parser_pattern = r'XMLParser\s*\([^)]*\)'
        matches = list(re.finditer(secure_parser_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + 'XMLParser()' + code[match.end():]
            mutants.append((mutant, "Removed XMLParser security settings"))

        # Enable external entities via feature
        if 'setFeature' in code and 'external-general-entities' in code:
            mutant = code.replace('False)', 'True)')
            mutants.append((mutant, "Enabled external general entities"))

        # Handle SAX parser - disable features that prevent XXE
        if 'sax' in code.lower():
            # SAX: Disable external entity feature
            sax_feature_pattern = r'setFeature\s*\([^,]+,\s*False\s*\)'
            matches = list(re.finditer(sax_feature_pattern, code))
            for match in matches:
                mutant = code[:match.start()] + match.group().replace('False', 'True') + code[match.end():]
                mutants.append((mutant, "Enabled SAX parser feature (XXE risk)"))

        # Handle minidom - replace with insecure parsing
        if 'minidom' in code:
            if 'parseString' in code:
                # Already using minidom.parseString which is vulnerable by default
                # Try to remove any security wrappers
                mutant = re.sub(r'defused_parseString\s*\(', 'parseString(', code)
                if mutant != code:
                    mutants.append((mutant, "Replaced secure parseString with vulnerable minidom"))

        # Handle lxml with parser settings
        if 'lxml' in code:
            # Remove huge_tree restriction
            if 'huge_tree=False' in code:
                mutant = code.replace('huge_tree=False', 'huge_tree=True')
                mutants.append((mutant, "Enabled huge_tree in lxml (can cause DoS)"))
            # Remove recover restriction for malformed XML
            if 'recover=False' in code:
                mutant = code.replace('recover=False', 'recover=True')
                mutants.append((mutant, "Enabled error recovery in lxml"))

        # Handle etree.parse with parser argument - remove secure parser
        parse_with_parser = re.search(r'(etree\.parse|ET\.parse)\s*\([^,]+,\s*parser\s*=\s*\w+\)', code)
        if parse_with_parser:
            # Remove the parser argument to use default (unsafe) parser
            mutant = re.sub(r'(etree\.parse|ET\.parse)\s*\(([^,]+),\s*parser\s*=\s*\w+\)',
                          r'\1(\2)', code)
            if mutant != code:
                mutants.append((mutant, "Removed secure parser from etree.parse"))

        # Handle fromstring with secure parser - common pattern
        fromstring_pattern = re.search(r'(etree\.fromstring|ET\.fromstring|lxml\.etree\.fromstring)\s*\([^,]+,\s*parser\s*=\s*\w+\)', code)
        if fromstring_pattern:
            mutant = re.sub(r'(etree\.fromstring|ET\.fromstring|lxml\.etree\.fromstring)\s*\(([^,]+),\s*parser\s*=\s*\w+\)',
                          r'\1(\2)', code)
            if mutant != code:
                mutants.append((mutant, "Removed secure parser from fromstring"))

        # Handle iterparse with secure settings
        iterparse_pattern = re.search(r'(etree\.iterparse|ET\.iterparse)\s*\([^)]+\)', code)
        if iterparse_pattern and ('forbid_dtd' in code or 'forbid_entities' in code):
            mutant = re.sub(r'forbid_dtd\s*=\s*True', 'forbid_dtd=False', code)
            mutant = re.sub(r'forbid_entities\s*=\s*True', 'forbid_entities=False', mutant)
            if mutant != code:
                mutants.append((mutant, "Disabled iterparse security restrictions"))

        # Handle defusedxml.fromstring → etree.fromstring
        if 'defusedxml.fromstring' in code or 'defused_fromstring' in code:
            mutant = code.replace('defusedxml.fromstring', 'etree.fromstring')
            mutant = mutant.replace('defused_fromstring', 'etree.fromstring')
            if mutant != code:
                mutants.append((mutant, "Replaced safe defusedxml.fromstring with etree.fromstring"))

        # Handle xml.etree.ElementTree.parse() - add unsafe options
        if 'ElementTree.parse' in code and 'defusedxml' not in code:
            # If using standard ElementTree.parse without defusedxml, it's already vulnerable
            # But if there's a custom parser, remove it
            et_parse_pattern = re.search(r'ElementTree\.parse\s*\([^,]+,\s*parser\s*=', code)
            if et_parse_pattern:
                mutant = re.sub(r'(ElementTree\.parse\s*\([^,]+),\s*parser\s*=[^)]+\)', r'\1)', code)
                if mutant != code:
                    mutants.append((mutant, "Removed custom parser from ElementTree.parse"))

        return mutants


class SSTI(SecurityMutationOperator):
    """
    Server-Side Template Injection (SSTI)

    Uses unsafe template rendering with user input.

    Example:
        template = env.get_template('page.html')
        return template.render(data=data)
        → return Template(user_input).render()
    """

    def __init__(self):
        super().__init__(
            name="SSTI",
            description="Enable server-side template injection",
            target_cwes=["CWE-1336", "CWE-94"]
        )

    def applies_to(self, code: str) -> bool:
        template_indicators = [
            'Template', 'render', 'jinja', 'Jinja2', 'render_template',
            'render_string', 'mako', 'django.template', 'Environment'
        ]
        return any(x in code for x in template_indicators)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Replace safe template loading with direct Template()
        safe_pattern = r'(\w+)\.get_template\s*\([^)]+\)'
        matches = list(re.finditer(safe_pattern, code))
        for match in matches:
            # Find variable being rendered
            render_pattern = rf'{match.group(0)}.*?\.render\s*\(([^)]*)\)'
            render_match = re.search(render_pattern, code, re.DOTALL)
            if render_match:
                mutant = code.replace(match.group(0), 'Template(user_input)')
                mutants.append((mutant, "Replaced safe template loading with Template(user_input)"))

        # Enable autoescape=False
        if 'autoescape=True' in code:
            mutant = code.replace('autoescape=True', 'autoescape=False')
            mutants.append((mutant, "Disabled template autoescaping"))

        # Replace render_template with render_template_string
        if 'render_template(' in code and 'render_template_string' not in code:
            # Find the template name and replace with user input
            pattern = r'render_template\s*\(\s*["\'][^"\']+["\']'
            matches = list(re.finditer(pattern, code))
            for match in matches:
                mutant = code[:match.start()] + 'render_template_string(user_input' + code[match.end():]
                mutants.append((mutant, "Replaced render_template with render_template_string(user_input)"))

        # Remove sandbox
        if 'SandboxedEnvironment' in code:
            mutant = code.replace('SandboxedEnvironment', 'Environment')
            mutants.append((mutant, "Replaced SandboxedEnvironment with Environment"))

        # Use string formatting in template
        format_pattern = r'\.render\s*\(\s*\w+\s*=\s*(\w+)\s*\)'
        matches = list(re.finditer(format_pattern, code))
        for match in matches:
            var = match.group(1)
            mutant = code[:match.start()] + f'.render({var}={var})' + code[match.end():]
            if mutant != code:
                mutants.append((mutant, "Modified template render call"))

        return mutants


class CORS_WEAK(SecurityMutationOperator):
    """
    Weak CORS Policy (CORS_WEAK)

    Weakens Cross-Origin Resource Sharing restrictions.

    Example:
        Access-Control-Allow-Origin: https://trusted.com
        → Access-Control-Allow-Origin: *
    """

    def __init__(self):
        super().__init__(
            name="CORS_WEAK",
            description="Weaken CORS policy to allow all origins",
            target_cwes=["CWE-942", "CWE-346"]
        )

    def applies_to(self, code: str) -> bool:
        cors_indicators = [
            'Access-Control', 'CORS', 'cors', 'allow_origin', 'allowed_origins',
            'CrossOrigin', 'cross_origin'
        ]
        return any(x in code for x in cors_indicators)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Replace specific origin with wildcard
        origin_pattern = r"['\"]Access-Control-Allow-Origin['\"]\s*[,:]\s*['\"]https?://[^'\"]+['\"]"
        matches = list(re.finditer(origin_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + "'Access-Control-Allow-Origin': '*'" + code[match.end():]
            mutants.append((mutant, "Changed CORS origin to wildcard *"))

        # Replace origins list with wildcard
        origins_list_pattern = r'(origins|allowed_origins|ALLOWED_ORIGINS)\s*=\s*\[[^\]]+\]'
        matches = list(re.finditer(origins_list_pattern, code))
        for match in matches:
            var_name = match.group(1)
            mutant = code[:match.start()] + f"{var_name} = ['*']" + code[match.end():]
            mutants.append((mutant, "Changed allowed origins to wildcard"))

        # Enable credentials with wildcard (dangerous)
        if "'Access-Control-Allow-Credentials': True" in code or '"Access-Control-Allow-Credentials": True' in code:
            # If credentials are allowed, adding * is a security issue
            if "'Access-Control-Allow-Origin'" in code or '"Access-Control-Allow-Origin"' in code:
                mutant = re.sub(
                    r"(['\"]Access-Control-Allow-Origin['\"]\s*[,:]\s*)['\"][^'\"]+['\"]",
                    r"\1'*'",
                    code
                )
                mutants.append((mutant, "Changed CORS to * while credentials are enabled"))

        # Remove origin validation
        origin_check_pattern = r'if\s+origin\s+not\s+in\s+[\w.]+:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(origin_check_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed CORS origin validation"))

        # Change supports_credentials to True
        if 'supports_credentials=False' in code:
            mutant = code.replace('supports_credentials=False', 'supports_credentials=True')
            mutants.append((mutant, "Enabled CORS credentials"))

        return mutants


class CSRF_REMOVE(SecurityMutationOperator):
    """
    Remove CSRF Protection (CSRF_REMOVE)

    Removes or bypasses CSRF token validation.

    Example:
        @csrf_protect
        def update_profile(request):
        → def update_profile(request):  # No CSRF protection
    """

    def __init__(self):
        super().__init__(
            name="CSRF_REMOVE",
            description="Remove CSRF token protection",
            target_cwes=["CWE-352"]
        )

    def applies_to(self, code: str) -> bool:
        csrf_indicators = [
            'csrf', 'CSRF', 'CSRFToken', 'csrf_token', '_token',
            'X-CSRF-Token', 'X-CSRFToken', 'csrfmiddlewaretoken'
        ]
        return any(x in code for x in csrf_indicators)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove @csrf_protect decorator
        csrf_decorator_pattern = r'@csrf_protect\s*\n'
        matches = list(re.finditer(csrf_decorator_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed @csrf_protect decorator"))

        # Add @csrf_exempt decorator
        func_pattern = r'(def\s+\w+\s*\([^)]*request[^)]*\)\s*:)'
        matches = list(re.finditer(func_pattern, code))
        for match in matches:
            if '@csrf_exempt' not in code[:match.start()]:
                mutant = code[:match.start()] + '@csrf_exempt\n' + code[match.start():]
                mutants.append((mutant, "Added @csrf_exempt decorator"))

        # Remove CSRF token validation
        csrf_check_pattern = r'if\s+not\s+[\w.]*csrf[\w.]*\s*[:(][^:]*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(csrf_check_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed CSRF token validation"))

        # Remove csrf_token from form
        form_pattern = r'<input[^>]*csrf[^>]*>\s*\n?'
        matches = list(re.finditer(form_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed CSRF token from form"))

        # Remove {% csrf_token %} template tag
        template_pattern = r'\{%\s*csrf_token\s*%\}\s*\n?'
        matches = list(re.finditer(template_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed {% csrf_token %} template tag"))

        # Disable CSRF middleware
        middleware_pattern = r"['\"]django\.middleware\.csrf\.CsrfViewMiddleware['\"],?\s*\n?"
        matches = list(re.finditer(middleware_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed CSRF middleware"))

        # Set CSRF_COOKIE_SECURE to False
        if 'CSRF_COOKIE_SECURE = True' in code:
            mutant = code.replace('CSRF_COOKIE_SECURE = True', 'CSRF_COOKIE_SECURE = False')
            mutants.append((mutant, "Set CSRF_COOKIE_SECURE to False"))

        return mutants


class WEAKRANDOM(SecurityMutationOperator):
    """
    Weak Random Number Generation (WEAKRANDOM)

    Replaces cryptographically secure random functions with weak PRNG.

    Example:
        secrets.token_bytes(32)
        → random.randbytes(32)

        secrets.token_hex(16)
        → '%032x' % random.getrandbits(128)
    """

    def __init__(self):
        super().__init__(
            name="WEAKRANDOM",
            description="Replace secure random with weak PRNG",
            target_cwes=["CWE-338", "CWE-330", "CWE-331"]
        )

    def applies_to(self, code: str) -> bool:
        secure_patterns = [
            'secrets.', 'os.urandom', 'SystemRandom',
            'token_bytes', 'token_hex', 'token_urlsafe',
            'secrets.choice', 'secrets.randbelow'
        ]
        return any(p in code for p in secure_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # secrets.token_bytes(n) → random.randbytes(n)
        pattern1 = r'secrets\.token_bytes\((\d+)\)'
        matches = list(re.finditer(pattern1, code))
        for match in matches:
            n = match.group(1)
            mutant = code[:match.start()] + f'random.randbytes({n})' + code[match.end():]
            # Add import random if not present
            if 'import random' not in mutant:
                mutant = 'import random\n' + mutant
            mutants.append((mutant, f"Replaced secrets.token_bytes with weak random.randbytes"))

        # secrets.token_hex(n) → '%0{n*2}x' % random.getrandbits(n*8)
        pattern2 = r'secrets\.token_hex\((\d+)\)'
        matches = list(re.finditer(pattern2, code))
        for match in matches:
            n = int(match.group(1))
            bits = n * 8
            hex_width = n * 2
            replacement = f"'%0{hex_width}x' % random.getrandbits({bits})"
            mutant = code[:match.start()] + replacement + code[match.end():]
            if 'import random' not in mutant:
                mutant = 'import random\n' + mutant
            mutants.append((mutant, f"Replaced secrets.token_hex with weak random.getrandbits"))

        # secrets.token_urlsafe(n) → base64.urlsafe_b64encode(random.randbytes(n)).decode()
        pattern3 = r'secrets\.token_urlsafe\((\d+)\)'
        matches = list(re.finditer(pattern3, code))
        for match in matches:
            n = match.group(1)
            replacement = f"base64.urlsafe_b64encode(random.randbytes({n})).rstrip(b'=').decode()"
            mutant = code[:match.start()] + replacement + code[match.end():]
            if 'import random' not in mutant:
                mutant = 'import random\n' + mutant
            if 'import base64' not in mutant:
                mutant = 'import base64\n' + mutant
            mutants.append((mutant, f"Replaced secrets.token_urlsafe with weak random"))

        # secrets.choice(seq) → random.choice(seq)
        pattern4 = r'secrets\.choice\('
        if re.search(pattern4, code):
            mutant = re.sub(pattern4, 'random.choice(', code)
            if 'import random' not in mutant:
                mutant = 'import random\n' + mutant
            mutants.append((mutant, "Replaced secrets.choice with weak random.choice"))

        # secrets.randbelow(n) → random.randint(0, n-1)
        pattern5 = r'secrets\.randbelow\(([^)]+)\)'
        matches = list(re.finditer(pattern5, code))
        for match in matches:
            n = match.group(1)
            replacement = f'random.randint(0, {n}-1)'
            mutant = code[:match.start()] + replacement + code[match.end():]
            if 'import random' not in mutant:
                mutant = 'import random\n' + mutant
            mutants.append((mutant, f"Replaced secrets.randbelow with weak random.randint"))

        # os.urandom(n) → random.randbytes(n)
        pattern6 = r'os\.urandom\((\d+)\)'
        matches = list(re.finditer(pattern6, code))
        for match in matches:
            n = match.group(1)
            mutant = code[:match.start()] + f'random.randbytes({n})' + code[match.end():]
            if 'import random' not in mutant:
                mutant = 'import random\n' + mutant
            mutants.append((mutant, f"Replaced os.urandom with weak random.randbytes"))

        # random.SystemRandom() → random.Random()
        if 'SystemRandom' in code:
            mutant = code.replace('random.SystemRandom()', 'random.Random()')
            mutant = mutant.replace('SystemRandom()', 'random.Random()')
            mutants.append((mutant, "Replaced SystemRandom with weak Random"))

        return mutants


# =============================================================================
# NEW OPERATORS FOR EXPANDED CWE COVERAGE
# =============================================================================

class EVALINJECT(SecurityMutationOperator):
    """
    Eval Injection (EVALINJECT) - CWE-95

    Replaces safe evaluation with unsafe eval/exec.
    """

    def __init__(self):
        super().__init__(
            name="EVALINJECT",
            description="Enable code injection via eval/exec",
            target_cwes=["CWE-95"]
        )

    def applies_to(self, code: str) -> bool:
        safe_patterns = ['ast.literal_eval', 'json.loads', 'safe_eval', 'literal_eval']
        return any(p in code for p in safe_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # ast.literal_eval → eval
        if 'ast.literal_eval' in code:
            mutant = code.replace('ast.literal_eval', 'eval')
            mutants.append((mutant, "ast.literal_eval → eval (code injection)"))

        # safe_eval → eval
        if 'safe_eval' in code:
            mutant = code.replace('safe_eval', 'eval')
            mutants.append((mutant, "safe_eval → eval"))

        # json.loads → eval (for JSON-like strings)
        if 'json.loads' in code:
            mutant = code.replace('json.loads', 'eval')
            mutants.append((mutant, "json.loads → eval (code injection)"))

        return mutants


class LOGINJECT(SecurityMutationOperator):
    """
    Log Injection (LOGINJECT) - CWE-117

    Removes log sanitization allowing log injection/forging.
    """

    def __init__(self):
        super().__init__(
            name="LOGINJECT",
            description="Remove log sanitization for log injection",
            target_cwes=["CWE-117"]
        )

    def applies_to(self, code: str) -> bool:
        log_patterns = ['logging.', 'logger.', 'log.info', 'log.error', 'log.warning', 'log.debug']
        sanitize_patterns = ['replace(', 'strip(', 'encode(', 'escape(', 'sanitize']
        return any(l in code for l in log_patterns) and any(s in code for s in sanitize_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove .replace('\n', '') or .replace('\r', '') before logging
        newline_sanitize = r'\.replace\s*\(\s*["\'][\\]?[nr]["\'],\s*["\']["\']s*\)'
        if re.search(newline_sanitize, code):
            mutant = re.sub(newline_sanitize, '', code)
            mutants.append((mutant, "Removed newline sanitization from log input"))

        # Remove .strip() before logging
        strip_pattern = r'\.strip\s*\(\s*\)'
        if re.search(strip_pattern, code) and 'log' in code.lower():
            mutant = re.sub(strip_pattern, '', code)
            mutants.append((mutant, "Removed strip() from log input"))

        return mutants


class OPENREDIRECT(SecurityMutationOperator):
    """
    Open Redirect (OPENREDIRECT) - CWE-601

    Removes URL validation allowing open redirect attacks.
    """

    def __init__(self):
        super().__init__(
            name="OPENREDIRECT",
            description="Remove redirect URL validation",
            target_cwes=["CWE-601"]
        )
        self.redirect_validators = [
            'is_safe_url', 'url_has_allowed_host', 'validate_redirect',
            'check_redirect', 'safe_redirect', 'allowed_redirect',
            'ALLOWED_HOSTS', 'startswith', 'urlparse'
        ]

    def applies_to(self, code: str) -> bool:
        if 'redirect' in code.lower():
            return any(v in code for v in self.redirect_validators)
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove is_safe_url check
        safe_url_pattern = r'if\s+not\s+is_safe_url\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(safe_url_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed is_safe_url redirect validation"))

        # Remove url_has_allowed_host check
        allowed_host_pattern = r'if\s+not\s+url_has_allowed_host\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(allowed_host_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed url_has_allowed_host check"))

        # Remove startswith check for redirect URLs
        startswith_pattern = r'if\s+not\s+[\w.]+\.startswith\s*\([^)]*["\']/[^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(startswith_pattern, code):
            if 'redirect' in code.lower():
                mutant = code[:match.start()] + code[match.end():]
                mutants.append((mutant, "Removed redirect URL prefix validation"))

        return mutants


class NOCERTVALID(SecurityMutationOperator):
    """
    Improper Certificate Validation (NOCERTVALID) - CWE-295

    Disables SSL/TLS certificate validation.
    """

    def __init__(self):
        super().__init__(
            name="NOCERTVALID",
            description="Disable certificate validation",
            target_cwes=["CWE-295"]
        )

    def applies_to(self, code: str) -> bool:
        patterns = ['verify=True', 'CERT_REQUIRED', 'check_hostname', 'ssl', 'https', 'requests.']
        return any(p in code for p in patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # verify=True → verify=False
        if 'verify=True' in code:
            mutant = code.replace('verify=True', 'verify=False')
            mutants.append((mutant, "Disabled SSL certificate verification"))

        # CERT_REQUIRED → CERT_NONE
        if 'CERT_REQUIRED' in code:
            mutant = code.replace('CERT_REQUIRED', 'CERT_NONE')
            mutants.append((mutant, "Changed CERT_REQUIRED to CERT_NONE"))

        # check_hostname = True → False
        if 'check_hostname = True' in code or 'check_hostname=True' in code:
            mutant = code.replace('check_hostname = True', 'check_hostname = False')
            mutant = mutant.replace('check_hostname=True', 'check_hostname=False')
            mutants.append((mutant, "Disabled hostname checking"))

        return mutants


class FILEUPLOAD(SecurityMutationOperator):
    """
    Unrestricted File Upload (FILEUPLOAD) - CWE-434

    Removes file type/extension validation.
    """

    def __init__(self):
        super().__init__(
            name="FILEUPLOAD",
            description="Remove file upload validation",
            target_cwes=["CWE-434"]
        )

    def applies_to(self, code: str) -> bool:
        upload_patterns = ['upload', 'file', 'multipart', 'request.files']
        extension_patterns = ['allowed_extensions', 'ALLOWED_EXTENSIONS', 'endswith', 'splitext', 'mimetype', 'content_type']
        return any(u in code.lower() for u in upload_patterns) and any(e in code for e in extension_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove extension check: if ext not in ALLOWED_EXTENSIONS
        ext_check = r'if\s+[\w.]+\s+not\s+in\s+(ALLOWED_EXTENSIONS|allowed_extensions)[^\n]*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(ext_check, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed file extension validation"))

        # Remove endswith check for extensions
        endswith_check = r'if\s+not\s+[\w.]+\.endswith\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(endswith_check, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed file extension endswith check"))

        # Remove mimetype/content_type check
        mime_check = r'if\s+[\w.]+\.(mimetype|content_type)\s+not\s+in[^\n]*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(mime_check, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed MIME type validation"))

        return mutants


class INFOEXPOSE(SecurityMutationOperator):
    """
    Information Exposure (INFOEXPOSE) - CWE-200

    Enables information disclosure through error messages, debug info, etc.
    """

    def __init__(self):
        super().__init__(
            name="INFOEXPOSE",
            description="Enable information exposure",
            target_cwes=["CWE-200", "CWE-209"]
        )

    def applies_to(self, code: str) -> bool:
        patterns = ['DEBUG', 'debug', 'traceback', 'exc_info', 'exception', 'error', 'except']
        return any(p in code for p in patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # DEBUG = False → DEBUG = True
        if 'DEBUG = False' in code or 'DEBUG=False' in code:
            mutant = code.replace('DEBUG = False', 'DEBUG = True')
            mutant = mutant.replace('DEBUG=False', 'DEBUG=True')
            mutants.append((mutant, "Enabled DEBUG mode (information exposure)"))

        # Remove generic exception handling that hides errors
        generic_except = r'except\s+Exception[^:]*:\s*\n(\s+)(pass|return\s+None|return\s*$)'
        for match in re.finditer(generic_except, code):
            indent = match.group(1)
            # Replace with traceback print
            replacement = f'except Exception as e:\n{indent}import traceback; traceback.print_exc()'
            mutant = code[:match.start()] + replacement + code[match.end():]
            mutants.append((mutant, "Exposed exception details"))

        return mutants


class WEAKKEY(SecurityMutationOperator):
    """
    Inadequate Encryption Strength (WEAKKEY) - CWE-326

    Reduces key sizes to weak values.
    """

    def __init__(self):
        super().__init__(
            name="WEAKKEY",
            description="Reduce cryptographic key size",
            target_cwes=["CWE-326"]
        )

    def applies_to(self, code: str) -> bool:
        patterns = ['key_size', 'bits', 'RSA', 'generate', 'AES', 'key_length']
        return any(p in code for p in patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # key_size=2048 → key_size=512
        key_size_pattern = r'key_size\s*=\s*(\d{4})'
        for match in re.finditer(key_size_pattern, code):
            original_size = match.group(1)
            mutant = code[:match.start()] + 'key_size=512' + code[match.end():]
            mutants.append((mutant, f"Reduced key_size from {original_size} to 512 bits"))

        # bits=256 → bits=64
        bits_pattern = r'bits\s*=\s*(128|256|512)'
        for match in re.finditer(bits_pattern, code):
            mutant = code[:match.start()] + 'bits=64' + code[match.end():]
            mutants.append((mutant, "Reduced encryption bits to weak 64-bit"))

        return mutants


class LDAPINJECT(SecurityMutationOperator):
    """
    LDAP Injection (LDAPINJECT) - CWE-90

    Enables LDAP injection by removing sanitization.
    """

    def __init__(self):
        super().__init__(
            name="LDAPINJECT",
            description="Enable LDAP injection",
            target_cwes=["CWE-90"]
        )

    def applies_to(self, code: str) -> bool:
        return 'ldap' in code.lower() or 'escape_dn' in code or 'escape_filter' in code

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove escape_dn_chars
        if 'escape_dn_chars' in code:
            pattern = r'escape_dn_chars\s*\(\s*([^)]+)\s*\)'
            for match in re.finditer(pattern, code):
                inner = match.group(1)
                mutant = code[:match.start()] + inner + code[match.end():]
                mutants.append((mutant, "Removed LDAP DN escaping"))

        # Remove escape_filter_chars
        if 'escape_filter_chars' in code:
            pattern = r'escape_filter_chars\s*\(\s*([^)]+)\s*\)'
            for match in re.finditer(pattern, code):
                inner = match.group(1)
                mutant = code[:match.start()] + inner + code[match.end():]
                mutants.append((mutant, "Removed LDAP filter escaping"))

        # Convert parameterized LDAP to string format
        if 'ldap' in code.lower() and '%s' in code:
            # (cn=%s) with bind → (cn='+user+')
            mutant = re.sub(r'%s', "'+user+'", code)
            mutants.append((mutant, "Converted LDAP parameter to string injection"))

        return mutants


class XMLBOMB(SecurityMutationOperator):
    """
    XML Entity Expansion / Billion Laughs (XMLBOMB) - CWE-776

    Removes XML entity expansion limits.
    """

    def __init__(self):
        super().__init__(
            name="XMLBOMB",
            description="Remove XML entity expansion protection",
            target_cwes=["CWE-776"]
        )

    def applies_to(self, code: str) -> bool:
        return 'xml' in code.lower() or 'etree' in code or 'lxml' in code or 'defusedxml' in code

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # defusedxml → xml.etree
        if 'defusedxml' in code:
            mutant = code.replace('defusedxml.ElementTree', 'xml.etree.ElementTree')
            mutant = mutant.replace('from defusedxml import', 'from xml.etree import')
            mutants.append((mutant, "Replaced defusedxml with vulnerable xml.etree"))

        # Remove huge_tree=False
        if 'huge_tree=False' in code:
            mutant = code.replace('huge_tree=False', 'huge_tree=True')
            mutants.append((mutant, "Enabled huge_tree (allows entity expansion)"))

        # Remove resolve_entities=False
        if 'resolve_entities=False' in code:
            mutant = code.replace('resolve_entities=False', 'resolve_entities=True')
            mutants.append((mutant, "Enabled entity resolution"))

        return mutants


class REGEXDOS(SecurityMutationOperator):
    """
    Regular Expression Denial of Service (REGEXDOS) - CWE-1333

    Introduces ReDoS vulnerable regex patterns.
    """

    def __init__(self):
        super().__init__(
            name="REGEXDOS",
            description="Introduce ReDoS vulnerable patterns",
            target_cwes=["CWE-1333", "CWE-400"]
        )

    def applies_to(self, code: str) -> bool:
        return 're.compile' in code or 're.match' in code or 're.search' in code or 'regex' in code.lower()

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Simple quantifiers → nested quantifiers (catastrophic backtracking)
        # [a-z]+ → (a+)+
        if 're.compile' in code or 're.match' in code:
            pattern = r'r["\']([^"\']+)["\']'
            for match in re.finditer(pattern, code):
                regex = match.group(1)
                # Add nested quantifier to make it vulnerable
                if '+' in regex or '*' in regex:
                    vulnerable = regex.replace('+', '+)+')
                    vulnerable = '(' + vulnerable if not vulnerable.startswith('(') else vulnerable
                    mutant = code[:match.start()] + f'r"{vulnerable}"' + code[match.end():]
                    mutants.append((mutant, "Introduced nested quantifier (ReDoS vulnerable)"))

        return mutants


class CREDEXPOSE(SecurityMutationOperator):
    """
    Insufficiently Protected Credentials (CREDEXPOSE) - CWE-522

    Weakens credential protection mechanisms.
    """

    def __init__(self):
        super().__init__(
            name="CREDEXPOSE",
            description="Weaken credential protection",
            target_cwes=["CWE-522"]
        )

    def applies_to(self, code: str) -> bool:
        patterns = ['password', 'credential', 'secret', 'token', 'hash', 'bcrypt', 'argon', 'scrypt']
        return any(p in code.lower() for p in patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # bcrypt.hashpw → plaintext
        if 'bcrypt.hashpw' in code:
            pattern = r'bcrypt\.hashpw\s*\(\s*([^,]+),\s*[^)]+\)'
            for match in re.finditer(pattern, code):
                password_var = match.group(1).strip()
                mutant = code[:match.start()] + password_var + code[match.end():]
                mutants.append((mutant, "Stored password in plaintext instead of bcrypt hash"))

        # Remove password hashing
        if 'hash(' in code.lower() and 'password' in code.lower():
            pattern = r'(\w+)\s*=\s*\w*hash\w*\s*\(\s*(\w+)\s*[^)]*\)'
            for match in re.finditer(pattern, code, re.IGNORECASE):
                var_name = match.group(1)
                original = match.group(2)
                mutant = code[:match.start()] + f'{var_name} = {original}' + code[match.end():]
                mutants.append((mutant, "Removed password hashing"))

        return mutants


class WEAKPASSREQ(SecurityMutationOperator):
    """
    Weak Password Requirements (WEAKPASSREQ) - CWE-521

    Removes password complexity requirements.
    """

    def __init__(self):
        super().__init__(
            name="WEAKPASSREQ",
            description="Remove password complexity requirements",
            target_cwes=["CWE-521"]
        )

    def applies_to(self, code: str) -> bool:
        patterns = ['password', 'len(', 'min_length', 'complexity', 'upper', 'lower', 'digit', 'special']
        return 'password' in code.lower() and any(p in code for p in patterns[1:])

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove length check: if len(password) < 8
        len_check = r'if\s+len\s*\(\s*\w*password\w*\s*\)\s*[<>=]+\s*\d+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(len_check, code, re.IGNORECASE):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed password length requirement"))

        # Remove complexity checks
        complexity_patterns = [
            (r'if\s+not\s+any\s*\([^)]*\.isupper[^)]*\)[^\n]*:\s*\n\s*(raise|return)[^\n]*\n', "uppercase"),
            (r'if\s+not\s+any\s*\([^)]*\.islower[^)]*\)[^\n]*:\s*\n\s*(raise|return)[^\n]*\n', "lowercase"),
            (r'if\s+not\s+any\s*\([^)]*\.isdigit[^)]*\)[^\n]*:\s*\n\s*(raise|return)[^\n]*\n', "digit"),
        ]
        for pattern, desc in complexity_patterns:
            for match in re.finditer(pattern, code):
                mutant = code[:match.start()] + code[match.end():]
                mutants.append((mutant, f"Removed password {desc} requirement"))

        return mutants


class MISSINGAUTH(SecurityMutationOperator):
    """
    Missing Authorization (MISSINGAUTH) - CWE-862, CWE-863

    Removes authorization checks for sensitive operations.
    """

    def __init__(self):
        super().__init__(
            name="MISSINGAUTH",
            description="Remove authorization checks",
            target_cwes=["CWE-862", "CWE-863"]
        )

    def applies_to(self, code: str) -> bool:
        patterns = ['has_permission', 'is_admin', 'is_owner', 'can_access', 'authorize', 'allowed', 'role']
        return any(p in code.lower() for p in patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove permission checks
        perm_patterns = ['has_permission', 'has_perm', 'check_permission', 'can_access', 'is_allowed']
        for func in perm_patterns:
            pattern = rf'if\s+not\s+[\w.]*{func}\s*\([^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
            for match in re.finditer(pattern, code, re.IGNORECASE):
                mutant = code[:match.start()] + code[match.end():]
                mutants.append((mutant, f"Removed {func} authorization check"))

        # Replace permission check with True
        for func in perm_patterns:
            pattern = rf'[\w.]*{func}\s*\([^)]*\)'
            for match in re.finditer(pattern, code, re.IGNORECASE):
                mutant = code[:match.start()] + 'True' + code[match.end():]
                mutants.append((mutant, f"Bypassed {func} with True"))

        return mutants


class HTTPRS(SecurityMutationOperator):
    """
    HTTP Response Splitting (HTTPRS) - CWE-113

    Removes header injection sanitization.
    """

    def __init__(self):
        super().__init__(
            name="HTTPRS",
            description="Enable HTTP response splitting",
            target_cwes=["CWE-113"]
        )

    def applies_to(self, code: str) -> bool:
        return 'header' in code.lower() and ('replace' in code or 'strip' in code or 'encode' in code)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove newline stripping from headers
        if 'header' in code.lower():
            strip_pattern = r'\.replace\s*\(\s*["\'][\\]?[rn]["\'],\s*["\']["\'\s*\)'
            if re.search(strip_pattern, code):
                mutant = re.sub(strip_pattern, '', code)
                mutants.append((mutant, "Removed CRLF sanitization from headers"))

        return mutants


# Export all operators
__all__ = [
    'SecurityMutationOperator',
    'PSQLI',
    'RVALID',
    'INPUTVAL',
    'SUBDOMAIN_SPOOF',
    'RHTTPO',
    'WEAKCRYPTO',
    'HARDCODE',
    'RMAUTH',
    'PATHCONCAT',
    'CMDINJECT',
    'RENCRYPT',
    'DESERIAL',
    'SSRF',
    'IDOR',
    'XXE',
    'SSTI',
    'CORS_WEAK',
    'CSRF_REMOVE',
    'WEAKRANDOM',
    # New operators for expanded CWE coverage
    'EVALINJECT',
    'LOGINJECT',
    'OPENREDIRECT',
    'NOCERTVALID',
    'FILEUPLOAD',
    'INFOEXPOSE',
    'WEAKKEY',
    'LDAPINJECT',
    'XMLBOMB',
    'REGEXDOS',
    'CREDEXPOSE',
    'WEAKPASSREQ',
    'MISSINGAUTH',
    'HTTPRS',
]
