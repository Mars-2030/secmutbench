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

    def generate_valid_mutants(self, code: str) -> List[Tuple[str, str]]:
        """
        Generate mutants and filter out any that don't compile.

        This wraps mutate() with a post-compilation gate to ensure
        all returned mutants are syntactically valid Python.
        """
        raw_mutants = self.mutate(code)
        valid = []
        for mutant_code, description in raw_mutants:
            try:
                compile(mutant_code, "<mutant>", "exec")
                valid.append((mutant_code, description))
            except SyntaxError:
                pass  # Silently drop non-compiling mutants
        return valid

    def get_mutation_locations(self, code: str) -> List[int]:
        """Return line numbers where mutations can be applied"""
        return []


def remove_if_block_safely(code: str, pattern: str, flags: int = 0) -> List[Tuple[str, str, re.Match]]:
    """
    Remove if-blocks matching the pattern, filtering out non-compiling results.

    This removes the matched block and verifies the result compiles.
    Non-compiling mutants are silently skipped.

    Returns:
        List of (mutated_code, description_suffix, match) tuples
    """
    results = []
    matches = list(re.finditer(pattern, code, flags))

    for match in matches:
        # Simply remove the matched block
        mutant = code[:match.start()] + code[match.end():]

        # Verify the result compiles before including it
        try:
            ast.parse(mutant)
            results.append((mutant, "", match))
        except SyntaxError:
            # Skip non-compiling mutants - this is expected for some patterns
            pass

    return results


def replace_if_body_with_pass(code: str, pattern: str, flags: int = 0) -> List[Tuple[str, str, re.Match]]:
    """
    Replace the body of if-blocks matching the pattern with 'pass'.

    Creates "dead check" mutants where the security check exists
    but its enforcement action (raise/return) is replaced with pass.

    Returns:
        List of (mutated_code, description_suffix, match) tuples
    """
    results = []
    matches = list(re.finditer(pattern, code, flags))

    for match in matches:
        matched_text = match.group()
        # Find the raise/return line and replace with pass
        body_match = re.search(r'(\n(\s+))(raise|return)\b[^\n]*', matched_text)
        if body_match:
            indent = body_match.group(2)
            new_text = matched_text[:body_match.start()] + '\n' + indent + 'pass\n'
            mutant = code[:match.start()] + new_text + code[match.end():]
            try:
                ast.parse(mutant)
                results.append((mutant, " (dead check)", match))
            except SyntaxError:
                pass

    return results


def replace_if_else_with_if_body(code: str, pattern: re.Pattern) -> List[Tuple[str, str]]:
    """
    Replace an if/else block with just the if-body, dedented to the if-statement's level.

    The pattern must have named groups 'indent' and 'if_body'.
    Returns list of (mutated_code, description) tuples that compile successfully.
    """
    results = []
    for match in pattern.finditer(code):
        indent = match.group('indent')
        if_body = match.group('if_body')
        # Dedent the if-body: remove one level of indentation (the extra indent inside the if)
        dedented_lines = []
        for line in if_body.split('\n'):
            if line.strip():
                # Remove one extra indentation level beyond the if-indent
                if line.startswith(indent + '    '):
                    dedented_lines.append(indent + line[len(indent) + 4:])
                elif line.startswith(indent + '\t'):
                    dedented_lines.append(indent + line[len(indent) + 1:])
                else:
                    dedented_lines.append(line)
            else:
                dedented_lines.append(line)
        dedented_body = '\n'.join(dedented_lines)
        if not dedented_body.endswith('\n'):
            dedented_body += '\n'
        mutant = code[:match.start()] + dedented_body + code[match.end():]
        try:
            ast.parse(mutant)
            results.append((mutant, ""))
        except SyntaxError:
            pass
    return results


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

        # EXPANDED: Handle more SQL patterns from external sources
        # Pattern: query variable with execute
        if re.search(r'\w+\s*=\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']', code, re.IGNORECASE):
            return True

        # Pattern: db connection with query method
        if re.search(r'\.(?:query|execute|executemany|run|fetch)\s*\(', code):
            return True

        # Pattern: psycopg2, sqlite3, mysql connector patterns
        if re.search(r'(?:psycopg2|sqlite3|mysql|pymysql|cx_Oracle)\.connect', code):
            return True

        # Pattern: SQLAlchemy session patterns
        if re.search(r'session\.(?:execute|query|add|delete)', code):
            return True

        # Pattern: Django ORM raw queries
        if 'objects.raw(' in code or 'connection.cursor()' in code:
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

        # EXPANDED: Handle more SQL patterns from external sources

        # Pattern: ORM/SQLAlchemy filter with kwargs
        # secure: Model.query.filter_by(id=user_id)
        # → insecure: Model.query.filter(text(f"id = {user_id}"))
        filter_by_pattern = r'(\w+)\.query\.filter_by\s*\(([^)]+)\)'
        for match in re.finditer(filter_by_pattern, code):
            model = match.group(1)
            kwargs = match.group(2)
            # Extract key=value pairs
            pairs = re.findall(r'(\w+)\s*=\s*(\w+)', kwargs)
            if pairs:
                conditions = ' AND '.join([f"{k} = {{{v}}}" for k, v in pairs])
                mutant = code[:match.start()] + f'{model}.query.filter(text(f"{conditions}"))' + code[match.end():]
                mutants.append((mutant, "[Expanded] ORM filter_by to raw SQL"))

        # Pattern: Django ORM filter → raw SQL
        # secure: Model.objects.filter(id=user_id)
        # → insecure: Model.objects.raw(f"SELECT * FROM model WHERE id = {user_id}")
        django_filter_pattern = r'(\w+)\.objects\.filter\s*\(([^)]+)\)'
        for match in re.finditer(django_filter_pattern, code):
            model = match.group(1)
            kwargs = match.group(2)
            pairs = re.findall(r'(\w+)\s*=\s*(\w+)', kwargs)
            if pairs:
                conditions = ' AND '.join([f"{k} = {{{v}}}" for k, v in pairs])
                table = model.lower()
                mutant = code[:match.start()] + f'{model}.objects.raw(f"SELECT * FROM {table} WHERE {conditions}")' + code[match.end():]
                mutants.append((mutant, "[Expanded] Django filter to raw SQL"))

        # Pattern: psycopg2/sqlite3 with named parameters
        # secure: cur.execute("SELECT * FROM users WHERE id = %(id)s", {"id": user_id})
        # → insecure: cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
        named_param_pattern = r'\.execute\s*\(\s*["\']([^"\']*%\(\w+\)s[^"\']*)["\'],\s*\{([^}]+)\}\s*\)'
        for match in re.finditer(named_param_pattern, code):
            query = match.group(1)
            params_dict = match.group(2)
            # Extract param_name: variable mappings
            mappings = re.findall(r'["\'](\w+)["\']\s*:\s*(\w+)', params_dict)
            new_query = query
            for param_name, var_name in mappings:
                new_query = new_query.replace(f'%({param_name})s', '{' + var_name + '}')
            mutant = code[:match.start()] + f'.execute(f"{new_query}")' + code[match.end():]
            mutants.append((mutant, "[Expanded] Named params to f-string"))

        # Pattern: cursor.execute with list params
        # secure: cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])
        # → insecure: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        list_param_pattern = r'\.execute\s*\(\s*["\']([^"\']*\?[^"\']*)["\'],\s*\[([^\]]+)\]\s*\)'
        for match in re.finditer(list_param_pattern, code):
            query = match.group(1)
            params_str = match.group(2)
            params = [p.strip() for p in params_str.split(',')]
            new_query = query
            for param in params:
                new_query = new_query.replace('?', '{' + param + '}', 1)
            mutant = code[:match.start()] + f'.execute(f"{new_query}")' + code[match.end():]
            mutants.append((mutant, "[Expanded] List params to f-string"))

        # Pattern: SQLAlchemy text() with bindparams
        # secure: db.execute(text("SELECT * FROM users WHERE id = :id").bindparams(id=user_id))
        # → insecure: db.execute(f"SELECT * FROM users WHERE id = {user_id}")
        text_bindparams_pattern = r'\.execute\s*\(\s*text\s*\(\s*["\']([^"\']+)["\']\s*\)\.bindparams\s*\(([^)]+)\)\s*\)'
        for match in re.finditer(text_bindparams_pattern, code):
            query = match.group(1)
            params = match.group(2)
            # Extract param=value pairs
            mappings = re.findall(r'(\w+)\s*=\s*(\w+)', params)
            new_query = query
            for param_name, var_name in mappings:
                new_query = new_query.replace(f':{param_name}', '{' + var_name + '}')
            mutant = code[:match.start()] + f'.execute(f"{new_query}")' + code[match.end():]
            mutants.append((mutant, "[Expanded] SQLAlchemy text/bindparams to f-string"))

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

        # EXPANDED: More validation patterns from external sources
        # Length validation
        if re.search(r'if\s+len\s*\([^)]+\)\s*[<>]=?\s*\d+', code):
            return True
        # Type checking
        if re.search(r'isinstance\s*\([^,]+,\s*(str|int|float|bool)', code):
            return True
        # None/empty checks
        if re.search(r'if\s+(not\s+)?\w+\s*:', code) and 'raise' in code:
            return True
        # Whitelist checks
        if re.search(r'if\s+\w+\s+(not\s+)?in\s+\w*(allowed|valid|safe|whitelist)', code, re.IGNORECASE):
            return True
        # Django/Flask form validation
        if '.is_valid()' in code or '.validate()' in code:
            return True
        # Werkzeug/Flask secure filename
        if 'secure_filename' in code:
            return True
        # URL validation
        if 'urlparse' in code and ('scheme' in code or 'netloc' in code):
            return True
        # Neutralization via .replace() for CWE-74/CWE-116
        if re.search(r"\.replace\s*\(\s*['\"]\\\\?[nr]", code):
            return True
        # Field allowlist for CWE-915 (mass assignment)
        if re.search(r'\b(?:ALLOWED_FIELDS|allowed_fields|MODIFIABLE_SETTINGS)\b', code):
            return True
        # Path safety checks in archive extraction
        if 'os.path.isabs' in code or ('".."' in code and 'in' in code):
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

        # Neutralization via .replace(): remove .replace('\n', ' ') or .replace('\r', ' ')
        # For CWE-74 (injection neutralization) and CWE-116 (output encoding)
        replace_pattern = r"\.replace\s*\(\s*['\"]\\\\?[nr]['\"],\s*['\"][^'\"]*['\"]\s*\)"
        if re.search(replace_pattern, code):
            mutant = re.sub(replace_pattern, '', code)
            if mutant != code:
                mutants.append((mutant, "Removed input neutralization via replace()"))

        # Path safety check in tarfile/zipfile extraction
        # Pattern: if os.path.isabs(entry.name) or ".." in entry.name: return False
        path_safety = r'([ \t]*)if\s+os\.path\.isabs\s*\([^)]+\)\s+or\s+["\']\.\.["\']\s+in\s+\w+[^:]*:\s*\n\s*(return|raise|continue)[^\n]*\n'
        for match in re.finditer(path_safety, code):
            indent = match.group(1)
            # Replace with pass instead of removing to avoid empty loop bodies
            mutant = code[:match.start()] + indent + "pass  # path check removed\n" + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Removed path traversal check in archive extraction"))
            except SyntaxError:
                pass

        # Whitelist/allowlist field filtering (CWE-915 mass assignment)
        # Pattern: if key not in ALLOWED_FIELDS: continue/raise
        allowlist_skip = r'if\s+\w+\s+not\s+in\s+(?:ALLOWED_FIELDS|allowed_fields|MODIFIABLE_SETTINGS|allowed)\s*:\s*\n\s*continue\n'
        for match in re.finditer(allowlist_skip, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed field allowlist check (mass assignment)"))

        # Pattern: for key in data: if key in ALLOWED_FIELDS → accept all
        allowlist_check = r'if\s+\w+\s+in\s+(?:ALLOWED_FIELDS|allowed_fields|allowed)\s*:\s*\n'
        for match in re.finditer(allowlist_check, code):
            # Replace the check with always-true
            mutant = code[:match.start()] + 'if True:\n' + code[match.end():]
            mutants.append((mutant, "Bypassed field allowlist (mass assignment)"))

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
        # Check for number comparisons
        if re.search(r'if\s+.*[<>]=?\s*\d+', code):
            return True
        # Check for error handling (input validation)
        if 'ValueError' in code or 'TypeError' in code:
            return True
        # Check for type conversion functions
        if any(x in code for x in ['.isdigit()', '.isnumeric()', 'int(', 'float(']):
            return True
        # Check for URL/IP validation patterns
        if any(x in code for x in ['urlparse', 'ipaddress.ip_address', '.scheme', '.netloc']):
            return True
        # Check for regex validation
        if 're.match(' in code and 'raise ValueError' in code:
            return True
        # Check for string contains validation (path traversal prevention)
        if any(x in code for x in ['".." in', '"/" in', '"\\\\" in']):
            return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # === EASY: Remove simple range check ===
        # Pattern: if age < 0:\n    raise ValueError
        # Uses helper function for proper indentation handling
        simple_range = r'if\s+\w+\s*[<>]=?\s*\d+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, simple_range):
            mutants.append((mutant, "[Easy] Removed simple range check"))

        # === MEDIUM: Remove compound range check ===
        # Pattern: if age < 0 or age > 150:
        compound_range = r'if\s+\w+\s*[<>]=?\s*\d+\s+or\s+\w+\s*[<>]=?\s*\d+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, compound_range):
            mutants.append((mutant, "[Medium] Removed compound range validation"))

        # === MEDIUM: Remove range with 'not' pattern ===
        # Pattern: if not (0 <= age <= 150):
        not_range = r'if\s+not\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, not_range):
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
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Hard] Removed try/except ValueError - invalid input not caught"))
            except SyntaxError:
                pass

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

        # === NEW: Remove URL scheme validation ===
        # Pattern: if parsed.scheme not in ('http', 'https'):
        url_scheme = r"if\s+\w+\.scheme\s+not\s+in\s+\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n"
        matches = list(re.finditer(url_scheme, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed URL scheme validation"))

        # === NEW: Remove URL netloc validation ===
        # Pattern: if not parsed.netloc:
        url_netloc = r"if\s+not\s+\w+\.netloc\s*:\s*\n\s*(raise|return)[^\n]*\n"
        matches = list(re.finditer(url_netloc, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed URL domain validation"))

        # === NEW: Remove regex match validation ===
        # Pattern: if not re.match(pattern, ...):
        regex_check = r"if\s+not\s+re\.match\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n"
        matches = list(re.finditer(regex_check, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed regex pattern validation"))

        # === NEW: Remove string contains check for path traversal ===
        # Pattern: if ".." in name or "/" in name:
        string_contains = r'if\s+["\'][^"\']+["\']\s+in\s+\w+(\s+or\s+["\'][^"\']+["\']\s+in\s+\w+)*\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(string_contains, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Easy] Removed string contains check"))

        # === NEW: Remove ipaddress validation try/except ===
        # Pattern: try: ipaddress.ip_address(...) except ValueError:
        ip_check = r'try\s*:\s*\n(\s+)\w+\s*=\s*ipaddress\.ip_address\((\w+)\)\s*\n[^e]*except\s+ValueError[^:]*:\s*\n\s+(raise|return)[^\n]*\n'
        matches = list(re.finditer(ip_check, code))
        for match in matches:
            indent = match.group(1)
            var_name = match.group(2)  # Extract actual variable name from ipaddress.ip_address(var)
            # Remove the try/except, keep just a naive parse without validation
            mutant = code[:match.start()] + f'{indent}parts = {var_name}.split(".")\n{indent}return tuple(int(p) for p in parts)\n' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Hard] Removed IP address validation"))
            except SyntaxError:
                pass

        # === NEW: Remove empty/none check ===
        # Pattern: if not name:
        empty_check = r'if\s+not\s+\w+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(empty_check, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Easy] Removed empty/null check"))

        # === Pass-variant mutants (dead security checks) ===
        for mutant, _, _ in replace_if_body_with_pass(code, simple_range):
            mutants.append((mutant, "[Easy] Dead range check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, compound_range):
            mutants.append((mutant, "[Medium] Dead compound range check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, not_range):
            mutants.append((mutant, "[Medium] Dead 'not in range' check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, type_check):
            mutants.append((mutant, "[Hard] Dead type check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, empty_check):
            mutants.append((mutant, "[Easy] Dead empty/null check (pass instead of raise)"))

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
        # Check for isalnum/re.match input validation in URL construction context
        if ('url' in code_lower or 'domain' in code_lower) and ('.isalnum()' in code or 're.match' in code):
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

        # === NEW: Remove re.match validation for subdomain/domain ===
        # CWEval pattern: if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain): return fallback
        rematch_domain = r'[ \t]*if\s+not\s+re\.match\s*\([^)]+,\s*\w+\s*\)\s*:\s*\n\s*(return|raise)[^\n]*\n'
        for match in re.finditer(rematch_domain, code):
            mutant = code[:match.start()] + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Easy] Removed regex domain validation"))
            except SyntaxError:
                pass

        # === NEW: Remove netloc == X or netloc.endswith('.' + X) if/else ===
        # CWEval CWE-20 pattern (may span multiple lines):
        #   if target_url.netloc == domain_url.netloc or target_url.netloc.endswith(
        #       '.' + domain_url.netloc
        #   ):
        #       return target
        #   else:
        #       return fallback
        # Mutation: always return target (remove else branch)
        netloc_if_else = re.compile(
            r'(?P<indent>[ \t]*)if\s+[\w.]+\.netloc\s*==\s*[\w.]+\.netloc\s+or\s+[\w.]+\.netloc\.endswith\s*\('
            r'.*?\)\s*:\s*\n'
            r'(?P<if_body>(?:(?P=indent)[ \t]+[^\n]+\n)+)'
            r'(?P=indent)else\s*:\s*\n'
            r'(?:(?P=indent)[ \t]+[^\n]+(?:\n|$))+',
            re.DOTALL
        )
        match = netloc_if_else.search(code)
        if match:
            # Replace the if/else with just the if-body (always accept)
            indent = match.group('indent')
            if_body = match.group('if_body')
            # Dedent if_body by one level
            dedented = re.sub(r'^' + indent + r'    ', indent, if_body, flags=re.MULTILINE)
            mutant = code[:match.start()] + dedented + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Medium] Removed netloc domain validation (always accept)"))
            except SyntaxError:
                pass

        # === NEW: Remove isalnum() validation for user IDs ===
        # CWEval CWE-918 pattern: if not user_id or not user_id.isalnum(): return None
        isalnum_check = r'[ \t]*if\s+not\s+\w+\s+or\s+not\s+\w+\.isalnum\s*\(\)\s*:\s*\n\s*(return|raise)[^\n]*\n'
        for match in re.finditer(isalnum_check, code):
            mutant = code[:match.start()] + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Easy] Removed isalnum() input validation"))
            except SyntaxError:
                pass

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
        # Only replace algorithm names that appear as string arguments or standalone calls
        # KDFs (pbkdf2_hmac, bcrypt, scrypt, argon2) are function names — replacing
        # them with md5/sha1 creates invalid calls (wrong arg count). Removed.
        self.multi_replacements = {
            'sha256': ['md5', 'sha1'],
            'sha384': ['md5', 'sha1'],
            'sha512': ['md5', 'sha1'],  # M7 fix: sha256 is strong per NIST
            'sha3_256': ['md5', 'sha1'],
            'sha3_512': ['md5', 'sha1'],
            'AES': ['DES', 'RC4'],
            'Fernet': ['DES', 'RC4'],
        }

    def applies_to(self, code: str) -> bool:
        for strong in self.multi_replacements.keys():
            if strong.lower() in code.lower():
                return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # C3 fix: Use word-boundary regex instead of global str.replace()
        # This prevents corrupting variable names, comments, and import paths
        for strong, weak_list in self.multi_replacements.items():
            if strong in code:
                # Use word boundaries to only match algorithm names, not substrings
                pattern = re.compile(r'\b' + re.escape(strong) + r'\b')
                for weak in weak_list:
                    mutant = pattern.sub(weak, code)
                    if mutant != code:
                        mutants.append((mutant, f"{strong} → {weak}"))

            # Case insensitive for some
            elif strong.lower() in code.lower():
                pattern = re.compile(r'\b' + re.escape(strong) + r'\b', re.IGNORECASE)
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
        rounds_pattern = r',\s*rounds\s*=\s*(\d+)'
        rounds_match = re.search(rounds_pattern, code)
        if rounds_match:
            mutant = re.sub(rounds_pattern, '', code)
            mutants.append((mutant, "Removed rounds parameter"))
            # Reduce rounds to 1 (distinct from removal)
            original_rounds = int(rounds_match.group(1))
            if original_rounds > 1:
                mutant2 = re.sub(rounds_pattern, ', rounds=1', code)
                mutants.append((mutant2, f"Reduced rounds from {original_rounds} to 1"))

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
        # C4 fix: \\s* → \s* (was matching literal backslash)
        dict_pattern = r'(\w+)\s*\[\s*["\'](\w*(?:password|secret|token|key|credential)\w*)["\']\s*\]'
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
        # Additional security-critical auth patterns
        self.security_auth_patterns = [
            'jwt.decode', 'bcrypt.checkpw', 'hmac.compare_digest',
            'InvalidTokenError', 'expires_at', 'rate_limit',
        ]

    def applies_to(self, code: str) -> bool:
        code_lower = code.lower()
        # Check traditional auth patterns
        for pattern in self.auth_patterns:
            if pattern.lower() in code_lower:
                return True
        # Check security-critical patterns
        for pattern in self.security_auth_patterns:
            if pattern.lower() in code_lower:
                return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        for auth_func in self.auth_patterns:
            # Pattern: if not auth_func(): raise/return
            # Uses helper function for proper indentation handling
            pattern = rf'if\s+not\s+{auth_func}\s*\([^)]*\)\s*:\s*\n(\s+)(raise|return)[^\n]*\n'
            for mutant, _, _ in remove_if_block_safely(code, pattern, re.IGNORECASE):
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

        # === NEW: JWT token validation bypass ===
        # Pattern: try: jwt.decode(...) except jwt.InvalidTokenError: raise
        jwt_try_pattern = r'(\s*)try:\s*\n\s+return\s+jwt\.decode\((\w+)[^)]*\)\s*\n\s+except\s+(?:jwt\.)?(?:InvalidTokenError|PyJWTError|Exception)[^:]*:\s*\n\s+(raise|return)[^\n]*\n'
        for match in re.finditer(jwt_try_pattern, code):
            indent = match.group(1)
            token_var = match.group(2)  # Extract actual token variable name
            # Replace with base64 decode (insecure - no signature check)
            replacement = (
                f'{indent}import base64\n'
                f'{indent}payload = {token_var}.split(".")[1]\n'
                f'{indent}return json.loads(base64.b64decode(payload + "=="))\n'
            )
            mutant = code[:match.start()] + replacement + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Bypassed JWT signature verification"))
            except SyntaxError:
                pass

        # === NEW: bcrypt.checkpw bypass ===
        # Use balanced parenthesis matching instead of regex for nested parens
        if 'bcrypt.checkpw' in code:
            # Find bcrypt.checkpw( and match balanced parentheses
            idx = code.find('bcrypt.checkpw(')
            while idx != -1:
                # Find matching closing paren
                paren_start = idx + len('bcrypt.checkpw')
                depth = 0
                end = paren_start
                for i in range(paren_start, len(code)):
                    if code[i] == '(':
                        depth += 1
                    elif code[i] == ')':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                if end > paren_start:
                    mutant = code[:idx] + "user['password'] == password" + code[end:]
                    try:
                        ast.parse(mutant)
                        mutants.append((mutant, "Bypassed bcrypt password check with plain comparison"))
                    except SyntaxError:
                        pass
                idx = code.find('bcrypt.checkpw(', idx + 1)

        # === NEW: hmac.compare_digest bypass ===
        # Pattern: return hmac.compare_digest(...)
        hmac_pattern = r'hmac\.compare_digest\(([^,]+),\s*([^)]+)\)'
        for match in re.finditer(hmac_pattern, code):
            arg1, arg2 = match.group(1), match.group(2)
            # Replace with simple == (timing attack vulnerable)
            mutant = code[:match.start()] + f'{arg1.strip()} == {arg2.strip()}' + code[match.end():]
            mutants.append((mutant, "Replaced hmac.compare_digest with timing-vulnerable =="))

        # === NEW: Session expiry bypass ===
        # Pattern: if time.time() > session.get('expires_at', 0): ... return False
        expiry_pattern = r'if\s+time\.time\(\)\s*>\s*session\.get\([^)]+\)\s*:\s*\n\s+[^\n]+\n\s+return\s+False\s*\n'
        for match in re.finditer(expiry_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed session expiry check"))

        # === NEW: Rate limit bypass ===
        # Pattern: if ... attempts >= N: raise ValueError("Too many")
        rate_limit_pattern = r"if[^:]+attempts[^:]+>=\s*\d+\s*:\s*\n\s+raise\s+ValueError\([^)]*[Tt]oo many[^)]*\)\s*\n"
        for match in re.finditer(rate_limit_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed rate limiting check"))

        # === Pass-variant mutants (dead auth checks) ===
        for auth_func in self.auth_patterns:
            pattern = rf'if\s+not\s+{auth_func}\s*\([^)]*\)\s*:\s*\n(\s+)(raise|return)[^\n]*\n'
            for mutant, _, _ in replace_if_body_with_pass(code, pattern, re.IGNORECASE):
                mutants.append((mutant, f"Dead auth check: {auth_func} (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, request_auth_pattern):
            mutants.append((mutant, "Dead request.user.is_authenticated check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, flask_auth_pattern):
            mutants.append((mutant, "Dead current_user.is_authenticated check (pass instead of raise)"))

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
            # Replace .resolve() with .absolute() (no symlink resolution)
            mutant2 = re.sub(resolve_pattern, '.absolute()', code)
            if mutant2 != code:
                mutants.append((mutant2, "[Medium] Replaced .resolve() with .absolute() (no symlink resolution)"))

        # === EASY: Remove str().startswith() path validation ===
        # Uses helper function for proper indentation handling
        startswith_pattern = r'if\s+not\s+str\(.+?\)\.startswith\s*\(.+?\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, startswith_pattern):
            mutants.append((mutant, "[Easy] Removed path prefix validation"))

        # === EASY: Remove variable.startswith() check (with nested parens support) ===
        startswith_var_pattern = r'if\s+not\s+\w+\.startswith\s*\(.+?\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, startswith_var_pattern):
            mutants.append((mutant, "[Easy] Removed path startswith validation"))

        # === MEDIUM: Replace pathlib / operator with f-string (with parens) ===
        # C9 fix: Wrap in Path() so downstream .resolve() calls still work
        # Pattern: (base / filename)
        pathlib_paren_pattern = r'\((\w+)\s*/\s*(\w+)\)'
        matches = list(re.finditer(pathlib_paren_pattern, code))
        for match in matches:
            base_var = match.group(1)
            file_var = match.group(2)
            replacement = f'Path(f"{{str({base_var})}}/{{str({file_var})}}")'
            mutant = code[:match.start()] + replacement + code[match.end():]
            mutants.append((mutant, f"[Medium] Replaced ({base_var} / {file_var}) with f-string (no canonicalization)"))

        # === MEDIUM: Replace pathlib / operator WITHOUT parens (FIX Bug B) ===
        # Pattern: var1 / var2 (assignment context to avoid matching division)
        # Match: file_path = base_dir / filename
        pathlib_noparen_pattern = r'(\w+)\s*=\s*(\w+)\s*/\s*(\w+)(?!\s*[/\d])'  # Avoid division context
        matches = list(re.finditer(pathlib_noparen_pattern, code))
        for match in matches:
            result_var = match.group(1)
            base_var = match.group(2)
            file_var = match.group(3)
            # Check this looks like pathlib (not arithmetic)
            if any(kw in code for kw in ['Path', 'pathlib', 'directory', 'folder', 'path']):
                # C9 fix: Wrap in Path() so downstream .resolve() calls still work
                replacement = f'{result_var} = Path(f"{{str({base_var})}}/{{str({file_var})}}")'
                mutant = code[:match.start()] + replacement + code[match.end():]
                mutants.append((mutant, f"[Medium] Replaced {base_var} / {file_var} with f-string (no canonicalization)"))

        # === MEDIUM: Replace Path(...) / operator ===
        # C9 fix: Wrap in Path() so downstream .resolve() calls still work
        pathlib_pattern = r'(Path\([^)]+\))\s*/\s*(\w+)'
        matches = list(re.finditer(pathlib_pattern, code))
        for match in matches:
            path_obj = match.group(1)
            filename = match.group(2)
            replacement = f'Path(f"{{str({path_obj})}}/{{str({filename})}}")'
            mutant = code[:match.start()] + replacement + code[match.end():]
            mutants.append((mutant, "[Medium] Replaced Path / operator with f-string (no canonicalization)"))

        # === MEDIUM: Remove normpath/realpath/abspath (handle nested parens) ===
        for func in ['normpath', 'realpath', 'abspath']:
            # FIX Bug A: Use balanced approach for nested parens
            pattern = rf'os\.path\.{func}\s*\((.+?)\)(?=\s*[,):\]\n])'
            matches = list(re.finditer(pattern, code))
            for match in matches:
                inner = match.group(1)
                mutant = code[:match.start()] + inner + code[match.end():]
                mutants.append((mutant, f"[Medium] Removed os.path.{func}"))
                # Identity variant: realpath(x) → str(x)
                if func == 'realpath':
                    mutant2 = code[:match.start()] + f'str({inner})' + code[match.end():]
                    mutants.append((mutant2, f"[Medium] Replaced os.path.realpath with str() (identity)"))

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
        # Uses helper function to filter out non-compiling results
        full_block_pattern = r'if\s+not\s+[^:]+:\s*\n\s*(raise\s+ValueError\([^)]*(?:traversal|path|invalid)[^)]*\)|return\s+None)\n?'
        for mutant, _, _ in remove_if_block_safely(code, full_block_pattern, re.IGNORECASE):
            mutants.append((mutant, "[Hard] Removed path validation block"))

        # === HARD: Remove relative_to validation block (FIX Bug C) ===
        # SecCodePLT pattern: try: path.resolve().relative_to(base.resolve()) except ValueError: raise/return
        relative_to_try_pattern = r'try:\s*\n\s*[^\n]*\.relative_to\([^\n]+\)\s*\n\s*except\s+ValueError[^:]*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(relative_to_try_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Hard] Removed relative_to path validation"))

        # === HARD: Remove .relative_to() call inline ===
        relative_to_inline = r'\.relative_to\([^)]+\)'
        if re.search(relative_to_inline, code):
            mutant = re.sub(relative_to_inline, '', code)
            mutants.append((mutant, "[Hard] Removed .relative_to() call"))

        # === Pass-variant mutants (dead path validation) ===
        for mutant, _, _ in replace_if_body_with_pass(code, startswith_pattern):
            mutants.append((mutant, "[Easy] Dead path prefix check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, startswith_var_pattern):
            mutants.append((mutant, "[Easy] Dead path startswith check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, full_block_pattern, re.IGNORECASE):
            mutants.append((mutant, "[Hard] Dead path validation (pass instead of raise)"))

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
        # Basic subprocess/os patterns
        if any(x in code for x in ['subprocess', 'os.system', 'os.popen', 'Popen', 'check_output']):
            return True
        # EXPANDED: More command execution patterns
        if 'shlex' in code:  # shlex.split, shlex.quote
            return True
        if 'shell=' in code:  # Any shell= parameter
            return True
        if re.search(r'\brun\s*\(', code) and 'import subprocess' in code:
            return True
        # Commands module (deprecated but still used)
        if 'commands.' in code or 'getoutput' in code:
            return True
        # asyncio subprocess
        if 'asyncio.create_subprocess' in code:
            return True
        return False

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
        # Use AST to safely parse list elements instead of naive comma splitting
        list_pattern = r'subprocess\.(run|call|Popen|check_output)\s*\(\s*\[([^\]]+)\]'
        matches = list(re.finditer(list_pattern, code))

        for match in matches:
            func = match.group(1)
            args_str = match.group(2)
            # Use AST to parse the list elements safely
            try:
                parsed_list = ast.parse(f'[{args_str}]', mode='eval')
                parts = []
                has_variable = False
                for elt in parsed_list.body.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        parts.append(elt.value)
                    else:
                        # Non-literal (variable, call, etc.) - use f-string interpolation
                        src = ast.get_source_segment(f'[{args_str}]', elt)
                        if src is None:
                            src = args_str  # fallback
                        parts.append('{' + src + '}')
                        has_variable = True
                if not has_variable:
                    continue  # No variables to inject through
                cmd_string = ' '.join(parts)
            except (SyntaxError, ValueError):
                continue  # Skip if we can't parse the list

            # Variant 3: f-string with shell=True
            replacement = f'subprocess.{func}(f"{cmd_string}", shell=True'
            mutant = code[:match.start()] + replacement + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Variant 3] Converted to f-string shell command"))
            except SyntaxError:
                pass

            # Variant 4: Replace with os.system
            os_cmd = f'os.system(f"{cmd_string}")'
            mutant2 = code[:match.start()] + os_cmd + code[match.end():]
            if 'import os' not in mutant2 and 'from os' not in mutant2:
                mutant2 = 'import os\n' + mutant2
            try:
                ast.parse(mutant2)
                mutants.append((mutant2, "[Variant 4] Replaced subprocess with os.system"))
            except SyntaxError:
                pass

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

        # EXPANDED: Handle shlex.split patterns (common in secure transformations)
        # Pattern: subprocess.run(shlex.split(cmd), shell=False)
        # → subprocess.run(cmd, shell=True)
        shlex_split_pattern = r'subprocess\.(run|call|Popen|check_output)\s*\(\s*shlex\.split\s*\(\s*([^)]+)\s*\)'
        for match in re.finditer(shlex_split_pattern, code):
            func = match.group(1)
            cmd_arg = match.group(2).strip()
            # Replace shlex.split(x) with just x and add shell=True
            mutant = code[:match.start()] + f'subprocess.{func}({cmd_arg}, shell=True' + code[match.end():]
            mutants.append((mutant, "[Expanded] shlex.split to shell=True"))

            # Also try os.system variant
            mutant2 = code[:match.start()] + f'os.system({cmd_arg})' + code[match.end():]
            if 'import os' not in mutant2:
                mutant2 = 'import os\n' + mutant2
            mutants.append((mutant2, "[Expanded] shlex.split to os.system"))

        # EXPANDED: Handle check=True removal (allows command failures to be silently ignored)
        if 'check=True' in code:
            mutant = code.replace('check=True', 'check=False')
            mutants.append((mutant, "[Expanded] Disabled check=True safety"))

        # NOTE: capture_output removal was removed — it's a functional change, not a security vulnerability

        # EXPANDED: Handle asyncio.create_subprocess_shell patterns
        asyncio_pattern = r'asyncio\.create_subprocess_exec\s*\(\s*([^)]+)\)'
        for match in re.finditer(asyncio_pattern, code):
            args = match.group(1)
            # Convert to shell version
            mutant = code[:match.start()] + f'asyncio.create_subprocess_shell({args})' + code[match.end():]
            mutants.append((mutant, "[Expanded] asyncio exec to shell"))

        # EXPANDED: Handle commands.getoutput (deprecated but seen in old code)
        getoutput_pattern = r'subprocess\.getoutput\s*\(\s*([^)]+)\s*\)'
        for match in re.finditer(getoutput_pattern, code):
            cmd = match.group(1)
            # getoutput already runs in shell, but we can make it worse
            mutant = code[:match.start()] + f'os.popen({cmd}).read()' + code[match.end():]
            mutants.append((mutant, "[Expanded] getoutput to os.popen"))

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
        # URL construction with regex validation (CWEval pattern)
        if 're.match' in code and ('url' in code.lower() or 'domain' in code.lower()):
            return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # === NEW: Remove re.match validation for URL/domain construction ===
        # Pattern: if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain_prefix): return fallback
        rematch_url = r'[ \t]*if\s+not\s+re\.match\s*\([^)]+,\s*\w+\s*\)\s*:\s*\n\s*(return|raise)[^\n]*\n'
        for match in re.finditer(rematch_url, code):
            mutant = code[:match.start()] + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Easy] Removed regex validation for URL/domain input"))
            except SyntaxError:
                pass

        # === EASY: Remove 'hostname in BLOCKED_HOSTS' check ===
        # Matches both variable names (BLOCKED_HOSTS) and list literals (['localhost', ...])
        blocked_hosts_pattern = r'[ \t]*if\s+[\w.]+\.hostname\s+in\s+(?:\w+|\[[^\]]*\])[^:]*:\s*\n\s*(raise|return)[^\n]*\n'
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

        # === MEDIUM: Remove 'not in allowed_hosts/ALLOWED_DOMAINS' check ===
        # Matches: allowed_hosts, ALLOWED_HOSTS, whitelist, ALLOWED_DOMAINS, SAFE_*_DOMAINS, etc.
        allowed_pattern = r'[ \t]*if\s+[\w.]+\s+not\s+in\s+\w*(?:allowed|ALLOWED|whitelist|WHITELIST|safe|SAFE)\w*[^\n]*:\s*\n\s*(raise|return)[^\n]*\n'
        matches = list(re.finditer(allowed_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Medium] Removed allowed hosts/domains validation"))
            except SyntaxError:
                pass

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

        # === NEW: Remove parsed_url.hostname not in ALLOWED_VAR check (SecCodePLT pattern) ===
        # Pattern: if parsed_url.hostname not in ALLOWED_DOMAINS: raise ValueError(...)
        hostname_allowlist = r'[ \t]*if\s+[\w.]+\.hostname\s+not\s+in\s+\w+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(hostname_allowlist, code):
            mutant = code[:match.start()] + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Easy] Removed hostname allowlist validation"))
            except SyntaxError:
                pass

        # === GENERAL: Remove scheme validation with list literal ===
        # Pattern: if parsed.scheme not in ['http', 'https']:
        scheme_list_check = r'[ \t]*if\s+[\w.]+\.scheme\s+not\s+in\s+\[[^\]]*\]\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(scheme_list_check, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "[Medium] Removed URL scheme validation"))

        # === GENERAL: Remove 'hostname in [list]' check ===
        # Pattern: if parsed.hostname in ['localhost', '127.0.0.1']:
        hostname_list_check = r'[ \t]*if\s+[\w.]+\s+in\s+\[[^\]]*\]\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(hostname_list_check, code):
            matched = match.group()
            if any(kw in matched.lower() for kw in ['host', 'local', '127', '10.', '192.', 'internal', 'private']):
                mutant = code[:match.start()] + code[match.end():]
                mutants.append((mutant, "[Easy] Removed hostname list check"))

        # === NEW: Empty blocklist variant ===
        # Replace blocklist sets/lists with empty set
        blocklist_def = re.search(
            r'((?:BLOCKED|DANGEROUS|INTERNAL|PRIVATE)_(?:HOSTS|IPS|DOMAINS|NETWORKS))\s*=\s*(?:\{[^}]+\}|\[[^\]]+\])',
            code, re.IGNORECASE
        )
        if blocklist_def:
            var_name = blocklist_def.group(1)
            mutant = code[:blocklist_def.start()] + f'{var_name} = set()' + code[blocklist_def.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "[Easy] Emptied blocklist (all hosts allowed)"))
            except SyntaxError:
                pass

        # === NEW: Extended validation bypass function names ===
        for func_name in ['is_safe_url', 'check_url', 'sanitize_url', 'validate_url_safety']:
            bypass_pattern = rf'[ \t]*if\s+not\s+{func_name}\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
            for match in re.finditer(bypass_pattern, code, re.IGNORECASE):
                mutant = code[:match.start()] + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, f"[Hard] Removed {func_name} validation"))
                except SyntaxError:
                    pass

        # === Pass-variant mutants (dead SSRF validation) ===
        ssrf_pass_patterns = [
            (rematch_url, 0, "[Easy] Dead regex URL validation"),
            (blocked_hosts_pattern, 0, "[Easy] Dead hostname blocklist"),
            (url_check_pattern, 0, "[Medium] Dead URL prefix/suffix validation"),
            (urlparse_check, 0, "[Medium] Dead urlparse host validation"),
            (allowed_pattern, re.IGNORECASE, "[Medium] Dead allowed hosts validation"),
            (safe_url_pattern, re.IGNORECASE, "[Hard] Dead is_safe_url validation"),
            (hostname_allowlist, 0, "[Easy] Dead hostname allowlist validation"),
            (scheme_list_check, 0, "[Medium] Dead URL scheme validation"),
        ]
        for pat, flg, desc in ssrf_pass_patterns:
            for mutant, _, _ in replace_if_body_with_pass(code, pat, flg):
                mutants.append((mutant, desc + " (pass instead of raise)"))

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

        # Remove owner_id check (using helper to filter non-compiling mutants)
        owner_check_pattern = r'if\s+[\w.]+\.owner_id\s*(!=|==)\s*[\w.]+:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, owner_check_pattern):
            mutants.append((mutant, "Removed owner_id authorization check"))

        # Remove user_id comparison (with object attribute)
        user_check_pattern = r'if\s+[\w.]+\s*(!=|==)\s*(current_user|request\.user|session\[.user.\])[\w.]*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, user_check_pattern):
            mutants.append((mutant, "Removed user authorization check"))

        # Remove simple user_id variable comparison (e.g., if user_id != current_user_id:)
        simple_user_check = r'if\s+(\w*user\w*)\s*(!=|==)\s*(\w*user\w*)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, simple_user_check, re.IGNORECASE):
            mutants.append((mutant, "Removed user ID comparison check"))

        # Remove has_permission check
        perm_pattern = r'if\s+not\s+[\w.]+\.has_permission\s*\([^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, perm_pattern):
            mutants.append((mutant, "Removed has_permission check"))

        # Remove can_access check
        access_pattern = r'if\s+not\s+(can_access|check_access|is_authorized)\s*\([^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, access_pattern, re.IGNORECASE):
            mutants.append((mutant, "Removed access authorization check"))

        # Replace authorization function with True (always compiles)
        for pattern in ['has_permission', 'can_access', 'is_owner', 'check_ownership']:
            func_pattern = rf'{pattern}\s*\([^)]*\)'
            matches = list(re.finditer(func_pattern, code, re.IGNORECASE))
            for match in matches:
                mutant = code[:match.start()] + 'True' + code[match.end():]
                mutants.append((mutant, f"Replaced {pattern}() with True"))

        # Alternative: Replace comparison with True/False to bypass check
        # Pattern: if user_id != current_user_id → if False
        user_comparison = r'(\w*user\w*)\s*(!=|==)\s*(\w*user\w*)'
        for match in re.finditer(user_comparison, code, re.IGNORECASE):
            op = match.group(2)
            # If != (should be equal), replace with False to bypass
            replacement = 'False' if op == '!=' else 'True'
            mutant = code[:match.start()] + replacement + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, f"Replaced user ID check with {replacement}"))
            except SyntaxError:
                pass

        # === Pass-variant mutants (dead authorization checks) ===
        for mutant, _, _ in replace_if_body_with_pass(code, owner_check_pattern):
            mutants.append((mutant, "Dead owner_id check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, user_check_pattern):
            mutants.append((mutant, "Dead user authorization check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, simple_user_check, re.IGNORECASE):
            mutants.append((mutant, "Dead user ID comparison (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, perm_pattern):
            mutants.append((mutant, "Dead has_permission check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, access_pattern, re.IGNORECASE):
            mutants.append((mutant, "Dead access authorization check (pass instead of raise)"))

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

        # === NEW: Remove resolve_entities=False entirely ===
        # Parser default is True, so removing the param enables entity resolution
        if 'resolve_entities=False' in code:
            resolve_param = r',\s*resolve_entities\s*=\s*False'
            mutant = re.sub(resolve_param, '', code)
            if mutant != code:
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Removed resolve_entities=False (defaults to True)"))
                except SyntaxError:
                    pass

        # === NEW: Remove parser= argument from parse/fromstring calls ===
        # Broader pattern covering any parse/fromstring with parser kwarg
        parser_kwarg = r'((?:\.parse|\.fromstring|\.iterparse)\s*\([^,]+),\s*parser\s*=\s*\w+'
        if re.search(parser_kwarg, code):
            mutant = re.sub(parser_kwarg, r'\1', code)
            if mutant != code:
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Removed parser= argument (uses default unsafe parser)"))
                except SyntaxError:
                    pass

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

        # Disable autoescape via select_autoescape
        if 'select_autoescape()' in code:
            mutant = code.replace('select_autoescape()', 'False')
            mutants.append((mutant, "Disabled autoescaping by replacing select_autoescape"))

        # H9 fix: Removed duplicate autoescape and render_template blocks

        # Replace env.from_string(ALLOWED_TEMPLATE) with Template(user_input)
        # Pattern: env.from_string(CONSTANT[key]) or env.from_string(template_var)
        from_string_pattern = r'(\w+)\.from_string\s*\([^)]+\)'
        for match in re.finditer(from_string_pattern, code):
            mutant = code[:match.start()] + 'Template(user_input)' + code[match.end():]
            # Make sure Template is importable
            if 'from jinja2 import' in mutant and 'Template' not in mutant.split('import')[1].split('\n')[0]:
                mutant = mutant.replace('from jinja2 import', 'from jinja2 import Template,')
            mutants.append((mutant, "Replaced safe env.from_string with Template(user_input)"))

        # Remove template allowlist check
        allowlist_pattern = r'if\s+\w+\s+not\s+in\s+(?:ALLOWED_TEMPLATES|PAGES|NOTIFICATIONS|templates)\s*:\s*\n\s*raise\s+ValueError[^\n]*\n'
        for match in re.finditer(allowlist_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed template allowlist validation"))

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

        # Add @csrf_exempt decorator (only if function doesn't already have inline CSRF validation)
        func_pattern = r'(def\s+\w+\s*\([^)]*request[^)]*\)\s*:)'
        matches = list(re.finditer(func_pattern, code))
        for match in matches:
            if '@csrf_exempt' not in code[:match.start()]:
                # Check if this function has inline CSRF validation - if so, skip decorator mutation
                func_body_start = match.end()
                # Find end of function (next def or end of code)
                next_def = code.find('\ndef ', func_body_start)
                func_body = code[func_body_start:next_def] if next_def > 0 else code[func_body_start:]
                if 'csrf' not in func_body.lower():
                    mutant = code[:match.start()] + '@csrf_exempt\n' + code[match.start():]
                    mutants.append((mutant, "Added @csrf_exempt decorator"))

        # IMPROVED: Remove CSRF token validation - handle compound conditions
        # Pattern 1: Simple check - if not csrf_token:
        simple_csrf_pattern = r'if\s+not\s+[\w.]*csrf[\w.]*\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(simple_csrf_pattern, code, re.IGNORECASE):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed simple CSRF check"))

        # Pattern 2: Compound check - if not csrf_token or not compare_digest(...):
        compound_csrf_pattern = r'if\s+not\s+[\w.]*csrf[\w.]*\s+or\s+not\s+[^:]+:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(compound_csrf_pattern, code, re.IGNORECASE):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed compound CSRF validation"))

        # Pattern 3: Compound with secrets.compare_digest
        compare_digest_pattern = r'if\s+not\s+[\w.]*csrf[\w.]*\s+or\s+not\s+[\w.]*compare_digest\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(compare_digest_pattern, code, re.IGNORECASE):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed CSRF compare_digest validation"))

        # Pattern 4: Multi-line compound condition
        multiline_csrf_pattern = r'if\s*\(\s*not\s+[\w.]*csrf[\w.]*\s+or[^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for match in re.finditer(multiline_csrf_pattern, code, re.IGNORECASE):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed multi-line CSRF validation"))

        # NEW: Remove entire CSRF validation block (token extraction through validation)
        # Matches: csrf_token = request.form.get('csrf_token')
        #          expected = session.get('csrf_token')
        #          if not csrf_token or not secrets.compare_digest(...):
        #              raise ValueError(...)
        csrf_block_pattern = r'(\s*)[\w.]*csrf[\w.]*\s*=\s*[\w.]+\.(?:get|form\.get|cookies\.get)\s*\([^)]*csrf[^)]*\)[^\n]*\n(?:.*?csrf.*?\n)*?\s*if\s+not\s+[\w.]*csrf[^:]+:\s*\n\s*(?:raise|return)[^\n]*\n'
        for match in re.finditer(csrf_block_pattern, code, re.IGNORECASE | re.DOTALL):
            indent = match.group(1)
            mutant = code[:match.start()] + f'{indent}pass  # CSRF validation removed\n' + code[match.end():]
            mutants.append((mutant, "Removed entire CSRF validation block"))

        # NEW: Remove CSRF validation block including if-block body
        # Handles patterns like:
        #     csrf_token = request.get("X-CSRF-Token")
        #     if csrf_token != expected:
        #         return False
        lines = code.split('\n')

        # Find lines with CSRF checks and their associated blocks
        i = 0
        while i < len(lines):
            line = lines[i]
            # Check for CSRF if-statement
            if re.search(r'if\s+.*csrf', line, re.IGNORECASE) and ':' in line:
                # Found an if-csrf block - find its extent
                if_indent = len(line) - len(line.lstrip())
                block_start = i
                block_end = i + 1

                # Find the end of the if-block (next line with same or less indent)
                while block_end < len(lines):
                    next_line = lines[block_end]
                    if next_line.strip():  # Non-empty line
                        next_indent = len(next_line) - len(next_line.lstrip())
                        if next_indent <= if_indent:
                            break
                    block_end += 1

                # Also check for preceding csrf_token = ... line
                if block_start > 0:
                    prev_line = lines[block_start - 1]
                    if re.search(r'csrf.*=', prev_line, re.IGNORECASE):
                        block_start -= 1

                # Create mutant with block replaced by pass
                new_lines = lines[:block_start]
                new_lines.append(' ' * if_indent + 'pass  # CSRF validation removed')
                new_lines.extend(lines[block_end:])
                mutant = '\n'.join(new_lines)

                if mutant != code:
                    try:
                        compile(mutant, '<string>', 'exec')
                        mutants.append((mutant, "Removed CSRF validation block"))
                    except SyntaxError:
                        pass  # Skip invalid mutants
            i += 1

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

        # NEW: Replace compare_digest with == (timing attack)
        if 'compare_digest' in code:
            # secrets.compare_digest(a, b) → a == b
            compare_pattern = r'[\w.]*compare_digest\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)'
            for match in re.finditer(compare_pattern, code):
                a, b = match.group(1).strip(), match.group(2).strip()
                mutant = code[:match.start()] + f'{a} == {b}' + code[match.end():]
                mutants.append((mutant, "Replaced compare_digest with == (timing attack)"))

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
            # Predictable constant variant
            mutant2 = code[:match.start()] + f"b'\\x00' * {n}" + code[match.end():]
            mutants.append((mutant2, f"Replaced secrets.token_bytes with predictable constant"))

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
            # Predictable constant variant
            mutant2 = code[:match.start()] + f"'a' * {hex_width}" + code[match.end():]
            mutants.append((mutant2, f"Replaced secrets.token_hex with predictable constant"))

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
            # Predictable constant variant
            mutant2 = code[:match.start()] + f"'A' * {n}" + code[match.end():]
            mutants.append((mutant2, f"Replaced secrets.token_urlsafe with predictable constant"))

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
            # Predictable constant variant
            mutant2 = code[:match.start()] + f"b'\\x00' * {n}" + code[match.end():]
            mutants.append((mutant2, f"Replaced os.urandom with predictable constant"))

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
        safe_patterns = ['ast.literal_eval', 'json.loads', 'safe_eval', 'literal_eval', 'ast.parse']
        # Also match restricted eval with builtins restriction, regex validation, or char allowlist
        has_restricted_eval = ('eval(' in code and ('__builtins__' in code or 're.match' in code or 're.fullmatch' in code))
        # Char allowlist before eval: allowed_chars = set(...); if not set(x).issubset(...)
        has_char_allowlist = ('eval(' in code and ('issubset' in code or 'allowed_chars' in code or 'allowed' in code.lower()))
        return any(p in code for p in safe_patterns) or has_restricted_eval or has_char_allowlist

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

        # ast.parse with eval mode → eval() directly
        # Pattern: tree = ast.parse(expr, mode='eval') ... → return eval(expr)
        if 'ast.parse' in code:
            # Replace the safe AST-based evaluation with direct eval
            # Find the function and replace ast.parse with eval
            ast_parse_pattern = r'ast\.parse\s*\(\s*(\w+).*?\)'
            matches = list(re.finditer(ast_parse_pattern, code))
            for match in matches:
                var_name = match.group(1)
                # Replace the entire function body that uses ast.parse with eval
                mutant = re.sub(
                    r'(def\s+\w+\s*\([^)]*\):\s*(?:"""[^"]*"""|\'\'\'[^\']*\'\'\')?\s*\n).*?(?=\ndef|\Z)',
                    lambda m: m.group(1) + f'    return eval({var_name})\n',
                    code,
                    flags=re.DOTALL
                )
                if mutant != code:
                    try:
                        ast.parse(mutant)
                        mutants.append((mutant, "ast.parse → eval (code injection)"))
                    except SyntaxError:
                        pass

        # NEW: Restricted eval with builtins → unrestricted eval
        # Pattern: eval(formula, {"__builtins__": {}}, {}) → eval(formula)
        # Also handles: eval(x, {"__builtins__": {}})
        builtins_patterns = [
            # eval(var, {"__builtins__": {}}, {})
            r'eval\s*\(\s*(\w+)\s*,\s*\{"__builtins__":\s*\{\}\}\s*,\s*\{\}\s*\)',
            # eval(var, {"__builtins__": {}})
            r'eval\s*\(\s*(\w+)\s*,\s*\{"__builtins__":\s*\{\}\}\s*\)',
            # eval(var, {}, {"__builtins__": {}})
            r'eval\s*\(\s*(\w+)\s*,\s*\{\}\s*,\s*\{"__builtins__":\s*\{\}\}\s*\)',
        ]
        for pattern in builtins_patterns:
            for match in re.finditer(pattern, code):
                var_name = match.group(1)
                mutant = code[:match.start()] + f'eval({var_name})' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Removed builtins restriction from eval"))
                except SyntaxError:
                    pass

        # === NEW: Remove AST node-type whitelist validation (SecCodePLT pattern) ===
        # Pattern:
        #   parsed = ast.parse(code_string, mode="eval")
        #   allowed_nodes = (ast.Expression, ast.BinOp, ...)
        #   if any(not isinstance(node, ...) for node in ast.walk(parsed)):
        #       result = 'Blocked!'
        #   else:
        #       compiled = compile(parsed, ...)
        #       result = eval(compiled)
        # Mutation: Replace entire if/else with direct eval(code_string)
        if 'ast.walk' in code and 'ast.parse' in code:
            # Find the input variable from ast.parse call
            parse_match = re.search(r'ast\.parse\s*\(\s*(\w+)', code)
            if parse_match:
                input_var = parse_match.group(1)
                # Match the entire if-any-isinstance/else block (use .*? with DOTALL for nested parens)
                ast_whitelist_pattern = re.compile(
                    r'(?P<indent>[ \t]*)if\s+any\(.*?ast\.walk.*?\)\s*:\s*\n'
                    r'(?:(?P=indent)[ \t]+[^\n]+\n)+'         # if-body (Blocked!)
                    r'(?P=indent)else\s*:\s*\n'
                    r'(?:(?P=indent)[ \t]+[^\n]+\n)+',        # else-body (compile+eval)
                    re.DOTALL
                )
                match = ast_whitelist_pattern.search(code)
                if match:
                    indent = match.group('indent')
                    replacement = f'{indent}result = eval({input_var})\n'
                    mutant = code[:match.start()] + replacement + code[match.end():]
                    try:
                        ast.parse(mutant)
                        mutants.append((mutant, "Removed AST whitelist validation (direct eval injection)"))
                    except SyntaxError:
                        pass

            # Also remove the allowed_nodes_types definition and ast.parse lines
            # to create a cleaner mutant
            if parse_match:
                input_var = parse_match.group(1)
                mutant = code
                # Remove allowed_nodes_types tuple definition
                mutant = re.sub(
                    r'[ \t]*\w+\s*=\s*\(\s*\n(?:\s*ast\.\w+,?\s*\n)+\s*\)\s*\n',
                    '', mutant
                )
                # Remove ast.parse line
                mutant = re.sub(
                    r'[ \t]*\w+\s*=\s*ast\.parse\s*\([^)]+\)\s*\n',
                    '', mutant
                )
                # Replace the if/else block with direct eval
                ast_if_else = re.compile(
                    r'(?P<indent>[ \t]*)if\s+any\(.*?ast\.walk.*?\)\s*:\s*\n'
                    r'(?:(?P=indent)[ \t]+[^\n]+\n)+'
                    r'(?P=indent)else\s*:\s*\n'
                    r'(?:(?P=indent)[ \t]+[^\n]+\n)+',
                    re.DOTALL
                )
                match2 = ast_if_else.search(mutant)
                if match2:
                    indent = match2.group('indent')
                    replacement = f'{indent}result = eval({input_var})\n'
                    mutant = mutant[:match2.start()] + replacement + mutant[match2.end():]
                    try:
                        ast.parse(mutant)
                        mutants.append((mutant, "Removed AST parsing and whitelist (direct eval injection)"))
                    except SyntaxError:
                        pass

        # NEW: Remove char-allowlist validation before eval
        # Pattern: allowed_chars = set('0123456789+-*/()'); if not set(expr).issubset(allowed_chars): return ''
        if 'issubset' in code and 'eval(' in code:
            # Remove the if-not-issubset validation block
            allowlist_if = r'[ \t]*if\s+not\s+set\s*\(\s*\w+\s*\)\.issubset\s*\([^)]+\)\s*:\s*\n\s*(return|raise)[^\n]*\n'
            for m, _, _ in remove_if_block_safely(code, allowlist_if):
                if 'eval(' in m:
                    mutants.append((m, "Removed char allowlist validation before eval (code injection)"))

        # NEW: Remove regex validation before eval
        # Pattern: if not re.match(...): raise ... → remove validation
        # Handle multi-line patterns by looking for the if block
        regex_validation_patterns = [
            # Standard if not re.match pattern
            r'if\s+not\s+re\.match\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n',
            r'if\s+not\s+re\.fullmatch\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n',
            # M11 fix: Only match variable names suggesting regex/validation result
            # (was r'if\s+not\s+\w+\s*:' which matched ANY null/empty check)
            r'if\s+not\s+(?:match|valid|validated|result|check|pattern_match)\s*:\s*\n\s*(raise|return)[^\n]*\n',
        ]
        for pattern in regex_validation_patterns:
            for m, _, _ in remove_if_block_safely(code, pattern):
                if 'eval(' in m:
                    mutants.append((m, "Removed regex validation before eval"))

        # === Pass-variant mutants (dead eval validation) ===
        if 'issubset' in code and 'eval(' in code:
            allowlist_if = r'[ \t]*if\s+not\s+set\s*\(\s*\w+\s*\)\.issubset\s*\([^)]+\)\s*:\s*\n\s*(return|raise)[^\n]*\n'
            for m, _, _ in replace_if_body_with_pass(code, allowlist_if):
                if 'eval(' in m:
                    mutants.append((m, "Dead char allowlist check (pass instead of raise)"))
        for pattern in regex_validation_patterns:
            for m, _, _ in replace_if_body_with_pass(code, pattern):
                if 'eval(' in m:
                    mutants.append((m, "Dead regex validation (pass instead of raise)"))

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
        log_patterns = ['logging.', 'logger.', 'log.info', 'log.error', 'log.warning', 'log.debug', 'log(', 'log_entry', 'log entry', 'Received:']
        sanitize_patterns = ['replace(', 'strip(', 'encode(', 'escape(', 'sanitize', 're.sub(']
        code_lower = code.lower()
        return any(l.lower() in code_lower for l in log_patterns) and any(s in code for s in sanitize_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove .replace('\n', ' ') or .replace('\r', ' ') or .replace('\n', '')
        # Matches: .replace('\n', ' '), .replace('\\n', ''), .replace("\r", " ")
        newline_sanitize = r"\.replace\s*\(\s*['\"]\\\\?[nr]['\"],\s*['\"][^'\"]*['\"]\s*\)"
        if re.search(newline_sanitize, code):
            mutant = re.sub(newline_sanitize, '', code)
            mutants.append((mutant, "Removed newline sanitization from log input"))

        # Remove re.sub(r'[\n\r\t]', ' ', ...) sanitization
        resub_sanitize = r"re\.sub\s*\(\s*[r]?['\"][^'\"]*\\\\[nrt][^'\"]*['\"],\s*['\"][^'\"]*['\"],\s*\w+\s*\)"
        for match in re.finditer(resub_sanitize, code):
            # Replace the re.sub call with just the variable name
            full_match = match.group()
            # Extract the variable being sanitized (last argument)
            var_match = re.search(r',\s*(\w+)\s*\)$', full_match)
            if var_match:
                var_name = var_match.group(1)
                mutant = code.replace(full_match, var_name)
                mutants.append((mutant, "Removed re.sub sanitization from log input"))

        # Remove .strip() before logging
        strip_pattern = r'\.strip\s*\(\s*\)'
        if re.search(strip_pattern, code) and 'log' in code.lower():
            mutant = re.sub(strip_pattern, '', code)
            mutants.append((mutant, "Removed strip() from log input"))

        # === NEW: Remove .encode('unicode_escape') sanitization ===
        unicode_escape = r"\.encode\s*\(\s*['\"]unicode_escape['\"]\s*\)"
        if re.search(unicode_escape, code):
            mutant = re.sub(unicode_escape, '', code)
            mutants.append((mutant, "Removed unicode_escape encoding from log input"))

        # === NEW: Bypass sanitization function calls ===
        # Pattern: sanitize_log(x) → x, clean_log_input(x) → x
        for func_name in ['sanitize_log', 'clean_log_input', 'sanitize_input', 'escape_log']:
            sanitize_pattern = rf'{func_name}\s*\(\s*(\w+)\s*\)'
            for match in re.finditer(sanitize_pattern, code):
                var_name = match.group(1)
                mutant = code[:match.start()] + var_name + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, f"Bypassed {func_name}() sanitization"))
                except SyntaxError:
                    pass

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
            'ALLOWED_HOSTS', 'ALLOWED_DOMAINS', 'startswith', 'urlparse'
        ]

    def applies_to(self, code: str) -> bool:
        if 'redirect' in code.lower():
            return any(v in code for v in self.redirect_validators)
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove is_safe_url check
        safe_url_pattern = r'if\s+not\s+is_safe_url\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, safe_url_pattern):
            mutants.append((mutant, "Removed is_safe_url redirect validation"))

        # Remove url_has_allowed_host check
        allowed_host_pattern = r'if\s+not\s+url_has_allowed_host\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, allowed_host_pattern):
            mutants.append((mutant, "Removed url_has_allowed_host check"))

        # Remove startswith check for redirect URLs
        startswith_pattern = r'if\s+not\s+[\w.]+\.startswith\s*\([^)]*["\']/[^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, startswith_pattern):
            if 'redirect' in code.lower():
                mutants.append((mutant, "Removed redirect URL prefix validation"))

        # NEW: Remove urlparse netloc checks (common pattern)
        # Pattern: if parsed.netloc and parsed.netloc != "domain":
        netloc_pattern = r'if\s+[\w.]+\.netloc\s+and\s+[\w.]+\.netloc\s*!=\s*["\'][^"\']+["\']\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, netloc_pattern):
            mutants.append((mutant, "Removed netloc domain validation (open redirect)"))

        # Pattern: if parsed.netloc: (simple netloc existence check)
        simple_netloc_pattern = r'if\s+[\w.]+\.netloc\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, simple_netloc_pattern):
            mutants.append((mutant, "Removed netloc check (open redirect)"))

        # Pattern: if parsed.scheme and parsed.scheme not in ('http', 'https'):
        scheme_pattern = r'if\s+[\w.]+\.scheme\s+and\s+[\w.]+\.scheme\s+not\s+in[^\n]*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, scheme_pattern):
            mutants.append((mutant, "Removed scheme validation (open redirect)"))

        # Alternative: Replace netloc check with False
        if '.netloc' in code:
            netloc_check = r'[\w.]+\.netloc\s+and\s+[\w.]+\.netloc\s*!=\s*["\'][^"\']+["\']'
            for match in re.finditer(netloc_check, code):
                mutant = code[:match.start()] + 'False' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Bypassed netloc domain check"))
                except SyntaxError:
                    pass

        # NEW: Remove ALLOWED_DOMAINS check (common pattern)
        # Pattern: if parsed.netloc and parsed.netloc not in ALLOWED_DOMAINS:
        allowed_domains_pattern = r'if\s+[\w.]+\.netloc\s+and\s+[\w.]+\.netloc\s+not\s+in\s+\w+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for m, _, _ in remove_if_block_safely(code, allowed_domains_pattern):
            mutants.append((m, "Removed ALLOWED_DOMAINS check (open redirect)"))

        # Alternative: Replace "not in ALLOWED_DOMAINS" with False
        not_in_allowed = r'[\w.]+\.netloc\s+and\s+[\w.]+\.netloc\s+not\s+in\s+\w+'
        for match in re.finditer(not_in_allowed, code):
            mutant = code[:match.start()] + 'False' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Bypassed ALLOWED_DOMAINS check"))
            except SyntaxError:
                pass

        # === NEW: Remove positive domain allowlist check (SecCodePLT pattern) ===
        # Pattern: if redirect_domain == base_domain or redirect_domain in ALLOWED_DOMAINS:
        #              return redirect_url
        #          else:
        #              raise ValueError("Invalid redirect URL")
        # Mutation: Remove if/else, keep only the if-body (always redirect)
        positive_allowlist = re.compile(
            r'(?P<indent>[ \t]*)if\s+\w+\s*==\s*\w+\s+or\s+\w+\s+in\s+\w*(?:ALLOWED|allowed)\w*\s*:\s*\n'
            r'(?P<if_body>(?:(?P=indent)[ \t]+[^\n]+\n)+)'
            r'(?P=indent)else\s*:\s*\n'
            r'(?:(?P=indent)[ \t]+[^\n]+\n)+'
        )
        for mutant, _ in replace_if_else_with_if_body(code, positive_allowlist):
            mutants.append((mutant, "Removed domain allowlist validation (open redirect)"))

        # === NEW: Remove domain equality + 'in ALLOWED' check (variant) ===
        # Pattern: if domain in ALLOWED_DOMAINS: return url \n else: raise ...
        simple_allowlist = re.compile(
            r'(?P<indent>[ \t]*)if\s+\w+\s+in\s+\w*(?:ALLOWED|allowed)\w*\s*:\s*\n'
            r'(?P<if_body>(?:(?P=indent)[ \t]+[^\n]+\n)+)'
            r'(?P=indent)else\s*:\s*\n'
            r'(?:(?P=indent)[ \t]+[^\n]+\n)+'
        )
        for mutant, _ in replace_if_else_with_if_body(code, simple_allowlist):
            mutants.append((mutant, "Removed domain allowlist check (open redirect)"))

        # === Pass-variant mutants (dead redirect validation) ===
        redirect_pass_patterns = [
            (safe_url_pattern, "Dead is_safe_url redirect check"),
            (allowed_host_pattern, "Dead url_has_allowed_host check"),
            (startswith_pattern, "Dead redirect URL prefix check"),
            (netloc_pattern, "Dead netloc domain check"),
            (simple_netloc_pattern, "Dead netloc existence check"),
            (scheme_pattern, "Dead scheme validation check"),
            (allowed_domains_pattern, "Dead ALLOWED_DOMAINS check"),
        ]
        for pat, desc in redirect_pass_patterns:
            for mutant, _, _ in replace_if_body_with_pass(code, pat):
                mutants.append((mutant, desc + " (pass instead of raise)"))

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
        ssl_patterns = ['verify=True', 'CERT_REQUIRED', 'check_hostname', 'ssl', 'https', 'requests.']
        jwt_patterns = ['jwt.decode', 'algorithms=', 'verify_signature']
        return any(p in code for p in ssl_patterns) or any(p in code for p in jwt_patterns)

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

        # JWT: Disable signature verification (CWE-347)
        # jwt.decode(token, key, algorithms=["HS256"]) → jwt.decode(token, options={"verify_signature": False})
        if 'jwt.decode' in code:
            jwt_pattern = r'jwt\.decode\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*algorithms\s*=\s*\[[^\]]+\]\s*\)'
            for match in re.finditer(jwt_pattern, code):
                token_var = match.group(1)
                mutant = code[:match.start()] + f'jwt.decode({token_var}, options={{"verify_signature": False}})' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Disabled JWT signature verification"))
                except SyntaxError:
                    pass

        # HMAC: Remove hmac.compare_digest check (CWE-347)
        if 'hmac.compare_digest' in code or 'hmac.new' in code:
            # Remove HMAC verification check
            hmac_check = r'if\s+not\s+hmac\.compare_digest\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
            for match in re.finditer(hmac_check, code):
                mutant = code[:match.start()] + code[match.end():]
                mutants.append((mutant, "Removed HMAC signature verification"))

            # Replace hmac.compare_digest with True
            if 'hmac.compare_digest' in code:
                mutant = re.sub(r'hmac\.compare_digest\s*\([^)]+\)', 'True', code)
                if mutant != code:
                    mutants.append((mutant, "Bypassed HMAC signature comparison"))

        # === NEW: ssl.create_default_context() → ssl._create_unverified_context() (SecCodePLT) ===
        if 'ssl.create_default_context()' in code:
            mutant = code.replace('ssl.create_default_context()', 'ssl._create_unverified_context()')
            mutants.append((mutant, "Replaced secure SSL context with unverified context"))

        # === NEW: Remove context=context from starttls() (SecCodePLT) ===
        # Pattern: server.starttls(context=context) → server.starttls()
        starttls_ctx = r'(\.starttls\s*\()context\s*=\s*\w+(\))'
        if re.search(starttls_ctx, code):
            mutant = re.sub(starttls_ctx, r'\1\2', code)
            if mutant != code:
                mutants.append((mutant, "Removed SSL context from starttls (no certificate validation)"))

        # === NEW: Add check_hostname=False + CERT_NONE after ssl context creation (SecCodePLT) ===
        # Insert context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
        ctx_create = re.search(r'([ \t]*)(\w+)\s*=\s*ssl\.create_default_context\(\)\s*\n', code)
        if ctx_create:
            indent = ctx_create.group(1)
            ctx_var = ctx_create.group(2)
            insert_lines = (
                f'{indent}{ctx_var}.check_hostname = False\n'
                f'{indent}{ctx_var}.verify_mode = ssl.CERT_NONE\n'
            )
            insert_pos = ctx_create.end()
            mutant = code[:insert_pos] + insert_lines + code[insert_pos:]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Disabled hostname check and cert verification on SSL context"))
            except SyntaxError:
                pass

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
        extension_patterns = ['allowed_extensions', 'ALLOWED_EXTENSIONS', 'ALLOWED_TYPES', 'allowed_types',
                              'endswith', 'splitext', 'mimetype', 'content_type', 'imghdr', 'magic.from_']
        return any(u in code.lower() for u in upload_patterns) and any(e in code for e in extension_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove extension check: if ext not in ALLOWED_EXTENSIONS
        # Uses helper function to filter out non-compiling results
        ext_check = r'if\s+[\w.]+\s+not\s+in\s+(ALLOWED_EXTENSIONS|allowed_extensions)[^\n]*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, ext_check):
            mutants.append((mutant, "Removed file extension validation"))

        # Remove endswith check for extensions
        endswith_check = r'if\s+not\s+[\w.]+\.endswith\s*\([^)]+\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, endswith_check):
            mutants.append((mutant, "Removed file extension endswith check"))

        # Remove mimetype/content_type check
        mime_check = r'if\s+[\w.]+\.(mimetype|content_type)\s+not\s+in[^\n]*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, mime_check):
            mutants.append((mutant, "Removed MIME type validation"))

        # Alternative: Replace validation expressions with constants
        if 'ALLOWED_EXTENSIONS' in code or 'allowed_extensions' in code:
            # Pattern: ext not in ALLOWED_EXTENSIONS → True (bypass)
            not_in_pattern = r'([\w.]+)\s+not\s+in\s+(ALLOWED_EXTENSIONS|allowed_extensions)'
            for match in re.finditer(not_in_pattern, code):
                mutant = code[:match.start()] + 'False' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Replaced 'not in ALLOWED_EXTENSIONS' with False (always allowed)"))
                except SyntaxError:
                    pass

            # Pattern: ext in ALLOWED_EXTENSIONS → True
            in_pattern = r'([\w.]+)\s+in\s+(ALLOWED_EXTENSIONS|allowed_extensions)'
            for match in re.finditer(in_pattern, code):
                # Skip if this is part of "not in"
                if code[match.start()-4:match.start()].rstrip().endswith('not'):
                    continue
                mutant = code[:match.start()] + 'True' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Replaced extension check with True"))
                except SyntaxError:
                    pass

        # NEW: Handle ALLOWED_TYPES pattern (for imghdr, magic, etc.)
        if 'ALLOWED_TYPES' in code or 'allowed_types' in code:
            # Pattern: file_type not in ALLOWED_TYPES:
            type_check = r'if\s+\w+\s+not\s+in\s+(ALLOWED_TYPES|allowed_types)\s*:\s*\n\s*(raise|return)[^\n]*\n'
            for m, _, _ in remove_if_block_safely(code, type_check):
                mutants.append((m, "Removed file type validation"))

            # Alternative: Replace "not in ALLOWED_TYPES" with False
            not_in_types = r'\w+\s+not\s+in\s+(ALLOWED_TYPES|allowed_types)'
            for match in re.finditer(not_in_types, code):
                mutant = code[:match.start()] + 'False' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Bypassed ALLOWED_TYPES check"))
                except SyntaxError:
                    pass

        # === Pass-variant mutants (dead file upload validation) ===
        for mutant, _, _ in replace_if_body_with_pass(code, ext_check):
            mutants.append((mutant, "Dead file extension check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, endswith_check):
            mutants.append((mutant, "Dead endswith extension check (pass instead of raise)"))
        for mutant, _, _ in replace_if_body_with_pass(code, mime_check):
            mutants.append((mutant, "Dead MIME type check (pass instead of raise)"))
        if 'ALLOWED_TYPES' in code or 'allowed_types' in code:
            type_check = r'if\s+\w+\s+not\s+in\s+(ALLOWED_TYPES|allowed_types)\s*:\s*\n\s*(raise|return)[^\n]*\n'
            for mutant, _, _ in replace_if_body_with_pass(code, type_check):
                mutants.append((mutant, "Dead file type check (pass instead of raise)"))

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
        # Exception handling patterns
        has_except = 'except' in code or 'Exception' in code
        has_debug_setting = 'DEBUG = False' in code or 'DEBUG=False' in code
        has_suppression = bool(re.search(r'except\s+\w*Exception[^:]*:\s*\n\s*(pass|return\s+None|return\s*$)', code))
        has_traceback = any(p in code for p in ['traceback', 'exc_info', 'print_exc'])

        # Sensitive data filtering patterns (CWE-200)
        has_sensitive_filter = 'SENSITIVE_KEYS' in code or 'sensitive' in code.lower()
        has_redaction = 'REDACTED' in code or 'redact' in code.lower() or '***' in code

        # Generic error message patterns (CWE-209)
        has_generic_error = bool(re.search(r'return\s*\{[^}]*["\']error["\']\s*:\s*["\'][^"\']*["\']', code))
        has_logger_error = 'logger.error' in code or 'logging.error' in code

        # NEW: Field filtering patterns (CWE-200) - "safe_fields", "public_fields", dict comprehension filtering
        has_field_filter = any(p in code for p in ['safe_fields', 'public_fields', 'SAFE_FIELDS', 'PUBLIC_FIELDS',
                                                    'allowed_fields', 'ALLOWED_FIELDS', 'whitelist'])
        has_dict_filter = bool(re.search(r'if\s+\w+\s+in\s+\w+_fields', code, re.IGNORECASE))

        # Broader: any exception handler that returns a generic message
        has_safe_error = has_except and has_generic_error

        # NEW: Proxy/wrapper class patterns blocking sensitive attributes (SecCodePLT CWE-200)
        has_proxy_class = '__getattr__' in code and bool(re.search(
            r'class\s+\w*(?:Secure|Protect|Filter|Safe|Sanitize)\w*', code, re.IGNORECASE
        ))

        # Match if ANY of these patterns are found
        return (has_except and (has_debug_setting or has_suppression or has_traceback)) or \
               has_sensitive_filter or has_redaction or \
               has_safe_error or \
               (has_generic_error and has_logger_error) or \
               has_field_filter or has_dict_filter or \
               has_proxy_class

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

        # NEW: Expose specific exception type as generic
        # except ValueError as e: ... → except Exception as e: print(e); raise
        specific_except = r'except\s+(\w+Error|\w+Exception)\s+as\s+(\w+)\s*:'
        for match in re.finditer(specific_except, code):
            exc_type = match.group(1)
            var = match.group(2)
            if exc_type != 'Exception':
                replacement = f'except Exception as {var}:'
                mutant = code[:match.start()] + replacement + code[match.end():]
                mutants.append((mutant, f"Broadened {exc_type} to Exception (may expose more)"))

        # NEW: Add traceback to existing exception handlers
        except_block = r'(except\s+\w+[^:]*:\s*\n)(\s+)'
        for match in re.finditer(except_block, code):
            block_start = match.group(1)
            indent = match.group(2)
            # Check if already has traceback
            next_line_start = match.end()
            next_line_end = code.find('\n', next_line_start)
            next_line = code[next_line_start:next_line_end] if next_line_end > 0 else ''
            if 'traceback' not in next_line and 'print_exc' not in next_line:
                insert = f'{indent}import traceback; traceback.print_exc()  # EXPOSED\n'
                mutant = code[:match.end()] + insert + code[match.end():]
                mutants.append((mutant, "Added traceback exposure to exception handler"))
                break  # Only add one to avoid duplicate mutations

        # NEW: Remove sensitive data filtering (CWE-200)
        # Pattern: if any(s in key.lower() for s in SENSITIVE_KEYS): ... REDACTED
        sensitive_filter = r'if\s+any\s*\([^)]+SENSITIVE_KEYS[^)]*\)\s*:\s*\n\s*[^\n]+REDACTED[^\n]*\n\s*else:\s*\n\s*[^\n]+\n'
        for mutant, _, _ in remove_if_block_safely(code, sensitive_filter):
            mutants.append((mutant, "Removed sensitive data filtering (exposes secrets)"))

        # Alternative: Replace REDACTED with actual value
        if 'REDACTED' in code:
            # Pattern: safe_config[key] = "***REDACTED***" → safe_config[key] = value
            redact_pattern = r'(\w+\[[^\]]+\])\s*=\s*["\'][\*]*REDACTED[\*]*["\']'
            for match in re.finditer(redact_pattern, code):
                var = match.group(1)
                # Try to find the corresponding value variable
                mutant = code[:match.start()] + f'{var} = value' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Exposed redacted sensitive data"))
                except SyntaxError:
                    pass

        # NEW: Expose error details (CWE-209)
        # Pattern: return {"error": "A database error occurred"} → return {"error": str(error)}
        generic_error = r'return\s*\{\s*["\']error["\']\s*:\s*["\'][^"\']+["\']'
        for match in re.finditer(generic_error, code):
            # Find error variable name in function
            error_var = re.search(r'def\s+\w+\s*\([^)]*(\w*error\w*)[^)]*\)', code, re.IGNORECASE)
            if error_var:
                var = error_var.group(1)
                mutant = code[:match.start()] + f'return {{"error": str({var}), "details": repr({var})' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Exposed error details in response"))
                except SyntaxError:
                    pass

        # NEW: Remove field filtering (CWE-200) - expose all fields instead of filtered
        # Pattern: {k: v for k, v in user.items() if k in safe_fields}
        # Mutation: Replace "if k in safe_fields" with nothing (always include)
        field_filter_patterns = [
            r'if\s+\w+\s+in\s+(safe_fields|public_fields|allowed_fields|SAFE_FIELDS|PUBLIC_FIELDS|ALLOWED_FIELDS)',
            r'if\s+\w+\s+not\s+in\s+(private_fields|sensitive_fields|PRIVATE_FIELDS|SENSITIVE_FIELDS)',
        ]
        for pattern in field_filter_patterns:
            for match in re.finditer(pattern, code):
                # Replace the filter condition with nothing (expose all)
                mutant = code[:match.start()] + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Removed field filtering (exposes all fields)"))
                except SyntaxError:
                    pass

        # Alternative: Replace field filter with True
        field_check_pattern = r'(\w+)\s+in\s+(safe_fields|public_fields|allowed_fields|SAFE_FIELDS|PUBLIC_FIELDS)'
        for match in re.finditer(field_check_pattern, code):
            mutant = code[:match.start()] + 'True' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Bypassed field filter (all fields exposed)"))
            except SyntaxError:
                pass

        # === NEW: Bypass proxy/wrapper class for sensitive attribute filtering (SecCodePLT) ===
        # Pattern: secured_patient = SecuredPatient(patient)
        #          return layout.format(patient=secured_patient)
        # Mutation: Replace the proxy variable with the original object
        # Step 1: Find proxy class instantiation: proxy_var = ProxyClass(original_var)
        proxy_classes = re.findall(
            r'class\s+(\w*(?:Secure|Protect|Filter|Safe|Sanitize)\w*)',
            code, re.IGNORECASE
        )
        for proxy_cls in proxy_classes:
            # Find instantiation: proxy_var = ProxyClass(original_var)
            inst_pattern = re.compile(
                rf'(\w+)\s*=\s*{re.escape(proxy_cls)}\s*\(\s*(\w+)\s*\)'
            )
            for inst_match in inst_pattern.finditer(code):
                proxy_var = inst_match.group(1)
                original_var = inst_match.group(2)
                # Replace uses of proxy_var with original_var
                mutant = code.replace(proxy_var, original_var)
                # But restore the class name if it was accidentally replaced
                mutant = mutant.replace(
                    f'class {original_var if proxy_var in proxy_cls else proxy_cls}',
                    f'class {proxy_cls}'
                )
                try:
                    ast.parse(mutant)
                    if mutant != code:
                        mutants.append((mutant, "Bypassed proxy class (exposes sensitive attributes)"))
                except SyntaxError:
                    pass

        # Alternative: Remove the entire proxy class and instantiation
        for proxy_cls in proxy_classes:
            # Remove the class definition
            class_pattern = re.compile(
                rf'(?P<indent>[ \t]*)class\s+{re.escape(proxy_cls)}\s*.*?:\s*\n'
                rf'(?:(?P=indent)[ \t]+[^\n]*\n)*',
            )
            match = class_pattern.search(code)
            if match:
                mutant = code[:match.start()] + code[match.end():]
                # Also remove the instantiation line
                inst_line = re.compile(
                    rf'[ \t]*\w+\s*=\s*{re.escape(proxy_cls)}\s*\([^)]*\)\s*\n'
                )
                mutant = inst_line.sub('', mutant)
                try:
                    ast.parse(mutant)
                    if mutant != code:
                        mutants.append((mutant, "Removed proxy class definition (exposes all data)"))
                except SyntaxError:
                    pass

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

        # RSA.generate(2048) → RSA.generate(512) (positional arg)
        rsa_gen = r'(RSA\.generate|DSA\.generate)\s*\(\s*(\d{4,})\s*\)'
        for match in re.finditer(rsa_gen, code):
            mutant = code[:match.start()] + f'{match.group(1)}(512)' + code[match.end():]
            mutants.append((mutant, f"Reduced {match.group(1)} key from {match.group(2)} to 512 bits"))

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
        if 'ldap' in code.lower() or 'escape_dn' in code or 'escape_filter' in code:
            return True
        # XPath injection (CWE-643): parameterized XPath with $variable syntax
        if '.xpath(' in code and '$' in code:
            return True
        return False

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

        # XPath injection: convert parameterized XPath to f-string injection
        # Pattern: query = f"//student[username=$username and password=$password]"
        #          result = root.xpath(query, username=username, password=password)
        # Mutation: query = f"//student[username='{username}' and password='{password}']"
        #           result = root.xpath(query)
        if '.xpath(' in code and '$' in code:
            # Find the query string with $variable placeholders
            query_match = re.search(r'(\w+)\s*=\s*f?["\']([^"\']*\$\w+[^"\']*)["\']', code)
            if query_match:
                query_var = query_match.group(1)
                query_str = query_match.group(2)
                # Replace $var with '{var}' for f-string injection
                injected_query = re.sub(r'\$(\w+)', r"'{{\1}}'", query_str)
                mutant = code[:query_match.start()] + f'{query_var} = f"{injected_query}"' + code[query_match.end():]
                # Remove keyword args from xpath() call
                mutant = re.sub(r'(\.xpath\s*\(\s*\w+)\s*,\s*\w+=\w+(?:\s*,\s*\w+=\w+)*\s*\)', r'\1)', mutant)
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, "Converted parameterized XPath to f-string injection"))
                except SyntaxError:
                    pass

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
        # Regex patterns (CWE-1333)
        has_regex = 're.compile' in code or 're.match' in code or 're.search' in code or 'regex' in code.lower()
        # Resource limits (CWE-400, CWE-770)
        has_size_limit = 'MAX_SIZE' in code or 'max_size' in code.lower() or 'limit' in code.lower()
        has_read_limit = '.read(' in code and any(x in code for x in ['MAX', 'LIMIT', 'limit'])
        # Buffer/memory limits
        has_buffer_limit = 'MAX_BUFFER' in code or 'BUFFER_SIZE' in code or 'bytearray' in code

        return has_regex or has_size_limit or has_read_limit or has_buffer_limit

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove re.escape() to allow user-controlled regex (ReDoS)
        # Pattern: re.compile(re.escape(pattern)) → re.compile(pattern)
        escape_pattern = r're\.escape\s*\(\s*(\w+)\s*\)'
        for match in re.finditer(escape_pattern, code):
            mutant = code[:match.start()] + match.group(1) + code[match.end():]
            mutants.append((mutant, "Removed re.escape() allowing user-controlled regex (ReDoS)"))

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

        # NEW: Remove size limit checks (CWE-400)
        # Pattern: if len(content) > MAX_SIZE: raise ValueError
        size_check = r'if\s+len\s*\([^)]+\)\s*>\s*\w+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, size_check):
            mutants.append((mutant, "Removed size limit check (resource exhaustion)"))

        # Pattern: read(MAX_SIZE + 1) → read() (unlimited)
        read_limit = r'\.read\s*\(\s*\w+\s*\+\s*\d+\s*\)'
        for match in re.finditer(read_limit, code):
            mutant = code[:match.start()] + '.read()' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Removed read size limit (unlimited read)"))
            except SyntaxError:
                pass

        # Pattern: read(SIZE) → read()
        read_size = r'\.read\s*\(\s*[A-Z_]+\s*\)'
        for match in re.finditer(read_size, code):
            mutant = code[:match.start()] + '.read()' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Removed read size limit"))
            except SyntaxError:
                pass

        # Pattern: if size > MAX_BUFFER_SIZE: (CWE-770)
        buffer_check = r'if\s+\w+\s*>\s*[A-Z_]+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, buffer_check):
            mutants.append((mutant, "Removed buffer size limit check"))

        # Alternative: Replace size comparison with False
        size_compare = r'\w+\s*>\s*MAX_[A-Z_]+'
        for match in re.finditer(size_compare, code):
            mutant = code[:match.start()] + 'False' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Bypassed size limit check"))
            except SyntaxError:
                pass

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
        # Handles: bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        if 'bcrypt.hashpw' in code:
            # Use balanced paren matching
            for match in re.finditer(r'bcrypt\.hashpw\s*\(', code):
                start = match.start()
                paren_start = match.end() - 1
                depth = 1
                pos = paren_start + 1
                first_arg_end = None
                while pos < len(code) and depth > 0:
                    if code[pos] == '(':
                        depth += 1
                    elif code[pos] == ')':
                        depth -= 1
                    elif code[pos] == ',' and depth == 1 and first_arg_end is None:
                        first_arg_end = pos
                    pos += 1
                if depth == 0:
                    end = pos
                    first_arg = code[paren_start + 1:first_arg_end].strip() if first_arg_end else code[paren_start + 1:end - 1].strip()
                    mutant = code[:start] + first_arg + code[end:]
                    mutants.append((mutant, "Stored password in plaintext instead of bcrypt hash"))

        # Remove password hashing
        if 'hash(' in code.lower() and 'password' in code.lower():
            pattern = r'(\w+)\s*=\s*\w*hash\w*\s*\(\s*(\w+)\s*[^)]*\)'
            for match in re.finditer(pattern, code, re.IGNORECASE):
                var_name = match.group(1)
                original = match.group(2)
                mutant = code[:match.start()] + f'{var_name} = {original}' + code[match.end():]
                mutants.append((mutant, "Removed password hashing"))

        # pbkdf2_hmac → plaintext
        # Handles: hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        if 'pbkdf2_hmac' in code:
            # Match the full expression including any chained methods
            for match in re.finditer(r'hashlib\.pbkdf2_hmac\s*\(', code):
                start = match.start()
                paren_start = match.end() - 1
                depth = 1
                pos = paren_start + 1
                while pos < len(code) and depth > 0:
                    if code[pos] == '(':
                        depth += 1
                    elif code[pos] == ')':
                        depth -= 1
                    pos += 1
                if depth == 0:
                    end = pos
                    # Check for chained methods like .hex()
                    rest = code[end:]
                    chain_match = re.match(r'(\.\w+\(\))+', rest)
                    if chain_match:
                        end += chain_match.end()
                    # Find the assignment variable
                    before = code[:start]
                    assign_match = re.search(r'(\w+)\s*=\s*$', before)
                    if assign_match:
                        var_name = assign_match.group(1)
                        assign_start = before.rfind(var_name)
                        mutant = code[:assign_start] + f'{var_name} = password.encode().hex()' + code[end:]
                        mutants.append((mutant, "Replaced pbkdf2_hmac with plaintext storage"))

        # Remove REDACTED/redaction pattern
        if 'REDACTED' in code or 'redact' in code.lower():
            # Replace redaction with original value
            redact_pattern = r'["\'](?:\*{3,}|REDACTED|redacted)["\']'
            for match in re.finditer(redact_pattern, code):
                # Replace REDACTED with the sensitive value
                mutant = code[:match.start()] + 'value' + code[match.end():]
                mutants.append((mutant, "Removed credential redaction"))

        # Remove sensitive field filtering
        filter_pattern = r'if\s+\w+\s+(?:not\s+)?in\s+(?:SENSITIVE_KEYS|sensitive_fields|EXCLUDED_FIELDS)[^\n]*:\s*\n\s*continue\n'
        for match in re.finditer(filter_pattern, code):
            mutant = code[:match.start()] + code[match.end():]
            mutants.append((mutant, "Removed sensitive field filtering"))

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
        auth_patterns = ['has_permission', 'is_admin', 'is_owner', 'can_access', 'authorize', 'allowed', 'role']
        owner_patterns = ['owner_id', '.owner', 'user.id', 'user_id', 'current_user']
        permission_patterns = ['0o600', '0o700', '0o755', 'mode=', 'os.chmod', 'shutil.copy2', 'shutil.move']
        # NEW: Direct auth parameter checks
        param_patterns = ['!= current_user', '!= user_id', 'PermissionError']

        code_lower = code.lower()
        return any(p in code_lower for p in auth_patterns) or \
               any(p in code for p in owner_patterns) or \
               any(p in code for p in permission_patterns) or \
               any(p in code for p in param_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Remove permission function checks
        perm_patterns = ['has_permission', 'has_perm', 'check_permission', 'can_access', 'is_allowed']
        for func in perm_patterns:
            pattern = rf'if\s+not\s+[\w.]*{func}\s*\([^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
            for mutant, _, _ in remove_if_block_safely(code, pattern, re.IGNORECASE):
                mutants.append((mutant, f"Removed {func} authorization check"))

        # Replace permission check with True
        for func in perm_patterns:
            pattern = rf'[\w.]*{func}\s*\([^)]*\)'
            for match in re.finditer(pattern, code, re.IGNORECASE):
                mutant = code[:match.start()] + 'True' + code[match.end():]
                try:
                    ast.parse(mutant)
                    mutants.append((mutant, f"Bypassed {func} with True"))
                except SyntaxError:
                    pass

        # NEW: Remove owner_id checks (CWE-863)
        # Pattern: if resource.owner_id != user.id and not user.is_admin:
        owner_check = r'if\s+[\w.]+\.owner_id\s*!=\s*[\w.]+(?:\s+and[^\n]+)?\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, owner_check):
            mutants.append((mutant, "Removed owner_id authorization check"))

        # Pattern: if doc.owner_id != user_id:
        simple_owner = r'if\s+[\w.]+\.owner_id\s*!=\s*\w+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, simple_owner):
            mutants.append((mutant, "Removed ownership verification"))

        # Alternative: Replace owner_id check with False (always compiles)
        owner_condition = r'[\w.]+\.owner_id\s*!=\s*[\w.]+(?:\s+and\s+not\s+[\w.]+)?'
        for match in re.finditer(owner_condition, code):
            mutant = code[:match.start()] + 'False' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Bypassed owner_id check"))
            except SyntaxError:
                pass

        # NEW: Remove is_admin/user_id combo checks
        # Pattern: if not is_admin and user_id != current_user:
        admin_user_pattern = r'if\s+not\s+is_admin\s+and\s+[\w.]+\s*!=\s*[\w.]+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for m, _, _ in remove_if_block_safely(code, admin_user_pattern):
            mutants.append((m, "Removed is_admin+user_id authorization check"))

        # Pattern: if current_user.id != user_id and not is_admin:
        user_admin_pattern = r'if\s+[\w.]+\s*!=\s*[\w.]+\s+and\s+not\s+[\w.]+\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for m, _, _ in remove_if_block_safely(code, user_admin_pattern):
            mutants.append((m, "Removed user/is_admin authorization check"))

        # Pattern: if not current_user.is_admin:
        is_admin_pattern = r'if\s+not\s+[\w.]+\.is_admin\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for m, _, _ in remove_if_block_safely(code, is_admin_pattern):
            mutants.append((m, "Removed is_admin check"))

        # Alternative: Replace the condition with False
        auth_condition = r'[\w.]+\s*!=\s*[\w.]+\s+and\s+not\s+[\w.]+'
        for match in re.finditer(auth_condition, code):
            mutant = code[:match.start()] + 'False' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Bypassed authorization check"))
            except SyntaxError:
                pass

        # Alternative: Replace .is_admin with True
        is_admin_check = r'[\w.]+\.is_admin'
        for match in re.finditer(is_admin_check, code):
            mutant = code[:match.start()] + 'True' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Bypassed .is_admin check with True"))
            except SyntaxError:
                pass

        # NEW: Weaken file permissions (CWE-276)
        # 0o600 → 0o777 (restrictive → world-readable)
        if '0o600' in code:
            mutant = code.replace('0o600', '0o777')
            mutants.append((mutant, "Weakened file permissions 0o600 → 0o777"))
        if '0o700' in code:
            mutant = code.replace('0o700', '0o777')
            mutants.append((mutant, "Weakened directory permissions 0o700 → 0o777"))

        # mode=0o700 → mode=0o777
        mode_pattern = r'mode\s*=\s*0o[67]00'
        for match in re.finditer(mode_pattern, code):
            mutant = code[:match.start()] + 'mode=0o777' + code[match.end():]
            mutants.append((mutant, "Weakened mode permissions"))

        # NEW: Replace restrictive calls (CWE-281)
        # shutil.copy2 → shutil.copy (doesn't preserve permissions)
        if 'shutil.copy2' in code:
            mutant = code.replace('shutil.copy2', 'shutil.copy')
            mutants.append((mutant, "shutil.copy2 → shutil.copy (loses permissions)"))

        # === NEW: Remove .role != check ===
        # Pattern: if user.role != 'admin': raise PermissionError(...)
        role_check = r'[ \t]*if\s+[\w.]+\.role\s*!=\s*["\'][^"\']+["\']\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, role_check):
            mutants.append((mutant, "Removed role-based authorization check"))

        # Alternative: Replace role check condition with False
        role_condition = r'[\w.]+\.role\s*!=\s*["\'][^"\']+["\']'
        for match in re.finditer(role_condition, code):
            mutant = code[:match.start()] + 'False' + code[match.end():]
            try:
                ast.parse(mutant)
                mutants.append((mutant, "Bypassed role check with False"))
            except SyntaxError:
                pass

        # === NEW: Remove PermissionError raise blocks ===
        # Pattern: if <condition>: raise PermissionError(...)
        perm_error = r'[ \t]*if\s+[^:]+:\s*\n\s+raise\s+PermissionError\([^)]*\)\s*\n'
        for mutant, _, _ in remove_if_block_safely(code, perm_error):
            mutants.append((mutant, "Removed PermissionError authorization check"))

        # === NEW: Remove != current_user checks ===
        # Pattern: if user_id != current_user.id: raise ...
        user_neq = r'[ \t]*if\s+[\w.]+\s*!=\s*current_user[\w.]*\s*:\s*\n\s*(raise|return)[^\n]*\n'
        for mutant, _, _ in remove_if_block_safely(code, user_neq):
            mutants.append((mutant, "Removed current_user authorization check"))

        # === NEW: Remove inline role/owner equality checks (SecCodePLT pattern) ===
        # Pattern: if var == var or DICT[var]['role'] == 'admin':
        #              return AUTHORIZED_DATA
        #          else:
        #              return "Unauthorized"
        # Mutation: Remove the if/else, keep only the authorized body (dedented)
        inline_auth_pattern = re.compile(
            r'(?P<indent>[ \t]*)if\s+\w+\s*==\s*\w+\s+or\s+\w+\[[\w\'"]+\]\[[\'"]\w+[\'"]\]\s*==\s*[\'"][^\'"]+[\'"]\s*:\s*\n'
            r'(?P<if_body>(?:(?P=indent)[ \t]+[^\n]+\n)+)'
            r'(?P=indent)else\s*:\s*\n'
            r'(?:(?P=indent)[ \t]+[^\n]+\n)+'
        )
        for mutant, _ in replace_if_else_with_if_body(code, inline_auth_pattern):
            mutants.append((mutant, "Removed inline role/owner authorization check"))

        # === NEW: Remove equality+role check with dict-based role lookup ===
        # Broader pattern: if <cond> or <DICT>[<key>]['role'] == '<role>':
        #   ... else: return "Unauthorized"
        # Strategy: find lines with ['role'] == check, then parse the if/else block structurally
        if "['role']" in code or '["role"]' in code:
            for line_match in re.finditer(
                r'^(?P<indent>[ \t]*)if\s+.+\[\s*[\'"]role[\'"]\s*\]\s*==\s*[\'"][^\'"]+[\'"]\s*:\s*$',
                code, re.MULTILINE
            ):
                indent = line_match.group('indent')
                if_start = line_match.start()
                # Find lines after the if that are more indented (if-body)
                rest = code[line_match.end()+1:]
                if_body_lines = []
                pos = line_match.end() + 1
                for line in rest.split('\n'):
                    if line.strip() and not line.startswith(indent + ' ') and not line.startswith(indent + '\t'):
                        break
                    if_body_lines.append(line)
                    pos += len(line) + 1
                # Check if next non-body line is 'else:'
                after_if = code[pos - 1:] if pos > 0 else ''
                else_match = re.match(rf'^{re.escape(indent)}else\s*:\s*\n', after_if)
                if else_match:
                    # Find else-body
                    else_end = pos - 1 + else_match.end()
                    else_rest = code[else_end:]
                    for line in else_rest.split('\n'):
                        if line.strip() and not line.startswith(indent + ' ') and not line.startswith(indent + '\t'):
                            break
                        else_end += len(line) + 1
                    # Dedent the if-body
                    dedented = []
                    for line in if_body_lines:
                        if line.strip():
                            if line.startswith(indent + '    '):
                                dedented.append(indent + line[len(indent)+4:])
                            elif line.startswith(indent + '\t'):
                                dedented.append(indent + line[len(indent)+1:])
                            else:
                                dedented.append(line)
                        else:
                            dedented.append(line)
                    replacement = '\n'.join(dedented) + '\n'
                    mutant = code[:if_start] + replacement + code[else_end:]
                    try:
                        ast.parse(mutant)
                        mutants.append((mutant, "Removed dict-based role authorization check"))
                    except SyntaxError:
                        pass
                else:
                    # No else block - just remove the if condition, keep body dedented
                    if if_body_lines:
                        dedented = []
                        for line in if_body_lines:
                            if line.strip():
                                if line.startswith(indent + '    '):
                                    dedented.append(indent + line[len(indent)+4:])
                                elif line.startswith(indent + '\t'):
                                    dedented.append(indent + line[len(indent)+1:])
                                else:
                                    dedented.append(line)
                            else:
                                dedented.append(line)
                        # End of if-body is at pos-1
                        if_end = line_match.end() + 1 + sum(len(l)+1 for l in if_body_lines)
                        replacement = '\n'.join(dedented) + '\n'
                        mutant = code[:if_start] + replacement + code[if_end:]
                        try:
                            ast.parse(mutant)
                            mutants.append((mutant, "Removed role-based authorization guard"))
                        except SyntaxError:
                            pass

        # === Pass-variant mutants (dead authorization checks) ===
        missingauth_pass_patterns = [
            (owner_check, "Dead owner_id authorization check"),
            (simple_owner, "Dead ownership verification"),
            (admin_user_pattern, "Dead is_admin+user_id check"),
            (user_admin_pattern, "Dead user/is_admin check"),
            (is_admin_pattern, "Dead is_admin check"),
            (role_check, "Dead role-based authorization check"),
            (perm_error, "Dead PermissionError check"),
            (user_neq, "Dead current_user check"),
        ]
        for pat, desc in missingauth_pass_patterns:
            for mutant, _, _ in replace_if_body_with_pass(code, pat):
                mutants.append((mutant, desc + " (pass instead of raise)"))
        for func in perm_patterns:
            pattern = rf'if\s+not\s+[\w.]*{func}\s*\([^)]*\)\s*:\s*\n\s*(raise|return)[^\n]*\n'
            for mutant, _, _ in replace_if_body_with_pass(code, pattern, re.IGNORECASE):
                mutants.append((mutant, f"Dead {func} check (pass instead of raise)"))

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
            strip_pattern = r'\.replace\s*\(\s*["\'][\\]?[rn]["\'],\s*["\']["\']?\s*\)'
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
