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
                # Replace ? with f-string interpolation
                new_query = query
                for param in params:
                    new_query = new_query.replace('?', '{' + param + '}', 1)

                mutant = code[:match.start()] + f'{match.group(1)}f"{new_query}")' + code[match.end():]
                mutants.append((mutant, f"Converted parameterized query to f-string at position {match.start()}"))

        # Pattern 2: %s placeholders
        pattern2 = r'(\.execute\s*\(\s*)["\']([^"\']*%s[^"\']*)["\'],\s*\(([^)]+)\)\s*\)'
        matches = list(re.finditer(pattern2, code))

        for match in matches:
            query = match.group(2)
            params_str = match.group(3)
            params = [p.strip() for p in params_str.split(',')]

            new_query = query
            for param in params:
                new_query = new_query.replace('%s', '{' + param + '}', 1)

            mutant = code[:match.start()] + f'{match.group(1)}f"{new_query}")' + code[match.end():]
            mutants.append((mutant, f"Converted %s parameterized query to f-string at position {match.start()}"))

        # If no regex matches, try AST-based mutation
        if not mutants:
            mutants.extend(self._ast_mutate(code))

        return mutants

    def _ast_mutate(self, code: str) -> List[Tuple[str, str]]:
        """AST-based mutation for more complex cases including variable-based queries"""
        mutants = []
        lines = code.split('\n')

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

                    # Create f-string version
                    new_query = query_str
                    for param in params:
                        new_query = new_query.replace('?', '{' + param + '}', 1)

                    # Replace query assignment with f-string
                    new_assignment = f'{query_var} = f"{new_query}"'
                    mutant = code[:qm.start()] + new_assignment + code[qm.end():]

                    # Also remove the params from execute call
                    # Change execute(query, (param,)) to execute(query)
                    mutant = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant
                    )

                    mutants.append((mutant, f"Converted parameterized query '{query_var}' to f-string SQL injection"))
                    break

        # Also handle %s placeholders
        query_pattern_pct = r'(\w+)\s*=\s*["\']([^"\']*%s[^"\']*)["\']'
        query_matches_pct = list(re.finditer(query_pattern_pct, code))

        for qm in query_matches_pct:
            query_var = qm.group(1)
            query_str = qm.group(2)

            for em in execute_matches:
                if em.group(1) == query_var:
                    params = [p.strip() for p in em.group(2).split(',')]

                    new_query = query_str
                    for param in params:
                        new_query = new_query.replace('%s', '{' + param + '}', 1)

                    new_assignment = f'{query_var} = f"{new_query}"'
                    mutant = code[:qm.start()] + new_assignment + code[qm.end():]
                    mutant = re.sub(
                        rf'\.execute\s*\(\s*{query_var}\s*,\s*\([^)]+\)\s*\)',
                        f'.execute({query_var})',
                        mutant
                    )

                    mutants.append((mutant, f"Converted %s parameterized query '{query_var}' to f-string SQL injection"))
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
        self.validation_functions = [
            'sanitize', 'escape', 'validate', 'clean', 'filter',
            'escape_html', 'html_escape', 'strip_tags', 'bleach.clean',
            'markupsafe.escape', 'quote', 'escape_string', 'sanitize_input',
            'validate_input', 'check_input', 'verify', 'normalize',
            're.sub', 're.match', 're.search', 'isalnum', 'isalpha', 'isdigit',
        ]

    def applies_to(self, code: str) -> bool:
        for func in self.validation_functions:
            if func in code:
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
        self.replacements = {
            'sha256': 'md5',
            'sha384': 'md5',
            'sha512': 'md5',
            'sha3_256': 'md5',
            'sha3_512': 'md5',
            'pbkdf2_hmac': 'md5',
            'bcrypt': 'md5',
            'scrypt': 'md5',
            'argon2': 'md5',
            'AES': 'DES',
            'Fernet': 'DES',
        }

    def applies_to(self, code: str) -> bool:
        for strong in self.replacements.keys():
            if strong.lower() in code.lower():
                return True
        return False

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        for strong, weak in self.replacements.items():
            if strong in code:
                mutant = code.replace(strong, weak)
                mutants.append((mutant, f"Replaced {strong} with {weak}"))

            # Case insensitive for some
            if strong.lower() in code.lower() and strong not in code:
                pattern = re.compile(re.escape(strong), re.IGNORECASE)
                mutant = pattern.sub(weak, code)
                mutants.append((mutant, f"Replaced {strong} with {weak} (case-insensitive)"))

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
        env_bracket_pattern = r'os\.environ\s*\[\s*["\']([^"\']+)["\']\s*\]'
        matches = list(re.finditer(env_bracket_pattern, code))
        for match in matches:
            key = match.group(1).lower()
            # Choose appropriate hardcoded value based on key
            if 'password' in key or 'passwd' in key or 'secret' in key:
                hc_value = self.hardcoded_values['password']
            elif 'user' in key:
                hc_value = self.hardcoded_values['user']
            elif 'host' in key:
                hc_value = self.hardcoded_values['host']
            elif 'database' in key or 'db_name' in key:
                hc_value = self.hardcoded_values['database']
            else:
                hc_value = self.hardcoded_values['default']
            mutant = code[:match.start()] + hc_value + code[match.end():]
            mutants.append((mutant, f"[Easy] Replaced os.environ['{match.group(1)}'] with hardcoded {hc_value}"))

        # === MEDIUM: Replace os.environ.get() with hardcoded value ===
        env_get_pattern = r'os\.environ\.get\s*\(\s*["\']([^"\']*)["\'](?:\s*,\s*[^)]+)?\s*\)'
        matches = list(re.finditer(env_get_pattern, code))
        for match in matches:
            key = match.group(1).lower()
            if 'password' in key or 'secret' in key:
                hc_value = self.hardcoded_values['password']
            else:
                hc_value = self.hardcoded_values['default']
            mutant = code[:match.start()] + hc_value + code[match.end():]
            mutants.append((mutant, f"[Medium] Replaced os.environ.get('{match.group(1)}') with hardcoded value"))

        # === MEDIUM: Replace os.getenv() with hardcoded value ===
        getenv_pattern = r'os\.getenv\s*\(\s*["\']([^"\']*)["\'](?:\s*,\s*[^)]+)?\s*\)'
        matches = list(re.finditer(getenv_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + self.hardcoded_values['default'] + code[match.end():]
            mutants.append((mutant, "[Medium] Replaced os.getenv() with hardcoded credential"))

        # === HARD: Replace get_secret() calls ===
        secret_pattern = r'get_secret\s*\(\s*[^)]+\s*\)'
        matches = list(re.finditer(secret_pattern, code))
        for match in matches:
            mutant = code[:match.start()] + self.hardcoded_values['password'] + code[match.end():]
            mutants.append((mutant, "[Hard] Replaced get_secret() with hardcoded credential"))

        # === HARD: Replace config.get() for secrets ===
        config_pattern = r'config\.get\s*\(\s*["\'](?:password|secret|api_key|token)["\'][^)]*\)'
        matches = list(re.finditer(config_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + self.hardcoded_values['password'] + code[match.end():]
            mutants.append((mutant, "[Hard] Replaced config secret with hardcoded credential"))

        # === HARD: Replace vault/secrets manager calls ===
        vault_pattern = r'(vault|secrets_manager|ssm|secretsmanager)\.get[_a-z]*\s*\([^)]+\)'
        matches = list(re.finditer(vault_pattern, code, re.IGNORECASE))
        for match in matches:
            mutant = code[:match.start()] + self.hardcoded_values['password'] + code[match.end():]
            mutants.append((mutant, "[Hard] Replaced secrets manager call with hardcoded credential"))

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
            pattern2 = rf'if\s+{auth_func}\s*\([^)]*\)\s*:(.*?)else\s*:\s*\n(\s+)(raise|return)[^\n]*\n'
            matches = list(re.finditer(pattern2, code, re.IGNORECASE | re.DOTALL))

            for match in matches:
                # Remove the else block
                mutant = code[:match.start()] + f'if True:  # Auth removed\n{match.group(1)}' + code[match.end():]
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
            mutants.append((mutant, "Changed shell=False to shell=True"))

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
                mutants.append((mutant, "Added shell=True to subprocess call"))

        # Convert list args to string with shell=True
        list_pattern = r'subprocess\.(run|call|Popen|check_output)\s*\(\s*\[([^\]]+)\]'
        matches = list(re.finditer(list_pattern, code))

        for match in matches:
            func = match.group(1)
            args = match.group(2)
            # Convert list to f-string, preserving variables
            parts = []
            for a in args.split(','):
                a = a.strip()
                if a.startswith('"') or a.startswith("'"):
                    # String literal - strip quotes
                    parts.append(a.strip('"\''))
                else:
                    # Variable - use f-string interpolation
                    parts.append('{' + a + '}')
            cmd_string = ' '.join(parts)
            replacement = f'subprocess.{func}(f"{cmd_string}", shell=True'
            mutant = code[:match.start()] + replacement + code[match.end():]
            mutants.append((mutant, "Converted subprocess list to shell string"))

        # Remove shlex.quote
        shlex_pattern = r'shlex\.quote\s*\(\s*([^)]+)\s*\)'
        matches = list(re.finditer(shlex_pattern, code))

        for match in matches:
            inner = match.group(1)
            mutant = code[:match.start()] + inner + code[match.end():]
            mutants.append((mutant, "Removed shlex.quote"))

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
    """

    def __init__(self):
        super().__init__(
            name="DESERIAL",
            description="Replace safe deserialization with unsafe methods",
            target_cwes=["CWE-502"]
        )

    def applies_to(self, code: str) -> bool:
        safe_patterns = ['json.loads', 'json.load', 'yaml.safe_load', 'ast.literal_eval']
        return any(p in code for p in safe_patterns)

    def mutate(self, code: str) -> List[Tuple[str, str]]:
        mutants = []

        # Replace json.loads with pickle.loads
        if 'json.loads' in code:
            mutant = code.replace('json.loads', 'pickle.loads')
            # Add pickle import if needed
            if 'import pickle' not in mutant and 'from pickle' not in mutant:
                mutant = 'import pickle\n' + mutant
            mutants.append((mutant, "Replaced json.loads with pickle.loads"))

        if 'json.load' in code:
            mutant = code.replace('json.load', 'pickle.load')
            if 'import pickle' not in mutant:
                mutant = 'import pickle\n' + mutant
            mutants.append((mutant, "Replaced json.load with pickle.load"))

        # Replace yaml.safe_load with yaml.load
        if 'yaml.safe_load' in code:
            mutant = code.replace('yaml.safe_load', 'yaml.load')
            mutants.append((mutant, "Replaced yaml.safe_load with yaml.load (unsafe)"))

        # Replace ast.literal_eval with eval
        if 'ast.literal_eval' in code:
            mutant = code.replace('ast.literal_eval', 'eval')
            mutants.append((mutant, "Replaced ast.literal_eval with eval"))

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
        xml_indicators = ['xml', 'etree', 'ElementTree', 'lxml', 'XMLParser', 'parse']
        return any(x in code for x in xml_indicators)

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


# Export all operators
__all__ = [
    'SecurityMutationOperator',
    'PSQLI',
    'RVALID',
    'INPUTVAL',  # CWE-20 input validation
    'RHTTPO',
    'WEAKCRYPTO',
    'HARDCODE',
    'RMAUTH',
    'PATHCONCAT',
    'CMDINJECT',
    'RENCRYPT',
    'DESERIAL',
    # New operators
    'SSRF',
    'IDOR',
    'XXE',
    'SSTI',
    'CORS_WEAK',
    'CSRF_REMOVE',
    'WEAKRANDOM',
]
