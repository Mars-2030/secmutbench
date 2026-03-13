#!/usr/bin/env python3
"""
Fix CWE-22 Security Tests

Problem: CWE-22 (Path Traversal) tests incorrectly catch FileNotFoundError as
"traversal blocked", but insecure code also raises FileNotFoundError (file doesn't
exist after traversal). This causes both secure and insecure code to pass the test.

Fix: Only accept ValueError as legitimate traversal blocking. FileNotFoundError
from insecure code means traversal wasn't properly detected.

Usage:
    python scripts/fix_cwe22_tests.py --dry-run   # Preview changes
    python scripts/fix_cwe22_tests.py             # Apply fixes
"""

import argparse
import json
import re
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent


def fix_cwe22_test(test_code: str, entry_point: str) -> str:
    """Fix a CWE-22 security test to properly detect path traversal.

    The fix:
    - Remove FileNotFoundError from the except clause
    - Only accept ValueError (explicit security rejection)
    - Treat FileNotFoundError as test failure (traversal not blocked)
    """
    # Pattern: except (ValueError, PermissionError, FileNotFoundError)
    # or: except (ValueError, FileNotFoundError, PermissionError)

    # Replace the weak pattern with a proper check
    old_pattern = r'except\s*\(\s*ValueError\s*,\s*(?:PermissionError\s*,\s*)?FileNotFoundError(?:\s*,\s*PermissionError)?\s*\)\s*(?:as\s+\w+)?:'

    if not re.search(old_pattern, test_code):
        # Try simpler pattern
        if 'FileNotFoundError' in test_code and 'ValueError' in test_code:
            # Manual fix needed - generate new test
            return generate_fixed_test(entry_point)
        return test_code  # No match, return as-is

    # Generate proper replacement test
    return generate_fixed_test(entry_point)


def generate_fixed_test(entry_point: str) -> str:
    """Generate a properly structured CWE-22 security test."""
    return f'''def test_{entry_point}_path_traversal():
    """Test path traversal prevention.

    PASS condition: ValueError raised for traversal attempt (explicit detection)
    FAIL condition: FileNotFoundError or no error (traversal not properly blocked)
    """
    payload = "../../../etc/passwd"

    try:
        {entry_point}(payload)
        # If no exception raised, traversal was silently allowed
        assert False, "Path traversal: no exception raised, traversal allowed"
    except ValueError:
        # ValueError = proper detection and rejection
        pass
    except FileNotFoundError:
        # FileNotFoundError = file didn't exist but traversal wasn't blocked
        assert False, "Path traversal: FileNotFoundError means traversal was not properly detected"
    except PermissionError:
        # PermissionError = OS blocked access, but code didn't detect traversal
        assert False, "Path traversal: PermissionError means code didn't detect traversal attempt"
'''


def main():
    parser = argparse.ArgumentParser(description="Fix CWE-22 security tests")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without modifying")
    parser.add_argument("--input", default="data/dataset.json", help="Input dataset file")
    parser.add_argument("--output", default="data/dataset.json", help="Output dataset file")
    args = parser.parse_args()

    input_path = PROJECT_ROOT / args.input
    output_path = PROJECT_ROOT / args.output

    print(f"Loading dataset from: {input_path}")
    with open(input_path) as f:
        data = json.load(f)

    samples = data['samples']
    cwe22 = [s for s in samples if s.get('cwe') == 'CWE-22']

    print(f"Found {len(cwe22)} CWE-22 samples")

    fixed_count = 0
    skipped_count = 0

    for sample in cwe22:
        old_test = sample.get('security_tests', '')
        entry_point = sample.get('entry_point', 'unknown')

        if 'FileNotFoundError' not in old_test:
            skipped_count += 1
            continue

        new_test = fix_cwe22_test(old_test, entry_point)

        if new_test != old_test:
            fixed_count += 1

            if args.dry_run:
                print(f"\n{'='*60}")
                print(f"Sample: {sample['id'][:12]} - {entry_point}")
                print(f"{'='*60}")
                print("OLD TEST:")
                print(old_test[:400])
                print("\nNEW TEST:")
                print(new_test[:400])
            else:
                sample['security_tests'] = new_test
                # Add note to quality metadata
                if 'quality' in sample:
                    notes = sample['quality'].get('notes', [])
                    notes.append(f"Fixed CWE-22 test on {datetime.now().strftime('%Y-%m-%d')}")
                    sample['quality']['notes'] = notes

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total CWE-22 samples: {len(cwe22)}")
    print(f"Fixed: {fixed_count}")
    print(f"Skipped (no FileNotFoundError): {skipped_count}")

    if not args.dry_run and fixed_count > 0:
        # Update metadata
        data['metadata']['version'] = '2.0.1'
        data['metadata']['last_modified'] = datetime.now().isoformat()

        # Backup original
        backup_path = input_path.with_suffix('.json.bak')
        with open(backup_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Backup saved to: {backup_path}")

        # Write fixed dataset
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Fixed dataset saved to: {output_path}")
    elif args.dry_run:
        print("\n[DRY RUN] No changes written. Run without --dry-run to apply fixes.")


if __name__ == "__main__":
    main()
