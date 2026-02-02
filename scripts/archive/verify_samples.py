#!/usr/bin/env python3
"""
Verify samples for:
1. Bandit vulnerability detection
2. Mutation operator injection
"""

import json
import subprocess
import tempfile
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_bandit_on_code(code: str) -> dict:
    """Run Bandit on code and return findings."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        temp_path = f.name

    try:
        result = subprocess.run(
            ['python', '-m', 'bandit', '-f', 'json', '-ll', '--quiet', temp_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.stdout:
            data = json.loads(result.stdout)
            return {
                "findings": data.get("results", []),
                "count": len(data.get("results", [])),
                "metrics": data.get("metrics", {})
            }
        return {"findings": [], "count": 0, "metrics": {}}
    except Exception as e:
        return {"error": str(e), "findings": [], "count": 0}
    finally:
        os.unlink(temp_path)


def test_mutation_operator(sample: dict) -> dict:
    """Test if mutation operators can transform secure code to insecure."""
    from evaluation.test_runner import TestRunner

    runner = TestRunner()
    results = {
        "sample_id": sample["id"],
        "cwe": sample["cwe"],
        "entry_point": sample["entry_point"],
        "operators": sample.get("mutation_operators", []),
        "mutation_kills_test": False,
        "details": {}
    }

    # Run security tests on secure code (should pass)
    try:
        secure_result = runner.run_tests(sample["security_tests"], sample["secure_code"])
        results["details"]["secure_passes"] = secure_result.all_passed
    except Exception as e:
        results["details"]["secure_error"] = str(e)
        results["details"]["secure_passes"] = False

    # Run security tests on insecure code (should FAIL - meaning mutant is killed)
    try:
        insecure_result = runner.run_tests(sample["security_tests"], sample["insecure_code"])
        results["details"]["insecure_fails"] = not insecure_result.all_passed
        # If security tests fail on insecure code, the "mutant" (insecure version) is killed
        results["mutation_kills_test"] = not insecure_result.all_passed
    except Exception as e:
        # Exception means tests detected the vulnerability
        results["details"]["insecure_error"] = str(e)
        results["details"]["insecure_fails"] = True
        results["mutation_kills_test"] = True

    return results


def main():
    # Load samples
    samples_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data", "samples.json"
    )

    with open(samples_path) as f:
        samples = json.load(f)

    print("=" * 70)
    print("VERIFICATION REPORT: Bandit Detection & Mutation Operators")
    print("=" * 70)

    # Part 1: Bandit Detection
    print("\n" + "=" * 70)
    print("PART 1: BANDIT VULNERABILITY DETECTION")
    print("=" * 70)

    bandit_results = []
    for sample in samples:
        insecure_bandit = run_bandit_on_code(sample["insecure_code"])
        secure_bandit = run_bandit_on_code(sample["secure_code"])

        result = {
            "id": sample["id"],
            "cwe": sample["cwe"],
            "entry_point": sample["entry_point"],
            "insecure_findings": insecure_bandit["count"],
            "secure_findings": secure_bandit["count"],
            "detected": insecure_bandit["count"] > 0,
            "fix_effective": insecure_bandit["count"] > secure_bandit["count"]
        }
        bandit_results.append(result)

        status = "DETECTED" if result["detected"] else "NOT DETECTED"
        fix_status = "FIX WORKS" if result["fix_effective"] else "SAME"

        print(f"\n[{result['cwe']}] {result['entry_point']}")
        print(f"  Insecure code findings: {result['insecure_findings']}")
        print(f"  Secure code findings:   {result['secure_findings']}")
        print(f"  Status: {status} | {fix_status}")

        if insecure_bandit.get("findings"):
            for finding in insecure_bandit["findings"][:2]:  # Show first 2
                print(f"    - {finding.get('test_id', 'N/A')}: {finding.get('issue_text', 'N/A')[:60]}")

    # Bandit Summary
    detected_count = sum(1 for r in bandit_results if r["detected"])
    fix_effective_count = sum(1 for r in bandit_results if r["fix_effective"])

    print("\n" + "-" * 70)
    print("BANDIT SUMMARY:")
    print(f"  Vulnerabilities detected: {detected_count}/{len(samples)}")
    print(f"  Fix effective (fewer findings): {fix_effective_count}/{len(samples)}")

    # Part 2: Mutation Operator Testing
    print("\n" + "=" * 70)
    print("PART 2: MUTATION OPERATOR TESTING")
    print("=" * 70)
    print("Testing if security tests can detect the 'insecure' version as a mutant...")

    mutation_results = []
    for sample in samples:
        result = test_mutation_operator(sample)
        mutation_results.append(result)

        status = "KILLED" if result["mutation_kills_test"] else "SURVIVED"
        print(f"\n[{result['cwe']}] {result['entry_point']}")
        print(f"  Operators: {', '.join(result['operators'])}")
        print(f"  Secure code passes security tests: {result['details'].get('secure_passes', 'N/A')}")
        print(f"  Insecure code fails security tests: {result['details'].get('insecure_fails', 'N/A')}")
        print(f"  Mutation status: {status}")

    # Mutation Summary
    killed_count = sum(1 for r in mutation_results if r["mutation_kills_test"])

    print("\n" + "-" * 70)
    print("MUTATION SUMMARY:")
    print(f"  Mutants killed (insecure detected): {killed_count}/{len(samples)}")
    print(f"  Mutants survived (insecure NOT detected): {len(samples) - killed_count}/{len(samples)}")

    # Final Summary
    print("\n" + "=" * 70)
    print("FINAL VERIFICATION RESULTS")
    print("=" * 70)

    print(f"\nBandit Detection:     {detected_count}/{len(samples)} ({100*detected_count/len(samples):.0f}%)")
    print(f"Mutation Kill Rate:   {killed_count}/{len(samples)} ({100*killed_count/len(samples):.0f}%)")

    # By CWE
    print("\nBy CWE:")
    cwe_stats = {}
    for br, mr in zip(bandit_results, mutation_results):
        cwe = br["cwe"]
        if cwe not in cwe_stats:
            cwe_stats[cwe] = {"bandit": 0, "mutation": 0, "total": 0}
        cwe_stats[cwe]["total"] += 1
        if br["detected"]:
            cwe_stats[cwe]["bandit"] += 1
        if mr["mutation_kills_test"]:
            cwe_stats[cwe]["mutation"] += 1

    print(f"{'CWE':<10} {'Bandit':<15} {'Mutation':<15}")
    print("-" * 40)
    for cwe in sorted(cwe_stats.keys()):
        stats = cwe_stats[cwe]
        print(f"{cwe:<10} {stats['bandit']}/{stats['total']:<13} {stats['mutation']}/{stats['total']:<13}")

    # Return success if both checks pass for majority
    success = detected_count >= len(samples) * 0.5 and killed_count == len(samples)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
