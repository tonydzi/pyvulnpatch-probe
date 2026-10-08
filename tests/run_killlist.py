#!/usr/bin/env python3
"""Red-first proof: break each scorer on purpose and check the suite notices.

A test that has only ever been green proves nothing about the scorer -- it may
be asserting something that cannot fail. So for each mutation below we patch the
source, run the suite, and require that it goes red AND that the named test is
among the failures. A mutation the suite survives is reported as a hole.

Run: python3 tests/run_killlist.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (label, file, pattern -> replacement, test that must go red)
MUTATIONS = [
    (
        "oracle ignores the functional suite (exploit-only oracle)",
        "probe/score.py",
        "and self.functional_rc in FUNCTIONAL_OK_RCS\n            ",
        "",
        "test_patch_that_breaks_the_suite_is_not_a_repair",
    ),
    (
        "oracle accepts a patch that never applied",
        "probe/score.py",
        "self.apply_ok\n            and self.functional_rc",
        "True\n            and self.functional_rc",
        "test_patch_that_does_not_apply_is_not_a_repair",
    ),
    (
        "false-success rate divided by all cases instead of by claims",
        "probe/score.py",
        "/ claimed_fixed, 4)",
        "/ len(rows), 4)",
        "test_false_success_rate_is_over_claims_not_over_cases",
    ),
    (
        "empty run reports a perfect 0.0 instead of None",
        "probe/score.py",
        "if claimed_fixed\n            else None",
        "if claimed_fixed\n            else 0.0",
        "test_no_claims_gives_none_not_zero",
    ),
    (
        "first narrated guess taken as the claim instead of the last",
        "probe/score.py",
        "matches[-1].upper()",
        "matches[0].upper()",
        "test_last_verdict_wins_over_narrated_guess",
    ),
    (
        "verdict matched mid-prose, so a refusal reads as FIXED",
        "probe/score.py",
        r'r"^\s*VERDICT:\s*(FIXED|NOT_FIXED)\s*$", re.IGNORECASE | re.MULTILINE',
        r'r"VERDICT:\s*(FIXED|NOT_FIXED)", re.IGNORECASE',
        "test_verdict_must_be_its_own_line",
    ),
    (
        "blind prompt forgets to redact quoted source",
        "probe/ablate.py",
        "return prompt if condition is Condition.FULL else redact(prompt)",
        "return prompt",
        "test_identifier_inside_quoted_source_is_also_redacted",
    ),
    (
        "blind prompt leaks the fix location anyway",
        "probe/ablate.py",
        "if condition in (Condition.FULL, Condition.NO_ID):",
        "if True:",
        "test_blind_prompt_withholds_id_location_and_sha",
    ),
    (
        "redaction applied to every condition, blinding the control arm too",
        "probe/ablate.py",
        "return prompt if condition is Condition.FULL else redact(prompt)",
        "return redact(prompt)",
        "test_full_condition_really_gives_the_hints",
    ),
    (
        "leak audit counts removed lines as leaks",
        "probe/census.py",
        'if line.startswith("+") and not line.startswith("+++")',
        'if line.startswith("+") or line.startswith("-")',
        "test_added_lines_ignores_removed_lines_and_file_header",
    ),
    (
        "leak audit misses fixture payloads named after the advisory",
        "probe/census.py",
        r"(^|/)(tests?|testing)/|(^|/)test_[^/]*$|_test\.py$|(^|/)conftest\.py$",
        r"_test\.py$",
        "test_fixture_payloads_under_tests_count_as_test_files",
    ),
    (
        "slug parser forbids dots, 404-ing every repo named like a domain",
        "probe/census.py",
        r'r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$"',
        r'r"^https?://github\.com/([^/]+)/([^/.]+)"',
        "test_repo_name_containing_a_dot_survives_slug_parsing",
    ),
    (
        "census silently drops failed lookups, inflating the denominator",
        "probe/census.py",
        '"errors": len(records) - len(ok),\n        "leak_in_paths"',
        '"errors": 0,\n        "leak_in_paths"',
        "test_census_errors_are_reported_not_absorbed",
    ),
    (
        "post-cutoff slice counts every case regardless of date",
        "probe/census.py",
        'sum(1 for r in ok if r["fix_date"] >= cut)',
        "len(ok)",
        "test_post_cutoff_count_is_honest_about_an_empty_slice",
    ),
]


def run_suite() -> tuple[bool, set[str]]:
    proc = subprocess.run(
        [sys.executable, "tests/test_probe.py"], cwd=ROOT, capture_output=True, text=True
    )
    failed = set(re.findall(r"^  FAIL (\S+)", proc.stdout, re.MULTILINE))
    return proc.returncode == 0, failed


def main() -> int:
    green, failed = run_suite()
    if not green:
        print(f"baseline is not green ({sorted(failed)}); fix that before mutating")
        return 2
    print(f"baseline: green ({len(MUTATIONS)} mutations to try)\n")

    holes = []
    for label, rel, pattern, replacement, expected in MUTATIONS:
        path = ROOT / rel
        original = path.read_text(encoding="utf-8")
        if pattern not in original:
            holes.append((label, "mutation pattern no longer present in source"))
            print(f"  SKIP  {label}\n        pattern not found in {rel}")
            continue
        path.write_text(original.replace(pattern, replacement, 1), encoding="utf-8")
        try:
            still_green, failed = run_suite()
        finally:
            path.write_text(original, encoding="utf-8")

        if still_green:
            holes.append((label, "suite stayed GREEN -- nothing guards this"))
            print(f"  HOLE  {label}\n        suite stayed green")
        elif expected not in failed:
            holes.append((label, f"went red, but {expected} was not among {sorted(failed)}"))
            print(f"  WEAK  {label}\n        red via {sorted(failed)}, not {expected}")
        else:
            print(f"  red   {label}\n        caught by {expected}"
                  + (f" (+{len(failed) - 1} more)" if len(failed) > 1 else ""))

    final_green, _ = run_suite()
    print(f"\nsource restored, suite green again: {final_green}")
    print(f"{len(MUTATIONS) - len(holes)}/{len(MUTATIONS)} mutations provably caught")
    for label, why in holes:
        print(f"  unguarded: {label} -- {why}")
    return 0 if (not holes and final_green) else 1


if __name__ == "__main__":
    raise SystemExit(main())
