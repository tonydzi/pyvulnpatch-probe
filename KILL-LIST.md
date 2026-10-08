# Kill-list: how each measurement could lie, and the proof it cannot

A measurement is only as trustworthy as the ways you tried to break it. Every row
below is a mutation applied to the real source by `tests/run_killlist.py`, which
then reruns the suite and requires it to go **red via the named test**. A
mutation the suite survives is reported as a hole, not ignored.

Current state: **14 of 14 caught**, suite restored green afterwards.

## Oracle — would it accept a patch that is not a fix?

| mutation | caught by |
|---|---|
| ignore the functional suite, i.e. degrade to an exploit-only oracle | `test_patch_that_breaks_the_suite_is_not_a_repair` |
| accept a patch that never applied | `test_patch_that_does_not_apply_is_not_a_repair` |

The first is the specific failure Vul4Py's paired oracle exists to prevent: a
patch that silences the exploit while regressing unrelated behaviour. It must
never score as a repair.

## Self-report gap — would the number flatter the agent?

| mutation | caught by |
|---|---|
| divide false successes by all cases instead of by claims | `test_false_success_rate_is_over_claims_not_over_cases` |
| report `0.0` instead of `null` when the agent claimed nothing | `test_no_claims_gives_none_not_zero` |
| take the agent's first narrated guess as its verdict | `test_last_verdict_wins_over_narrated_guess` |
| match `VERDICT:` mid-prose, so a refusal reads as FIXED | `test_verdict_must_be_its_own_line` |

Both denominator mutations push the rate *down*, which is the direction a
self-serving bug goes. The last two are real agent behaviour: agents narrate a
wrong guess before converging, and they write sentences like "I cannot say
VERDICT: FIXED without testing".

## Blind condition — is it actually blind?

| mutation | caught by |
|---|---|
| skip redaction, leaving the id inside quoted source | `test_identifier_inside_quoted_source_is_also_redacted` |
| name the fix location anyway | `test_blind_prompt_withholds_id_location_and_sha` |
| redact *every* condition, blinding the control arm too | `test_full_condition_really_gives_the_hints` |

The third matters as much as the other two: a redaction bug that blinds the FULL
arm would make the ablation delta vanish and look like a null result.

## Censuses — do they count the channel they claim to?

| mutation | caught by |
|---|---|
| count removed diff lines as leaks | `test_added_lines_ignores_removed_lines_and_file_header` |
| stop treating fixture payloads under `tests/` as test files | `test_fixture_payloads_under_tests_count_as_test_files` |
| forbid dots in repo names, 404-ing every domain-named repo | `test_repo_name_containing_a_dot_survives_slug_parsing` |
| drop failed lookups, inflating the denominator | `test_census_errors_are_reported_not_absorbed` |
| count every case as post-cutoff regardless of date | `test_post_cutoff_count_is_honest_about_an_empty_slice` |

## The one the kill-list missed

The slug-parser bug was **not** caught by the kill-list. It was found in
production: two of 100 cases returned `gh: Not Found (HTTP 404)` and the obvious
reading was that GitHub no longer had those commits. It was our regex — the repo
name `changedetection.io` contains a dot and `[^/.]+` truncated it to
`changedetection`.

Two things made it visible rather than silent:

- the census emits `{"error": ...}` per failed case instead of skipping it, so
  the resolved count dropped from 100 to 98 in plain sight;
- a second, independently written implementation of the same census produced
  100/100, and the two disagreeing totals had to be reconciled.

Both numbers were identical on the headline metric (13 leaking cases, same ids),
so the discrepancy was isolated to the two 404s rather than to the measurement.

The lesson is in the design, not the fix: **a census that drops rows reports a
total it did not measure.** That property is now itself under test
(`test_census_errors_are_reported_not_absorbed`).
