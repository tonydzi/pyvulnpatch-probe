#!/usr/bin/env python3
"""Two censuses over a Python AVR corpus, computed from public git history only
-- no model calls, no redistribution of anyone's corpus.

Why this file exists
--------------------
Vul4Py (arXiv:2608.00692) is, as of October 2026, the only Python
automated-vulnerability-repair benchmark whose every entry carries a paired
oracle (exploit test must flip, project test suite must stay green). It reports
neither of the two numbers below, and both are prerequisites for believing any
solve rate measured on it.

date_census    The committer date of each fix commit. A solve rate is evidence
               about repair ability only on cases the model could not have
               memorised, so the fix-date distribution bounds how large a
               post-cutoff claim can arithmetically be.

leak_census    Whether the advisory identifier (CVE-.../GHSA-...) appears in the
               test files the fix commit added -- in their paths, or in their
               added lines. Where it does, an agent that reads the repository
               recovers the identifier even when the prompt withholds it, so a
               "no hints" condition is not hintless on those cases.

Both take `vuln_id,repo_url,fix_commit` rows and ask the GitHub API about
commits that are already public. Output is JSONL, one record per case.
"""
from __future__ import annotations

import csv
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

# Advisory identifiers. GHSA ids are three 4-char groups from a reduced
# alphabet; CVE ids carry a 4-digit year and at least four sequence digits.
ADVISORY_ID = re.compile(
    r"(CVE-\d{4}-\d{4,}|GHSA-[2-9a-hjkmnp-z]{4}-[2-9a-hjkmnp-z]{4}-[2-9a-hjkmnp-z]{4})",
    re.IGNORECASE,
)

# A path is test-ish if it sits under a tests directory, or is named like a
# test. Fixture and payload files under a tests directory count too: their
# filenames are where GHSA ids leak most often.
TEST_PATH = re.compile(
    r"(^|/)(tests?|testing)/|(^|/)test_[^/]*$|_test\.py$|(^|/)conftest\.py$"
)

# The repo name may legitimately contain dots (changedetection.io), so it is
# matched greedily and only a trailing `.git` is stripped afterwards. An earlier
# `[^/.]+` here silently turned changedetection.io into changedetection and the
# API answered 404, which read as "GitHub lost the commit" rather than as a bug.
GITHUB_REPO = re.compile(r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")


class CorpusError(RuntimeError):
    pass


@dataclass(frozen=True)
class Case:
    vuln_id: str
    repo_url: str
    fix_commit: str

    @property
    def slug(self) -> str:
        m = GITHUB_REPO.match(self.repo_url.rstrip("/"))
        if not m:
            raise CorpusError(f"{self.vuln_id}: not a GitHub URL: {self.repo_url!r}")
        return f"{m.group(1)}/{m.group(2)}"


def read_corpus(csv_path: Path) -> list[Case]:
    """Read the corpus index. Requires vuln_id, repo_url and fix_commit."""
    with csv_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = {"vuln_id", "repo_url", "fix_commit"} - set(reader.fieldnames or [])
        if missing:
            raise CorpusError(f"{csv_path}: missing columns {sorted(missing)}")
        cases = [
            Case(r["vuln_id"].strip(), r["repo_url"].strip(), r["fix_commit"].strip())
            for r in reader
            if r.get("vuln_id", "").strip()
        ]
    if not cases:
        raise CorpusError(f"{csv_path}: no rows")
    return cases


def fetch_commit(slug: str, sha: str) -> dict:
    """Return the GitHub commit object, or raise carrying the API's own words."""
    proc = subprocess.run(
        ["gh", "api", f"repos/{slug}/commits/{sha}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise CorpusError(proc.stderr.strip()[:200] or f"gh api exit {proc.returncode}")
    return json.loads(proc.stdout)


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path))


def advisory_ids(text: str) -> list[str]:
    """Advisory identifiers in `text`, uppercased, deduplicated, sorted."""
    return sorted({m.group(0).upper() for m in ADVISORY_ID.finditer(text or "")})


def added_lines(patch: str) -> str:
    """The '+' side of a unified diff hunk, minus the '+++' file header.

    Only added lines matter here: a '-' line is pre-existing code the fix
    removed, and counting it would credit the fix with a leak it did not make.
    """
    return "\n".join(
        line[1:]
        for line in (patch or "").splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def leak_record(case: Case, commit: dict) -> dict:
    """Which identifiers an agent could recover from the fix commit's tests.

    `in_paths` is what a directory listing reveals; `in_added_lines` is what
    reading the test source reveals. `in_commit_message` is a control -- the
    harness never shows it to the agent, but it is the channel through which the
    fix reached any training corpus.
    """
    files = commit.get("files") or []
    tests = [f for f in files if is_test_path(f.get("filename", ""))]
    in_paths = advisory_ids(" ".join(f.get("filename", "") for f in tests))
    in_added = advisory_ids("\n".join(added_lines(f.get("patch", "")) for f in tests))
    return {
        "vuln_id": case.vuln_id,
        "repo": case.slug,
        "n_files_changed": len(files),
        "n_test_files": len(tests),
        "test_paths": [f.get("filename") for f in tests],
        "in_paths": in_paths,
        "in_added_lines": in_added,
        "leaks": sorted(set(in_paths) | set(in_added)),
        "in_commit_message": advisory_ids(commit.get("commit", {}).get("message", "")),
    }


def date_record(case: Case, commit: dict) -> dict:
    return {
        "vuln_id": case.vuln_id,
        "repo": case.slug,
        "fix_commit": case.fix_commit,
        "fix_date": commit.get("commit", {}).get("committer", {}).get("date"),
    }


BUILDERS = {"dates": date_record, "leaks": leak_record}


def run_census(cases: Iterable[Case], kind: str) -> Iterator[dict]:
    """Yield one record per case.

    A case that fails yields {'error': ...} rather than vanishing: a census that
    silently drops rows reports a total it did not measure.
    """
    build = BUILDERS[kind]
    for case in cases:
        try:
            yield build(case, fetch_commit(case.slug, case.fix_commit))
        except (CorpusError, json.JSONDecodeError) as exc:
            yield {"vuln_id": case.vuln_id, "error": str(exc)}


def summarise_leaks(records: list[dict]) -> dict:
    ok = [r for r in records if "error" not in r]
    return {
        "cases": len(records),
        "resolved": len(ok),
        "errors": len(records) - len(ok),
        "leak_in_paths": sum(1 for r in ok if r["in_paths"]),
        "leak_in_added_lines": sum(1 for r in ok if r["in_added_lines"]),
        "leak_either": sum(1 for r in ok if r["leaks"]),
        "leak_in_commit_message": sum(1 for r in ok if r["in_commit_message"]),
        "no_test_files_in_fix": sum(1 for r in ok if r["n_test_files"] == 0),
        "leaking_ids": sorted(r["vuln_id"] for r in ok if r["leaks"]),
    }


def summarise_dates(records: list[dict], cutoffs: dict[str, str]) -> dict:
    ok = [r for r in records if r.get("fix_date")]
    by_year: dict[str, int] = {}
    for r in ok:
        year = r["fix_date"][:4]
        by_year[year] = by_year.get(year, 0) + 1
    return {
        "cases": len(records),
        "resolved": len(ok),
        "errors": len(records) - len(ok),
        "by_year": dict(sorted(by_year.items())),
        "after_cutoff": {
            name: sum(1 for r in ok if r["fix_date"] >= cut)
            for name, cut in cutoffs.items()
        },
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("kind", choices=sorted(BUILDERS))
    ap.add_argument(
        "--corpus", type=Path, required=True, help="CSV: vuln_id,repo_url,fix_commit"
    )
    ap.add_argument("--out", type=Path, required=True, help="JSONL output path")
    ap.add_argument(
        "--cutoff",
        action="append",
        default=[],
        metavar="NAME=YYYY-MM-DD",
        help="report a post-cutoff count for this model cutoff (repeatable)",
    )
    args = ap.parse_args(argv)

    records = list(run_census(read_corpus(args.corpus), args.kind))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    if args.kind == "leaks":
        summary = summarise_leaks(records)
    else:
        summary = summarise_dates(records, dict(c.split("=", 1) for c in args.cutoff))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if summary["errors"]:
        print(
            f"\n{summary['errors']} of {summary['cases']} cases could not be "
            f"resolved; the counts above are over the {summary['resolved']} that could."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
