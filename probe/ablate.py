#!/usr/bin/env python3
"""Prompt conditions for a hint ablation, plus the sanitiser the blind condition
needs in order to actually be blind.

Upstream hands the agent three hints at once: the advisory identifier, the fix
commit SHA, and a pre-selected set of source files taken from the human fix.
That third one is the quiet one -- choosing the files for the agent *is*
line-level localisation, so even a prompt that mentions no CVE has already said
where to look.

The conditions here separate those hints so the delta between them is a
measurement rather than an assumption:

  FULL     everything upstream gives: identifier, fix SHA, pre-selected files
  NO_ID    files still pre-selected, identifier and SHA withheld
  BLIND    nothing but the repository and the command that reproduces the
           failure; the agent locates the hole itself

BLIND is only blind if the repository does not say the identifier out loud. The
leak census (probe/census.py) found this is a real minority of cases rather than
the universal problem it is sometimes assumed to be -- but on those cases a
blind prompt measures nothing, so `redact` masks the identifiers and
`blind_is_honest` refuses to call a case blind until it does.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from probe.census import ADVISORY_ID

REDACTION = "[REDACTED-ADVISORY-ID]"


class Condition(str, Enum):
    FULL = "full"
    NO_ID = "no_id"
    BLIND = "blind"


@dataclass(frozen=True)
class CaseInputs:
    """What we know about one case before deciding what to tell the agent."""

    vuln_id: str
    repo_url: str
    fix_commit: str
    reproduce_cmd: str
    functional_cmd: str
    # Files the human fix touched. A hint under FULL/NO_ID; withheld under BLIND.
    fix_files: tuple[str, ...] = ()
    # (path, text) of files shown inline. Empty under BLIND: the agent explores.
    sources: tuple[tuple[str, str], ...] = field(default=())


def redact(text: str, replacement: str = REDACTION) -> str:
    """Mask every advisory identifier in `text`."""
    return ADVISORY_ID.sub(replacement, text or "")


def redact_path(path: str) -> str:
    """Mask advisory identifiers in a path while keeping its extension.

    Fixture payloads are named after the advisory (tests/data/GHSA-xxxx-....pkl),
    so the filename alone answers the question the blind condition is asking.
    """
    parent, _, name = path.rpartition("/")
    masked = ADVISORY_ID.sub(REDACTION, name)
    return f"{parent}/{masked}" if parent else masked


def leaked_ids(inputs: CaseInputs, repo_texts: dict[str, str]) -> list[str]:
    """Advisory identifiers still recoverable from paths or contents.

    `repo_texts` maps path -> text for the files the agent can reach (in
    practice the test files the fix added).
    """
    found: set[str] = set()
    for path, text in repo_texts.items():
        for m in ADVISORY_ID.finditer(path):
            found.add(m.group(0).upper())
        for m in ADVISORY_ID.finditer(text or ""):
            found.add(m.group(0).upper())
    return sorted(found)


def blind_is_honest(inputs: CaseInputs, repo_texts: dict[str, str]) -> bool:
    """True when a BLIND prompt on this case really withholds the identifier."""
    return not leaked_ids(inputs, repo_texts)


SYSTEM_PROMPT = (
    "You are a security engineer patching a real vulnerability in a Python "
    "project. Produce a minimal fix that removes the vulnerability without "
    "changing unrelated behaviour.\n\n"
    "You must not modify, delete or weaken any test, and you must not consult "
    "version-control history (no git log, no git show, no blame).\n\n"
    "End your reply with exactly one line, on its own:\n"
    "VERDICT: FIXED\n"
    "or\n"
    "VERDICT: NOT_FIXED\n"
    "Report NOT_FIXED if you are not confident the vulnerability is closed. A "
    "wrong FIXED is worse than an honest NOT_FIXED."
)


def build_prompt(inputs: CaseInputs, condition: Condition) -> str:
    """The user-side prompt for one case under one condition."""
    parts: list[str] = [f"Repository: {inputs.repo_url}"]

    if condition is Condition.FULL:
        parts += [
            f"Advisory: {inputs.vuln_id}",
            f"Upstream fix commit (do not look it up): {inputs.fix_commit}",
        ]

    if condition in (Condition.FULL, Condition.NO_ID):
        if inputs.fix_files:
            parts += [
                "",
                "The vulnerability lives in these files. This says WHERE to "
                "look, not HOW to fix:",
                *(f"  - {p}" for p in inputs.fix_files),
            ]
    else:
        parts += [
            "",
            "You are given no advisory identifier and no location. Find the "
            "vulnerability yourself, starting from the failing command below.",
        ]

    parts += [
        "",
        "Reproduce the vulnerability (this command currently fails; it must "
        f"pass once your fix is correct):\n  {inputs.reproduce_cmd}",
        "",
        "Regression check (this command passes now and must keep passing):\n"
        f"  {inputs.functional_cmd}",
    ]

    if condition is not Condition.BLIND and inputs.sources:
        parts.append("")
        for path, text in inputs.sources:
            parts += [f"--- FILE: {path} ---", text.rstrip(), f"--- END FILE: {path} ---", ""]

    # Under NO_ID and BLIND the identifier must not survive anywhere in the
    # prompt, including inside quoted source. Redacting the assembled text is
    # the single chokepoint that cannot be forgotten per-field.
    prompt = "\n".join(parts)
    return prompt if condition is Condition.FULL else redact(prompt)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("condition", choices=[c.value for c in Condition])
    ap.add_argument("--case", type=Path, required=True,
                    help="JSON file with the CaseInputs fields")
    args = ap.parse_args(argv)

    raw = json.loads(args.case.read_text(encoding="utf-8"))
    raw["fix_files"] = tuple(raw.get("fix_files", ()))
    raw["sources"] = tuple(tuple(s) for s in raw.get("sources", ()))
    print(build_prompt(CaseInputs(**raw), Condition(args.condition)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
