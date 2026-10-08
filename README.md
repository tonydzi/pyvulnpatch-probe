# pyvulnpatch-probe

Three measurements that a Python vulnerability-patching benchmark needs before
its solve rate means anything, and that the existing ones do not report.

This is **not** another benchmark. It does not ship a corpus. It is an audit and
ablation layer that runs on top of an existing Python AVR corpus and answers
questions about the *measurement*, not about the models.

## Why this exists

As of October 2026 the landscape is:

| benchmark | language | patching? | paired oracle? |
|---|---|---|---|
| [PatchBench](https://arxiv.org/abs/2609.04075) (Sep 2026) | C/C++ only | yes | yes |
| [Vul4Py](https://arxiv.org/abs/2608.00692) (Aug 2026) | Python | yes | yes |
| [CyberChainBench](https://arxiv.org/abs/2606.26216) (Jun 2026) | Solidity | yes | economic |
| [Vulnerability Localization Benchmark](https://arxiv.org/abs/2609.15939) (Sep 2026) | multi | no (localisation) | n/a |

Python *is* covered, by Vul4Py — 100 real vulnerabilities, 60 projects, 60 CWEs,
each with a paired oracle (exploit test must flip from fail to pass; the
project's own pytest suite must stay green). Vul4Py reports OpenHands repairing
41/100, the best directly-prompted LLM 4/100, and a specialised AVR tool 2/100.

What is missing is not another corpus. It is the arithmetic that tells you
whether those numbers measure repair ability:

1. **Every agent is handed the answer's address.** Vul4Py gives every condition
   the advisory identifier, the fix commit SHA, and a pre-selected set of source
   files drawn from the human fix. Choosing the files *is* line-level
   localisation. There is no condition without it, so the hint's contribution to
   41/100 is unmeasured.
2. **Contamination is named, not measured.** The paper lists "leakage of fix
   commits into LLM training data" under threats to validity. No date split, no
   post-cutoff slice.
3. **The agent is never asked what it thinks it did.** The oracle is compared
   only to itself (exploit-only vs paired). Nobody measures the agent asserting
   a hole is closed while the oracle disagrees — operationally the worst
   outcome, because a confident wrong answer closes the incident.

## What this measures

### 1. Leak census — is a "no hints" condition actually hintless?

```bash
python3 -m probe.census leaks --corpus data/corpus-vul4py.csv --out data/leaks.jsonl
```

Withholding the CVE id from the prompt means nothing if the repository says it
out loud. Measured over Vul4Py's 100 cases (100/100 resolved, 0 errors):

| channel | cases |
|---|---|
| advisory id in a **test file's path** | 4 / 100 |
| advisory id in the test's **added lines** | 13 / 100 |
| **either** — a blind prompt is not blind here | **13 / 100** |
| in the fix **commit message** (control; never shown to the agent) | 32 / 100 |
| fix commit adds no test file at all | 4 / 100 |

The path leaks are fixture payloads named after the advisory
(`tests/data2/GHSA-3gf5-cxq9-w223.pkl`) — one such directory names ten
advisories at once, so a single `ls` hands over nine neighbours too.

This number is worth stating because the common assumption is worse than
reality. A reviewer on this design argued the leak is near-universal and makes
hint ablation "an illusion"; measured, it is 13%. Material, and cheap to
sanitise — not fatal. `probe/ablate.py` masks those ids and
`blind_is_honest()` refuses to label a case blind until it does.

### 2. Date census — how large can a post-cutoff claim be?

```bash
python3 -m probe.census dates --corpus data/corpus-vul4py.csv --out data/dates.jsonl \
  --cutoff "GPT-4o 2023-10"=2023-10-01 \
  --cutoff "Claude Sonnet 4 ~2025-03"=2025-03-01 \
  --cutoff "2026 frontier models ~2026-05"=2026-05-01
```

Fix commits by year: 2017:2 · 2018:1 · 2020:3 · 2021:3 · 2022:5 · 2023:18 ·
2024:34 · 2025:34.

Post-cutoff slice: **71** cases for GPT-4o, **30** for Claude Sonnet 4,
**0** for any 2026-cutoff model.

**This result kills the clean version of measurement 2, and that is the finding.**
Vul4Py's corpus stops in 2025, so on a current model there is no uncontaminated
slice at all — not a small one, zero. Any post-cutoff claim about a 2026 model on
this corpus is arithmetically unavailable. For the models Vul4Py itself used the
slice is real (30 and 71), so the split is worth running *against their numbers*;
it is not a path to a fresh result on current models. Doing that needs either new
2026 advisories or semantics-preserving perturbation of the existing ones, and
both are larger projects than this one.

### 3. Self-report gap — does the agent know whether it succeeded?

```bash
python3 -m probe.score runs/<agent>/
```

Each case records two independent verdicts and crosses them:

| | oracle: repaired | oracle: not repaired |
|---|---|---|
| agent claims FIXED | `true_success` | **`false_success`** |
| agent claims NOT_FIXED | `unclaimed_success` | `honest_failure` |
| agent states nothing | `no_verdict` | `no_verdict` |

`false_success_rate` is `false_success / claimed_fixed` — the share of the
agent's own assertions that the oracle refused. It is reported as `null`, never
`0.0`, when the agent made no assertions, so an empty run cannot read as a
flawless one.

## Honest status

**Measured and reproducible now** (no model calls, no API keys, no money): the
leak census and the date census, both over all 100 cases, both green end to end.
Every number in this README came out of the code in this repo.

**Built and tested but not yet run against a live agent**: the hint-ablation
prompt conditions (`probe/ablate.py`) and the self-report scorer
(`probe/score.py`). Until that run happens this repo reports **no solve rate and
no false-success rate** — the scorers are verified against synthetic patches
only, and you should not cite a rate from here.

What such a run costs, grounded in Vul4Py's own Table 2 (mean API spend per
instance on a Claude Sonnet 4 backbone: OpenHands $1.32, SWE-agent $1.43, direct
prompting $0.03–0.05):

| scope | runs | expected | hard ceiling with a per-case cap |
|---|---|---|---|
| smoke test, 3 cases × 3 conditions | 9 | ≈$12 | $27 at $3/case |
| minimum real measurement, 10 × 3 | 30 | ≈$40 | $45 at $1.50/case |
| publishable, 30 × 3 | 90 | ≈$119 | $135 at $1.50/case |

The direct-prompting arm is ~30× cheaper but scores 4–5/100 upstream, so an
ablation delta measured there sits on the floor and is noise. The number only
means something on an agentic backbone.

**Not done**: perturbation-based contamination measurement (the replacement for
measurement 2 suggested above), open-weight backbones, languages other than
Python.

## Verification

`tests/test_probe.py` is a kill-list: 27 assertions, each naming a specific way
a measurement could lie.

`tests/run_killlist.py` is the red-first proof. It breaks each scorer on purpose
— oracle ignoring the functional suite, false-success rate divided by the wrong
denominator, blind prompt forgetting to redact quoted source, leak audit
counting removed lines — reruns the suite, and requires it to go red via the
named test. **14 of 14 mutations are provably caught.** A test that has only
ever been green proves nothing about the scorer.

```bash
python3 tests/test_probe.py      # 27 passed
python3 tests/run_killlist.py    # 14/14 mutations provably caught
```

One bug was found this way in production rather than by the kill-list: the
GitHub slug parser forbade dots, so `changedetection.io` became
`changedetection` and two cases reported `404`. That read as "GitHub lost the
commit" until the slug was printed. Both the fix and a mutation guarding it are
now in place — see `KILL-LIST.md`.

## Licence

This repo is MIT (`LICENSE`). Citing it: `CITATION.cff`.

## Attribution and licensing of the corpus

The corpus this operates on is **Vul4Py**, by Tan Bui, Ting Zhang, Ferdian
Thung, Yunpeng Xiong, Penghao Jiang, Xin Zhou and David Lo (Singapore
Management University / Monash / UNSW) — [arXiv:2608.00692](https://arxiv.org/abs/2608.00692),
harness at [github.com/tabudz/vul4py](https://github.com/tabudz/vul4py). The
paired-oracle design is theirs; this repo adds measurements around it and claims
nothing about the corpus itself.

⚠️ **That repository ships no LICENSE file**, which under default copyright means
all rights reserved. This repo therefore contains **none of their code and none
of their data** — only our own scripts plus `data/corpus-vul4py.csv`, a list of
public `(advisory id, repo URL, fix commit)` triples. Anyone wanting to run this
should clone their harness themselves and comply with whatever terms they set.
Asking them to add an explicit licence is the first thing worth doing here.

Benchmarks referenced for scope comparison: PatchBench (arXiv:2609.04075),
CyberChainBench (arXiv:2606.26216), Vulnerability Localization Benchmark
(arXiv:2609.15939). Advisory data originates from OSV and the GitHub Advisory
Database.

## Scope and safety

Every vulnerability referenced here is **already public and already fixed** —
each one has a published advisory and an upstream patch, both predating this
work. Nothing here produces a new exploit, and no exploit text is included: the
reproducers live in the upstream projects' own test suites. This is defensive
measurement of whether automated repair works.

---

<!--ecosystem-map:start-->

## 🧩 One piece of a working system

This repository is one piece lifted out of a live operation: one engineer running operations,
an AI cofounder, and a fleet of machines that reach consensus with each other and wake the
human only for money or the irreversible. It was extracted after it survived production,
not written as a demo — and it runs on its own: nothing here phones home to the rest.

**See how the whole thing fits together → [SYSTEM.md](https://github.com/tonydzi/tonydzi/blob/main/SYSTEM.md)**

<!--ecosystem-map:end-->

## AI contributors

This project is built by a human + AI team, and the git log says so: Claude writes most of
the code, Codex and Grok review it, Gemini feeds the research. Each is credited on a commit
**only if its output changed that commit's content** — no decorative credits. Lab-wide
policy, one source for every repo: [AI-CONTRIBUTORS.md](https://github.com/tonydzi/.github/blob/main/AI-CONTRIBUTORS.md).
