# Comparing Claude's security-scanning approaches on EatHub

Three different ways of pointing Claude at the same codebase, run against the
same target app: **[EatHub](https://github.com/smacica/Eathub)**, an
Express/SQLite recipe-sharing API (vendored in this repo at
[`targets/eathub/`](targets/eathub/), threat-modeled in
[`THREAT_MODEL.md`](THREAT_MODEL.md)).

| | Scope | Method | Verification | Found | Results |
|---|---|---|---|---|---|
| **`/security-review`** | Diff only (`main` → branch) | Single-pass LLM read + independent FP filter | None — reasoning only | **1 MEDIUM** (2 more raised, then self-rejected) | [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) |
| **Static skill scan** (this repo) | Whole codebase | LLM read, broad, then multi-agent triage | 3-vote adversarial re-verification per finding, still reasoning only | **2 HIGH / 4 MEDIUM / 1 LOW** (from 13 raw: 4H/5M/4L) | [`VULN-FINDINGS.md`](VULN-FINDINGS.md) → [`TRIAGE.md`](TRIAGE.md) |
| **Reference pipeline** (`vuln-pipeline`, this repo) | HTTP-reachable attack surface only | Agent writes a PoC, replays it against a live sandboxed instance | Execution — a detector oracle actually has to fire, twice, in two separate containers | **1 HIGH / 1 MEDIUM** (3 crashes submitted, 1 killed on review) | [`results/eathub/20260816T195551Z/`](results/eathub/20260816T195551Z/) |

The short version:

- `/security-review` — cheap and fast, but only sees your diff.
- Static skill scan — sees everything, but produces things a human (or a
  second pass) has to believe.
- Reference pipeline — fewest false positives, because it has to actually
  break the app; costs coverage, since it only reaches what it can exploit
  inside a sandbox.

The counts aren't directly comparable — different scopes, different bars. The
overlap is small on purpose: each approach found things the other two didn't.

---

## 1. `/security-review` — diff-only skill

The built-in
[`claude-code-security-review`](https://github.com/anthropics/claude-code-security-review)
skill, not something this repo ships. Requires git, only diffs the current
branch against `main` — meant for incremental changes, not a codebase audit.

- **Run:** Opus 5, against the branch adding backend logging (pino logger,
  `pino-http` middleware, audit events). Cheap — few commits to read.
- **Result:** [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md)

| Finding | Verdict |
|---|---|
| Plaintext credentials written to logs via the error serializer (`index.js:70`) | **Confirmed — Medium** |
| Correlation id taken from client-controlled `X-Request-Id` (`request_log.js:47`) | Rejected (false positive) |
| `trust proxy` makes the logged `ip` spoofable (`index.js:40`) | Rejected (false positive) |

**The confirmed finding**, in short:

- The new error handler logs the full error object
  (`req.log.error({ err }, 'unhandled error')`).
- `pino`'s default error serializer copies every enumerable own property onto
  the log line.
- `body-parser` attaches the raw request body to a JSON-parse-failure error.
- So a malformed signup/login POST puts the victim's plaintext password and
  email into the retained log stream.
- Full chain: [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md#finding-1--plaintext-credentials-written-to-logs-via-the-error-serializer)

### Correction: "the harness found this too but downgraded it as dev-only"

Not what happened:

- [`VULN-FINDINGS.md`](VULN-FINDINGS.md) does have an entry at the same lines,
  under *Checked and clean*: *"Error middleware does not leak. `index.js:68-75`
  returns a generic message and logs the error server-side."*
- But it's timestamped `2026-08-15T07:59:02Z`, before the logging branch — at
  that point the handler still did `console.error(err.message)`, a genuinely
  clean line. The static scan never re-ran against the changed code.
- On severity: [`THREAT_MODEL.md`](THREAT_MODEL.md) and
  [`TRIAGE.md`](TRIAGE.md) both score against the **intended production
  deployment**, not the current local-only state, deliberately — so "it's only
  dev" isn't how this repo's triage policy would have scored it either.

**What it structurally can't catch**, per the skill's own [false-positive
policy](https://github.com/anthropics/claude-code-security-review#false-positive-filtering):
DoS, rate limiting, memory/CPU exhaustion, input validation without proven
impact, open redirects. This run's own "Excluded by policy" line adds resource
exhaustion, secrets at rest, missing hardening, log spoofing, and
doc-only findings. Filtered by design, not missed by accident.

---

## 2. `defending-code-reference-harness` scan (this repo)

Built for whole-codebase, ongoing scanning rather than one diff. Two genuinely
different halves.

### 2a. Static skill scan

Three skills, run in sequence, re-runnable as the codebase changes:

| Skill | Purpose | Output |
|---|---|---|
| [`/threat-model`](.claude/skills/threat-model/) | Profile the target — access, trust boundaries, assets, attack surface. Run once unless the app changes. | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| [`/vuln-scan`](.claude/skills/vuln-scan/) | Broad static read across the whole tree — finds everything, including false positives, no code execution | [`VULN-FINDINGS.md`](VULN-FINDINGS.md) |
| [`/triage`](.claude/skills/triage/) | 3 independent subagents per finding vote real/false-positive, then dedupe + re-rank by exploitability | [`TRIAGE.md`](TRIAGE.md) |
| `/patch` | Generates candidate fixes | *(not run this pass)* |

- **Run:** interactive, two ~5-hour Claude Pro sessions. Token-heavy — three
  verifier subagents per finding plus a ranking pass.
- **Raw:** [`VULN-FINDINGS.md`](VULN-FINDINGS.md) — 13 findings (4 HIGH /
  5 MEDIUM / 4 LOW, several under 0.4 confidence).
- **Triaged:** [`TRIAGE.md`](TRIAGE.md) — 0 duplicates, 6 false positives,
  7 acted-on (**2 HIGH / 4 MEDIUM / 1 LOW**). Two of the seven are flagged
  `needs_manual_test` because a session limit killed their verifier agents
  mid-run, not because of an analytical call (see the caveat at the top of
  `TRIAGE.md`).

**The two HIGH findings that survived triage:**

- **Account takeover via Google sign-in linking** (`db.js:553`) — attacker
  pre-registers the victim's email locally; victim later signs in with Google;
  the app sets `email_verified = 1` on the pre-existing row without checking
  who created it. The attacker's own password now unlocks the victim's account.
- **Upload extension trusted from the client** (`file_uploud.js:10`) — a
  `.html`/`.svg` upload is served back same-origin with no content-type
  sniffing or CSP → stored XSS on the app's own origin.

**Triage also killed things the raw scan claimed:** a hardcoded session-secret
fallback that looked like full auth bypass turned out not to be exploitable
against a server-side session store; a SQL-injection claim on the internal
query helpers was unanimously rejected because every call site uses literal
identifiers. Read [`TRIAGE.md`](TRIAGE.md)'s "What the verifiers changed"
before acting on its list.

### 2b. Reference pipeline (`vuln-pipeline`)

The part that actually runs the app: `recon → find → grade ("verify") → report
→ patch`, in a loop, each agent in its own gVisor sandbox with only a JSON PoC
crossing the trust boundary.

This repo originally shipped only a C/C++ + AddressSanitizer harness, so the
EatHub target was built with `/customize` first — swapping the ASAN detector
for a `run_poc.js` runner that replays an HTTP PoC and checks nine security
oracles (data-integrity, cross-account access, origin escape, CORS
misconfiguration, unsafe uploaded content-type, info disclosure, uncaught
exceptions, unexpected 5xx, hangs — table in
[`targets/eathub/README.md`](targets/eathub/README.md#the-oracle-set)).

**Available subcommands:**

| Command | Does | Used this pass? |
|---|---|---|
| `vuln-pipeline recon <target>` | Proposes focus areas from the source | Yes, via `--auto-focus` |
| `vuln-pipeline run <target> --runs N --parallel --stream` | Find + grade + judge + report, streamed as each crash lands | **Yes** — the whole loop |
| `vuln-pipeline dedup <results_dir>` | Groups crashes by signature (batch mode) | No — `--stream` dedupes live |
| `vuln-pipeline report <results_dir>` | Standalone exploitability report per crash (batch recovery) | No — folded into `--stream` |
| `vuln-pipeline patch <results_dir>` | Generates + verifies a fix per crash | **No** — skipped, same as the static side |

- **Run:** Sonnet 5, `run --stream` with 3 parallel find-agents over
  recon-proposed focus areas. Most token-intensive of the three — every find,
  grade, and report step is its own agent in its own container.
- **Results:** [`results/eathub/20260816T195551Z/`](results/eathub/20260816T195551Z/)
  — [`focus_areas.json`](results/eathub/20260816T195551Z/focus_areas.json)
  (recon output), [`found_bugs.jsonl`](results/eathub/20260816T195551Z/found_bugs.jsonl)
  (crashes as they landed), `run_00N/result.json` (grade verdicts),
  [`reports/`](results/eathub/20260816T195551Z/reports/) (judge log, manifest,
  per-bug reports + PoC bytes).

**What the run produced — 3 finds, 3 reports, 2 real bugs:**

| Bug | Oracle / route | Grade | Report verdict |
|---|---|---|---|
| [`bug_01`](results/eathub/20260816T195551Z/reports/bug_01/report.json) | `UNSAFE_CONTENT_TYPE` — `POST /api/recipes` | passed, 3/3 replays, score 0.90 | **HIGH** — attacker plants a script-executing SVG served back unauthenticated same-origin |
| [`bug_00`](results/eathub/20260816T195551Z/reports/bug_00/report.json) | `DATA_INTEGRITY_VIOLATION` — `POST /api/recipes/:id/like` | passed, 3/3 replays, score 0.94 | **MEDIUM** — 5 concurrent likes produce duplicate `likes` rows and ranking drift; corruption is durable |
| [`bug_02`](results/eathub/20260816T195551Z/reports/bug_02/report.json) | `CROSS_ACCOUNT_ACCESS` — `DELETE /api/comments/:id` | **rejected** at grade, score 0.05 | **NOT-A-BUG** — recipe owners deleting comments on their own recipes is the documented rule (`db.js:362-387`) |

`bug_02` is the interesting one: the oracle fired for real (actor 1 deleted
owner 2's comment, HTTP 200, 3/3 runs), and both the grade agent and the
report agent independently killed it as intended behaviour. The execution
evidence is necessary but not sufficient — a second reader still has to decide
whether the violated invariant was ever an invariant.

**Scope, honestly:**

- The sandbox seeds a disposable instance with synthetic fixtures and **Google
  OAuth, SMTP, and the Gemini integration all unconfigured and disabled by
  design** — see [`engagement_context.md`](targets/eathub/engagement_context.md)
  and the `attack_surface` note in [`config.yaml`](targets/eathub/config.yaml).
- That's a deliberate cut, not an oversight: a fake Google IdP inside the
  sandbox is new attack surface that can itself manufacture false positives.
  Deferred as v2 work.
- The effect: anything needing a real OAuth round-trip is out of reach —
  including both triaged findings that hinge on Google linking (account
  takeover, missing OAuth `state`).
- `targets/eathub/README.md`'s coverage table puts the pipeline's honest reach
  at **3 of the 7** triaged true positives (upload content-type confusion,
  CORS credential reflection, Host-header verification links). The other four
  are OAuth-gated, hardening-only with no reachable PoC (the session-secret
  fallback), or a measured non-issue (the ReDoS candidate ran in 0.26 ms at
  the body-size cap).
- The flagship finding — the check-then-act race in the like/ranking counter
  (`db.js:140-201`, `bug_00` above) — **isn't in the static triage list at
  all.** It was only found because the pipeline can fire concurrent requests
  at a live process. That's the argument for running it *alongside* the static
  scan, not instead of it.

---

## Where to look

- [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) — `/security-review` output (diff-only), 1 MEDIUM
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — EatHub's threat model
- [`VULN-FINDINGS.md`](VULN-FINDINGS.md) — raw static scan (`/vuln-scan`), 13 findings
- [`TRIAGE.md`](TRIAGE.md) — triaged static findings, 2 HIGH / 4 MEDIUM / 1 LOW
- [`results/eathub/20260816T195551Z/`](results/eathub/20260816T195551Z/) — the pipeline run: focus areas, found bugs, grade verdicts, transcripts
  - [`reports/manifest.jsonl`](results/eathub/20260816T195551Z/reports/manifest.jsonl) — bug-id assignments
  - [`reports/judge_log.jsonl`](results/eathub/20260816T195551Z/reports/judge_log.jsonl) — NEW/DUP verdicts with reasoning
  - [`reports/bug_01/report.json`](results/eathub/20260816T195551Z/reports/bug_01/report.json) — the HIGH (stored SVG XSS)
  - [`reports/bug_00/report.json`](results/eathub/20260816T195551Z/reports/bug_00/report.json) — the MEDIUM (like/ranking race)
- [`targets/eathub/`](targets/eathub/) — the vendored app, `run_poc.js` runner, oracle set, and the pipeline's coverage table against `TRIAGE.md`
- [`github.com/smacica/Eathub`](https://github.com/smacica/Eathub) — the real upstream app these scans target
- [`HARNESS-README.md`](HARNESS-README.md) — this repo's original upstream README (pipeline internals, setup, docs index)
- [`docs/blog-post.md`](docs/blog-post.md) — the discovery → triage → patch loop, and using a threat model to scope discovery and calibrate triage severity
